//! When a pod worker should look at its pod again while a readiness probe
//! still has to pass.
//!
//! Without this, the per-pod worker waited for its 5 s fallback timer or for
//! the next full sync tick, so a pod whose probe passed 0.2 s after its
//! container started was marked Ready only on the next tick (0.2, 1.0, 1.9,
//! 2.9 s ...). Kubernetes runs each readiness probe on its own
//! `periodSeconds` after `initialDelaySeconds`.
//!
//! The rule here: while a container with a readiness probe is not Ready, the
//! worker re-syncs after a short wait that starts at [`FIRST_WAIT`] and
//! doubles per attempt, never longer than the probe's `periodSeconds`, and
//! never before `initialDelaySeconds` has passed since the container started.
//! Once every probed container is Ready, the worker falls back to its normal
//! timer.

use chrono::{DateTime, Utc};
use rusternetes_common::resources::{ContainerState, Pod};
use std::time::Duration;

/// The first re-check after a container with a readiness probe starts.
pub const FIRST_WAIT: Duration = Duration::from_millis(100);

/// Kubernetes' default `periodSeconds`.
const DEFAULT_PERIOD_SECS: i32 = 10;

/// How long the pod worker waits before it syncs `pod` again.
///
/// `attempt` counts the fast re-checks done since the pod last had every
/// probed container Ready (0 for the first). `fallback` is the worker's
/// normal timer; the answer is never longer than it.
pub fn readiness_wait(pod: &Pod, attempt: u32, fallback: Duration, now: DateTime<Utc>) -> Duration {
    if pod.metadata.deletion_timestamp.is_some() {
        return fallback;
    }
    let Some(spec) = pod.spec.as_ref() else {
        return fallback;
    };
    let statuses = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref());
    let mut wait: Option<Duration> = None;
    for c in &spec.containers {
        let Some(probe) = c.readiness_probe.as_ref() else {
            continue;
        };
        let status = statuses.and_then(|v| v.iter().find(|s| s.name == c.name));
        if status.map(|s| s.ready).unwrap_or(false) {
            continue;
        }
        let period =
            Duration::from_secs(probe.period_seconds.unwrap_or(DEFAULT_PERIOD_SECS).max(1) as u64);
        let fast = FIRST_WAIT
            .checked_mul(1u32 << attempt.min(16))
            .unwrap_or(period)
            .min(period);
        // Not before initialDelaySeconds since the container started.
        let delay = probe.initial_delay_seconds.unwrap_or(0).max(0) as i64;
        let started = status.and_then(|s| match &s.state {
            Some(ContainerState::Running { started_at }) => *started_at,
            _ => None,
        });
        let until_delay = started
            .map(|t| t + chrono::Duration::seconds(delay) - now)
            .and_then(|d| d.to_std().ok())
            .unwrap_or(Duration::ZERO);
        let this = fast.max(until_delay);
        wait = Some(wait.map_or(this, |w| w.min(this)));
    }
    wait.map_or(fallback, |w| w.min(fallback))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_common::resources::{
        Container, ContainerStatus, HTTPGetAction, PodSpec, PodStatus, Probe,
    };

    const FALLBACK: Duration = Duration::from_secs(5);

    fn probe(period: i32, delay: Option<i32>) -> Probe {
        Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/".into()),
                port: serde_json::from_value(serde_json::json!(80)).unwrap(),
                host: None,
                scheme: None,
                http_headers: None,
            }),
            tcp_socket: None,
            exec: None,
            initial_delay_seconds: delay,
            timeout_seconds: None,
            period_seconds: Some(period),
            success_threshold: None,
            failure_threshold: None,
            grpc: None,
            termination_grace_period_seconds: None,
        }
    }

    fn pod(p: Option<Probe>, ready: Option<bool>, started: Option<DateTime<Utc>>) -> Pod {
        let mut container: Container =
            serde_json::from_value(serde_json::json!({"name": "nginx", "image": "nginx"})).unwrap();
        container.readiness_probe = p;
        let mut pod: Pod = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": "bench-start-1", "namespace": "default"},
            "spec": {"containers": []}
        }))
        .unwrap();
        pod.spec = Some(PodSpec {
            containers: vec![container],
            ..pod.spec.unwrap()
        });
        if let Some(r) = ready {
            let mut cs: ContainerStatus =
                serde_json::from_value(serde_json::json!({"name": "nginx", "ready": r, "restartCount": 0, "image": "nginx", "imageID": ""}))
                    .unwrap();
            cs.ready = r;
            cs.state = Some(ContainerState::Running {
                started_at: started,
            });
            let mut st: PodStatus = serde_json::from_value(serde_json::json!({})).unwrap();
            st.container_statuses = Some(vec![cs]);
            pod.status = Some(st);
        }
        pod
    }

    /// The bench's case: nginx with `periodSeconds: 1` answers its probe
    /// 0.15 s after the container started. Simulate the worker: sync, wait
    /// `readiness_wait`, sync again; the sync that runs the probe at or after
    /// 0.15 s marks the pod Ready. That must happen within 0.3 s.
    #[test]
    fn a_probe_that_passes_at_once_is_ready_within_0_3_s_of_start() {
        let t0: DateTime<Utc> = "2026-11-02T14:00:00Z".parse().unwrap();
        let passes_at = chrono::Duration::milliseconds(150);
        let mut t = t0;
        let mut attempt = 0;
        // First sync after the start: the status is not written yet.
        let mut p = pod(Some(probe(1, None)), None, None);
        loop {
            t += chrono::Duration::from_std(readiness_wait(&p, attempt, FALLBACK, t)).unwrap();
            attempt += 1;
            if t - t0 >= passes_at {
                break;
            }
            p = pod(Some(probe(1, None)), Some(false), Some(t0));
        }
        let took = (t - t0).to_std().unwrap();
        assert!(
            took <= Duration::from_millis(300),
            "Ready {took:?} after start"
        );
    }

    #[test]
    fn the_wait_never_exceeds_period_seconds() {
        let now: DateTime<Utc> = "2026-11-02T14:00:00Z".parse().unwrap();
        let p = pod(Some(probe(1, None)), Some(false), Some(now));
        for attempt in 0..20 {
            assert!(readiness_wait(&p, attempt, FALLBACK, now) <= Duration::from_secs(1));
        }
        assert_eq!(readiness_wait(&p, 0, FALLBACK, now), FIRST_WAIT);
    }

    #[test]
    fn initial_delay_seconds_is_honoured() {
        let started: DateTime<Utc> = "2026-11-02T14:00:00Z".parse().unwrap();
        let now = started + chrono::Duration::milliseconds(500);
        let p = pod(Some(probe(1, Some(2))), Some(false), Some(started));
        let wait = readiness_wait(&p, 0, FALLBACK, now);
        assert!(wait >= Duration::from_millis(1500), "{wait:?}");
        assert!(wait <= Duration::from_millis(1600), "{wait:?}");
    }

    #[test]
    fn ready_or_unprobed_pods_keep_the_normal_timer() {
        let now: DateTime<Utc> = "2026-11-02T14:00:00Z".parse().unwrap();
        assert_eq!(
            readiness_wait(
                &pod(Some(probe(1, None)), Some(true), Some(now)),
                0,
                FALLBACK,
                now
            ),
            FALLBACK
        );
        assert_eq!(
            readiness_wait(&pod(None, None, None), 0, FALLBACK, now),
            FALLBACK
        );
    }
}
