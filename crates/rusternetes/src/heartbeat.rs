//! **The control-plane components' heartbeats.**
//!
//! The all-in-one runs the API server, the scheduler and the controller manager as tasks of one
//! process, and a task that ends (an error, a panic) leaves the process running. So each one
//! says it is alive the way the kubelet does (`kube-node-lease`): a Lease in `kube-system`
//! named `<component>-<node>` (`kube-apiserver-cp`, `kube-scheduler-cp`,
//! `kube-controller-manager-cp`), labelled `tunnr.io/component-heartbeat=<component>`, its
//! `renewTime` moved every [`EVERY`] while the component's task runs. The API server's beat
//! also needs its port to accept a connection. A rolling upgrade reads these to know a control
//! plane is up again; a component that stopped stops renewing.

use std::sync::Arc;
use std::time::Duration;

use rusternetes_common::resources::{Lease, LeaseSpec};
use rusternetes_storage::{Storage, StorageBackend};

/// Whether a component is alive (its task runs, or it stands by for the control-plane lease).
pub type Alive = Arc<dyn Fn() -> bool + Send + Sync>;

/// How often a beat renews.
pub const EVERY: Duration = Duration::from_secs(10);
/// The label each heartbeat Lease carries, its value the component.
pub const LABEL: &str = "tunnr.io/component-heartbeat";

/// The Lease name of `component` on `node`.
pub fn lease_name(component: &str, node: &str) -> String {
    format!("{component}-{node}")
}

async fn renew(storage: &StorageBackend, component: &str, node: &str) {
    let name = lease_name(component, node);
    let key = format!("/registry/leases/kube-system/{name}");
    let now = chrono::Utc::now();
    match storage.get::<Lease>(&key).await {
        Ok(mut lease) => {
            if let Some(spec) = lease.spec.as_mut() {
                spec.renew_time = Some(now);
            }
            if let Err(e) = storage.update(&key, &lease).await {
                tracing::warn!("heartbeat {name}: update failed: {e}");
            }
        }
        Err(_) => {
            let mut lease = Lease::new(name.clone(), "kube-system").with_spec(LeaseSpec {
                holder_identity: Some(node.to_string()),
                lease_duration_seconds: Some(40),
                acquire_time: Some(now),
                renew_time: Some(now),
                lease_transitions: Some(0),
                preferred_holder: None,
                strategy: None,
            });
            let mut labels = std::collections::HashMap::new();
            labels.insert(LABEL.to_string(), component.to_string());
            lease.metadata.labels = Some(labels.into_iter().collect());
            if let Err(e) = storage.create(&key, &lease).await {
                tracing::warn!("heartbeat {name}: create failed: {e}");
            }
        }
    }
}

/// Renew each component's Lease while it is alive ([`Alive`]); the API server's while its port
/// answers.
pub fn spawn(
    storage: Arc<StorageBackend>,
    node: String,
    tasks: Vec<(&'static str, Alive)>,
    api_server: bool,
    api_bind: String,
) {
    tokio::spawn(async move {
        let api_port = api_bind.rsplit_once(':').map(|(_, p)| p.to_string()).unwrap_or_else(|| "6443".into());
        let mut timer = tokio::time::interval(EVERY);
        loop {
            timer.tick().await;
            if api_server
                && tokio::net::TcpStream::connect(format!("127.0.0.1:{api_port}")).await.is_ok()
            {
                renew(&storage, "kube-apiserver", &node).await;
            }
            for (component, alive) in &tasks {
                if alive() {
                    renew(&storage, component, &node).await;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_heartbeat_lease_is_named_by_component_and_node() {
        assert_eq!(super::lease_name("kube-scheduler", "cp"), "kube-scheduler-cp");
    }
}
