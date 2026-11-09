//! Which pod a container (or a CNI attachment) on this node belongs to.
//!
//! The node names a pod's containers `<pod>_<container>`, its sandbox
//! `<pod>_pause`. A pod name is a DNS-1123 subdomain and a container name a
//! DNS-1123 label: neither holds `_`, so a name splits at its first `_` into
//! one pod name and one container name. A pod's containers are the names whose
//! pod part IS the pod's name: `func-web_main` holds `web_` but is pod
//! `func-web`'s, never pod `web`'s. A substring match on `web_` gave pod `web`
//! the IP of `func-web_main` (another namespace), and stopped and removed
//! that pod's containers with `web`'s.
//!
//! The name is the pod's name alone, not its namespace, so two pods of one
//! name in two namespaces share it. Each container therefore also carries its
//! pod's identity as labels (the CRI runtimes' keys), and each CNI attachment
//! its pod's `CNI_ARGS`: a container or an attachment that names another pod
//! is never this pod's. Containers made before the labels existed name no pod
//! ([`Claim::is_anonymous`]); for them only the name speaks.

use std::collections::HashMap;

use rusternetes_common::resources::Pod;

use crate::backend::ContainerSummary;

/// The label with the name of a container's pod.
pub const POD_NAME_LABEL: &str = "io.kubernetes.pod.name";
/// The label with the namespace of a container's pod.
pub const POD_NAMESPACE_LABEL: &str = "io.kubernetes.pod.namespace";
/// The label with the uid of a container's pod.
pub const POD_UID_LABEL: &str = "io.kubernetes.pod.uid";

/// The pod's namespace (`default` when it names none, as the kubelet reads it).
pub fn namespace(pod: &Pod) -> &str {
    pod.metadata.namespace.as_deref().unwrap_or("default")
}

/// The pod name and the container name of a node container name (with or
/// without Docker's leading `/`).
pub fn split(name: &str) -> Option<(&str, &str)> {
    name.trim_start_matches('/').split_once('_')
}

/// Whether the container `name` is named for pod `pod_name`.
pub fn is_named_for(name: &str, pod_name: &str) -> bool {
    split(name).is_some_and(|(pod, _)| pod == pod_name)
}

/// Whether the container `name` is a pod's sandbox (`<pod>_pause`).
pub fn is_pause(name: &str) -> bool {
    split(name).is_some_and(|(_, container)| container == "pause")
}

/// The backend's name filter for pod `pod_name`'s containers. A first cut
/// only: Docker reads it as a regular expression, where a `.` of a pod name
/// matches any character; [`is_named_for`] is the exact test.
pub fn name_filter(pod_name: &str) -> String {
    format!("^/{}_", pod_name)
}

/// Whether a listed container is named for pod `pod_name`.
pub fn summary_is_named_for(c: &ContainerSummary, pod_name: &str) -> bool {
    c.names
        .as_ref()
        .is_some_and(|names| names.iter().any(|n| is_named_for(n, pod_name)))
}

/// A listed container's name, without the leading `/`.
pub fn summary_name(c: &ContainerSummary) -> &str {
    c.names
        .as_ref()
        .and_then(|names| names.first())
        .map(|n| n.trim_start_matches('/'))
        .unwrap_or("")
}

/// The identity labels the node puts on every container of `pod`.
pub fn labels(pod: &Pod) -> HashMap<String, String> {
    let mut labels = HashMap::from([
        (POD_NAME_LABEL.to_string(), pod.metadata.name.clone()),
        (POD_NAMESPACE_LABEL.to_string(), namespace(pod).to_string()),
    ]);
    if !pod.metadata.uid.is_empty() {
        labels.insert(POD_UID_LABEL.to_string(), pod.metadata.uid.clone());
    }
    labels
}

/// The pod a container's labels or an attachment's `CNI_ARGS` name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claim {
    pub namespace: Option<String>,
    pub name: Option<String>,
    pub uid: Option<String>,
}

impl Claim {
    /// The pod a container's labels name.
    pub fn from_labels(labels: Option<&HashMap<String, String>>) -> Self {
        let get = |k: &str| {
            labels
                .and_then(|l| l.get(k))
                .filter(|v| !v.is_empty())
                .cloned()
        };
        Self {
            namespace: get(POD_NAMESPACE_LABEL),
            name: get(POD_NAME_LABEL),
            uid: get(POD_UID_LABEL),
        }
    }

    /// The pod a CNI attachment's `CNI_ARGS` name
    /// (`K8S_POD_NAMESPACE=…;K8S_POD_NAME=…;K8S_POD_UID=…`).
    pub fn from_cni_args(args: Option<&str>) -> Self {
        let mut claim = Self::default();
        for pair in args.unwrap_or("").split(';') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            if v.is_empty() {
                continue;
            }
            match k {
                "K8S_POD_NAMESPACE" => claim.namespace = Some(v.to_string()),
                "K8S_POD_NAME" => claim.name = Some(v.to_string()),
                "K8S_POD_UID" => claim.uid = Some(v.to_string()),
                _ => {}
            }
        }
        claim
    }

    /// Names no pod (made before identities were kept): only the name speaks.
    pub fn is_anonymous(&self) -> bool {
        self.namespace.is_none() && self.name.is_none() && self.uid.is_none()
    }

    /// Whether this names `pod`: its namespace and its name, and its uid when
    /// both have one (an earlier pod of the same name is another pod).
    pub fn is_of(&self, pod: &Pod) -> bool {
        let ns_ok = self
            .namespace
            .as_deref()
            .is_none_or(|n| n == namespace(pod));
        let name_ok = self.name.as_deref().is_none_or(|n| n == pod.metadata.name);
        let uid_ok = match self.uid.as_deref() {
            Some(uid) if !pod.metadata.uid.is_empty() => uid == pod.metadata.uid,
            _ => true,
        };
        ns_ok && name_ok && uid_ok
    }

    /// Whether this names a pod of another namespace than `pod`'s.
    pub fn is_other_namespace(&self, pod: &Pod) -> bool {
        self.namespace
            .as_deref()
            .is_some_and(|n| n != namespace(pod))
    }
}

impl std::fmt::Display for Claim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}",
            self.namespace.as_deref().unwrap_or("?"),
            self.name.as_deref().unwrap_or("?")
        )?;
        if let Some(uid) = &self.uid {
            write!(f, " (uid {uid})")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(namespace: &str, name: &str, uid: &str) -> Pod {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": namespace, "uid": uid},
            "spec": {"containers": []}
        }))
        .unwrap()
    }

    #[test]
    fn a_name_is_a_pods_by_its_structure_never_by_a_piece_of_it() {
        assert_eq!(split("/web_main"), Some(("web", "main")));
        assert_eq!(split("func-web_main"), Some(("func-web", "main")));
        assert!(is_named_for("/web_main", "web"));
        assert!(is_named_for("web_pause", "web"));
        assert!(!is_named_for("/func-web_main", "web"));
        assert!(!is_named_for("/func-web_pause", "web"));
        assert!(!is_named_for("/web-2_main", "web"));
        assert!(!is_named_for("/web", "web"));
        assert!(!is_named_for("/rusternetes-api-server", "rusternetes"));
        assert!(is_pause("/web_pause"));
        assert!(!is_pause("/web_pause-helper"));
        assert!(!is_pause("/pause_main"));
    }

    #[test]
    fn labels_name_the_pod() {
        let l = labels(&pod("a", "web", "u-1"));
        assert_eq!(l[POD_NAMESPACE_LABEL], "a");
        assert_eq!(l[POD_NAME_LABEL], "web");
        assert_eq!(l[POD_UID_LABEL], "u-1");
        assert!(Claim::from_labels(Some(&l)).is_of(&pod("a", "web", "u-1")));
    }

    #[test]
    fn a_claim_is_of_a_pod_by_namespace_name_and_uid() {
        let a = pod("a", "web", "u-a");
        let claim = Claim::from_cni_args(Some(
            "IgnoreUnknown=1;K8S_POD_NAMESPACE=a;K8S_POD_NAME=web;K8S_POD_INFRA_CONTAINER_ID=x;K8S_POD_UID=u-a",
        ));
        assert!(claim.is_of(&a));
        assert!(!claim.is_other_namespace(&a));
        // The same name in namespace b is another pod.
        let b = pod("b", "web", "u-b");
        assert!(!claim.is_of(&b));
        assert!(claim.is_other_namespace(&b));
        // An earlier pod of the same name and namespace is another pod too,
        // but not another namespace's.
        let again = pod("a", "web", "u-a2");
        assert!(!claim.is_of(&again));
        assert!(!claim.is_other_namespace(&again));
        // A pod without a uid (made straight in the store) is told by its
        // namespace and name.
        assert!(claim.is_of(&pod("a", "web", "")));
        // Containers made before the labels name no pod: the name speaks.
        let anonymous = Claim::from_labels(None);
        assert!(anonymous.is_anonymous());
        assert!(anonymous.is_of(&b));
        assert!(!anonymous.is_other_namespace(&b));
        assert_eq!(claim.to_string(), "a/web (uid u-a)");
    }
}
