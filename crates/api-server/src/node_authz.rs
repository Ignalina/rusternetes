//! **The cluster's authorizer**: the Node authorizer for node certificates,
//! RBAC for everyone else (and for what the Node authorizer has no opinion
//! on), `system:masters` the admin.
//!
//! A node is `CN=system:node:<node>` in group `system:nodes` (the certificate
//! the join door issues). Through the API server it gets what a kubelet and
//! a node proxy need, the same as the served store's per-node limits
//! (tunnr-etcd `authz`) and upstream's Node authorizer + NodeRestriction:
//!
//! | resource | allowed |
//! |---|---|
//! | nodes | get/list/watch; create, update, patch (incl. status) of its own Node only |
//! | leases (coordination.k8s.io) | its own Lease in `kube-node-lease`: get, create, update, patch |
//! | csinodes (storage.k8s.io) | get/list/watch; create, update, patch of its own only |
//! | pods | get/list/watch; update, patch (incl. status) and delete of pods bound to it (`spec.nodeName`) |
//! | events (core, events.k8s.io) | create, update, patch |
//! | services, endpoints, endpointslices, volumeattachments, csidrivers, runtimeclasses | get/list/watch |
//! | namespaces | get |
//! | secrets, configmaps, persistentvolumeclaims, serviceaccounts | get, only when a pod bound to it refers to it |
//! | persistentvolumes | get, only when bound to such a claim |
//! | tokenreviews, subjectaccessreviews | create |
//! | configmaps `kube-system/<prefix><node>` (with [`ClusterAuthorizer::with_node_configmaps`]) | get any node's; create, update, patch its own (a node publishes facts its peers read, e.g. a WireGuard public key) |
//!
//! Everything else goes to RBAC, where `system:nodes` has no binding: 403.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use rusternetes_common::auth::UserInfo;
use rusternetes_common::authz::{Authorizer, Decision, RBACAuthorizer, RequestAttributes};
use rusternetes_common::Result;
use rusternetes_storage::{build_key, build_prefix, Storage, StorageBackend};
use serde_json::Value;

/// The node a user is, when it is one (`system:node:<node>` in `system:nodes`).
pub fn node_of(user: &UserInfo) -> Option<&str> {
    let node = user.username.strip_prefix("system:node:")?;
    (!node.is_empty() && user.groups.iter().any(|g| g == "system:nodes")).then_some(node)
}

/// Node authorizer, then RBAC.
pub struct ClusterAuthorizer {
    storage: Arc<StorageBackend>,
    rbac: RBACAuthorizer<StorageBackend>,
    /// `kube-system/<prefix><node>` ConfigMaps nodes publish (`--node-configmap-prefix`).
    node_configmap_prefix: Option<String>,
}

/// The namespace of the ConfigMaps nodes publish.
pub const NODE_CONFIGMAP_NAMESPACE: &str = "kube-system";

impl ClusterAuthorizer {
    pub fn new(storage: Arc<StorageBackend>) -> Self {
        Self { rbac: RBACAuthorizer::new(storage.clone()), storage, node_configmap_prefix: None }
    }

    /// Nodes publish ConfigMaps `kube-system/<prefix><node>`: each node may
    /// get every node's, and create, update and patch its own; never list
    /// (kube-system holds other ConfigMaps).
    pub fn with_node_configmaps(mut self, prefix: Option<String>) -> Self {
        self.node_configmap_prefix = prefix.filter(|p| !p.is_empty());
        self
    }

    /// The pods bound to `node`, in `namespace` (all namespaces: `None`).
    async fn bound_pods(&self, node: &str, namespace: Option<&str>) -> Result<Vec<Value>> {
        let pods: Vec<Value> = self.storage.list(&build_prefix("pods", namespace)).await?;
        Ok(pods
            .into_iter()
            .filter(|p| p.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node))
            .collect())
    }

    /// Does a pod bound to `node` in `namespace` refer to `resource`/`name`?
    async fn referenced(&self, node: &str, namespace: &str, resource: &str, name: &str) -> Result<bool> {
        for pod in self.bound_pods(node, Some(namespace)).await? {
            if pod_refs(&pod, resource).contains(name) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Is PersistentVolume `name` bound to a claim a pod bound to `node` uses?
    async fn pv_referenced(&self, node: &str, name: &str) -> Result<bool> {
        for pod in self.bound_pods(node, None).await? {
            let ns = pod.pointer("/metadata/namespace").and_then(Value::as_str).unwrap_or("default").to_string();
            for claim in pod_refs(&pod, "persistentvolumeclaims") {
                if let Ok(pvc) = self.storage.get::<Value>(&build_key("persistentvolumeclaims", Some(&ns), &claim)).await {
                    if pvc.pointer("/spec/volumeName").and_then(Value::as_str) == Some(name) {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Is pod `namespace`/`name` bound to `node`?
    async fn pod_bound(&self, node: &str, namespace: &str, name: &str) -> bool {
        self.storage
            .get::<Value>(&build_key("pods", Some(namespace), name))
            .await
            .ok()
            .is_some_and(|p| p.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node))
    }

    /// The Node authorizer's decision for `node` (true = allow).
    async fn node_allows(&self, node: &str, a: &RequestAttributes) -> Result<bool> {
        let v = a.verb.as_str();
        let read = matches!(v, "get" | "list" | "watch");
        let sub = a.subresource.as_deref();
        let own = a.name.as_deref() == Some(node);
        let write_own = own && matches!(v, "get" | "create" | "update" | "patch");
        Ok(match (a.api_group.as_str(), a.resource.as_str()) {
            ("", "nodes") => match sub {
                None => read || write_own,
                Some("status") => write_own,
                _ => false,
            },
            ("coordination.k8s.io", "leases") => {
                sub.is_none() && a.namespace.as_deref() == Some("kube-node-lease") && write_own
            }
            ("storage.k8s.io", "csinodes") => sub.is_none() && (read || write_own),
            ("", "pods") => match (sub, a.namespace.as_deref(), a.name.as_deref()) {
                (None, _, _) if read => true,
                (None | Some("status"), Some(ns), Some(name)) if matches!(v, "update" | "patch" | "delete") => {
                    self.pod_bound(node, ns, name).await
                }
                _ => false,
            },
            ("", "events") | ("events.k8s.io", "events") => matches!(v, "create" | "update" | "patch"),
            ("", "services")
            | ("", "endpoints")
            | ("discovery.k8s.io", "endpointslices")
            | ("storage.k8s.io", "volumeattachments")
            | ("storage.k8s.io", "csidrivers")
            | ("node.k8s.io", "runtimeclasses") => read && sub.is_none(),
            ("", "namespaces") => v == "get" && sub.is_none(),
            ("", "configmaps")
                if self.node_configmap_prefix.as_deref().is_some_and(|p| {
                    a.namespace.as_deref() == Some(NODE_CONFIGMAP_NAMESPACE)
                        && sub.is_none()
                        && a.name.as_deref().is_some_and(|n| n.starts_with(p))
                        && (v == "get" || (matches!(v, "create" | "update" | "patch") && a.name.as_deref() == Some(&format!("{p}{node}"))))
                }) =>
            {
                true
            }
            ("", r @ ("secrets" | "configmaps" | "persistentvolumeclaims" | "serviceaccounts")) => {
                match (v, sub, a.namespace.as_deref(), a.name.as_deref()) {
                    ("get", None, Some(ns), Some(name)) => self.referenced(node, ns, r, name).await?,
                    _ => false,
                }
            }
            ("", "persistentvolumes") => match (v, sub, a.name.as_deref()) {
                ("get", None, Some(name)) => self.pv_referenced(node, name).await?,
                _ => false,
            },
            ("authentication.k8s.io", "tokenreviews") | ("authorization.k8s.io", "subjectaccessreviews") => v == "create",
            _ => false,
        })
    }
}

/// What a pod refers to, by resource: Secrets (volumes incl. projected and
/// CSI, env, envFrom, imagePullSecrets, its ServiceAccount's
/// `<name>-token`), ConfigMaps (volumes incl. projected, env, envFrom),
/// PersistentVolumeClaims (volumes) and its ServiceAccount.
pub fn pod_refs(pod: &Value, resource: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let spec = match pod.get("spec") {
        Some(s) => s,
        None => return out,
    };
    let s = |v: Option<&Value>| v.and_then(Value::as_str).map(str::to_string);
    let arr = |v: Option<&Value>| v.and_then(Value::as_array).cloned().unwrap_or_default();
    let sa = s(spec.get("serviceAccountName")).unwrap_or_else(|| "default".to_string());
    let containers: Vec<Value> = ["containers", "initContainers", "ephemeralContainers"]
        .iter()
        .flat_map(|k| arr(spec.get(*k)))
        .collect();
    match resource {
        "secrets" => {
            out.insert(format!("{sa}-token"));
            for v in arr(spec.get("volumes")) {
                out.extend(s(v.pointer("/secret/secretName")));
                out.extend(s(v.pointer("/csi/nodePublishSecretRef/name")));
                for p in arr(v.pointer("/projected/sources")) {
                    out.extend(s(p.pointer("/secret/name")));
                }
            }
            for c in &containers {
                for e in arr(c.get("env")) {
                    out.extend(s(e.pointer("/valueFrom/secretKeyRef/name")));
                }
                for e in arr(c.get("envFrom")) {
                    out.extend(s(e.pointer("/secretRef/name")));
                }
            }
            for r in arr(spec.get("imagePullSecrets")) {
                out.extend(s(r.get("name")));
            }
        }
        "configmaps" => {
            for v in arr(spec.get("volumes")) {
                out.extend(s(v.pointer("/configMap/name")));
                for p in arr(v.pointer("/projected/sources")) {
                    out.extend(s(p.pointer("/configMap/name")));
                }
            }
            for c in &containers {
                for e in arr(c.get("env")) {
                    out.extend(s(e.pointer("/valueFrom/configMapKeyRef/name")));
                }
                for e in arr(c.get("envFrom")) {
                    out.extend(s(e.pointer("/configMapRef/name")));
                }
            }
        }
        "persistentvolumeclaims" => {
            for v in arr(spec.get("volumes")) {
                out.extend(s(v.pointer("/persistentVolumeClaim/claimName")));
            }
        }
        "serviceaccounts" => {
            out.insert(sa);
        }
        _ => {}
    }
    out
}

#[async_trait]
impl Authorizer for ClusterAuthorizer {
    async fn authorize(&self, attrs: &RequestAttributes) -> Result<Decision> {
        if let Some(node) = node_of(&attrs.user) {
            if self.node_allows(node, attrs).await? {
                return Ok(Decision::Allow);
            }
            return Ok(match self.rbac.authorize(attrs).await? {
                Decision::Allow => Decision::Allow,
                Decision::Deny(_) => Decision::Deny(format!(
                    "node {node} may not {} {}{}{} (Node authorizer)",
                    attrs.verb,
                    attrs.resource,
                    attrs.subresource.as_deref().map(|s| format!("/{s}")).unwrap_or_default(),
                    attrs.namespace.as_deref().map(|n| format!(" in namespace {n}")).unwrap_or_default(),
                )),
            });
        }
        self.rbac.authorize(attrs).await
    }

    async fn get_user_rules(
        &self,
        user: &UserInfo,
        namespace: &str,
    ) -> Result<(
        Vec<rusternetes_common::resources::ResourceRule>,
        Vec<rusternetes_common::resources::NonResourceRule>,
    )> {
        self.rbac.get_user_rules(user, namespace).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_storage::memory::MemoryStorage;
    use serde_json::json;

    fn user(name: &str, groups: &[&str]) -> UserInfo {
        UserInfo {
            username: name.into(),
            uid: String::new(),
            groups: groups.iter().map(|g| g.to_string()).chain(["system:authenticated".to_string()]).collect(),
            extra: Default::default(),
        }
    }

    async fn cluster() -> ClusterAuthorizer {
        let st = Arc::new(StorageBackend::Memory(Arc::new(MemoryStorage::new())));
        let pod = |name: &str, node: &str, secret: &str, cm: &str, claim: &str| {
            json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "default"},
                   "spec": {"nodeName": node, "serviceAccountName": "web",
                            "containers": [{"name": "c", "image": "x", "env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": secret, "key": "k"}}}]}],
                            "volumes": [{"name": "v", "configMap": {"name": cm}}, {"name": "d", "persistentVolumeClaim": {"claimName": claim}},
                                        {"name": "kube-api-access", "projected": {"sources": [{"configMap": {"name": "kube-root-ca.crt"}}]}}]}})
        };
        st.create(&build_key("pods", Some("default"), "a"), &pod("a", "w1", "s-a", "cm-a", "pvc-a")).await.unwrap();
        st.create(&build_key("pods", Some("default"), "b"), &pod("b", "w2", "s-b", "cm-b", "pvc-b")).await.unwrap();
        for (claim, vol) in [("pvc-a", "pv-a"), ("pvc-b", "pv-b")] {
            st.create(&build_key("persistentvolumeclaims", Some("default"), claim),
                      &json!({"metadata": {"name": claim, "namespace": "default"}, "spec": {"volumeName": vol}})).await.unwrap();
        }
        ClusterAuthorizer::new(st)
    }

    async fn allowed(az: &ClusterAuthorizer, u: &UserInfo, verb: &str, group: &str, res: &str, ns: Option<&str>, name: Option<&str>, sub: Option<&str>) -> bool {
        let mut a = RequestAttributes::new(u.clone(), verb, res).with_api_group(group);
        if let Some(n) = ns { a = a.with_namespace(n); }
        if let Some(n) = name { a = a.with_name(n); }
        if let Some(s) = sub { a = a.with_subresource(s); }
        az.authorize(&a).await.unwrap() == Decision::Allow
    }

    #[tokio::test]
    async fn a_node_gets_its_own_objects_only() {
        let az = cluster().await;
        let w1 = user("system:node:w1", &["system:nodes"]);
        let d = Some("default");
        // Its own Node, Lease, CSINode; reads of every Node.
        assert!(allowed(&az, &w1, "update", "", "nodes", None, Some("w1"), Some("status")).await);
        assert!(allowed(&az, &w1, "create", "", "nodes", None, Some("w1"), None).await);
        assert!(allowed(&az, &w1, "get", "", "nodes", None, Some("w2"), None).await);
        assert!(!allowed(&az, &w1, "update", "", "nodes", None, Some("w2"), Some("status")).await);
        assert!(!allowed(&az, &w1, "patch", "", "nodes", None, Some("w2"), None).await);
        assert!(!allowed(&az, &w1, "delete", "", "nodes", None, Some("w2"), None).await);
        assert!(!allowed(&az, &w1, "create", "", "nodes", None, None, None).await);
        assert!(allowed(&az, &w1, "update", "coordination.k8s.io", "leases", Some("kube-node-lease"), Some("w1"), None).await);
        assert!(!allowed(&az, &w1, "update", "coordination.k8s.io", "leases", Some("kube-node-lease"), Some("w2"), None).await);
        assert!(!allowed(&az, &w1, "update", "coordination.k8s.io", "leases", Some("kube-system"), Some("w1"), None).await);
        assert!(allowed(&az, &w1, "create", "storage.k8s.io", "csinodes", None, Some("w1"), None).await);
        assert!(!allowed(&az, &w1, "create", "storage.k8s.io", "csinodes", None, Some("w2"), None).await);
        // Pods: read all, write only its own.
        assert!(allowed(&az, &w1, "list", "", "pods", None, None, None).await);
        assert!(allowed(&az, &w1, "patch", "", "pods", d, Some("a"), Some("status")).await);
        assert!(!allowed(&az, &w1, "patch", "", "pods", d, Some("b"), Some("status")).await);
        assert!(!allowed(&az, &w1, "delete", "", "pods", d, Some("b"), None).await);
        assert!(!allowed(&az, &w1, "create", "", "pods", d, None, None).await);
        // Secrets, ConfigMaps, claims and volumes its pods use; no others, no lists.
        assert!(allowed(&az, &w1, "get", "", "secrets", d, Some("s-a"), None).await);
        assert!(allowed(&az, &w1, "get", "", "secrets", d, Some("web-token"), None).await);
        assert!(!allowed(&az, &w1, "get", "", "secrets", d, Some("s-b"), None).await);
        assert!(!allowed(&az, &w1, "list", "", "secrets", d, None, None).await);
        assert!(!allowed(&az, &w1, "watch", "", "secrets", None, None, None).await);
        assert!(allowed(&az, &w1, "get", "", "configmaps", d, Some("cm-a"), None).await);
        assert!(allowed(&az, &w1, "get", "", "configmaps", d, Some("kube-root-ca.crt"), None).await);
        assert!(!allowed(&az, &w1, "get", "", "configmaps", d, Some("cm-b"), None).await);
        assert!(!allowed(&az, &w1, "update", "", "configmaps", d, Some("cm-a"), None).await);
        assert!(allowed(&az, &w1, "get", "", "persistentvolumeclaims", d, Some("pvc-a"), None).await);
        assert!(!allowed(&az, &w1, "get", "", "persistentvolumeclaims", d, Some("pvc-b"), None).await);
        assert!(allowed(&az, &w1, "get", "", "persistentvolumes", None, Some("pv-a"), None).await);
        assert!(!allowed(&az, &w1, "get", "", "persistentvolumes", None, Some("pv-b"), None).await);
        // Workloads, RBAC, cluster-scoped writes, other namespaces' objects: refused.
        assert!(!allowed(&az, &w1, "create", "apps", "deployments", d, None, None).await);
        assert!(!allowed(&az, &w1, "create", "rbac.authorization.k8s.io", "clusterrolebindings", None, None, None).await);
        assert!(!allowed(&az, &w1, "create", "", "namespaces", None, None, None).await);
        assert!(!allowed(&az, &w1, "delete", "", "namespaces", None, Some("default"), None).await);
        assert!(!allowed(&az, &w1, "create", "apiextensions.k8s.io", "customresourcedefinitions", None, None, None).await);
        assert!(!allowed(&az, &w1, "get", "", "pods", d, Some("a"), Some("exec")).await);
        assert!(allowed(&az, &w1, "create", "", "events", d, None, None).await);
        assert!(allowed(&az, &w1, "list", "", "services", None, None, None).await);
        // The name alone is not a node: system:nodes is needed.
        let fake = user("system:node:w1", &[]);
        assert!(!allowed(&az, &fake, "get", "", "nodes", None, Some("w1"), None).await);
    }

    #[tokio::test]
    async fn nodes_publish_their_own_prefixed_configmap_and_read_the_others() {
        let st = Arc::new(StorageBackend::Memory(Arc::new(MemoryStorage::new())));
        let w1 = user("system:node:w1", &["system:nodes"]);
        let ks = Some("kube-system");
        let off = ClusterAuthorizer::new(st.clone());
        assert!(!allowed(&off, &w1, "create", "", "configmaps", ks, Some("tunnr-wg-w1"), None).await);
        let az = ClusterAuthorizer::new(st).with_node_configmaps(Some("tunnr-wg-".into()));
        assert!(allowed(&az, &w1, "create", "", "configmaps", ks, Some("tunnr-wg-w1"), None).await);
        assert!(allowed(&az, &w1, "update", "", "configmaps", ks, Some("tunnr-wg-w1"), None).await);
        assert!(allowed(&az, &w1, "get", "", "configmaps", ks, Some("tunnr-wg-w2"), None).await);
        assert!(!allowed(&az, &w1, "update", "", "configmaps", ks, Some("tunnr-wg-w2"), None).await);
        assert!(!allowed(&az, &w1, "delete", "", "configmaps", ks, Some("tunnr-wg-w2"), None).await);
        assert!(!allowed(&az, &w1, "list", "", "configmaps", ks, None, None).await);
        assert!(!allowed(&az, &w1, "get", "", "configmaps", ks, Some("tunnr-join-tokens"), None).await);
        assert!(!allowed(&az, &w1, "create", "", "configmaps", Some("default"), Some("tunnr-wg-w1"), None).await);
        assert!(!allowed(&az, &w1, "create", "", "configmaps", ks, None, None).await);
    }

    #[tokio::test]
    async fn masters_are_admin_and_others_need_rbac() {
        let az = cluster().await;
        let admin = user("admin", &["system:masters"]);
        assert!(allowed(&az, &admin, "create", "apps", "deployments", Some("default"), None, None).await);
        assert!(allowed(&az, &admin, "get", "", "secrets", Some("default"), Some("s-b"), None).await);
        let sa = user("system:serviceaccount:default:web", &["system:serviceaccounts"]);
        assert!(!allowed(&az, &sa, "list", "", "pods", None, None, None).await);
        let srv = user("rusternetes-apiserver", &[]);
        assert!(!allowed(&az, &srv, "list", "", "secrets", None, None, None).await);
    }
}
