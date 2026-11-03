//! Custom resources nodes write about themselves (tunnr's `disks.tunnr.io`
//! views of a node's drives and volumes), end to end through the router with
//! authentication on: the Node authorizer's `--node-named-resource` and
//! `--node-status-resource` rules, the status subresource's merge patch, a
//! viewer ClusterRole, and the CRD's printer columns as a Table.

use axum::{
    body::Body,
    http::{Method, Request},
};
use rusternetes_api_server::authn::PeerIdentity;
use rusternetes_api_server::node_authz::ClusterAuthorizer;
use rusternetes_api_server::{router::build_router, state::ApiServerState};
use rusternetes_common::auth::{TokenManager, UserInfo};
use rusternetes_common::observability::MetricsRegistry;
use rusternetes_storage::{memory::MemoryStorage, StorageBackend};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const G: &str = "/apis/disks.tunnr.io/v1alpha1";

fn cluster() -> axum::Router {
    let backend = Arc::new(StorageBackend::Memory(Arc::new(MemoryStorage::new())));
    let az = ClusterAuthorizer::new(backend.clone()).with_node_resources(
        &["tunnrdisks.disks.tunnr.io".into()],
        &["tunnrvolumes.disks.tunnr.io=tunnr.io/node".into()],
    );
    let state = Arc::new(ApiServerState::new(
        backend,
        Arc::new(TokenManager::new_random()),
        Arc::new(az),
        Arc::new(MetricsRegistry::new()),
        false,
    ));
    build_router(state, None)
}

fn cert(cn: &str, groups: &[&str]) -> UserInfo {
    UserInfo {
        username: cn.into(),
        uid: String::new(),
        groups: groups
            .iter()
            .map(|g| g.to_string())
            .chain(["system:authenticated".into()])
            .collect(),
        extra: Default::default(),
    }
}

async fn call(
    r: &axum::Router,
    who: &UserInfo,
    method: Method,
    uri: &str,
    body: Option<Value>,
    accept: Option<&str>,
) -> (u16, Value) {
    let ctype = if method == Method::PATCH {
        "application/merge-patch+json"
    } else {
        "application/json"
    };
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", ctype);
    if let Some(a) = accept {
        b = b.header("accept", a);
    }
    let mut req = b
        .body(body.map_or(Body::empty(), |v| Body::from(v.to_string())))
        .unwrap();
    req.extensions_mut()
        .insert(PeerIdentity(Some(Arc::new(who.clone()))));
    let resp = r.clone().oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 16 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn crd(plural: &str, kind: &str, columns: Value) -> Value {
    json!({
        "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
        "metadata": {"name": format!("{plural}.disks.tunnr.io")},
        "spec": {
            "group": "disks.tunnr.io", "scope": "Cluster",
            "names": {"plural": plural, "singular": kind.to_lowercase(), "kind": kind, "listKind": format!("{kind}List")},
            "versions": [{
                "name": "v1alpha1", "served": true, "storage": true,
                "subresources": {"status": {}},
                "additionalPrinterColumns": columns,
                "schema": {"openAPIV3Schema": {"type": "object", "properties": {
                    "status": {"type": "object", "x-kubernetes-preserve-unknown-fields": true}}}}
            }]
        }
    })
}

fn obj(kind: &str, name: &str, node: &str) -> Value {
    json!({"apiVersion": "disks.tunnr.io/v1alpha1", "kind": kind, "metadata": {"name": name, "labels": {"tunnr.io/node": node}}})
}

#[tokio::test]
async fn nodes_write_their_own_views_viewers_only_read() {
    let r = cluster();
    let admin = cert("admin", &["system:masters"]);
    let w1 = cert("system:node:w1", &["system:nodes"]);
    let ui = cert("console", &["tunnr-disk-viewers"]);
    let cols = json!([
        {"name": "Node", "type": "string", "jsonPath": ".status.node"},
        {"name": "Size", "type": "string", "jsonPath": ".status.size"},
        {"name": "State", "type": "string", "jsonPath": ".status.state"},
        {"name": "Volumes", "type": "integer", "jsonPath": ".status.volumeCount"},
        {"name": "Reason", "type": "string", "jsonPath": ".status.reason", "priority": 1},
        {"name": "Age", "type": "date", "jsonPath": ".metadata.creationTimestamp"}
    ]);
    for (p, k) in [("tunnrdisks", "TunnrDisk"), ("tunnrvolumes", "TunnrVolume")] {
        let (s, b) = call(
            &r,
            &admin,
            Method::POST,
            "/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
            Some(crd(p, k, cols.clone())),
            None,
        )
        .await;
        assert_eq!(s, 201, "{b}");
    }

    // TunnrDisks: a node creates and updates its own (<node>.<drive>), never another's.
    let (s, b) = call(
        &r,
        &w1,
        Method::POST,
        &format!("{G}/tunnrdisks"),
        Some(obj("TunnrDisk", "w1.td-drv-a", "w1")),
        None,
    )
    .await;
    assert_eq!(s, 201, "{b}");
    let (s, _) = call(
        &r,
        &w1,
        Method::POST,
        &format!("{G}/tunnrdisks"),
        Some(obj("TunnrDisk", "w2.td-drv-a", "w2")),
        None,
    )
    .await;
    assert_eq!(s, 403, "another node's drive");
    let (s, _) = call(
        &r,
        &admin,
        Method::POST,
        &format!("{G}/tunnrdisks"),
        Some(obj("TunnrDisk", "w2.td-mir-b", "w2")),
        None,
    )
    .await;
    assert_eq!(s, 201);
    // Two status merge patches: both halves stay.
    let st = |v: Value| Some(json!({"status": v}));
    let (s, b) = call(
        &r,
        &w1,
        Method::PATCH,
        &format!("{G}/tunnrdisks/w1.td-drv-a/status"),
        st(json!({"node": "w1", "size": "9 GiB", "state": "in-use", "volumeCount": 1})),
        None,
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let (s, b) = call(
        &r,
        &w1,
        Method::PATCH,
        &format!("{G}/tunnrdisks/w1.td-drv-a/status"),
        st(json!({"reason": "", "health": "ok"})),
        None,
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let (_, got) = call(
        &r,
        &w1,
        Method::GET,
        &format!("{G}/tunnrdisks/w1.td-drv-a"),
        None,
        None,
    )
    .await;
    assert_eq!(
        (
            got["status"]["state"].as_str(),
            got["status"]["health"].as_str()
        ),
        (Some("in-use"), Some("ok")),
        "{got}"
    );
    let (s, _) = call(
        &r,
        &w1,
        Method::PATCH,
        &format!("{G}/tunnrdisks/w2.td-mir-b/status"),
        st(json!({"state": "refused"})),
        None,
    )
    .await;
    assert_eq!(s, 403);
    let (s, _) = call(
        &r,
        &w1,
        Method::DELETE,
        &format!("{G}/tunnrdisks/w2.td-mir-b"),
        None,
        None,
    )
    .await;
    assert_eq!(s, 403);
    let (s, l) = call(&r, &w1, Method::GET, &format!("{G}/tunnrdisks"), None, None).await;
    assert_eq!((s, l["items"].as_array().map(Vec::len)), (200, Some(2)));

    // TunnrVolumes: the control plane makes them; a node writes the status of the ones labelled for it.
    for (v, n) in [("pvc-a", "w1"), ("pvc-b", "w2")] {
        let (s, b) = call(
            &r,
            &admin,
            Method::POST,
            &format!("{G}/tunnrvolumes"),
            Some(obj("TunnrVolume", v, n)),
            None,
        )
        .await;
        assert_eq!(s, 201, "{b}");
    }
    let (s, _) = call(
        &r,
        &w1,
        Method::POST,
        &format!("{G}/tunnrvolumes"),
        Some(obj("TunnrVolume", "pvc-x", "w1")),
        None,
    )
    .await;
    assert_eq!(s, 403, "a node never creates a volume view");
    let (s, b) = call(&r, &w1, Method::PATCH, &format!("{G}/tunnrvolumes/pvc-a/status"), Some(json!({"metadata": {"labels": {"tunnr.io/node": "w2"}}, "status": {"local": {"mirror": "degraded"}}})), None).await;
    assert_eq!(s, 200, "{b}");
    let (_, got) = call(
        &r,
        &admin,
        Method::GET,
        &format!("{G}/tunnrvolumes/pvc-a"),
        None,
        None,
    )
    .await;
    assert_eq!(
        got["metadata"]["labels"]["tunnr.io/node"], "w1",
        "a status write does not move the label: {got}"
    );
    assert_eq!(got["status"]["local"]["mirror"], "degraded");
    let (s, _) = call(
        &r,
        &w1,
        Method::PATCH,
        &format!("{G}/tunnrvolumes/pvc-b/status"),
        Some(json!({"status": {"local": {}}})),
        None,
    )
    .await;
    assert_eq!(s, 403, "labelled for w2");
    let (s, _) = call(
        &r,
        &w1,
        Method::PATCH,
        &format!("{G}/tunnrvolumes/pvc-a"),
        Some(json!({"metadata": {"labels": {"tunnr.io/node": "w1"}}})),
        None,
    )
    .await;
    assert_eq!(s, 403, "the object itself is the control plane's");
    let (s, _) = call(
        &r,
        &w1,
        Method::DELETE,
        &format!("{G}/tunnrvolumes/pvc-a"),
        None,
        None,
    )
    .await;
    assert_eq!(s, 403);

    // A viewer: nothing until the ClusterRole is bound; then list and get, never write.
    let (s, _) = call(&r, &ui, Method::GET, &format!("{G}/tunnrdisks"), None, None).await;
    assert_eq!(s, 403);
    let (s, b) = call(&r, &admin, Method::POST, "/apis/rbac.authorization.k8s.io/v1/clusterroles", Some(json!({
        "metadata": {"name": "tunnr-disk-viewer"},
        "rules": [{"apiGroups": ["disks.tunnr.io"], "resources": ["tunnrdisks", "tunnrvolumes"], "verbs": ["get", "list", "watch"]}]})), None).await;
    assert_eq!(s, 201, "{b}");
    let (s, b) = call(&r, &admin, Method::POST, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", Some(json!({
        "metadata": {"name": "tunnr-disk-viewers"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "tunnr-disk-viewer"},
        "subjects": [{"kind": "Group", "name": "tunnr-disk-viewers", "apiGroup": "rbac.authorization.k8s.io"}]})), None).await;
    assert_eq!(s, 201, "{b}");
    for p in ["tunnrdisks", "tunnrvolumes"] {
        let (s, _) = call(&r, &ui, Method::GET, &format!("{G}/{p}"), None, None).await;
        assert_eq!(s, 200, "{p}");
    }
    let (s, _) = call(
        &r,
        &ui,
        Method::GET,
        &format!("{G}/tunnrvolumes/pvc-a"),
        None,
        None,
    )
    .await;
    assert_eq!(s, 200);
    let (s, _) = call(
        &r,
        &ui,
        Method::PATCH,
        &format!("{G}/tunnrdisks/w1.td-drv-a/status"),
        st(json!({"state": "pool"})),
        None,
    )
    .await;
    assert_eq!(s, 403);
    let (s, _) = call(
        &r,
        &ui,
        Method::DELETE,
        &format!("{G}/tunnrvolumes/pvc-a"),
        None,
        None,
    )
    .await;
    assert_eq!(s, 403);
    let (s, _) = call(
        &r,
        &ui,
        Method::POST,
        &format!("{G}/tunnrdisks"),
        Some(obj("TunnrDisk", "w9.x", "w9")),
        None,
    )
    .await;
    assert_eq!(s, 403);

    // `kubectl get tunnrdisks`: the CRD's printer columns as a Table (Name first, priority kept).
    let (s, t) = call(
        &r,
        &ui,
        Method::GET,
        &format!("{G}/tunnrdisks"),
        None,
        Some("application/json;as=Table;v=v1;g=meta.k8s.io,application/json"),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(t["kind"], "Table", "{t}");
    let names: Vec<&str> = t["columnDefinitions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["Name", "Node", "Size", "State", "Volumes", "Reason", "Age"]
    );
    assert_eq!(t["columnDefinitions"][5]["priority"], 1);
    let rows = t["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    let row = rows
        .iter()
        .find(|r| r["cells"][0] == "w1.td-drv-a")
        .expect("w1's row");
    assert_eq!(row["cells"][1], "w1");
    assert_eq!(row["cells"][2], "9 GiB");
    assert_eq!(row["cells"][3], "in-use");
    assert_eq!(row["cells"][4], 1);
    assert!(
        row["cells"][6].as_str().is_some_and(|a| a.ends_with('s')),
        "age: {}",
        row["cells"][6]
    );
    assert_eq!(
        row["object"]["metadata"]["name"], "w1.td-drv-a",
        "the row's object (metadata)"
    );
    let other = rows
        .iter()
        .find(|r| r["cells"][0] == "w2.td-mir-b")
        .unwrap();
    assert_eq!(
        other["cells"][1],
        Value::Null,
        "a missing field is an empty cell"
    );
    // One object as a Table too.
    let (_, t) = call(
        &r,
        &ui,
        Method::GET,
        &format!("{G}/tunnrdisks/w1.td-drv-a"),
        None,
        Some("application/json;as=Table;v=v1;g=meta.k8s.io"),
    )
    .await;
    assert_eq!(
        (t["kind"].as_str(), t["rows"].as_array().map(Vec::len)),
        (Some("Table"), Some(1)),
        "{t}"
    );
}
