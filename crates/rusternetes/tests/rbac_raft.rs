//! RBAC across three control planes: a RoleBinding written through one
//! Raft replica is honoured AT ONCE by the authorizer of the two others
//! (read-your-writes: every authorizer read is a linearizable read through
//! the leader's read index), and a deleted one is gone at once. The store is
//! three tunnr-etcd Raft replicas on loopback, each used as etcd by its own
//! "control plane" (EtcdStorage + the API server's ClusterAuthorizer).
#![cfg(feature = "store-raft")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rusternetes_api_server::node_authz::ClusterAuthorizer;
use rusternetes_common::auth::UserInfo;
use rusternetes_common::authz::{Authorizer, Decision, RequestAttributes};
use rusternetes_storage::{etcd::EtcdStorage, Storage, StorageBackend};
use serde_json::json;
use tunnr_etcd::server::raft::{self, Peer, RaftConfig, RaftNode};
use tunnr_etcd::server::{serve_raft, ServeOptions};

fn free_port() -> std::net::SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

struct Cp {
    _node: Arc<RaftNode>,
    store: Arc<StorageBackend>,
    authz: ClusterAuthorizer,
}

async fn three() -> Vec<Cp> {
    let name = format!("rk-rbac-raft-{}", std::process::id());
    let mut peers = BTreeMap::new();
    let mut client = BTreeMap::new();
    for id in 1..=3u64 {
        let cl = free_port();
        peers.insert(
            id,
            Peer {
                raft_addr: free_port().to_string(),
                client_url: format!("http://{cl}"),
            },
        );
        client.insert(id, cl);
    }
    let mut nodes = Vec::new();
    for id in 1..=3u64 {
        let dir = std::env::temp_dir().join(format!("{name}-{id}"));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cfg = RaftConfig::new(
            id,
            peers.clone(),
            peers[&id].raft_addr.parse().unwrap(),
            dir,
        );
        cfg.heartbeat = Duration::from_millis(100);
        cfg.election_min = Duration::from_millis(400);
        cfg.election_max = Duration::from_millis(800);
        cfg.wait = Duration::from_secs(5);
        let node = raft::start(cfg).await.unwrap();
        let l = tokio::net::TcpListener::bind(client[&id]).await.unwrap();
        tokio::spawn({
            let node = node.clone();
            async move {
                let _ = serve_raft(node, l, ServeOptions::default(), std::future::pending()).await;
            }
        });
        nodes.push(node);
    }
    let mut cps = Vec::new();
    for (i, node) in nodes.into_iter().enumerate() {
        let id = i as u64 + 1;
        let st = Arc::new(StorageBackend::Etcd(
            EtcdStorage::new(vec![format!("http://{}", client[&id])])
                .await
                .unwrap(),
        ));
        cps.push(Cp {
            _node: node,
            authz: ClusterAuthorizer::new(st.clone()),
            store: st,
        });
    }
    // A leader with a quorum: the first write goes through.
    for _ in 0..100 {
        if cps[0]
            .store
            .create::<serde_json::Value>(
                "/registry/namespaces/default",
                &json!({"metadata": {"name": "default"}}),
            )
            .await
            .is_ok()
        {
            return cps;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no Raft leader");
}

fn sa(name: &str) -> UserInfo {
    UserInfo {
        username: format!("system:serviceaccount:default:{name}"),
        uid: String::new(),
        groups: vec![
            "system:serviceaccounts".into(),
            "system:serviceaccounts:default".into(),
            "system:authenticated".into(),
        ],
        extra: Default::default(),
    }
}

async fn may_list_pods(cp: &Cp, who: &str) -> bool {
    let a = RequestAttributes::new(sa(who), "list", "pods")
        .with_namespace("default")
        .with_api_group("");
    cp.authz.authorize(&a).await.unwrap() == Decision::Allow
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rolebinding_written_on_one_control_plane_counts_at_once_on_the_others() {
    let cps = three().await;
    cps[0]
        .store
        .create::<serde_json::Value>(
            "/registry/roles/default/pod-reader",
            &json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "pod-reader", "namespace": "default"},
                    "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}]}),
        )
        .await
        .unwrap();
    let mut late = Vec::new();
    for i in 0..60usize {
        let who = format!("app-{i}");
        let (w, a, b) = (i % 3, (i + 1) % 3, (i + 2) % 3);
        assert!(
            !may_list_pods(&cps[a], &who).await,
            "{who} allowed before its binding"
        );
        let key = format!("/registry/rolebindings/default/{who}");
        cps[w]
            .store
            .create::<serde_json::Value>(
                &key,
                &json!({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": who, "namespace": "default"},
                        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "pod-reader"},
                        "subjects": [{"kind": "ServiceAccount", "name": who, "namespace": "default"}]}),
            )
            .await
            .unwrap();
        // At once, on the two other control planes.
        for o in [a, b] {
            if !may_list_pods(&cps[o], &who).await {
                late.push(format!(
                    "{who}: written on cp{} not yet allowed on cp{}",
                    w + 1,
                    o + 1
                ));
            }
        }
        // And a delete is gone at once everywhere.
        cps[b].store.delete(&key).await.unwrap();
        for o in [w, a] {
            if may_list_pods(&cps[o], &who).await {
                late.push(format!(
                    "{who}: deleted on cp{} still allowed on cp{}",
                    b + 1,
                    o + 1
                ));
            }
        }
    }
    assert!(
        late.is_empty(),
        "{} stale RBAC reads:\n{}",
        late.len(),
        late.join("\n")
    );
}
