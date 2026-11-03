//! The API server with authentication on (`skip_auth = false`): who may do
//! what through the router, end to end (authentication, the URL-level
//! authorization, the handlers). A client certificate's identity is given as
//! the connection's `PeerIdentity`, as the TLS acceptor sets it.

use axum::{
    body::Body,
    http::{Method, Request},
};
use rusternetes_api_server::authn::PeerIdentity;
use rusternetes_api_server::node_authz::ClusterAuthorizer;
use rusternetes_api_server::{router::build_router, state::ApiServerState};
use rusternetes_common::auth::{ServiceAccountClaims, TokenManager, UserInfo};
use rusternetes_common::observability::MetricsRegistry;
use rusternetes_storage::{memory::MemoryStorage, StorageBackend};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

fn cluster() -> (axum::Router, Arc<TokenManager>) {
    let backend = Arc::new(StorageBackend::Memory(Arc::new(MemoryStorage::new())));
    let tm = Arc::new(TokenManager::new_random());
    let state = Arc::new(ApiServerState::new(
        backend.clone(),
        tm.clone(),
        Arc::new(ClusterAuthorizer::new(backend)),
        Arc::new(MetricsRegistry::new()),
        false,
    ));
    (build_router(state, None), tm)
}

fn cert_user(cn: &str, groups: &[&str]) -> UserInfo {
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

enum Who<'a> {
    Nobody,
    Cert(UserInfo),
    Token(&'a str),
}

async fn call(
    r: &axum::Router,
    who: &Who<'_>,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> u16 {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Who::Token(t) = who {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let mut req = b
        .body(body.map_or(Body::empty(), |v| Body::from(v.to_string())))
        .unwrap();
    if let Who::Cert(u) = who {
        req.extensions_mut()
            .insert(PeerIdentity(Some(Arc::new(u.clone()))));
    }
    r.clone().oneshot(req).await.unwrap().status().as_u16()
}

fn node(name: &str) -> Value {
    json!({"apiVersion": "v1", "kind": "Node", "metadata": {"name": name}})
}

fn deployment() -> Value {
    json!({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "d", "namespace": "default"},
           "spec": {"replicas": 1, "selector": {"matchLabels": {"a": "b"}},
                    "template": {"metadata": {"labels": {"a": "b"}}, "spec": {"containers": [{"name": "c", "image": "x"}]}}}})
}

#[tokio::test]
async fn who_may_do_what() {
    let (r, tm) = cluster();
    let admin = Who::Cert(cert_user("admin", &["system:masters"]));
    let w1 = Who::Cert(cert_user("system:node:w1", &["system:nodes"]));

    // No credentials: 401 everywhere but health.
    assert_eq!(
        call(&r, &Who::Nobody, Method::GET, "/api/v1/namespaces", None).await,
        401
    );
    assert_eq!(call(&r, &Who::Nobody, Method::GET, "/api", None).await, 401);
    assert_eq!(
        call(&r, &Who::Nobody, Method::GET, "/version", None).await,
        401
    );
    assert_eq!(
        call(&r, &Who::Nobody, Method::GET, "/healthz", None).await,
        200
    );
    // A token signed with the well-known default secret, or unsigned: 401.
    let claims = ServiceAccountClaims::new("default".into(), "kube-system".into(), "u".into(), 1);
    let forged = TokenManager::new(b"rusternetes-secret-change-in-production")
        .generate_token(claims.clone())
        .unwrap();
    assert_eq!(
        call(
            &r,
            &Who::Token(&forged),
            Method::GET,
            "/api/v1/namespaces",
            None
        )
        .await,
        401
    );
    let head = forged.split('.').next().unwrap();
    let unsigned = format!("{head}.{}.", forged.split('.').nth(1).unwrap());
    assert_eq!(
        call(
            &r,
            &Who::Token(&unsigned),
            Method::GET,
            "/api/v1/namespaces",
            None
        )
        .await,
        401
    );

    // The admin certificate: everything.
    assert_eq!(
        call(&r, &admin, Method::POST, "/api/v1/nodes", Some(node("w2"))).await,
        201
    );
    assert_eq!(
        call(
            &r,
            &admin,
            Method::POST,
            "/apis/apps/v1/namespaces/default/deployments",
            Some(deployment())
        )
        .await,
        201
    );
    assert_eq!(
        call(&r, &admin, Method::GET, "/api/v1/secrets", None).await,
        200
    );

    // A node certificate: its own Node; not another node's, no Deployments, no Secrets list,
    // no cluster-scoped writes.
    assert_eq!(
        call(&r, &w1, Method::POST, "/api/v1/nodes", Some(node("w1"))).await,
        201
    );
    assert_eq!(
        call(&r, &w1, Method::POST, "/api/v1/nodes", Some(node("w3"))).await,
        403
    );
    assert_eq!(
        call(&r, &w1, Method::GET, "/api/v1/nodes/w2", None).await,
        200
    );
    assert_eq!(
        call(&r, &w1, Method::DELETE, "/api/v1/nodes/w2", None).await,
        403
    );
    assert_eq!(
        call(
            &r,
            &w1,
            Method::PATCH,
            "/api/v1/nodes/w2",
            Some(json!({"metadata": {"labels": {"x": "y"}}}))
        )
        .await,
        403
    );
    assert_eq!(
        call(
            &r,
            &w1,
            Method::POST,
            "/apis/apps/v1/namespaces/default/deployments",
            Some(deployment())
        )
        .await,
        403
    );
    assert_eq!(
        call(&r, &w1, Method::GET, "/api/v1/secrets", None).await,
        403
    );
    assert_eq!(
        call(
            &r,
            &w1,
            Method::GET,
            "/api/v1/namespaces/kube-system/secrets/anything",
            None
        )
        .await,
        403
    );
    assert_eq!(
        call(
            &r,
            &w1,
            Method::POST,
            "/api/v1/namespaces",
            Some(json!({"metadata": {"name": "evil"}}))
        )
        .await,
        403
    );
    assert_eq!(call(&r, &w1, Method::POST, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
                    Some(json!({"metadata": {"name": "evil"}, "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
                                "subjects": [{"kind": "Group", "name": "system:nodes"}]}))).await, 403);

    // A ServiceAccount token: only what RBAC grants (nothing yet), then a Role's rules.
    let sa = tm
        .generate_token(ServiceAccountClaims::new(
            "reader".into(),
            "default".into(),
            "u".into(),
            1,
        ))
        .unwrap();
    assert_eq!(
        call(
            &r,
            &Who::Token(&sa),
            Method::GET,
            "/api/v1/namespaces/default/pods",
            None
        )
        .await,
        403
    );
    assert_eq!(
        call(&r, &Who::Token(&sa), Method::GET, "/api", None).await,
        200
    );
    assert_eq!(call(&r, &admin, Method::POST, "/apis/rbac.authorization.k8s.io/v1/namespaces/default/roles",
                    Some(json!({"metadata": {"name": "pod-reader", "namespace": "default"},
                                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}]}))).await, 201);
    assert_eq!(call(&r, &admin, Method::POST, "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings",
                    Some(json!({"metadata": {"name": "reader", "namespace": "default"},
                                "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "pod-reader"},
                                "subjects": [{"kind": "ServiceAccount", "name": "reader", "namespace": "default"}]}))).await, 201);
    assert_eq!(
        call(
            &r,
            &Who::Token(&sa),
            Method::GET,
            "/api/v1/namespaces/default/pods",
            None
        )
        .await,
        200
    );
    assert_eq!(
        call(
            &r,
            &Who::Token(&sa),
            Method::GET,
            "/api/v1/namespaces/kube-system/pods",
            None
        )
        .await,
        403
    );
    assert_eq!(
        call(
            &r,
            &Who::Token(&sa),
            Method::GET,
            "/api/v1/namespaces/default/secrets",
            None
        )
        .await,
        403
    );
    assert_eq!(
        call(
            &r,
            &Who::Token(&sa),
            Method::POST,
            "/apis/apps/v1/namespaces/default/deployments",
            Some(deployment())
        )
        .await,
        403
    );
}

async fn call_json(
    r: &axum::Router,
    who: &Who<'_>,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Who::Token(t) = who {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    let mut req = b
        .body(body.map_or(Body::empty(), |v| Body::from(v.to_string())))
        .unwrap();
    if let Who::Cert(u) = who {
        req.extensions_mut()
            .insert(PeerIdentity(Some(Arc::new(u.clone()))));
    }
    let resp = r.clone().oneshot(req).await.unwrap();
    let st = resp.status().as_u16();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (st, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn token_request(pod: &str, uid: Option<&str>, seconds: i64) -> Value {
    let mut r = json!({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
                       "spec": {"audiences": [], "expirationSeconds": seconds}});
    if !pod.is_empty() {
        r["spec"]["boundObjectRef"] =
            json!({"apiVersion": "v1", "kind": "Pod", "name": pod, "uid": uid});
    }
    r
}

/// Bound ServiceAccount tokens: a node asks (TokenRequest) only for a pod
/// bound to it and that pod's ServiceAccount; the token is short-lived and
/// holds only while its pod does; no long-lived token Secret is made.
#[tokio::test]
async fn bound_tokens_through_token_request() {
    use rusternetes_storage::Storage as _;
    let backend = Arc::new(StorageBackend::Memory(Arc::new(MemoryStorage::new())));
    let tm = Arc::new(TokenManager::new_random());
    let state = Arc::new(ApiServerState::new(
        backend.clone(),
        tm.clone(),
        Arc::new(ClusterAuthorizer::new(backend.clone())),
        Arc::new(MetricsRegistry::new()),
        false,
    ));
    let r = build_router(state, None);
    let admin = Who::Cert(cert_user("admin", &["system:masters"]));
    let w1 = Who::Cert(cert_user("system:node:w1", &["system:nodes"]));
    let w2 = Who::Cert(cert_user("system:node:w2", &["system:nodes"]));
    for sa in ["web", "other"] {
        assert_eq!(
            call(
                &r,
                &admin,
                Method::POST,
                "/api/v1/namespaces/default/serviceaccounts",
                Some(json!({"metadata": {"name": sa, "namespace": "default"}}))
            )
            .await,
            201
        );
    }
    // No long-lived token Secret for a ServiceAccount.
    assert!(backend
        .get::<Value>("/registry/secrets/default/web-token")
        .await
        .is_err());
    let pod = json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "web-1", "namespace": "default", "uid": "uid-1"},
                     "spec": {"nodeName": "w1", "serviceAccountName": "web", "containers": [{"name": "c", "image": "x"}]}});
    backend
        .create("/registry/pods/default/web-1", &pod)
        .await
        .unwrap();
    let url = "/api/v1/namespaces/default/serviceaccounts/web/token";

    // w1, for its own pod: a token of at least 10 minutes.
    let (st, body) = call_json(
        &r,
        &w1,
        Method::POST,
        url,
        Some(token_request("web-1", Some("uid-1"), 60)),
    )
    .await;
    assert!(st == 200 || st == 201, "{st} {body}");
    let token = body
        .pointer("/status/token")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let (iat, exp) = rusternetes_common::auth::token_times(&token).unwrap();
    assert_eq!(exp - iat, 600);
    // It authenticates as the ServiceAccount (RBAC grants it nothing: 403, not 401).
    assert_eq!(
        call(&r, &Who::Token(&token), Method::GET, "/api", None).await,
        200
    );
    assert_eq!(
        call(
            &r,
            &Who::Token(&token),
            Method::GET,
            "/api/v1/namespaces/default/pods",
            None
        )
        .await,
        403
    );

    // Another node, another ServiceAccount, no binding, a wrong uid: refused.
    assert_eq!(
        call(
            &r,
            &w2,
            Method::POST,
            url,
            Some(token_request("web-1", Some("uid-1"), 600))
        )
        .await,
        403
    );
    assert_eq!(
        call(
            &r,
            &w1,
            Method::POST,
            "/api/v1/namespaces/default/serviceaccounts/other/token",
            Some(token_request("web-1", Some("uid-1"), 600))
        )
        .await,
        403
    );
    assert_eq!(
        call(
            &r,
            &w1,
            Method::POST,
            url,
            Some(token_request("", None, 600))
        )
        .await,
        403
    );
    assert_eq!(
        call(
            &r,
            &w1,
            Method::POST,
            url,
            Some(token_request("web-1", Some("uid-9"), 600))
        )
        .await,
        403
    );
    // A node reads no ServiceAccount token Secret.
    assert_eq!(
        call(
            &r,
            &w1,
            Method::GET,
            "/api/v1/namespaces/default/secrets/web-token",
            None
        )
        .await,
        403
    );

    // The pod replaced (same name, new uid), then gone: the token is 401.
    let mut again = pod.clone();
    again["metadata"]["uid"] = json!("uid-2");
    backend
        .update("/registry/pods/default/web-1", &again)
        .await
        .unwrap();
    assert_eq!(
        call(&r, &Who::Token(&token), Method::GET, "/api", None).await,
        401
    );
    backend
        .delete("/registry/pods/default/web-1")
        .await
        .unwrap();
    assert_eq!(
        call(&r, &Who::Token(&token), Method::GET, "/api", None).await,
        401
    );
    // An unbound token (a requested legacy Secret's) still authenticates.
    let legacy = tm
        .generate_token(ServiceAccountClaims::new(
            "web".into(),
            "default".into(),
            "u".into(),
            1,
        ))
        .unwrap();
    assert_eq!(
        call(&r, &Who::Token(&legacy), Method::GET, "/api", None).await,
        200
    );
}
