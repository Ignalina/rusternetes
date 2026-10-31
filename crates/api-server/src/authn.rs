//! **Who is calling**: x509 client certificates and bearer tokens, and what a
//! request asks for (its authorization attributes, read from the URL).
//!
//! * A client certificate from the cluster CA (verified by the TLS layer,
//!   `--client-ca-file`) is the user `CN`, in the groups `O` (one group per
//!   `O`), plus `system:authenticated`: `O=system:masters` is the cluster
//!   admin, `CN=system:node:<node>, O=system:nodes` a node.
//! * Without a certificate, `Authorization: Bearer <token>` is a ServiceAccount
//!   token signed with the cluster's service-account key (or a bootstrap
//!   token); a bad token is 401.
//! * Neither: 401. There is no anonymous user.
//!
//! The TLS layer asks for a client certificate but does not require one
//! (pods have only their ServiceAccount token); a certificate that does not
//! verify against the cluster CA still fails the handshake.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{Method, Request, Uri};
use rusternetes_common::auth::{BootstrapTokenManager, TokenManager, UserInfo};
use rusternetes_common::authz::RequestAttributes;
use tokio::io::{AsyncRead, AsyncWrite};

/// The connection's verified client certificate, as a user (`None`: the
/// client sent none). Every request on the connection carries it.
#[derive(Clone, Debug, Default)]
pub struct PeerIdentity(pub Option<Arc<UserInfo>>);

/// The user a client certificate names: `CN` the user name, each `O` a group,
/// plus `system:authenticated`. `None` when it has no usable `CN`.
pub fn user_from_cert_der(der: &[u8]) -> Option<UserInfo> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let subject = cert.subject();
    let cn = subject.iter_common_name().next()?.as_str().ok()?.trim().to_string();
    if cn.is_empty() {
        return None;
    }
    let mut groups: Vec<String> = subject
        .iter_organization()
        .filter_map(|o| o.as_str().ok().map(|s| s.to_string()))
        .collect();
    groups.push("system:authenticated".to_string());
    Some(UserInfo {
        uid: String::new(),
        username: cn,
        groups,
        extra: Default::default(),
    })
}

/// Returns the token of an `Authorization: Bearer <token>` header. The scheme name is
/// case-insensitive; the Python Kubernetes client sends it in lowercase.
pub fn bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("Bearer") {
        Some(token.trim()).filter(|t| !t.is_empty())
    } else {
        None
    }
}

/// Authenticate one request: the client certificate first, then a bearer
/// token. `Err` is the 401 message.
pub fn authenticate(
    peer: Option<&UserInfo>,
    authorization: Option<&str>,
    tokens: &TokenManager,
    bootstrap: &BootstrapTokenManager,
) -> Result<UserInfo, &'static str> {
    if let Some(user) = peer {
        return Ok(user.clone());
    }
    match authorization {
        Some(h) => {
            let token = bearer_token(h).ok_or("Unauthorized: unsupported Authorization scheme")?;
            if let Ok(claims) = tokens.validate_token(token) {
                Ok(UserInfo::from_service_account_claims(&claims))
            } else if let Ok(b) = bootstrap.validate_token(token) {
                Ok(UserInfo::from_bootstrap_token(&b))
            } else {
                Err("Unauthorized: invalid bearer token")
            }
        }
        None => Err("Unauthorized: a client certificate from the cluster CA or a bearer token is required"),
    }
}

/// A bound ServiceAccount token holds only while its pod does: the pod
/// exists with the uid in the token, runs on the node in the token (when
/// it names one) and is not deleted for more than a minute (upstream's
/// bound-token validation). `Err` is the 401 message.
pub async fn check_bound(user: &UserInfo, storage: &rusternetes_storage::StorageBackend) -> Result<(), String> {
    use rusternetes_storage::Storage as _;
    let Some((ns, name, uid)) = rusternetes_common::auth::bound_pod(user) else {
        return Ok(());
    };
    let pod: serde_json::Value = match storage.get(&rusternetes_storage::build_key("pods", Some(&ns), &name)).await {
        Ok(p) => p,
        Err(rusternetes_common::Error::NotFound(_)) => {
            return Err(format!("Unauthorized: the token's pod {ns}/{name} no longer exists"))
        }
        // The store is not answering: not this token's fault (503 is the caller's).
        Err(e) => return Err(format!("the token's pod {ns}/{name} cannot be read: {e}")),
    };
    let s = |p: &str| pod.pointer(p).and_then(|v| v.as_str()).unwrap_or("").to_string();
    if !uid.is_empty() && s("/metadata/uid") != uid {
        return Err(format!("Unauthorized: the token's pod {ns}/{name} was replaced (uid {uid})"));
    }
    if let Some(node) = rusternetes_common::auth::bound_node(user) {
        let on = s("/spec/nodeName");
        if !on.is_empty() && on != node {
            return Err(format!("Unauthorized: the token's pod {ns}/{name} is on {on}, not {node}"));
        }
    }
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&s("/metadata/deletionTimestamp")) {
        if chrono::Utc::now().signed_duration_since(t) > chrono::Duration::seconds(60) {
            return Err(format!("Unauthorized: the token's pod {ns}/{name} is deleted"));
        }
    }
    Ok(())
}

/// Subresources of a Namespace (`/api/v1/namespaces/<name>/<sub>`), not
/// namespaced resources.
const NAMESPACE_SUBRESOURCES: &[&str] = &["status", "finalize"];

/// A resource request's authorization attributes, read from its method and
/// URL the way upstream's RequestInfoFactory does: `/api/v1/…` (core) and
/// `/apis/<group>/<version>/…`, an optional `watch/` prefix, an optional
/// `namespaces/<ns>/`, then `<resource>[/<name>[/<subresource>]]`. The verb
/// is get/list/watch (GET; `?watch=true` or the prefix is watch), create
/// (POST), update (PUT), patch (PATCH), delete/deletecollection (DELETE).
/// `None`: not a resource URL.
pub fn request_attributes(method: &Method, uri: &Uri, user: UserInfo) -> Option<RequestAttributes> {
    let parts: Vec<&str> = uri.path().split('/').filter(|p| !p.is_empty()).collect();
    let (group, mut rest) = match parts.as_slice() {
        ["api", _version, rest @ ..] => ("", rest),
        ["apis", group, _version, rest @ ..] => (*group, rest),
        _ => return None,
    };
    let mut watch = uri
        .query()
        .is_some_and(|q| q.split('&').any(|kv| kv == "watch=true" || kv == "watch=1"));
    if rest.first() == Some(&"watch") {
        watch = true;
        rest = &rest[1..];
    }
    let mut namespace: Option<&str> = None;
    if rest.first() == Some(&"namespaces") && rest.len() > 1 {
        namespace = Some(rest[1]);
        if rest.len() > 2 && !NAMESPACE_SUBRESOURCES.contains(&rest[2]) {
            rest = &rest[2..];
        }
    }
    let resource = *rest.first()?;
    let name = rest.get(1).copied();
    let subresource = rest.get(2).copied();
    let verb = match *method {
        Method::GET | Method::HEAD if watch => "watch",
        Method::GET | Method::HEAD if name.is_some() => "get",
        Method::GET | Method::HEAD => "list",
        Method::POST => "create",
        Method::PUT => "update",
        Method::PATCH => "patch",
        Method::DELETE if name.is_some() => "delete",
        Method::DELETE => "deletecollection",
        _ => return None,
    };
    let mut a = RequestAttributes::new(user, verb, resource).with_api_group(group);
    if let Some(ns) = namespace {
        a = a.with_namespace(ns);
    }
    if let Some(n) = name {
        a = a.with_name(n);
    }
    if let Some(s) = subresource {
        a = a.with_subresource(s);
    }
    Some(a)
}

/// The TLS acceptor that also reads the client certificate: every request
/// on the connection gets [`PeerIdentity`] as an extension.
#[derive(Clone)]
pub struct PeerCertAcceptor<A> {
    pub inner: A,
}

impl<A, I, S> axum_server::accept::Accept<I, S> for PeerCertAcceptor<A>
where
    A: axum_server::accept::Accept<I, S, Stream = tokio_rustls::server::TlsStream<I>> + Clone + Send + Sync + 'static,
    A::Future: Send + 'static,
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = WithPeer<A::Service>;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (stream, service) = fut.await?;
            let user = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .and_then(|c| user_from_cert_der(c.as_ref()))
                .map(Arc::new);
            Ok((stream, WithPeer { inner: service, peer: PeerIdentity(user) }))
        })
    }
}

/// A connection's service with its [`PeerIdentity`] added to every request.
#[derive(Clone)]
pub struct WithPeer<S> {
    inner: S,
    peer: PeerIdentity,
}

impl<S, B> tower::Service<Request<B>> for WithPeer<S>
where
    S: tower::Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.peer.clone());
        self.inner.call(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(dn: &[(rcgen::DnType, &str)]) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        for (t, v) in dn {
            p.distinguished_name.push(t.clone(), *v);
        }
        p.self_signed(&key).unwrap().der().to_vec()
    }

    fn anyone() -> UserInfo {
        UserInfo { username: "u".into(), uid: String::new(), groups: vec![], extra: Default::default() }
    }

    #[test]
    fn a_certificate_names_its_user_and_groups() {
        use rcgen::DnType::*;
        let admin = user_from_cert_der(&cert(&[(CommonName, "admin"), (OrganizationName, "system:masters")])).unwrap();
        assert_eq!(admin.username, "admin");
        assert!(admin.groups.contains(&"system:masters".to_string()));
        assert!(admin.groups.contains(&"system:authenticated".to_string()));
        let node = user_from_cert_der(&cert(&[(CommonName, "system:node:w1"), (OrganizationName, "system:nodes")])).unwrap();
        assert_eq!(node.username, "system:node:w1");
        assert_eq!(node.groups, vec!["system:nodes".to_string(), "system:authenticated".to_string()]);
        // The control plane's serving certificate: a user in no group.
        let srv = user_from_cert_der(&cert(&[(CommonName, "rusternetes-apiserver")])).unwrap();
        assert_eq!(srv.groups, vec!["system:authenticated".to_string()]);
        assert!(user_from_cert_der(&cert(&[(OrganizationName, "system:masters")])).is_none());
    }

    #[test]
    fn no_credentials_or_a_bad_token_is_401() {
        let tm = TokenManager::new_random();
        let bt = BootstrapTokenManager::new();
        assert!(authenticate(None, None, &tm, &bt).is_err());
        assert!(authenticate(None, Some("Bearer nonsense"), &tm, &bt).is_err());
        assert!(authenticate(None, Some("Basic YTpi"), &tm, &bt).is_err());
        let forged = TokenManager::new(b"rusternetes-secret-change-in-production")
            .generate_token(rusternetes_common::auth::ServiceAccountClaims::new("default".into(), "default".into(), "u".into(), 1))
            .unwrap();
        assert!(authenticate(None, Some(&format!("Bearer {forged}")), &tm, &bt).is_err());
        let good = tm
            .generate_token(rusternetes_common::auth::ServiceAccountClaims::new("coredns".into(), "kube-system".into(), "u".into(), 1))
            .unwrap();
        let u = authenticate(None, Some(&format!("Bearer {good}")), &tm, &bt).unwrap();
        assert_eq!(u.username, "system:serviceaccount:kube-system:coredns");
        // A certificate wins over a token.
        let mut admin = anyone();
        admin.username = "admin".into();
        assert_eq!(authenticate(Some(&admin), Some("Bearer nonsense"), &tm, &bt).unwrap().username, "admin");
    }

    fn attrs(m: Method, uri: &str) -> RequestAttributes {
        request_attributes(&m, &uri.parse().unwrap(), anyone()).unwrap()
    }

    #[test]
    fn the_url_says_what_is_asked() {
        let a = attrs(Method::GET, "/api/v1/namespaces/kube-system/secrets/cilium-ca");
        assert_eq!((a.verb.as_str(), a.resource.as_str(), a.namespace.as_deref(), a.name.as_deref(), a.api_group.as_str()), ("get", "secrets", Some("kube-system"), Some("cilium-ca"), ""));
        let a = attrs(Method::GET, "/api/v1/pods?watch=true&fieldSelector=spec.nodeName%3Dw1");
        assert_eq!((a.verb.as_str(), a.resource.as_str(), a.namespace.as_deref()), ("watch", "pods", None));
        let a = attrs(Method::GET, "/api/v1/watch/namespaces/default/pods");
        assert_eq!((a.verb.as_str(), a.namespace.as_deref()), ("watch", Some("default")));
        let a = attrs(Method::POST, "/apis/apps/v1/namespaces/default/deployments");
        assert_eq!((a.verb.as_str(), a.resource.as_str(), a.api_group.as_str(), a.name.as_deref()), ("create", "deployments", "apps", None));
        let a = attrs(Method::PUT, "/api/v1/nodes/w1/status");
        assert_eq!((a.verb.as_str(), a.resource.as_str(), a.name.as_deref(), a.subresource.as_deref(), a.namespace.as_deref()), ("update", "nodes", Some("w1"), Some("status"), None));
        let a = attrs(Method::PATCH, "/api/v1/namespaces/default/pods/web/status");
        assert_eq!((a.verb.as_str(), a.subresource.as_deref()), ("patch", Some("status")));
        let a = attrs(Method::DELETE, "/api/v1/namespaces/default/pods");
        assert_eq!(a.verb, "deletecollection");
        let a = attrs(Method::GET, "/api/v1/namespaces/default");
        assert_eq!((a.verb.as_str(), a.resource.as_str(), a.name.as_deref()), ("get", "namespaces", Some("default")));
        let a = attrs(Method::PUT, "/api/v1/namespaces/default/finalize");
        assert_eq!((a.resource.as_str(), a.name.as_deref(), a.subresource.as_deref()), ("namespaces", Some("default"), Some("finalize")));
        let a = attrs(Method::GET, "/apis/coordination.k8s.io/v1/namespaces/kube-node-lease/leases/w1");
        assert_eq!((a.api_group.as_str(), a.resource.as_str(), a.name.as_deref()), ("coordination.k8s.io", "leases", Some("w1")));
        let a = attrs(Method::GET, "/apis/cilium.io/v2/ciliumnodes");
        assert_eq!((a.api_group.as_str(), a.resource.as_str(), a.verb.as_str()), ("cilium.io", "ciliumnodes", "list"));
        assert!(request_attributes(&Method::GET, &"/healthz".parse().unwrap(), anyone()).is_none());
        assert!(request_attributes(&Method::GET, &"/apis".parse().unwrap(), anyone()).is_none());
    }
}
