use crate::{middleware::AuthContext, state::ApiServerState};
use axum::{
    body::Bytes,
    extract::{Path, State},
    Extension, Json,
};
use rusternetes_common::{
    authz::{Decision, RequestAttributes},
    resources::{
        SelfSubjectReview, SelfSubjectReviewStatus, TokenRequest, TokenRequestStatus, TokenReview,
        TokenReviewStatus, UserInfo,
    },
    Result,
};
use rusternetes_storage::Storage;
use std::sync::Arc;
use tracing::{info, warn};

/// Create a TokenReview (authentication.k8s.io/v1)
/// TokenReview attempts to authenticate a token to a known user.
pub async fn create_token_review(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Json(mut token_review): Json<TokenReview>,
) -> Result<Json<TokenReview>> {
    info!("Creating token review");

    // Check authorization - creating a TokenReview requires impersonation privileges
    let attrs = RequestAttributes::new(auth_ctx.user.clone(), "create", "tokenreviews")
        .with_api_group("authentication.k8s.io");

    if let Decision::Deny(reason) = state.authorizer.authorize(&attrs).await? {
        return Err(rusternetes_common::Error::Forbidden(reason));
    }

    // Authenticate the provided token using the available authentication mechanisms
    // Try service account token first
    let status = if let Ok(claims) = state.token_manager.validate_token(&token_review.spec.token) {
        // Valid service account token
        TokenReviewStatus {
            authenticated: Some(true),
            user: Some(UserInfo {
                username: Some(claims.sub.clone()),
                uid: Some(claims.uid),
                groups: Some(vec![
                    "system:serviceaccounts".to_string(),
                    format!("system:serviceaccounts:{}", claims.namespace),
                    "system:authenticated".to_string(),
                ]),
                extra: Some({
                    let mut extra = std::collections::HashMap::new();
                    // K8s expects credential-id with JTI prefix for SA tokens
                    let jti = format!("JTI={}", uuid::Uuid::new_v4());
                    extra.insert(
                        "authentication.kubernetes.io/credential-id".to_string(),
                        vec![jti],
                    );
                    // Include pod binding info if present in claims
                    if let Some(ref pod_name) = claims.pod_name {
                        extra.insert(
                            "authentication.kubernetes.io/pod-name".to_string(),
                            vec![pod_name.clone()],
                        );
                    }
                    if let Some(ref pod_uid) = claims.pod_uid {
                        extra.insert(
                            "authentication.kubernetes.io/pod-uid".to_string(),
                            vec![pod_uid.clone()],
                        );
                    }
                    if let Some(ref node_name) = claims.node_name {
                        extra.insert(
                            "authentication.kubernetes.io/node-name".to_string(),
                            vec![node_name.clone()],
                        );
                    }
                    if let Some(ref node_uid) = claims.node_uid {
                        extra.insert(
                            "authentication.kubernetes.io/node-uid".to_string(),
                            vec![node_uid.clone()],
                        );
                    }
                    extra
                }),
            }),
            audiences: token_review.spec.audiences.clone(),
            error: None,
        }
    } else {
        // Token validation failed - could be bootstrap token, OIDC, or invalid
        // For now, mark as unauthenticated
        // Note: Full implementation would try other auth mechanisms here
        // (bootstrap tokens, OIDC, webhook auth, etc.)
        TokenReviewStatus {
            authenticated: Some(false),
            user: None,
            audiences: None,
            error: Some(
                "Token authentication failed - not a valid service account token".to_string(),
            ),
        }
    };

    token_review.status = Some(status);
    Ok(Json(token_review))
}

/// Create a TokenRequest (authentication.k8s.io/v1)
/// TokenRequest requests a token for a given service account.
pub async fn create_token_request(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Path((namespace, service_account_name)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<TokenRequest>> {
    // Parse the body manually — the K8s client may send protobuf or JSON with extra
    // fields that Axum's Json<T> extractor rejects with a 422, which is not a proper
    // Kubernetes Status error.  Manual parsing gives us control over the error response.
    let mut token_request: TokenRequest = serde_json::from_slice(&body).map_err(|e| {
        warn!(
            "Failed to decode TokenRequest body ({} bytes): {}",
            body.len(),
            e
        );
        rusternetes_common::Error::InvalidResource(format!("failed to decode: {}", e))
    })?;
    info!(
        "Creating token request for service account {}/{}",
        namespace, service_account_name
    );

    // Check authorization: create serviceaccounts/token (the URL's attributes,
    // as the authz middleware checks them).
    let attrs = RequestAttributes::new(auth_ctx.user.clone(), "create", "serviceaccounts")
        .with_api_group("")
        .with_namespace(&namespace)
        .with_name(&service_account_name)
        .with_subresource("token");

    if let Decision::Deny(reason) = state.authorizer.authorize(&attrs).await? {
        return Err(rusternetes_common::Error::Forbidden(reason));
    }

    // Set metadata from path params so response includes them
    token_request.metadata.name = service_account_name.clone();
    token_request.metadata.namespace = Some(namespace.clone());

    // Verify the service account exists
    let sa_key =
        rusternetes_storage::build_key("serviceaccounts", Some(&namespace), &service_account_name);
    let sa: rusternetes_common::resources::ServiceAccount = state.storage.get(&sa_key).await?;

    // The bound object (a Pod): it must exist, have the uid asked for and run
    // as this ServiceAccount. A node asks only for a pod bound to it
    // (upstream NodeRestriction).
    let bound = bound_pod_for(&state, &namespace, &service_account_name, token_request.spec.bound_object_ref.as_ref()).await?;
    if let Some(node) = crate::node_authz::node_of(&auth_ctx.user) {
        match &bound {
            Some(b) if b.node.as_deref() == Some(node) => {}
            Some(_) => {
                return Err(rusternetes_common::Error::Forbidden(format!(
                    "node {node} may request a token only for a pod bound to it"
                )))
            }
            None => {
                return Err(rusternetes_common::Error::Forbidden(format!(
                    "node {node} may request only pod-bound tokens"
                )))
            }
        }
    }

    // Lifetime: at least 10 minutes, at most --service-account-max-token-expiration.
    let expiration_seconds =
        rusternetes_common::auth::token_expiration(token_request.spec.expiration_seconds);
    token_request.spec.expiration_seconds = Some(expiration_seconds);

    let now = chrono::Utc::now();
    let expiration_timestamp = now
        .checked_add_signed(chrono::Duration::seconds(expiration_seconds))
        .ok_or_else(|| {
            rusternetes_common::Error::Internal("Failed to calculate expiration time".to_string())
        })?;

    let mut claims = rusternetes_common::auth::ServiceAccountClaims {
        sub: format!(
            "system:serviceaccount:{}:{}",
            namespace, service_account_name
        ),
        namespace: namespace.clone(),
        uid: sa.metadata.uid.clone(),
        iat: now.timestamp(),
        exp: expiration_timestamp.timestamp(),
        iss: "https://kubernetes.default.svc.cluster.local".to_string(),
        aud: vec!["rusternetes".to_string()],
        kubernetes: Some(rusternetes_common::auth::KubernetesClaims {
            namespace: namespace.clone(),
            svcacct: rusternetes_common::auth::KubeRef {
                name: service_account_name.clone(),
                uid: sa.metadata.uid.clone(),
            },
            pod: None,
            node: None,
        }),
        pod_name: None,
        pod_uid: None,
        node_name: None,
        node_uid: None,
    };

    if !token_request.spec.audiences.is_empty() {
        claims.aud = token_request.spec.audiences.clone();
    }

    if let Some(b) = bound {
        claims.pod_name = Some(b.name.clone());
        claims.pod_uid = Some(b.uid.clone());
        claims.node_name = b.node.clone();
        claims.node_uid = b.node_uid.clone();
        if let Some(k) = claims.kubernetes.as_mut() {
            k.pod = Some(rusternetes_common::auth::KubeRef { name: b.name, uid: b.uid });
            k.node = b.node.map(|n| rusternetes_common::auth::KubeRef { name: n, uid: b.node_uid.unwrap_or_default() });
        }
    }

    let token = state.token_manager.generate_token(claims)?;

    // Ensure apiVersion and kind are set
    token_request.api_version = "authentication.k8s.io/v1".to_string();
    token_request.kind = "TokenRequest".to_string();
    token_request.metadata.ensure_creation_timestamp();

    token_request.status = Some(TokenRequestStatus {
        token,
        expiration_timestamp: rusternetes_common::time::k8s_time::format(&expiration_timestamp),
    });

    Ok(Json(token_request))
}

/// The pod a TokenRequest binds to.
pub(crate) struct BoundPod {
    pub name: String,
    pub uid: String,
    pub node: Option<String>,
    pub node_uid: Option<String>,
}

/// Resolve a TokenRequest's `boundObjectRef`: `None` without one; a Pod
/// that exists, has the uid asked for (when one is given) and runs as
/// `service_account`; any other kind is refused.
pub(crate) async fn bound_pod_for(
    state: &ApiServerState,
    namespace: &str,
    service_account: &str,
    r: Option<&rusternetes_common::resources::BoundObjectReference>,
) -> Result<Option<BoundPod>> {
    let Some(r) = r else { return Ok(None) };
    if r.kind.as_deref() == Some("Secret") {
        // Bound to a Secret: it must exist (no pod binding).
        let name = r.name.clone().unwrap_or_default();
        state
            .storage
            .get::<serde_json::Value>(&rusternetes_storage::build_key("secrets", Some(namespace), &name))
            .await
            .map_err(|_| rusternetes_common::Error::Forbidden(format!("the bound secret {namespace}/{name} does not exist")))?;
        return Ok(None);
    }
    if r.kind.as_deref() != Some("Pod") {
        return Err(rusternetes_common::Error::InvalidResource(format!(
            "boundObjectRef.kind {:?}: only Pod is supported",
            r.kind
        )));
    }
    let name = r
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| rusternetes_common::Error::InvalidResource("boundObjectRef.name is required".into()))?;
    let pod: rusternetes_common::resources::Pod = state
        .storage
        .get(&rusternetes_storage::build_key("pods", Some(namespace), &name))
        .await
        .map_err(|_| rusternetes_common::Error::Forbidden(format!("the bound pod {namespace}/{name} does not exist")))?;
    if let Some(uid) = r.uid.as_deref().filter(|u| !u.is_empty()) {
        if uid != pod.metadata.uid {
            return Err(rusternetes_common::Error::Forbidden(format!(
                "the bound pod {namespace}/{name} has uid {}, not {uid}",
                pod.metadata.uid
            )));
        }
    }
    let spec = pod.spec.as_ref();
    let sa = spec
        .and_then(|s| s.service_account_name.clone())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "default".to_string());
    if sa != service_account {
        return Err(rusternetes_common::Error::Forbidden(format!(
            "the bound pod {namespace}/{name} runs as ServiceAccount {sa}, not {service_account}"
        )));
    }
    let node = spec.and_then(|s| s.node_name.clone()).filter(|n| !n.is_empty());
    let mut node_uid = None;
    if let Some(n) = &node {
        if let Ok(nd) = state
            .storage
            .get::<rusternetes_common::resources::Node>(&rusternetes_storage::build_key("nodes", None::<&str>, n))
            .await
        {
            node_uid = Some(nd.metadata.uid.clone()).filter(|u| !u.is_empty());
        }
    }
    Ok(Some(BoundPod { name, uid: pod.metadata.uid.clone(), node, node_uid }))
}

/// Create a SelfSubjectReview (authentication.k8s.io/v1)
/// SelfSubjectReview contains the user information that the kube-apiserver has about the user making this request.
pub async fn create_self_subject_review(
    State(state): State<Arc<ApiServerState>>,
    Extension(auth_ctx): Extension<AuthContext>,
    Json(mut self_subject_review): Json<SelfSubjectReview>,
) -> Result<Json<SelfSubjectReview>> {
    info!("Creating self subject review for user: {:?}", auth_ctx.user);

    // Check authorization - creating a SelfSubjectReview is always allowed
    let attrs = RequestAttributes::new(auth_ctx.user.clone(), "create", "selfsubjectreviews")
        .with_api_group("authentication.k8s.io");

    if let Decision::Deny(reason) = state.authorizer.authorize(&attrs).await? {
        return Err(rusternetes_common::Error::Forbidden(reason));
    }

    // Return the current user's information
    self_subject_review.status = Some(SelfSubjectReviewStatus {
        user_info: Some(UserInfo {
            username: Some(auth_ctx.user.username.clone()),
            uid: Some(auth_ctx.user.uid.clone()),
            groups: Some(auth_ctx.user.groups.clone()),
            extra: Some(auth_ctx.user.extra.clone()),
        }),
    });

    Ok(Json(self_subject_review))
}

#[cfg(test)]
#[cfg(feature = "integration-tests")] // Disable incomplete tests
mod tests {
    use super::*;
    use crate::state::MockAuth;
    use rusternetes_common::resources::TokenReviewSpec;

    #[tokio::test]
    async fn test_token_review_authenticated() {
        // This test would verify that a valid token returns authenticated=true
        // Implementation would depend on the actual auth system
    }

    #[tokio::test]
    async fn test_token_review_unauthenticated() {
        // This test would verify that an invalid token returns authenticated=false
    }

    #[tokio::test]
    async fn test_self_subject_review() {
        // This test would verify that SelfSubjectReview returns the current user's info
    }
}
