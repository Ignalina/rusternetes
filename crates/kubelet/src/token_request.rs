//! **Bound ServiceAccount tokens for a node without the cluster's key** (a
//! worker): the kubelet asks an API server for each pod's token with a
//! TokenRequest (`POST /api/v1/namespaces/<ns>/serviceaccounts/<sa>/token`,
//! `boundObjectRef` the pod), as upstream's kubelet token manager does. It
//! authenticates with the node's client certificate; the API server's Node
//! authorizer lets a node ask only for the ServiceAccounts of pods bound to
//! it, and the token holds only while that pod does.
//!
//! The certificate files are read for every request: a renewed node
//! certificate is used at once.

use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};

/// Where the API servers are and which identity this node shows them.
#[derive(Clone, Debug)]
pub struct ApiTokenClient {
    /// `https://<host>:<port>` each; tried in turn.
    pub servers: Vec<String>,
    /// The cluster CA (PEM file): the only root.
    pub ca_file: String,
    /// The node's client certificate and key (PEM files).
    pub cert_file: String,
    pub key_file: String,
}

static CLIENT: OnceLock<ApiTokenClient> = OnceLock::new();

/// Install the node's TokenRequest client (false: one was installed already).
pub fn install(c: ApiTokenClient) -> bool {
    CLIENT.set(c).is_ok()
}

/// The node's TokenRequest client, when there is one.
pub fn client() -> Option<&'static ApiTokenClient> {
    CLIENT.get()
}

/// The TokenRequest body for a pod's token.
pub fn request_body(
    pod_name: &str,
    pod_uid: &str,
    audiences: &[String],
    expiration_seconds: i64,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "audiences": audiences,
            "expirationSeconds": expiration_seconds,
            "boundObjectRef": {"apiVersion": "v1", "kind": "Pod", "name": pod_name, "uid": pod_uid},
        },
    })
}

/// The token in a TokenRequest answer.
pub fn token_of(answer: &serde_json::Value) -> Result<String> {
    answer
        .pointer("/status/token")
        .and_then(|t| t.as_str())
        .filter(|t| t.split('.').count() == 3)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("the TokenRequest answer holds no token"))
}

impl ApiTokenClient {
    fn http(&self) -> Result<reqwest::Client> {
        let ca = std::fs::read(&self.ca_file).with_context(|| self.ca_file.clone())?;
        let mut id = std::fs::read(&self.cert_file).with_context(|| self.cert_file.clone())?;
        id.push(b'\n');
        id.extend(std::fs::read(&self.key_file).with_context(|| self.key_file.clone())?);
        Ok(reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .identity(reqwest::Identity::from_pem(&id)?)
            .timeout(std::time::Duration::from_secs(10))
            .build()?)
    }

    /// A token for `namespace`/`service_account`, bound to the pod.
    pub async fn token(
        &self,
        namespace: &str,
        service_account: &str,
        pod_name: &str,
        pod_uid: &str,
        audiences: &[String],
        expiration_seconds: i64,
    ) -> Result<String> {
        if self.servers.is_empty() {
            bail!("no API server to ask for a token");
        }
        let http = self.http()?;
        let body = request_body(pod_name, pod_uid, audiences, expiration_seconds);
        let mut last = String::new();
        for s in &self.servers {
            let url = format!(
                "{}/api/v1/namespaces/{namespace}/serviceaccounts/{service_account}/token",
                s.trim_end_matches('/')
            );
            match http.post(&url).json(&body).send().await {
                Ok(r) if r.status().is_success() => {
                    return token_of(&r.json::<serde_json::Value>().await?)
                }
                Ok(r) => {
                    let st = r.status();
                    let text = r.text().await.unwrap_or_default();
                    last = format!(
                        "{url}: HTTP {st}: {}",
                        text.chars().take(200).collect::<String>()
                    );
                    // A refusal is the same on every API server.
                    if st.as_u16() == 403 || st.as_u16() == 404 {
                        break;
                    }
                }
                Err(e) => last = format!("{url}: {e}"),
            }
        }
        bail!("TokenRequest for {namespace}/{service_account} (pod {pod_name}): {last}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_request_binds_the_pod() {
        let b = request_body("web", "u-1", &["api".to_string()], 600);
        assert_eq!(b["spec"]["boundObjectRef"]["kind"], "Pod");
        assert_eq!(b["spec"]["boundObjectRef"]["name"], "web");
        assert_eq!(b["spec"]["boundObjectRef"]["uid"], "u-1");
        assert_eq!(b["spec"]["expirationSeconds"], 600);
        assert_eq!(b["spec"]["audiences"][0], "api");
    }

    #[test]
    fn an_answer_without_a_token_is_an_error() {
        assert!(token_of(&serde_json::json!({"status": {}})).is_err());
        assert!(token_of(&serde_json::json!({"status": {"token": "x"}})).is_err());
        assert_eq!(
            token_of(&serde_json::json!({"status": {"token": "a.b.c"}})).unwrap(),
            "a.b.c"
        );
    }
}
