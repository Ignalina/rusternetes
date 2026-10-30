//! How the API server reaches a kubelet's node server (`<node>:10250`) for
//! exec, attach and container logs: plain HTTP, or — configured once at
//! start ([`configure`]) — mutual TLS, the kubelet's serving certificate
//! checked against the cluster CA (its node IP in it) and the API server's
//! own client certificate presented (the kubelet takes control-plane
//! certificates only).

use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};

/// The TLS files (PEM).
#[derive(Clone, Debug)]
pub struct KubeletClientTls {
    /// The CA a kubelet's serving certificate must chain to.
    pub ca_file: String,
    /// The API server's client certificate and key.
    pub cert_file: String,
    pub key_file: String,
}

static TLS: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// The client config, from the files.
pub fn client_config(t: &KubeletClientTls) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let read = |p: &str| std::fs::read(p).with_context(|| p.to_string());
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(&read(&t.ca_file)?) {
        roots.add(c.context("the kubelet CA")?).context("the kubelet CA")?;
    }
    let certs = CertificateDer::pem_slice_iter(&read(&t.cert_file)?)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("the kubelet client certificate")?;
    let key = PrivateKeyDer::from_pem_slice(&read(&t.key_file)?).context("the kubelet client key")?;
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?)
}

/// Use mutual TLS to the kubelets from now on.
pub fn configure(t: &KubeletClientTls) -> Result<()> {
    let cfg = client_config(t)?;
    let _ = TLS.set(Arc::new(cfg));
    Ok(())
}

/// Is mutual TLS on?
pub fn tls() -> bool {
    TLS.get().is_some()
}

/// `https` or `http`.
pub fn http_scheme() -> &'static str {
    if tls() { "https" } else { "http" }
}

/// `wss` or `ws`.
pub fn ws_scheme() -> &'static str {
    if tls() { "wss" } else { "ws" }
}

/// An HTTP client for the kubelets.
pub fn http_client(timeout: Option<std::time::Duration>) -> Result<reqwest::Client> {
    let mut b = reqwest::Client::builder();
    if let Some(cfg) = TLS.get() {
        b = b.use_preconfigured_tls((**cfg).clone());
    }
    if let Some(t) = timeout {
        b = b.timeout(t);
    }
    Ok(b.build()?)
}

/// A byte stream to a kubelet: TCP, or TLS over it.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Connect to `host:port` (an IP, as `node_kubelet_addr` gives), over TLS
/// when it is on.
pub async fn connect(addr: &str) -> Result<Box<dyn Io>> {
    let tcp = tokio::net::TcpStream::connect(addr).await.with_context(|| addr.to_string())?;
    let Some(cfg) = TLS.get() else {
        return Ok(Box::new(tcp));
    };
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h).trim_start_matches('[').trim_end_matches(']');
    let ip: std::net::IpAddr = host.parse().with_context(|| format!("{host} is not an IP address"))?;
    let tls = tokio_rustls::TlsConnector::from(cfg.clone())
        .connect(ServerName::IpAddress(ip.into()), tcp)
        .await
        .with_context(|| format!("TLS to the kubelet at {addr}"))?;
    Ok(Box::new(tls))
}
