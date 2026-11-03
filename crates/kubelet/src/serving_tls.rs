//! The kubelet's node server (`:10250`: exec, attach, container logs,
//! metrics) over mutual TLS.
//!
//! It serves a certificate from the cluster CA and accepts a client only
//! with a certificate from that CA that is NOT a node's
//! (`CN=system:node:<node>`): the API server forwarding exec, attach and
//! logs, or another control-plane identity. A client without a certificate
//! (a pod, anyone on the network), with a certificate of another CA, or with
//! a node's certificate is refused in the TLS handshake; plaintext cannot
//! complete one.

use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

/// The node server's TLS files (PEM).
#[derive(Clone, Debug)]
pub struct ServingTls {
    pub cert_file: String,
    pub key_file: String,
    /// The cluster CA: a client certificate must chain to it.
    pub client_ca_file: String,
}

/// A client certificate's CN, if it parses.
pub fn common_name(der: &[u8]) -> Option<String> {
    let (_, c) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = c.subject().iter_common_name().next()?.as_str().ok()?.to_string();
    Some(cn)
}

/// May this client certificate (already chained to the CA) use the node server?
pub fn control_plane(cn: &str) -> bool {
    !cn.is_empty() && !cn.starts_with("system:node:")
}

/// The CA's chain check, then: not a node's certificate.
#[derive(Debug)]
pub struct ControlPlaneOnly(pub Arc<dyn ClientCertVerifier>);

impl ClientCertVerifier for ControlPlaneOnly {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.0.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.0.verify_client_cert(end_entity, intermediates, now)?;
        match common_name(end_entity) {
            Some(cn) if control_plane(&cn) => Ok(ClientCertVerified::assertion()),
            Some(cn) => Err(rustls::Error::General(format!(
                "the node server takes control-plane certificates only, not {cn}"
            ))),
            None => Err(rustls::Error::General("a client certificate without a CN".into())),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

impl ServingTls {
    /// The server config: its certificate, mandatory control-plane client auth.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let read = |p: &str| std::fs::read(p).with_context(|| p.to_string());
        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile_certs(&read(&self.cert_file)?).context("the serving certificate")?;
        let key = rustls::pki_types::pem::PemObject::from_pem_slice(&read(&self.key_file)?)
            .map(|k: PrivateKeyDer<'static>| k)
            .context("the serving key")?;
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile_certs(&read(&self.client_ca_file)?).context("the client CA")? {
            roots.add(c).context("the client CA")?;
        }
        let inner = rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .context("the client verifier")?;
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(ControlPlaneOnly(inner)))
            .with_single_cert(certs, key)?;
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

fn rustls_pemfile_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    Ok(CertificateDer::pem_slice_iter(pem).collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_control_plane_names_pass() {
        assert!(control_plane("rusternetes-apiserver"));
        assert!(control_plane("admin"));
        assert!(!control_plane("system:node:worker"));
        assert!(!control_plane(""));
    }
}
