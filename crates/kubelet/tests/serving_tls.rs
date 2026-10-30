//! The node server over mutual TLS (`serving_tls`): the API server's
//! client certificate is served; no certificate, a node's certificate, a
//! certificate of another CA and plaintext are refused.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
use rusternetes_kubelet::serving_tls::ServingTls;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, name);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    Ca { cert: p.self_signed(&key).unwrap(), key }
}

fn leaf(ca: &Ca, cn: &str, server: bool) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, cn);
    if server {
        p.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    }
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    (p.signed_by(&key, &ca.cert, &ca.key).unwrap().pem(), key.serialize_pem())
}

async fn serve(cluster: &Ca, dir: &std::path::Path) -> std::net::SocketAddr {
    let (c, k) = leaf(cluster, "system:node:worker", true);
    std::fs::write(dir.join("node.crt"), c).unwrap();
    std::fs::write(dir.join("node.key"), k).unwrap();
    std::fs::write(dir.join("ca.crt"), cluster.cert.pem()).unwrap();
    let t = ServingTls {
        cert_file: dir.join("node.crt").display().to_string(),
        key_file: dir.join("node.key").display().to_string(),
        client_ca_file: dir.join("ca.crt").display().to_string(),
    };
    let cfg = t.server_config().unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(l, axum_server::tls_rustls::RustlsConfig::from_config(cfg))
            .serve(app.into_make_service())
            .await
            .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    addr
}

fn client(cluster: &Ca, id: Option<(String, String)>) -> reqwest::Client {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut b = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(cluster.cert.pem().as_bytes()).unwrap())
        .timeout(std::time::Duration::from_secs(3));
    if let Some((c, k)) = id {
        b = b.identity(reqwest::Identity::from_pem(format!("{c}{k}").as_bytes()).unwrap());
    }
    b.build().unwrap()
}

#[tokio::test]
async fn only_a_control_plane_certificate_reaches_the_node_server() {
    let cluster = ca("cluster CA");
    let other = ca("another CA");
    let dir = tempfile::tempdir().unwrap();
    let addr = serve(&cluster, dir.path()).await;
    let url = format!("https://{addr}/healthz");
    let api = client(&cluster, Some(leaf(&cluster, "rusternetes-apiserver", false)));
    assert_eq!(api.get(&url).send().await.unwrap().text().await.unwrap(), "ok");
    assert!(client(&cluster, None).get(&url).send().await.is_err(), "no certificate");
    assert!(client(&cluster, Some(leaf(&cluster, "system:node:other", false))).get(&url).send().await.is_err(), "a node's certificate");
    assert!(client(&cluster, Some(leaf(&other, "rusternetes-apiserver", false))).get(&url).send().await.is_err(), "another CA");
    let plain = reqwest::Client::new().get(format!("http://{addr}/healthz")).send().await;
    assert!(plain.map(|r| !r.status().is_success()).unwrap_or(true), "plaintext");
    let _ = Arc::new(());
}
