//! WebSocket streaming for exec, attach and port-forward.
//!
//! The connection goes through rustls (no OpenSSL; the binary links
//! statically against musl) with the kubeconfig's CA and client certificate,
//! the same identity the REST client presents.
//!
//! Exec and attach speak the Kubernetes channel protocol
//! (`v5.channel.k8s.io`, falling back to `v4.channel.k8s.io`): every binary
//! frame starts with its channel (0 stdin, 1 stdout, 2 stderr, 3 status,
//! 4 resize). The end of stdin is the v5 close message `[255, 0]`.
//! Port-forward speaks `v4.channel.k8s.io` with two channels per port.
use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

/// Kubernetes streaming protocol channels
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamChannel {
    Stdin = 0,
    Stdout = 1,
    Stderr = 2,
    Error = 3,
    Resize = 4,
}

impl StreamChannel {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Stdin),
            1 => Some(Self::Stdout),
            2 => Some(Self::Stderr),
            3 => Some(Self::Error),
            4 => Some(Self::Resize),
            _ => None,
        }
    }
}

/// What exec and attach offer, newest first.
pub const EXEC_PROTOCOLS: &[&str] = &["v5.channel.k8s.io", "v4.channel.k8s.io"];

/// What port-forward offers.
pub const PORT_FORWARD_PROTOCOLS: &[&str] = &["v4.channel.k8s.io"];

/// v5's control channel: `[255, <stream>]` closes that stream.
pub const CLOSE_CHANNEL: u8 = 255;

/// A message in the Kubernetes streaming protocol
#[derive(Debug, Clone)]
pub struct StreamMessage {
    pub channel: StreamChannel,
    pub data: Bytes,
}

impl StreamMessage {
    pub fn new(channel: StreamChannel, data: impl Into<Bytes>) -> Self {
        Self {
            channel,
            data: data.into(),
        }
    }

    pub fn stdin(data: impl Into<Bytes>) -> Self {
        Self::new(StreamChannel::Stdin, data)
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(anyhow!("Empty message"));
        }

        let channel = StreamChannel::from_u8(data[0])
            .ok_or_else(|| anyhow!("Invalid channel: {}", data[0]))?;

        let payload = if data.len() > 1 {
            Bytes::copy_from_slice(&data[1..])
        } else {
            Bytes::new()
        };

        Ok(Self {
            channel,
            data: payload,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.data.len());
        buf.push(self.channel as u8);
        buf.extend_from_slice(&self.data);
        buf
    }
}

/// Any byte stream a WebSocket can run over (plain TCP or rustls).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub type WsStream = WebSocketStream<Box<dyn Io>>;

/// The rustls client configuration for the API server: trust `ca_pem` (or
/// the public web roots when there is none, or anything when `insecure`),
/// and present `cert_pem` + `key_pem` when given.
pub fn rustls_config(
    insecure: bool,
    ca_pem: Option<&[u8]>,
    cert_pem: Option<&[u8]>,
    key_pem: Option<&[u8]>,
) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("TLS protocol versions")?;
    let builder = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
    } else {
        let mut roots = rustls::RootCertStore::empty();
        match ca_pem {
            Some(ca) => {
                for c in rustls_pemfile::certs(&mut &ca[..]) {
                    roots
                        .add(c.context("certificate-authority")?)
                        .context("certificate-authority")?;
                }
            }
            None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        }
        builder.with_root_certificates(roots)
    };
    Ok(match (cert_pem, key_pem) {
        (Some(cert), Some(key)) => {
            let certs = rustls_pemfile::certs(&mut &cert[..])
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("client-certificate")?;
            let key = rustls_pemfile::private_key(&mut &key[..])
                .context("client-key")?
                .ok_or_else(|| anyhow!("client-key: no private key in PEM"))?;
            builder
                .with_client_auth_cert(certs, key)
                .context("client certificate / key")?
        }
        _ => builder.with_no_client_auth(),
    })
}

/// `insecure-skip-tls-verify`: accept any server certificate (signatures
/// are still checked, so the handshake itself stays sound).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Open a WebSocket to `url` (`ws://` or `wss://`), offering `protocols`,
/// with `token` as a bearer token and `tls` for `wss://`.
pub async fn connect(
    url: &str,
    protocols: &[&str],
    token: Option<&str>,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<WsStream> {
    let parsed = url::Url::parse(url).with_context(|| format!("URL {}", url))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("URL {} has no host", url))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| anyhow!("URL {} has no port", url))?;
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("connecting to {}:{}", host, port))?;
    let _ = tcp.set_nodelay(true);
    let io: Box<dyn Io> = match parsed.scheme() {
        "wss" => {
            let tls = tls.ok_or_else(|| anyhow!("no TLS configuration for {}", url))?;
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .with_context(|| format!("server name {}", host))?;
            Box::new(
                tokio_rustls::TlsConnector::from(tls)
                    .connect(name, tcp)
                    .await
                    .with_context(|| format!("TLS handshake with {}:{}", host, port))?,
            )
        }
        "ws" => Box::new(tcp),
        s => anyhow::bail!("unsupported URL scheme {}", s),
    };
    let mut req = url.into_client_request()?;
    if !protocols.is_empty() {
        req.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_str(&protocols.join(", "))?,
        );
    }
    if let Some(t) = token {
        req.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", t))?,
        );
    }
    let (ws, resp) = tokio_tungstenite::client_async(req, io)
        .await
        .map_err(|e| match e {
            tokio_tungstenite::tungstenite::Error::Http(r) => {
                let body = r
                    .body()
                    .as_ref()
                    .map(|b| String::from_utf8_lossy(b).trim().to_string())
                    .unwrap_or_default();
                anyhow!("the server answered {}: {}", r.status(), body)
            }
            e => anyhow!("WebSocket handshake: {}", e),
        })?;
    tracing::debug!(
        "websocket {} protocol {:?}",
        url,
        resp.headers().get("Sec-WebSocket-Protocol")
    );
    Ok(ws)
}

/// The exit code a v4/v5 status frame (channel 3) reports: `Ok(0)` for
/// Success, the `ExitCode` cause for NonZeroExitCode, an error otherwise.
pub fn exit_code_from_status(status: &[u8]) -> Result<i32> {
    let v: serde_json::Value = match serde_json::from_slice(status) {
        Ok(v) => v,
        Err(_) => anyhow::bail!("{}", String::from_utf8_lossy(status).trim()),
    };
    if v["status"] == "Success" {
        return Ok(0);
    }
    if v["reason"] == "NonZeroExitCode" {
        if let Some(code) = v["details"]["causes"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["reason"] == "ExitCode")
            .and_then(|c| c["message"].as_str())
            .and_then(|m| m.parse::<i32>().ok())
        {
            return Ok(code);
        }
    }
    anyhow::bail!(
        "{}",
        v["message"]
            .as_str()
            .unwrap_or("command failed")
            .to_string()
    )
}

/// Run an exec or attach session on `ws`: stdin (when `stdin`) goes to the
/// container until EOF, then the stream is closed with `[255, 0]`; stdout
/// and stderr are copied out until the server closes. Returns the remote
/// command's exit code.
pub async fn run_stream(ws: WsStream, stdin: bool) -> Result<i32> {
    let (mut write, mut read) = ws.split();

    let writer = stdin.then(|| {
        tokio::spawn(async move {
            let mut input = tokio::io::stdin();
            let mut buf = vec![0u8; 8192];
            loop {
                match input.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let msg = StreamMessage::stdin(buf[..n].to_vec()).encode();
                        if write.send(Message::Binary(msg)).await.is_err() {
                            return write;
                        }
                    }
                }
            }
            let _ = write
                .send(Message::Binary(vec![
                    CLOSE_CHANNEL,
                    StreamChannel::Stdin as u8,
                ]))
                .await;
            write
        })
    });

    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut exit: Option<Result<i32>> = None;
    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                let Some((&ch, payload)) = data.split_first() else {
                    continue;
                };
                match StreamChannel::from_u8(ch) {
                    Some(StreamChannel::Stdout) => {
                        stdout.write_all(payload).await?;
                        stdout.flush().await?;
                    }
                    Some(StreamChannel::Stderr) => {
                        stderr.write_all(payload).await?;
                        stderr.flush().await?;
                    }
                    Some(StreamChannel::Error) if !payload.is_empty() => {
                        exit = Some(exit_code_from_status(payload));
                    }
                    _ => {}
                }
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => {}
            Err(e) => {
                if exit.is_none() {
                    return Err(anyhow!("websocket: {}", e));
                }
                break;
            }
        }
    }
    if let Some(w) = writer {
        w.abort();
    }
    exit.unwrap_or(Ok(0))
}

/// Forward connections accepted on `listener` (bound to `bind_address`,
/// `local_port`) to `remote_port` of the pod, one WebSocket from `open` per
/// connection, printing what upstream kubectl prints.
pub async fn port_forward_serve(
    open: Arc<dyn Fn() -> futures::future::BoxFuture<'static, Result<WsStream>> + Send + Sync>,
    listener: tokio::net::TcpListener,
    bind_address: &str,
    local_port: u16,
    remote_port: u16,
) -> Result<()> {
    let shown = if bind_address.contains(':') {
        format!("[{}]", bind_address)
    } else {
        bind_address.to_string()
    };
    println!(
        "Forwarding from {}:{} -> {}",
        shown, local_port, remote_port
    );
    loop {
        let (tcp, _) = listener.accept().await?;
        println!("Handling connection for {}", local_port);
        let open = open.clone();
        tokio::spawn(async move {
            let result = async {
                let ws = open().await?;
                forward_connection(ws, tcp).await
            }
            .await;
            if let Err(e) = result {
                eprintln!(
                    "E{} portforward.go: an error occurred forwarding {} -> {}: {:#}",
                    chrono::Utc::now().format("%m%d %H:%M:%S%.6f"),
                    local_port,
                    remote_port,
                    e
                );
            }
        });
    }
}

/// Copy one TCP connection over a v4 port-forward WebSocket (one port:
/// channel 0 data, channel 1 errors; the server first sends each channel's
/// port as a little-endian u16).
pub async fn forward_connection(ws: WsStream, tcp: tokio::net::TcpStream) -> Result<()> {
    let (mut ws_write, mut ws_read) = ws.split();
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let mut seen_header = [false; 2];

    let up = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut frame = Vec::with_capacity(n + 1);
                    frame.push(0u8);
                    frame.extend_from_slice(&buf[..n]);
                    if ws_write.send(Message::Binary(frame)).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_write.close().await;
    });

    let mut error: Option<String> = None;
    while let Some(msg) = ws_read.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                let Some((&ch, payload)) = data.split_first() else {
                    continue;
                };
                if ch > 1 {
                    continue;
                }
                if !seen_header[ch as usize] {
                    // The first frame on each channel is its port.
                    seen_header[ch as usize] = true;
                    continue;
                }
                if ch == 0 {
                    if tcp_write.write_all(payload).await.is_err() {
                        break;
                    }
                } else if !payload.is_empty() {
                    error = Some(String::from_utf8_lossy(payload).into_owned());
                }
            }
            Ok(Message::Text(t)) => error = Some(t),
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => {}
        }
    }
    let _ = tcp_write.shutdown().await;
    up.abort();
    match error {
        Some(e) => Err(anyhow!("{}", e)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_success_and_exit_codes() {
        assert_eq!(
            exit_code_from_status(br#"{"status":"Success"}"#).unwrap(),
            0
        );
        let failure = br#"{"status":"Failure","message":"command terminated with exit code 3","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"3"}]}}"#;
        assert_eq!(exit_code_from_status(failure).unwrap(), 3);
        let err = exit_code_from_status(br#"{"status":"Failure","message":"container not found"}"#)
            .unwrap_err();
        assert_eq!(err.to_string(), "container not found");
        assert_eq!(
            exit_code_from_status(b"Exec error: boom")
                .unwrap_err()
                .to_string(),
            "Exec error: boom"
        );
    }

    #[test]
    fn insecure_and_ca_configs_build() {
        rustls_config(true, None, None, None).unwrap();
        rustls_config(false, None, None, None).unwrap();
        assert!(rustls_config(false, Some(b"not pem"), None, None).is_ok());
    }

    /// A TLS WebSocket echo server that requires a client certificate of its
    /// CA, then exec framing over it: the same path as `kubectl exec` against
    /// an API server with `--client-ca-file`.
    #[tokio::test]
    async fn exec_over_mutual_tls() {
        // A CA, a server certificate for 127.0.0.1 and a client certificate.
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf = |names: Vec<String>| {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(names)
                .unwrap()
                .signed_by(&key, &ca_cert, &ca_key)
                .unwrap();
            (cert, key)
        };
        let (srv_cert, srv_key) = leaf(vec!["127.0.0.1".into()]);
        let (cli_cert, cli_key) = leaf(vec!["admin".into()]);

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![srv_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::try_from(srv_key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let tls = acceptor.accept(tcp).await.unwrap();
            let mut ws = tokio_tungstenite::accept_hdr_async(
                tls,
                |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                 mut resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                    assert!(req.headers()["Sec-WebSocket-Protocol"]
                        .to_str()
                        .unwrap()
                        .contains("v5.channel.k8s.io"));
                    resp.headers_mut()
                        .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("v5.channel.k8s.io"));
                    Ok(resp)
                },
            )
            .await
            .unwrap();
            // Echo stdin to stdout until the v5 close of stdin, then exit 7.
            while let Some(Ok(Message::Binary(d))) = ws.next().await {
                if d == [CLOSE_CHANNEL, 0] {
                    break;
                }
                let mut out = d.clone();
                out[0] = 1;
                ws.send(Message::Binary(out)).await.unwrap();
            }
            let status = br#"{"status":"Failure","reason":"NonZeroExitCode","details":{"causes":[{"reason":"ExitCode","message":"7"}]}}"#;
            ws.send(Message::Binary([&[3u8][..], status].concat()))
                .await
                .unwrap();
            ws.close(None).await.unwrap();
        });

        let cfg = rustls_config(
            false,
            Some(ca_cert.pem().as_bytes()),
            Some(cli_cert.pem().as_bytes()),
            Some(cli_key.serialize_pem().as_bytes()),
        )
        .unwrap();
        let url = format!(
            "wss://127.0.0.1:{}/api/v1/namespaces/default/pods/p/exec",
            addr.port()
        );
        let mut ws = connect(&url, &["v5.channel.k8s.io"], None, Some(Arc::new(cfg)))
            .await
            .unwrap();
        ws.send(Message::Binary(vec![0, b'h', b'i'])).await.unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap(),
            Message::Binary(vec![1, b'h', b'i'])
        );
        ws.send(Message::Binary(vec![CLOSE_CHANNEL, 0]))
            .await
            .unwrap();
        let Message::Binary(status) = ws.next().await.unwrap().unwrap() else {
            panic!("no status")
        };
        assert_eq!(exit_code_from_status(&status[1..]).unwrap(), 7);
    }
}
