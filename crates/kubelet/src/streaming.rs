//! The node's streaming endpoints, which the API server proxies to for pods
//! on this node: exec and attach over WebSocket (the Kubernetes channel
//! protocol, as `v5.channel.k8s.io`/`v4.channel.k8s.io`), and followed logs.
//!
//! Channels: 0 stdin (in), 1 stdout, 2 stderr, 3 status (a `metav1.Status`
//! as JSON, then the socket closes). The end of stdin is `[255, 0]` (v5) or
//! an empty stdin frame.

use crate::backend::{
    ContainerBackend, CreateExecOptions, LogOutput, LogsOptions, StartExecResults,
};
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, RawQuery};
use axum::response::{IntoResponse, Response};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// The WebSocket subprotocols the node speaks for exec and attach.
pub const PROTOCOLS: [&str; 3] = ["v5.channel.k8s.io", "v4.channel.k8s.io", "channel.k8s.io"];

/// Exec/attach options from the query (`command` repeats).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct StreamQuery {
    pub command: Vec<String>,
    pub stdin: bool,
    pub tty: bool,
    pub follow: bool,
    pub tail_lines: Option<String>,
}

impl StreamQuery {
    pub fn parse(raw: Option<&str>) -> Self {
        let mut q = StreamQuery::default();
        let on = |v: &str| v == "true" || v == "1";
        for (k, v) in url::form_urlencoded::parse(raw.unwrap_or("").as_bytes()) {
            match k.as_ref() {
                "command" => q.command.push(v.into_owned()),
                "stdin" => q.stdin = on(&v),
                "tty" => q.tty = on(&v),
                "follow" => q.follow = on(&v),
                "tailLines" => q.tail_lines = Some(v.into_owned()),
                _ => {}
            }
        }
        q
    }
}

/// The v4/v5 status frame for `exit_code`.
pub fn status_frame(exit_code: i64) -> Vec<u8> {
    let status = if exit_code == 0 {
        r#"{"metadata":{},"status":"Success"}"#.to_string()
    } else {
        format!(
            r#"{{"metadata":{{}},"status":"Failure","message":"command terminated with non-zero exit code: error executing command [exit {0}], exit code {0}","reason":"NonZeroExitCode","details":{{"causes":[{{"reason":"ExitCode","message":"{0}"}}]}}}}"#,
            exit_code
        )
    };
    let mut f = vec![3u8];
    f.extend_from_slice(status.as_bytes());
    f
}

fn failure_frame(message: &str) -> Vec<u8> {
    let mut f = vec![3u8];
    f.extend_from_slice(
        serde_json::json!({"metadata": {}, "status": "Failure", "message": message})
            .to_string()
            .as_bytes(),
    );
    f
}

/// `GET /exec/{namespace}/{pod}/{container}?command=…&stdin=…` (WebSocket).
pub async fn exec(
    backend: Arc<dyn ContainerBackend>,
    Path((_namespace, pod, container)): Path<(String, String, String)>,
    RawQuery(raw): RawQuery,
    ws: WebSocketUpgrade,
) -> Response {
    let q = StreamQuery::parse(raw.as_deref());
    let name = format!("{}_{}", pod, container);
    ws.protocols(PROTOCOLS)
        .on_upgrade(move |socket| run_exec(socket, backend, name, q))
        .into_response()
}

/// Run `q.command` in container `name` and stream it over `socket`.
pub async fn run_exec(
    socket: WebSocket,
    backend: Arc<dyn ContainerBackend>,
    name: String,
    q: StreamQuery,
) {
    let (mut tx, mut rx) = socket.split();
    let started = async {
        let id = backend
            .create_exec(
                &name,
                CreateExecOptions {
                    cmd: Some(q.command.clone()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    attach_stdin: Some(q.stdin),
                    tty: Some(q.tty),
                },
            )
            .await?;
        let r = backend.start_exec(&id).await?;
        Ok::<_, anyhow::Error>((id, r))
    }
    .await;
    let (id, results) = match started {
        Ok(v) => v,
        Err(e) => {
            let _ = tx
                .send(Message::Binary(failure_frame(&e.to_string())))
                .await;
            let _ = tx.close().await;
            return;
        }
    };
    let (mut output, input) = match results {
        StartExecResults::Attached { output, input } => (output, input),
        StartExecResults::Detached => (futures::stream::empty().boxed(), None),
    };

    // Client → exec stdin, until the client closes stdin or the socket.
    let reader = tokio::spawn(async move {
        let mut input = input;
        while let Some(Ok(msg)) = rx.next().await {
            match msg {
                Message::Binary(d) => match d.split_first() {
                    Some((0, [])) => {
                        if let Some(mut w) = input.take() {
                            let _ = w.shutdown().await;
                        }
                    }
                    Some((0, payload)) => {
                        if let Some(w) = input.as_mut() {
                            if w.write_all(payload).await.is_err() || w.flush().await.is_err() {
                                input = None;
                            }
                        }
                    }
                    Some((255, [0])) => {
                        if let Some(mut w) = input.take() {
                            let _ = w.shutdown().await;
                        }
                    }
                    _ => {}
                },
                Message::Close(_) => break,
                _ => {}
            }
        }
        if let Some(mut w) = input.take() {
            let _ = w.shutdown().await;
        }
    });

    // Exec output → client.
    while let Some(chunk) = output.next().await {
        let frame = match chunk {
            Ok(LogOutput::StdErr { message }) => [&[2u8][..], &message].concat(),
            Ok(LogOutput::StdOut { message }) | Ok(LogOutput::Console { message }) => {
                [&[1u8][..], &message].concat()
            }
            Ok(LogOutput::StdIn { .. }) => continue,
            Err(_) => break,
        };
        if tx.send(Message::Binary(frame)).await.is_err() {
            reader.abort();
            return;
        }
    }

    // The exit code is written just before the output closes; wait briefly
    // for a runtime that records it a little later.
    let mut exit = None;
    for _ in 0..50 {
        match backend.inspect_exec(&id).await {
            Ok(i) if i.running == Some(false) => {
                exit = i.exit_code;
                break;
            }
            Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            Err(_) => break,
        }
    }
    let _ = tx
        .send(Message::Binary(status_frame(exit.unwrap_or(0))))
        .await;
    let _ = tx
        .send(Message::Close(Some(CloseFrame {
            code: 1000,
            reason: "".into(),
        })))
        .await;
    reader.abort();
}

/// `GET /attach/{namespace}/{pod}/{container}` (WebSocket): the container's
/// output from now on, until it stops. Its stdin is not attached (the
/// youki backend gives containers /dev/null).
pub async fn attach(
    backend: Arc<dyn ContainerBackend>,
    Path((_namespace, pod, container)): Path<(String, String, String)>,
    ws: WebSocketUpgrade,
) -> Response {
    let name = format!("{}_{}", pod, container);
    ws.protocols(PROTOCOLS)
        .on_upgrade(move |socket| async move {
            let (mut tx, mut rx) = socket.split();
            let mut logs = backend.logs(
                &name,
                LogsOptions {
                    stdout: true,
                    stderr: true,
                    tail: "0".into(),
                    follow: true,
                },
            );
            loop {
                tokio::select! {
                    chunk = logs.next() => match chunk {
                        Some(Ok(c)) => {
                            let ch = if matches!(c, LogOutput::StdErr { .. }) { 2u8 } else { 1u8 };
                            let body = c.to_string().into_bytes();
                            if tx.send(Message::Binary([&[ch][..], &body].concat())).await.is_err() {
                                return;
                            }
                        }
                        Some(Err(e)) => {
                            let _ = tx.send(Message::Binary(failure_frame(&e.to_string()))).await;
                            break;
                        }
                        None => {
                            let _ = tx.send(Message::Binary(status_frame(0))).await;
                            break;
                        }
                    },
                    msg = rx.next() => match msg {
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                        _ => {}
                    },
                }
            }
            let _ = tx.close().await;
        })
        .into_response()
}

/// `GET /containerLogs/{namespace}/{pod}/{container}[?tailLines=N][&follow=true]`
/// — a container's output from this node's backend, so the API server can
/// serve `pods/log` for pods on any node. With `follow` the body streams
/// until the container stops.
pub async fn container_logs(
    backend: Arc<dyn ContainerBackend>,
    Path((_namespace, pod, container)): Path<(String, String, String)>,
    RawQuery(raw): RawQuery,
) -> Response {
    let q = StreamQuery::parse(raw.as_deref());
    let name = format!("{}_{}", pod, container);
    let opts = LogsOptions {
        stdout: true,
        stderr: true,
        tail: q.tail_lines.clone().unwrap_or_else(|| "all".to_string()),
        follow: q.follow,
    };
    if q.follow {
        // Check the container exists before committing to a 200.
        if let Err(e) = backend.inspect_container(&name).await {
            return (axum::http::StatusCode::NOT_FOUND, e.to_string()).into_response();
        }
        let (mut tx, rx) = futures::channel::mpsc::channel::<std::io::Result<String>>(16);
        tokio::spawn(async move {
            let mut stream = backend.logs(&name, opts);
            while let Some(chunk) = stream.next().await {
                let item = chunk
                    .map(|c| c.to_string())
                    .map_err(|e| std::io::Error::other(e.to_string()));
                if tx.send(item).await.is_err() {
                    break;
                }
            }
        });
        return axum::body::Body::from_stream(rx).into_response();
    }
    let mut out = String::new();
    let mut stream = backend.logs(&name, opts);
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(c) => out.push_str(&c.to_string()),
            Err(e) => return (axum::http::StatusCode::NOT_FOUND, e.to_string()).into_response(),
        }
    }
    out.into_response()
}

/// The node server's streaming routes over `backend`.
pub fn routes(backend: Arc<dyn ContainerBackend>) -> axum::Router {
    use axum::routing::get;
    let (b1, b2, b3) = (backend.clone(), backend.clone(), backend);
    axum::Router::new()
        .route(
            "/containerLogs/:namespace/:pod/:container",
            get(move |p, q| container_logs(b1.clone(), p, q)),
        )
        .route(
            "/exec/:namespace/:pod/:container",
            get(move |p, q, ws| exec(b2.clone(), p, q, ws)),
        )
        .route(
            "/attach/:namespace/:pod/:container",
            get(move |p, ws| attach(b3.clone(), p, ws)),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::fake::FakeBackend;
    use tokio_tungstenite::tungstenite::Message as C;

    async fn serve(backend: Arc<dyn ContainerBackend>) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, routes(backend)).await.unwrap() });
        addr
    }

    #[test]
    fn query_with_repeated_commands() {
        let q = StreamQuery::parse(Some(
            "command=sh&command=-c&command=echo+hi%3B+exit+3&stdin=true&tty=1&tailLines=5",
        ));
        assert_eq!(q.command, ["sh", "-c", "echo hi; exit 3"]);
        assert!(q.stdin && q.tty && !q.follow);
        assert_eq!(q.tail_lines.as_deref(), Some("5"));
    }

    #[test]
    fn status_frames() {
        assert_eq!(
            &status_frame(0)[1..],
            br#"{"metadata":{},"status":"Success"}"#
        );
        let f: serde_json::Value = serde_json::from_slice(&status_frame(3)[1..]).unwrap();
        assert_eq!(f["reason"], "NonZeroExitCode");
        assert_eq!(f["details"]["causes"][0]["message"], "3");
    }

    #[tokio::test]
    async fn exec_streams_stdin_through_and_reports_success() {
        let b = Arc::new(FakeBackend::new("fake"));
        b.add("web_app", "running", 0);
        let addr = serve(b).await;
        let url = format!("ws://{}/exec/default/web/app?command=cat&stdin=true", addr);
        let mut req =
            tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(url)
                .unwrap();
        req.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            "v5.channel.k8s.io".parse().unwrap(),
        );
        let (mut ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        assert_eq!(
            resp.headers()["sec-websocket-protocol"],
            "v5.channel.k8s.io"
        );
        ws.send(C::Binary(b"\0hello\n".to_vec())).await.unwrap();
        ws.send(C::Binary(vec![255, 0])).await.unwrap();
        let mut out = Vec::new();
        let mut status = Vec::new();
        while let Some(Ok(m)) = ws.next().await {
            if let C::Binary(d) = m {
                match d[0] {
                    1 => out.extend_from_slice(&d[1..]),
                    3 => status = d[1..].to_vec(),
                    _ => {}
                }
            }
        }
        assert_eq!(out, b"hello\n");
        assert_eq!(status, br#"{"metadata":{},"status":"Success"}"#);
    }

    #[tokio::test]
    async fn exec_reports_exit_code_and_stderr() {
        let b = Arc::new(FakeBackend::new("fake"));
        b.add("web_app", "running", 0);
        let addr = serve(b).await;
        let url = format!("ws://{}/exec/default/web/app?command=false", addr);
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let mut err = Vec::new();
        let mut status = Vec::new();
        while let Some(Ok(m)) = ws.next().await {
            if let C::Binary(d) = m {
                match d[0] {
                    2 => err.extend_from_slice(&d[1..]),
                    3 => status = d[1..].to_vec(),
                    _ => {}
                }
            }
        }
        assert_eq!(err, b"failed\n");
        let s: serde_json::Value = serde_json::from_slice(&status).unwrap();
        assert_eq!(s["details"]["causes"][0]["message"], "1");
    }

    /// Container `web_app` of pod `web` in namespace `a`: its labels name
    /// the pod, the name holds no namespace.
    async fn web_app_of_namespace_a() -> Arc<FakeBackend> {
        let b = Arc::new(FakeBackend::new("fake"));
        let labels = std::collections::HashMap::from([
            (
                crate::pod_identity::POD_NAMESPACE_LABEL.to_string(),
                "a".to_string(),
            ),
            (
                crate::pod_identity::POD_NAME_LABEL.to_string(),
                "web".to_string(),
            ),
        ]);
        b.create_container(
            "web_app",
            crate::backend::ContainerConfig {
                labels: Some(labels),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        b.start_container("web_app").await.unwrap();
        b
    }

    /// The status line of a plain GET.
    async fn get_status(addr: std::net::SocketAddr, path: &str) -> String {
        use tokio::io::AsyncReadExt;
        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: node\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out.lines().next().unwrap_or("").to_string()
    }

    /// `exec` into pod `web` of namespace `b` must not run in pod `web` of
    /// namespace `a`: the node names both pods' containers `web_<container>`,
    /// and the namespace in the path was not read.
    #[tokio::test]
    async fn exec_and_attach_never_reach_a_same_named_pod_of_another_namespace() {
        let b = web_app_of_namespace_a().await;
        let addr = serve(b.clone()).await;
        for path in ["exec/b/web/app?command=cat", "attach/b/web/app"] {
            let url = format!("ws://{addr}/{path}");
            assert!(
                tokio_tungstenite::connect_async(url).await.is_err(),
                "{path} reached a/web"
            );
        }
        assert!(
            !b.calls().iter().any(|c| c.starts_with("exec ")),
            "{:?}",
            b.calls()
        );

        // Its own namespace's exec still runs.
        let url = format!("ws://{addr}/exec/a/web/app?command=false");
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        while let Some(Ok(_)) = ws.next().await {}
        assert!(b.calls().iter().any(|c| c == "exec web_app false"));
    }

    /// The logs of pod `web` in namespace `b` are not pod `web`'s of
    /// namespace `a`.
    #[tokio::test]
    async fn logs_never_come_from_a_same_named_pod_of_another_namespace() {
        let b = web_app_of_namespace_a().await;
        let addr = serve(b).await;
        let other = get_status(addr, "/containerLogs/b/web/app").await;
        assert!(other.contains(" 404 "), "{other}");
        let followed = get_status(addr, "/containerLogs/b/web/app?follow=true").await;
        assert!(followed.contains(" 404 "), "{followed}");
        let own = get_status(addr, "/containerLogs/a/web/app").await;
        assert!(own.contains(" 200 "), "{own}");
    }
}
