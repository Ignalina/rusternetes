use crate::client::ApiClient;
use crate::websocket;
use anyhow::Result;

/// Forward one or more local ports to a pod
pub async fn execute(
    client: &ApiClient,
    pod_name: &str,
    namespace: &str,
    ports: &[String],
    address: &str,
) -> Result<()> {
    if ports.is_empty() {
        anyhow::bail!("At least one port must be specified");
    }

    // `pod/NAME` names the pod too.
    let pod_name = pod_name
        .strip_prefix("pod/")
        .or_else(|| pod_name.strip_prefix("pods/"))
        .unwrap_or(pod_name);
    // Fail before listening when the pod does not exist, as upstream does.
    let pod_path = format!("/api/v1/namespaces/{}/pods/{}", namespace, pod_name);
    if !client.resource_exists(&pod_path).await? {
        anyhow::bail!(
            "Error from server (NotFound): pods \"{}\" not found",
            pod_name
        );
    }

    // `localhost` (the default) is 127.0.0.1 and ::1, as upstream binds it.
    let addresses: Vec<(String, bool)> = if address == "localhost" {
        vec![("127.0.0.1".into(), true), ("::1".into(), false)]
    } else {
        address
            .split(',')
            .map(|a| (a.trim().to_string(), true))
            .collect()
    };
    let mut listeners = Vec::new();
    for spec in ports {
        // "local:remote" or "port"
        let (local_port, remote_port) = parse_port_mapping(spec)?;
        let url_path = format!(
            "/api/v1/namespaces/{}/pods/{}/portforward?ports={}",
            namespace, pod_name, remote_port
        );
        let url = client.get_ws_url(&url_path)?;
        let token = client.get_token().cloned();
        let tls = client.ws_tls();
        let open: std::sync::Arc<
            dyn Fn() -> futures::future::BoxFuture<'static, Result<websocket::WsStream>>
                + Send
                + Sync,
        > = std::sync::Arc::new(move || {
            let (url, token, tls) = (url.clone(), token.clone(), tls.clone());
            Box::pin(async move {
                websocket::connect(
                    &url,
                    websocket::PORT_FORWARD_PROTOCOLS,
                    token.as_deref(),
                    Some(tls),
                )
                .await
            })
        });
        for (addr, required) in &addresses {
            let listener = match tokio::net::TcpListener::bind((addr.as_str(), local_port)).await {
                Ok(l) => l,
                Err(_) if !required => continue,
                Err(e) => anyhow::bail!("unable to listen on {}:{}: {}", addr, local_port, e),
            };
            let (open, addr) = (open.clone(), addr.clone());
            listeners.push(tokio::spawn(async move {
                websocket::port_forward_serve(open, listener, &addr, local_port, remote_port).await
            }));
        }
    }
    // Run until interrupted or a listener fails.
    let (first, _, _) = futures::future::select_all(listeners).await;
    first?
}

fn parse_port_mapping(port_spec: &str) -> Result<(u16, u16)> {
    if let Some((local, remote)) = port_spec.split_once(':') {
        let local_port = local.parse::<u16>()?;
        let remote_port = remote.parse::<u16>()?;
        Ok((local_port, remote_port))
    } else {
        // If only one port specified, use same for both local and remote
        let port = port_spec.parse::<u16>()?;
        Ok((port, port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_mapping_local_remote() {
        let (local, remote) = parse_port_mapping("8080:80").unwrap();
        assert_eq!(local, 8080);
        assert_eq!(remote, 80);
    }

    #[test]
    fn test_parse_port_mapping_same_port() {
        let (local, remote) = parse_port_mapping("3000").unwrap();
        assert_eq!(local, 3000);
        assert_eq!(remote, 3000);
    }

    #[test]
    fn test_parse_port_mapping_invalid() {
        let result = parse_port_mapping("abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_mapping_invalid_local() {
        let result = parse_port_mapping("abc:80");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_mapping_invalid_remote() {
        let result = parse_port_mapping("80:abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_mapping_high_port() {
        let (local, remote) = parse_port_mapping("65535:443").unwrap();
        assert_eq!(local, 65535);
        assert_eq!(remote, 443);
    }

    #[test]
    fn test_parse_port_mapping_overflow_fails() {
        // Port number exceeding u16 max should fail
        let result = parse_port_mapping("70000");
        assert!(result.is_err());
    }
}
