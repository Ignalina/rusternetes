use anyhow::{Context, Result};
use rusternetes_common::resources::{EndpointSlice, Endpoints};
use rusternetes_storage::Storage;
use rusternetes_storage::StorageBackend;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Get the API server's IP address from the network interface
/// This discovers the container's IP on the Docker/Podman network
fn get_api_server_ip() -> Result<String> {
    // An HA control plane advertises one address for all its API servers
    // (the virtual IP that follows the store's Raft leader).
    if let Ok(ip) = std::env::var("RUSTERNETES_ADVERTISE_ADDRESS") {
        if !ip.trim().is_empty() {
            debug!(
                "API server IP from RUSTERNETES_ADVERTISE_ADDRESS: {}",
                ip.trim()
            );
            return Ok(ip.trim().to_string());
        }
    }
    // Try to get IP from network interfaces
    // Look for non-loopback IPv4 addresses
    let interfaces = match get_if_addrs::get_if_addrs() {
        Ok(addrs) => addrs,
        Err(e) => {
            warn!("Failed to get network interfaces: {}", e);
            return Err(anyhow::anyhow!("Failed to get network interfaces: {}", e));
        }
    };

    // Find the first non-loopback IPv4 address
    for iface in interfaces {
        if !iface.is_loopback() {
            if let get_if_addrs::IfAddr::V4(addr) = iface.addr {
                let ip = addr.ip.to_string();
                info!(
                    "Discovered API server IP: {} (interface: {})",
                    ip, iface.name
                );
                return Ok(ip);
            }
        }
    }

    Err(anyhow::anyhow!("No non-loopback IPv4 address found"))
}

/// The namespaces every Kubernetes API server keeps in existence: `default`,
/// `kube-system`, `kube-public` and `kube-node-lease` (upstream: the
/// `system-namespaces` controller, `pkg/controlplane/controller/systemnamespaces`).
/// Components such as CNI agents and operators look their namespace up at
/// start and refuse to run when it is missing.
pub const SYSTEM_NAMESPACES: [&str; 4] =
    ["default", "kube-system", "kube-public", "kube-node-lease"];

/// Create each of [`SYSTEM_NAMESPACES`] that the store does not hold yet.
pub async fn bootstrap_system_namespaces(storage: Arc<StorageBackend>) -> Result<()> {
    use rusternetes_common::resources::{Namespace, NamespaceStatus};
    for name in SYSTEM_NAMESPACES {
        let key = rusternetes_storage::build_key("namespaces", None, name);
        if storage.get::<Namespace>(&key).await.is_ok() {
            continue;
        }
        let mut ns = Namespace::new(name);
        ns.metadata.ensure_uid();
        ns.metadata.ensure_creation_timestamp();
        ns.metadata.finalizers = Some(vec!["kubernetes".to_string()]);
        ns.status = Some(NamespaceStatus {
            phase: Some(rusternetes_common::types::Phase::Active),
            conditions: None,
        });
        match storage.create(&key, &ns).await {
            Ok(_) => info!("Created system namespace {}", name),
            // Another API server instance may have won the race.
            Err(rusternetes_common::Error::AlreadyExists(_)) => {}
            Err(e) => return Err(e).with_context(|| format!("create namespace {name}")),
        }
    }
    Ok(())
}

/// Bootstrap the kubernetes Service and Endpoints in the default namespace
/// This ensures the "kubernetes" service always points to this API server
pub async fn bootstrap_kubernetes_service(
    storage: Arc<StorageBackend>,
    api_server_port: u16,
) -> Result<()> {
    debug!("Bootstrapping kubernetes Service and Endpoints");

    // Get the API server's IP address
    let api_server_ip = get_api_server_ip().context("Failed to discover API server IP address")?;

    debug!(
        "API server IP: {}, Port: {}",
        api_server_ip, api_server_port
    );

    // Check if the kubernetes Endpoints already exist
    let endpoints_key = "/registry/endpoints/default/kubernetes";

    match storage.get::<Endpoints>(endpoints_key).await {
        Ok(mut endpoints) => {
            // Update existing endpoints
            debug!("Updating existing kubernetes Endpoints");
            // endpoints.subsets is Vec<EndpointSubset>
            if let Some(subset) = endpoints.subsets.first_mut() {
                // subset.addresses is Option<Vec<EndpointAddress>>
                if let Some(addresses) = &mut subset.addresses {
                    if let Some(addr) = addresses.first_mut() {
                        if addr.ip != api_server_ip {
                            info!(
                                "Updating API server IP from {} to {}",
                                addr.ip, api_server_ip
                            );
                            addr.ip = api_server_ip.clone();
                            storage
                                .update(endpoints_key, &endpoints)
                                .await
                                .context("Failed to update kubernetes Endpoints")?;
                        } else {
                            debug!("API server IP already correct: {}", api_server_ip);
                        }
                    }
                }
            }
        }
        Err(_) => {
            // Create new Endpoints if they don't exist
            info!("kubernetes Endpoints not found - creating new Endpoints");
            use rusternetes_common::resources::{EndpointAddress, EndpointPort, EndpointSubset};
            use rusternetes_common::types::{ObjectMeta, TypeMeta};

            let mut metadata = ObjectMeta::new("kubernetes");
            metadata.namespace = Some("default".to_string());

            let endpoints = Endpoints {
                type_meta: TypeMeta {
                    kind: "Endpoints".to_string(),
                    api_version: "v1".to_string(),
                },
                metadata,
                subsets: vec![EndpointSubset {
                    addresses: Some(vec![EndpointAddress {
                        ip: api_server_ip.clone(),
                        hostname: None,
                        node_name: None,
                        target_ref: None,
                    }]),
                    not_ready_addresses: None,
                    ports: Some(vec![EndpointPort {
                        name: Some("https".to_string()),
                        port: api_server_port,
                        protocol: Some("TCP".to_string()),
                        app_protocol: None,
                    }]),
                }],
            };

            storage
                .create(endpoints_key, &endpoints)
                .await
                .context("Failed to create kubernetes Endpoints")?;
            info!("Created kubernetes Endpoints with IP: {}", api_server_ip);
        }
    }

    // Also create/update an EndpointSlice for the kubernetes service.
    // The conformance test "should have Endpoints and EndpointSlices pointing to API Server"
    // (apiserver.go) expects both Endpoints AND EndpointSlices to exist for the "kubernetes" service.
    // The mirroring controller would handle this eventually, but bootstrapping it directly
    // ensures it's available immediately.
    let es_key = "/registry/endpointslices/default/kubernetes";
    match storage.get::<EndpointSlice>(es_key).await {
        Ok(mut es) => {
            // Update existing EndpointSlice
            let needs_update = es
                .endpoints
                .first()
                .map(|ep| ep.addresses.first().map(|a| a.as_str()) != Some(api_server_ip.as_str()))
                .unwrap_or(true);
            if needs_update {
                es.endpoints = vec![rusternetes_common::resources::endpointslice::Endpoint {
                    addresses: vec![api_server_ip.clone()],
                    conditions: Some(
                        rusternetes_common::resources::endpointslice::EndpointConditions {
                            ready: Some(true),
                            serving: Some(true),
                            terminating: Some(false),
                        },
                    ),
                    hostname: None,
                    target_ref: None,
                    node_name: None,
                    zone: None,
                    hints: None,
                    deprecated_topology: None,
                }];
                storage
                    .update(es_key, &es)
                    .await
                    .context("Failed to update kubernetes EndpointSlice")?;
                info!(
                    "Updated kubernetes EndpointSlice with IP: {}",
                    api_server_ip
                );
            }
        }
        Err(_) => {
            use rusternetes_common::resources::endpointslice::{
                Endpoint, EndpointConditions, EndpointPort,
            };
            use rusternetes_common::types::ObjectMeta;

            let mut metadata = ObjectMeta::new("kubernetes");
            metadata.namespace = Some("default".to_string());
            let mut labels = std::collections::HashMap::new();
            labels.insert(
                "kubernetes.io/service-name".to_string(),
                "kubernetes".to_string(),
            );
            labels.insert(
                "endpointslice.kubernetes.io/managed-by".to_string(),
                "endpointslice-mirroring-controller.k8s.io".to_string(),
            );
            metadata.labels = Some(labels);
            metadata.ensure_uid();
            metadata.ensure_creation_timestamp();

            let es = EndpointSlice {
                type_meta: rusternetes_common::types::TypeMeta {
                    kind: "EndpointSlice".to_string(),
                    api_version: "discovery.k8s.io/v1".to_string(),
                },
                metadata,
                address_type: "IPv4".to_string(),
                endpoints: vec![Endpoint {
                    addresses: vec![api_server_ip.clone()],
                    conditions: Some(EndpointConditions {
                        ready: Some(true),
                        serving: Some(true),
                        terminating: Some(false),
                    }),
                    hostname: None,
                    target_ref: None,
                    node_name: None,
                    zone: None,
                    hints: None,
                    deprecated_topology: None,
                }],
                ports: vec![EndpointPort {
                    name: Some("https".to_string()),
                    port: Some(api_server_port as i32),
                    protocol: Some("TCP".to_string()),
                    app_protocol: None,
                }],
            };

            storage
                .create(es_key, &es)
                .await
                .context("Failed to create kubernetes EndpointSlice")?;
            info!(
                "Created kubernetes EndpointSlice with IP: {}",
                api_server_ip
            );
        }
    }

    ensure_kubernetes_service(&storage, api_server_port).await
}

/// The `kubernetes` Service's ClusterIP: the first address of the service
/// CIDR (10.96.0.0/12, the ClusterIP allocator's and the default
/// ServiceCIDR's range), as upstream reserves it.
pub const KUBERNETES_SERVICE_IP: &str = "10.96.0.1";

/// The `default/kubernetes` Service object (upstream: the API server's
/// `kubernetes` service controller, `pkg/controlplane/controller/kubernetesservice`):
/// ClusterIP [`KUBERNETES_SERVICE_IP`], port 443 `https` to the API servers'
/// port, no selector (its Endpoints are the advertised address above).
/// Created when missing; an existing one is left as it is.
pub async fn ensure_kubernetes_service(
    storage: &Arc<StorageBackend>,
    api_server_port: u16,
) -> Result<()> {
    let key = rusternetes_storage::build_key("services", Some("default"), "kubernetes");
    if storage.get::<serde_json::Value>(&key).await.is_ok() {
        return Ok(());
    }
    let svc = kubernetes_service(api_server_port)?;
    match storage.create(&key, &svc).await {
        Ok(_) => {
            info!("Created the kubernetes Service (ClusterIP {KUBERNETES_SERVICE_IP}, 443 -> {api_server_port})");
            Ok(())
        }
        // Another API server of the same store was first.
        Err(rusternetes_common::Error::AlreadyExists(_)) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(
            "Failed to create the kubernetes Service: {e}"
        )),
    }
}

/// The `default/kubernetes` Service as upstream writes it.
pub fn kubernetes_service(api_server_port: u16) -> Result<rusternetes_common::resources::Service> {
    let meta = rusternetes_common::types::ObjectMeta::new("kubernetes");
    let v = serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "kubernetes",
            "namespace": "default",
            "uid": meta.uid,
            "creationTimestamp": meta.creation_timestamp,
            "labels": {"component": "apiserver", "provider": "kubernetes"},
        },
        "spec": {
            "type": "ClusterIP",
            "clusterIP": KUBERNETES_SERVICE_IP,
            "clusterIPs": [KUBERNETES_SERVICE_IP],
            "ipFamilies": ["IPv4"],
            "ipFamilyPolicy": "SingleStack",
            "internalTrafficPolicy": "Cluster",
            "sessionAffinity": "None",
            "ports": [{"name": "https", "port": 443, "protocol": "TCP", "targetPort": api_server_port}],
        },
    });
    serde_json::from_value(v).context("the kubernetes Service")
}

/// The root CA publisher (upstream's kube-controller-manager
/// root-ca-cert-publisher): ConfigMap `kube-root-ca.crt` with `ca.crt` = the
/// cluster CA in every namespace, which every pod's ServiceAccount volume
/// projects. Creates it where it is missing and corrects a wrong one.
#[allow(dead_code)] // used by the library's serve path; the api-server binary compiles this module again
pub async fn publish_root_ca(storage: &Arc<StorageBackend>, ca_pem: &str) -> Result<()> {
    let namespaces: Vec<serde_json::Value> = storage.list("/registry/namespaces/").await?;
    for ns in namespaces {
        let Some(name) = ns.pointer("/metadata/name").and_then(|n| n.as_str()) else {
            continue;
        };
        if ns.pointer("/metadata/deletionTimestamp").is_some() {
            continue;
        }
        let key = rusternetes_storage::build_key("configmaps", Some(name), "kube-root-ca.crt");
        match storage.get::<serde_json::Value>(&key).await {
            Ok(mut cm) => {
                if cm.pointer("/data/ca.crt").and_then(|c| c.as_str()) != Some(ca_pem) {
                    cm["data"] = serde_json::json!({ "ca.crt": ca_pem });
                    storage.update(&key, &cm).await?;
                    info!("kube-root-ca.crt in namespace {name}: set to the cluster CA");
                }
            }
            Err(_) => {
                let cm = serde_json::json!({
                    "apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {
                        "name": "kube-root-ca.crt", "namespace": name,
                        "uid": uuid::Uuid::new_v4().to_string(),
                        "creationTimestamp": rusternetes_common::time::k8s_time::format(&chrono::Utc::now()),
                    },
                    "data": { "ca.crt": ca_pem },
                });
                match storage.create(&key, &cm).await {
                    Ok(_) => info!("kube-root-ca.crt in namespace {name}: created"),
                    Err(e) => debug!("kube-root-ca.crt in namespace {name}: {e}"),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod kubernetes_service_tests {
    use super::*;

    #[test]
    fn the_kubernetes_service_is_upstreams() {
        let svc = kubernetes_service(6443).unwrap();
        let v = serde_json::to_value(&svc).unwrap();
        assert_eq!(v["metadata"]["namespace"], "default");
        assert_eq!(v["metadata"]["labels"]["component"], "apiserver");
        assert_eq!(v["metadata"]["labels"]["provider"], "kubernetes");
        assert_eq!(v["spec"]["type"], "ClusterIP");
        assert_eq!(v["spec"]["clusterIP"], "10.96.0.1");
        assert_eq!(v["spec"]["ports"][0]["name"], "https");
        assert_eq!(v["spec"]["ports"][0]["port"], 443);
        assert_eq!(v["spec"]["ports"][0]["targetPort"], 6443);
        assert!(
            v["spec"].get("selector").is_none_or(|s| s.is_null()),
            "no selector: its Endpoints are the API servers'"
        );
        assert!(!v["metadata"]["uid"].as_str().unwrap_or("").is_empty());
        assert!(v["metadata"]["creationTimestamp"].is_string());
    }

    #[test]
    fn the_first_service_ip_is_reserved_for_it() {
        // The allocator's first address is the kubernetes Service's.
        let a = crate::ip_allocator::ClusterIPAllocator::new();
        assert_eq!(a.allocate().as_deref(), Some(KUBERNETES_SERVICE_IP));
    }
}
