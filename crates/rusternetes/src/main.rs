//! Rusternetes — all-in-one Kubernetes in a single binary.
//!
//! Runs the API server, scheduler, controller manager, kubelet, and kube-proxy
//! as concurrent tokio tasks sharing a single storage backend.
//!
//! Usage:
//!   rusternetes                                   # SQLite at ./data/rusternetes.db
//!   rusternetes --data-dir /var/lib/rusternetes.db # custom path
//!   rusternetes --etcd-servers http://etcd:2379    # use etcd instead

mod heartbeat;

use anyhow::Result;
use clap::Parser;
use rusternetes_storage::{StorageBackend, StorageConfig};
use std::sync::Arc;
use tracing::{error, info, Level};

#[derive(Parser, Debug)]
#[command(name = "rusternetes")]
#[command(about = "Rusternetes — all-in-one Kubernetes in a single binary")]
#[command(version)]
struct Args {
    /// Storage backend: "sqlite", "etcd", "redis", or "redb"
    #[arg(long, default_value = "sqlite")]
    storage_backend: String,

    /// SQLite database path (only used when --storage-backend=sqlite)
    #[arg(long, default_value = "./data/rusternetes.db")]
    data_dir: String,

    /// Etcd endpoints, comma-separated (only used when --storage-backend=etcd)
    #[arg(long, default_value = "http://localhost:2379")]
    etcd_servers: String,

    /// Redis URL (only used when --storage-backend=redis)
    #[arg(long, default_value = "redis://localhost:6379")]
    redis_url: String,

    /// API server bind address
    #[arg(long, default_value = "0.0.0.0:6443")]
    bind_address: String,

    /// Node name for the embedded kubelet
    #[arg(long, default_value = "node-1")]
    node_name: String,

    /// Volume directory for pod volumes
    #[arg(long, default_value = "./data/volumes")]
    volume_dir: String,

    /// Cluster DNS IP
    #[arg(long, default_value = "10.96.0.10")]
    cluster_dns: String,

    /// Container network name
    #[arg(long, default_value = "rusternetes-network")]
    network: String,

    /// Enable TLS with self-signed certificates
    #[arg(long)]
    tls: bool,

    /// TLS certificate file
    #[arg(long)]
    tls_cert_file: Option<String>,

    /// TLS private key file
    #[arg(long)]
    tls_key_file: Option<String>,

    /// TLS Subject Alternative Names (comma-separated)
    #[arg(long, default_value = "localhost,127.0.0.1")]
    tls_san: String,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Controller sync interval in seconds
    #[arg(long, default_value = "5")]
    sync_interval: u64,

    /// Scheduler interval in seconds
    #[arg(long, default_value = "2")]
    scheduler_interval: u64,

    /// Kubelet sync interval in seconds
    #[arg(long, default_value = "3")]
    kubelet_sync_interval: u64,

    /// Kube-proxy sync interval in seconds
    #[arg(long, default_value = "1")]
    proxy_sync_interval: u64,

    /// Skip authentication (insecure, for development)
    #[arg(long, default_value = "true", num_args = 0..=1, default_missing_value = "true")]
    skip_auth: bool,

    /// Disable kube-proxy (useful when iptables is not available)
    #[arg(long)]
    disable_proxy: bool,

    /// Path to the console SPA build directory (enables web console at /console/)
    #[arg(long)]
    console_dir: Option<String>,

    /// Kubernetes service host override for pods (e.g. "api-server" in containerized deployments).
    /// Falls back to KUBERNETES_SERVICE_HOST_OVERRIDE env var if not set.
    #[arg(long)]
    kubernetes_service_host: Option<String>,

    /// Client CA certificate file for mTLS client certificate authentication
    #[arg(long)]
    client_ca_file: Option<String>,

    /// By default, a pod's resolv.conf lists the node's own DNS server first
    /// so pods can resolve sibling container names under Docker Compose.
    /// Set this flag outside Compose so pods resolve cluster Service names.
    #[arg(long, default_value = "false")]
    pod_prefer_cluster_dns: bool,

    /// Components to run, comma-separated. A worker node runs only
    /// `kubelet` against a remote store (`--storage-backend etcd`).
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "api-server,scheduler,controller-manager,kubelet,kube-proxy"
    )]
    components: Vec<String>,

    /// With `--storage-backend redb`: also serve the embedded store as etcd v3
    /// on this address, so kubelets on other nodes can use it
    /// (`--storage-backend etcd --etcd-servers http://<this>`). Plaintext,
    /// unless the three --serve-etcd-* TLS files are given.
    #[arg(long)]
    serve_etcd: Option<String>,

    /// The served store's certificate (PEM). With --serve-etcd-key-file and
    /// --serve-etcd-client-ca-file, --serve-etcd serves mutual TLS only: a
    /// client must present a certificate from that CA; plaintext is refused.
    #[arg(long)]
    serve_etcd_cert_file: Option<String>,

    /// The served store certificate's key (PEM).
    #[arg(long)]
    serve_etcd_key_file: Option<String>,

    /// The CA a client certificate of the served store must chain to (PEM).
    #[arg(long)]
    serve_etcd_client_ca_file: Option<String>,

    /// The CA the etcd servers' certificates must chain to (PEM). With
    /// --etcd-certfile and --etcd-keyfile, the etcd backend connects over
    /// TLS with that client certificate (https:// endpoints only).
    #[arg(long)]
    etcd_cafile: Option<String>,

    /// This client's certificate for the etcd servers (PEM).
    #[arg(long)]
    etcd_certfile: Option<String>,

    /// This client's key for the etcd servers (PEM).
    #[arg(long)]
    etcd_keyfile: Option<String>,

    /// The embedded kubelet registers its Node with this pod CIDR
    /// (`spec.podCIDR`), for CNIs that allocate from the node's range.
    #[arg(long)]
    pod_cidr: Option<String>,
}

/// All three of a TLS file set, or none.
fn all_or_none(
    what: &str,
    files: [(&str, &Option<String>); 3],
) -> Result<Option<[String; 3]>> {
    let given = files.iter().filter(|(_, v)| v.is_some()).count();
    match given {
        0 => Ok(None),
        3 => Ok(Some(files.map(|(_, v)| v.clone().unwrap_or_default()))),
        _ => {
            let missing: Vec<&str> = files
                .iter()
                .filter(|(_, v)| v.is_none())
                .map(|(n, _)| *n)
                .collect();
            anyhow::bail!("{what}: also give {}", missing.join(", "))
        }
    }
}

fn main() -> Result<()> {
    // Built by hand rather than with `#[tokio::main]` so the worker threads get
    // a stack large enough for the kubelet's pod sync path — see
    // `worker_stack_size`. Everything else matches what the macro expands to.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(rusternetes_common::async_runtime::worker_stack_size())
        .build()?
        .block_on(run())
}

async fn run() -> Result<()> {
    let args = Args::parse();
    #[cfg(feature = "etcd-tls")]
    {
        // More than one rustls crypto provider is built in; the etcd link's
        // client and server use the process default, as the API server does.
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        );
    }
    let etcd_client_tls = all_or_none(
        "etcd client TLS",
        [
            ("--etcd-cafile", &args.etcd_cafile),
            ("--etcd-certfile", &args.etcd_certfile),
            ("--etcd-keyfile", &args.etcd_keyfile),
        ],
    )?;
    let serve_etcd_tls = all_or_none(
        "--serve-etcd TLS",
        [
            ("--serve-etcd-cert-file", &args.serve_etcd_cert_file),
            ("--serve-etcd-key-file", &args.serve_etcd_key_file),
            ("--serve-etcd-client-ca-file", &args.serve_etcd_client_ca_file),
        ],
    )?;

    let level = match args.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    tracing_subscriber::fmt().with_max_level(level).init();

    info!("Starting Rusternetes (all-in-one)");

    // Initialize storage — all components share one instance
    let storage_config = match args.storage_backend.as_str() {
        #[cfg(feature = "redb")]
        "redb" => {
            info!("Using embedded redb storage at: {}", args.data_dir);
            StorageConfig::Redb {
                path: args.data_dir,
            }
        }
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            info!("Storage: SQLite at {}", args.data_dir);
            StorageConfig::Sqlite {
                path: args.data_dir,
            }
        }
        "etcd" => {
            let endpoints: Vec<String> = args
                .etcd_servers
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();
            match etcd_client_tls {
                Some([ca_file, cert_file, key_file]) => {
                    info!("Storage: etcd over TLS at {:?}", endpoints);
                    StorageConfig::EtcdTls {
                        endpoints,
                        tls: rusternetes_storage::EtcdClientTls {
                            ca_file,
                            cert_file,
                            key_file,
                        },
                    }
                }
                None => {
                    info!("Storage: etcd at {:?}", endpoints);
                    StorageConfig::Etcd { endpoints }
                }
            }
        }
        #[cfg(feature = "redis")]
        "redis" => {
            info!("Storage: Redis at {}", args.redis_url);
            StorageConfig::Redis {
                url: args.redis_url,
            }
        }
        other => {
            anyhow::bail!(
                "Unknown storage backend: {}. Use 'sqlite', 'etcd', 'redis', or 'redb'.",
                other
            );
        }
    };
    let storage = Arc::new(StorageBackend::new(storage_config).await?);

    info!("Storage initialized, starting components...");
    let on = |c: &str| args.components.iter().any(|x| x == c);
    for c in &args.components {
        if !["api-server", "scheduler", "controller-manager", "kubelet", "kube-proxy"]
            .contains(&c.as_str())
        {
            anyhow::bail!("Unknown component: {}", c);
        }
    }

    // --- The embedded store, served to other nodes as etcd v3 ---
    if let Some(addr) = args.serve_etcd.clone() {
        #[cfg(feature = "redb")]
        {
            let StorageBackend::Redb(redb) = storage.as_ref() else {
                anyhow::bail!("--serve-etcd needs --storage-backend redb");
            };
            let store = redb.store().clone();
            let tls = match serve_etcd_tls {
                Some([cert, key, ca]) => {
                    let read = |p: &str| {
                        std::fs::read(p).map_err(|e| anyhow::anyhow!("--serve-etcd TLS file {p}: {e}"))
                    };
                    Some(tunnr_etcd::server::ServeTls {
                        cert_pem: read(&cert)?,
                        key_pem: read(&key)?,
                        client_ca_pem: read(&ca)?,
                    })
                }
                None => None,
            };
            #[cfg(not(feature = "etcd-tls"))]
            if tls.is_some() {
                anyhow::bail!("--serve-etcd TLS needs the etcd-tls feature; refusing to serve plaintext");
            }
            let scheme = if tls.is_some() { "https" } else { "http" };
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            if tls.is_some() {
                info!(
                    "Serving the embedded store as etcd v3 on {} over mutual TLS (client certificate required, plaintext refused)",
                    addr
                );
            } else {
                info!("Serving the embedded store as etcd v3 on {} (plaintext)", addr);
            }
            let opts = tunnr_etcd::server::ServeOptions {
                client_url: format!("{scheme}://{addr}"),
                tls,
                ..Default::default()
            };
            tokio::spawn(async move {
                if let Err(e) =
                    tunnr_etcd::server::serve(store, listener, opts, std::future::pending()).await
                {
                    error!("etcd server error: {}", e);
                }
            });
        }
        #[cfg(not(feature = "redb"))]
        anyhow::bail!("--serve-etcd {} needs the redb feature", addr);
    }

    // --- API Server ---
    let api_storage = storage.clone();
    let api_config = rusternetes_api_server::ApiServerConfig {
        bind_address: args.bind_address.clone(),
        tls: args.tls,
        tls_cert_file: args.tls_cert_file.clone(),
        tls_key_file: args.tls_key_file.clone(),
        tls_self_signed: args.tls,
        tls_san: args.tls_san.clone(),
        skip_auth: args.skip_auth,
        console_dir: args.console_dir.map(std::path::PathBuf::from),
        client_ca_file: args.client_ca_file,
        ..Default::default()
    };
    let api_handle = if on("api-server") {
        Some(tokio::spawn(async move {
            if let Err(e) = rusternetes_api_server::run(api_storage, api_config).await {
                error!("API server error: {}", e);
            }
        }))
    } else {
        None
    };

    // Give API server a moment to bind before starting clients
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // --- Scheduler ---
    let sched_storage = storage.clone();
    let sched_config = rusternetes_scheduler::SchedulerConfig {
        interval: args.scheduler_interval,
    };
    let mut beats: Vec<(&'static str, tokio::task::JoinHandle<()>)> = Vec::new();
    if on("scheduler") {
        let h = tokio::spawn(async move {
            if let Err(e) = rusternetes_scheduler::run(sched_storage, sched_config).await {
                error!("Scheduler error: {}", e);
            }
        });
        beats.push(("kube-scheduler", h));
    }

    // --- Controller Manager ---
    let cm_storage = storage.clone();
    let cm_config = rusternetes_controller_manager::ControllerManagerConfig {
        sync_interval: args.sync_interval,
    };
    if on("controller-manager") {
        let h = tokio::spawn(async move {
            if let Err(e) = rusternetes_controller_manager::run(cm_storage, cm_config).await {
                error!("Controller manager error: {}", e);
            }
        });
        beats.push(("kube-controller-manager", h));
    }
    // The control-plane components' heartbeats: one Lease each in kube-system, renewed while
    // the component's task runs (src/heartbeat.rs) — what a rolling upgrade reads to know a
    // control plane is up again.
    if !beats.is_empty() || on("api-server") {
        heartbeat::spawn(storage.clone(), args.node_name.clone(), beats, on("api-server"), args.bind_address.clone());
    }

    // --- Kubelet ---
    let kubelet_storage = storage.clone();
    let kubelet_config = rusternetes_kubelet::KubeletConfig {
        node_name: args.node_name.clone(),
        volume_dir: args.volume_dir,
        cluster_dns: args.cluster_dns,
        cluster_domain: "cluster.local".to_string(),
        network: args.network,
        sync_interval: args.kubelet_sync_interval,
        metrics_port: 10250,
        kubernetes_service_host: args
            .kubernetes_service_host
            .clone()
            .or_else(|| std::env::var("KUBERNETES_SERVICE_HOST_OVERRIDE").ok())
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        pod_prefer_cluster_dns: args.pod_prefer_cluster_dns,
        pod_cidr: args.pod_cidr.clone(),
    };
    let kubelet_handle = if on("kubelet") {
        Some(tokio::spawn(async move {
            if let Err(e) = rusternetes_kubelet::run(kubelet_storage, kubelet_config).await {
                error!("Kubelet error: {}", e);
            }
        }))
    } else {
        None
    };

    // --- Kube-proxy ---
    if on("kube-proxy") && !args.disable_proxy {
        let proxy_storage = storage.clone();
        let proxy_config = rusternetes_kube_proxy::KubeProxyConfig {
            node_name: args.node_name,
            sync_interval: args.proxy_sync_interval,
        };
        tokio::spawn(async move {
            if let Err(e) = rusternetes_kube_proxy::run(proxy_storage, proxy_config).await {
                error!("Kube-proxy error: {}", e);
            }
        });
    } else {
        info!("Kube-proxy disabled");
    }

    info!("All components started");

    // The API server task blocks on its listener — wait for it or ctrl-c
    // Without an API server (a worker node), the kubelet is the task to wait for.
    let main_task = api_handle.or(kubelet_handle);
    let main_task = async move {
        match main_task {
            Some(h) => h.await,
            None => Ok(std::future::pending::<()>().await),
        }
    };
    tokio::select! {
        result = main_task => {
            if let Err(e) = result {
                error!("Main component task panicked: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal, stopping rusternetes");
        }
    }

    Ok(())
}
