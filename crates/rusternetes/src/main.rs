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
use tracing::{error, info, warn, Level};

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

    /// The cluster's service-account signing key (PEM, RSA or ECDSA P-256):
    /// the API server, the kubelet and the controller manager sign
    /// ServiceAccount tokens with it. Every control plane gets the same key.
    #[arg(long)]
    service_account_signing_key_file: Option<String>,

    /// The matching public key (PEM): ServiceAccount tokens are checked with it.
    #[arg(long)]
    service_account_key_file: Option<String>,

    /// Nodes publish ConfigMaps kube-system/<prefix><node>: a node may get
    /// every node's and create, update and patch its own (the Node authorizer).
    #[arg(long)]
    node_configmap_prefix: Option<String>,

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

    /// With the --serve-etcd TLS files: limit each node by its client
    /// certificate (CN=system:node:<node>), as the NodeRestriction admission
    /// plugin and the Node authorizer do — its own Node, Lease and CSINode,
    /// the status of pods bound to it, and the reads a kubelet makes; other
    /// cluster-CA certificates (the control plane) keep full access; nodes
    /// revoked in ConfigMap kube-system/tunnr-revoked-nodes are refused.
    /// Needs the etcd-authz feature.
    #[arg(long, default_value = "false")]
    serve_etcd_node_authz: bool,

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

    /// Raft mode for the served store (feature `store-raft`): this replica's
    /// id among --store-raft-peers. The store is then a tunnr-etcd Raft
    /// replica in --store-raft-dir, served on --serve-etcd (with the
    /// --serve-etcd-* TLS files, which also secure the peer link on port
    /// 2380), and the components use it as etcd (--storage-backend etcd
    /// --etcd-servers <this replica's own --serve-etcd URL>).
    #[arg(long)]
    store_raft_id: Option<u64>,

    /// Every replica, this one included: `1=10.77.0.1,2=10.77.0.2,3=10.77.0.3`
    /// (peer link on port 2380 unless `host:port` is given).
    #[arg(long)]
    store_raft_peers: Option<String>,

    /// Where the Raft replica keeps its log, snapshot and state.
    #[arg(long, default_value = "./data/raft")]
    store_raft_dir: String,

    /// Written `leader` / `follower` as this replica's leadership (confirmed by
    /// a quorum) changes; a node follows it with its virtual IP.
    #[arg(long)]
    store_raft_leader_file: Option<String>,

    /// Written every half second: this replica's Raft state (role, term,
    /// leader, log and applied index, each follower's lag on the leader) as
    /// `key=value` lines; a node's console shows it.
    #[arg(long)]
    store_raft_status_file: Option<String>,

    /// Run the scheduler and the controller manager only while this process
    /// holds the control-plane lease in the store (an HA control plane runs
    /// one of each at a time). Needs --storage-backend etcd. A process that
    /// loses the lease exits, so it starts again as a follower.
    #[arg(long)]
    leader_elect: bool,

    /// The embedded kubelet registers its Node with this pod CIDR
    /// (`spec.podCIDR`), for CNIs that allocate from the node's range.
    #[arg(long)]
    pod_cidr: Option<String>,

    /// The kubelet's node server (:10250: exec, attach, logs, metrics) over
    /// mutual TLS: its serving certificate (PEM). With
    /// --kubelet-tls-key-file and --kubelet-client-ca-file it takes only
    /// control-plane client certificates from that CA (never a node's,
    /// never none); plaintext is refused.
    #[arg(long)]
    kubelet_tls_cert_file: Option<String>,

    /// The kubelet serving certificate's key (PEM).
    #[arg(long)]
    kubelet_tls_key_file: Option<String>,

    /// The CA a client of the kubelet's node server must chain to (PEM).
    #[arg(long)]
    kubelet_client_ca_file: Option<String>,

    /// The API server reaches the kubelets over mutual TLS: their serving
    /// certificates checked against this CA (PEM)...
    #[arg(long)]
    kubelet_certificate_authority: Option<String>,

    /// ...presenting this client certificate (PEM)...
    #[arg(long)]
    kubelet_client_certificate: Option<String>,

    /// ...and its key (PEM).
    #[arg(long)]
    kubelet_client_key: Option<String>,
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
    let kubelet_serving_tls = all_or_none(
        "kubelet node server TLS",
        [
            ("--kubelet-tls-cert-file", &args.kubelet_tls_cert_file),
            ("--kubelet-tls-key-file", &args.kubelet_tls_key_file),
            ("--kubelet-client-ca-file", &args.kubelet_client_ca_file),
        ],
    )?
    .map(|[cert_file, key_file, client_ca_file]| rusternetes_kubelet::serving_tls::ServingTls {
        cert_file,
        key_file,
        client_ca_file,
    });
    let kubelet_client_tls = all_or_none(
        "API server to kubelet TLS",
        [
            ("--kubelet-certificate-authority", &args.kubelet_certificate_authority),
            ("--kubelet-client-certificate", &args.kubelet_client_certificate),
            ("--kubelet-client-key", &args.kubelet_client_key),
        ],
    )?
    .map(|[ca_file, cert_file, key_file]| rusternetes_api_server::kubelet_client::KubeletClientTls {
        ca_file,
        cert_file,
        key_file,
    });
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

    // --- Raft mode: this process is a replica of the store; start it and
    // serve it before the components connect to it as etcd. ---
    let raft_mode = args.store_raft_id.is_some();
    if let Some(id) = args.store_raft_id {
        #[cfg(feature = "store-raft")]
        start_store_replica(&args, id, serve_etcd_tls.clone()).await?;
        #[cfg(not(feature = "store-raft"))]
        anyhow::bail!("--store-raft-id {id} needs the store-raft feature");
    }

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
    if let Some(addr) = args.serve_etcd.clone().filter(|_| !raft_mode) {
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
            if args.serve_etcd_node_authz {
                if tls.is_none() {
                    anyhow::bail!("--serve-etcd-node-authz needs the --serve-etcd TLS files: a node is known by its client certificate");
                }
                #[cfg(not(feature = "etcd-authz"))]
                anyhow::bail!("--serve-etcd-node-authz needs the etcd-authz feature");
                #[cfg(feature = "etcd-authz")]
                info!("Served store: per-node limits on (CN=system:node:<node> writes its own objects only)");
            }
            let opts = tunnr_etcd::server::ServeOptions {
                client_url: format!("{scheme}://{addr}"),
                tls,
                node_authz: args
                    .serve_etcd_node_authz
                    .then(tunnr_etcd::server::NodeAuthz::default),
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

    // The cluster's ServiceAccount key: tokens are signed and checked with it
    // in this process (API server, kubelet, controller manager). A node
    // without it (a worker) signs none: its pods get their ServiceAccount's
    // token Secret, signed on a control plane.
    match (&args.service_account_signing_key_file, &args.service_account_key_file) {
        (Some(private), Some(public)) => {
            let tm = rusternetes_common::auth::TokenManager::from_key_files(private, public)?;
            rusternetes_common::auth::install_cluster_token_manager(Arc::new(tm));
            info!("ServiceAccount key: {}", public);
        }
        (None, None) => {}
        _ => anyhow::bail!("--service-account-signing-key-file and --service-account-key-file go together"),
    }
    if !args.skip_auth && on("api-server") && args.service_account_signing_key_file.is_none() {
        warn!("--skip-auth=false without --service-account-signing-key-file: ServiceAccount tokens hold for this process only");
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
        kubelet_client_tls,
        node_configmap_prefix: args.node_configmap_prefix.clone(),
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

    // --- Scheduler and Controller Manager ---
    let sched_storage = storage.clone();
    let sched_config = rusternetes_scheduler::SchedulerConfig {
        interval: args.scheduler_interval,
    };
    let cm_storage = storage.clone();
    let cm_config = rusternetes_controller_manager::ControllerManagerConfig {
        sync_interval: args.sync_interval,
    };
    let (run_sched, run_cm) = (on("scheduler"), on("controller-manager"));
    let start_sched_cm = move || {
        let mut started: Vec<(&'static str, tokio::task::JoinHandle<()>)> = Vec::new();
        if run_sched {
            started.push(("kube-scheduler", tokio::spawn(async move {
                if let Err(e) = rusternetes_scheduler::run(sched_storage, sched_config).await {
                    error!("Scheduler error: {}", e);
                }
            })));
        }
        if run_cm {
            started.push(("kube-controller-manager", tokio::spawn(async move {
                if let Err(e) = rusternetes_controller_manager::run(cm_storage, cm_config).await {
                    error!("Controller manager error: {}", e);
                }
            })));
        }
        started
    };
    // The control-plane components' heartbeats (src/heartbeat.rs): each component's Lease is
    // renewed while it is alive. Under --leader-elect a control plane that stands by (another
    // one holds the lease) is alive too: its election task runs and takes over when needed.
    let mut beats: Vec<(&'static str, heartbeat::Alive)> = Vec::new();
    if args.leader_elect && (run_sched || run_cm) {
        // An HA control plane runs one scheduler and one controller manager
        // at a time: they start once this process holds the control-plane
        // lease in the store (the rest of the process does not wait).
        let StorageBackend::Etcd(etcd) = storage.as_ref() else {
            anyhow::bail!("--leader-elect needs --storage-backend etcd");
        };
        let config = rusternetes_common::leader_election::LeaderElectionConfig {
            identity: format!("{}-{}", args.node_name, std::process::id()),
            lock_key: "/rusternetes/leader/control-plane".to_string(),
            lease_duration: 15,
            renew_interval: 5,
            retry_interval: 2,
        };
        let el = Arc::new(rusternetes_common::leader_election::LeaderElector::with_client(
            etcd.client(),
            config,
        ));
        let run = el.clone();
        tokio::spawn(async move {
            if let Err(e) = run.run().await {
                error!("Leader election error: {}", e);
            }
        });
        info!("Leader election on: the scheduler and the controller manager wait for the control-plane lease");
        let running: Arc<std::sync::Mutex<Vec<(&'static str, tokio::task::JoinHandle<()>)>>> =
            Arc::default();
        let slot = running.clone();
        let waiter = Arc::new(tokio::spawn(async move {
            while !el.is_leader().await {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
            info!("This control plane holds the lease: starting the scheduler and the controller manager");
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = start_sched_cm();
            // The lease runs 15 s: not leader for that long means another
            // control plane may hold it now. The controllers do not stop
            // cleanly, so the process ends and starts again as a follower.
            let mut since: Option<std::time::Instant> = None;
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                if el.is_leader().await {
                    since = None;
                } else if since.get_or_insert_with(std::time::Instant::now).elapsed()
                    > std::time::Duration::from_secs(15)
                {
                    error!("Lost the control-plane lease; exiting so this process starts again as a follower");
                    std::process::exit(3);
                }
            }
        }));
        for (component, wanted) in [("kube-scheduler", run_sched), ("kube-controller-manager", run_cm)] {
            if !wanted {
                continue;
            }
            let (waiter, running) = (waiter.clone(), running.clone());
            beats.push((component, Arc::new(move || {
                if waiter.is_finished() {
                    return false;
                }
                let r = running.lock().unwrap_or_else(|e| e.into_inner());
                // Standing by (not started here), or started and running.
                r.iter().find(|(c, _)| *c == component).is_none_or(|(_, h)| !h.is_finished())
            })));
        }
    } else {
        for (component, h) in start_sched_cm() {
            let h = Arc::new(h);
            beats.push((component, Arc::new(move || !h.is_finished())));
        }
    }
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
        serving_tls: kubelet_serving_tls,
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

/// Start this process's replica of the store (Raft mode) and serve it as
/// etcd v3 on --serve-etcd; wait (up to two minutes) until it knows a leader.
#[cfg(feature = "store-raft")]
async fn start_store_replica(args: &Args, id: u64, tls: Option<[String; 3]>) -> Result<()> {
    use tunnr_etcd::server::raft::{self, RaftConfig, RaftTls};
    let addr = args
        .serve_etcd
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--store-raft-id needs --serve-etcd <addr>"))?;
    if args.storage_backend != "etcd" {
        anyhow::bail!("--store-raft-id needs --storage-backend etcd (the components use the replica as etcd)");
    }
    let scheme = if tls.is_some() { "https" } else { "http" };
    let client_port: u16 = addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("--serve-etcd {addr}: no port"))?;
    let peers = raft::parse_peers(
        args.store_raft_peers
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--store-raft-id needs --store-raft-peers"))?,
        2380,
        scheme,
        client_port,
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    let me = peers
        .get(&id)
        .ok_or_else(|| anyhow::anyhow!("--store-raft-id {id} is not in --store-raft-peers"))?;
    let listen_port = me.raft_addr.rsplit_once(':').map(|(_, p)| p).unwrap_or("2380");
    let listen_host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("0.0.0.0");
    let listen: std::net::SocketAddr = format!("{listen_host}:{listen_port}").parse()?;
    let mut cfg = RaftConfig::new(id, peers.clone(), listen, &args.store_raft_dir);
    cfg.leader_file = args.store_raft_leader_file.clone().map(Into::into);
    cfg.status_file = args.store_raft_status_file.clone().map(Into::into);
    let read = |p: &str| std::fs::read(p).map_err(|e| anyhow::anyhow!("--serve-etcd TLS file {p}: {e}"));
    let serve_tls = match &tls {
        Some([cert, key, ca]) => {
            cfg.tls = Some(RaftTls {
                cert_pem: read(cert)?,
                key_pem: read(key)?,
                ca_pem: read(ca)?,
                peer_certs: Vec::new(),
            });
            Some(tunnr_etcd::server::ServeTls {
                cert_pem: read(cert)?,
                key_pem: read(key)?,
                client_ca_pem: read(ca)?,
            })
        }
        None => None,
    };
    let node = raft::start(cfg)
        .await
        .map_err(|e| anyhow::anyhow!("the store replica: {e}"))?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(
        "Store replica {} of {} (Raft) serving etcd v3 on {} ({}), peers {:?}",
        id,
        peers.len(),
        addr,
        if serve_tls.is_some() { "mutual TLS" } else { "plaintext" },
        peers.values().map(|p| p.raft_addr.clone()).collect::<Vec<_>>()
    );
    if args.serve_etcd_node_authz {
        if serve_tls.is_none() {
            anyhow::bail!("--serve-etcd-node-authz needs the --serve-etcd TLS files: a node is known by its client certificate");
        }
        #[cfg(not(feature = "etcd-authz"))]
        anyhow::bail!("--serve-etcd-node-authz needs the etcd-authz feature");
        #[cfg(feature = "etcd-authz")]
        info!("Store replica: per-node limits on, checked against committed state on every replica");
    }
    let opts = tunnr_etcd::server::ServeOptions {
        client_url: format!("{scheme}://{addr}"),
        tls: serve_tls,
        node_authz: args.serve_etcd_node_authz.then(tunnr_etcd::server::NodeAuthz::default),
        ..Default::default()
    };
    let served = node.clone();
    tokio::spawn(async move {
        if let Err(e) = tunnr_etcd::server::serve_raft(served, listener, opts, std::future::pending()).await {
            error!("store replica server error: {}", e);
        }
    });
    let t0 = std::time::Instant::now();
    while node.leader().is_none() && t0.elapsed() < std::time::Duration::from_secs(120) {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    match node.leader() {
        Some(l) => info!("Store replica {}: leader is replica {}", id, l),
        None => tracing::warn!("Store replica {}: no leader yet after two minutes; starting the components anyway", id),
    }
    Ok(())
}
