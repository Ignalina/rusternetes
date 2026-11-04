use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

use super::config::{CniConfigManager, NetworkConfigList};
use super::plugin::CniPluginManager;
use super::result::{CniError, CniResult, ErrorCode};
use super::CniCommand;

/// Network attachment information for a container
#[derive(Debug, Clone)]
pub struct NetworkAttachment {
    /// Container ID
    pub container_id: String,

    /// Network namespace path
    pub netns: String,

    /// Interface name
    pub ifname: String,

    /// Network configuration used
    pub network: String,

    /// CNI result from ADD operation
    pub result: CniResult,
}

/// CNI Runtime - high-level interface for container network lifecycle
pub struct CniRuntime {
    /// Plugin manager
    plugin_manager: Arc<Mutex<CniPluginManager>>,

    /// Configuration manager
    config_manager: CniConfigManager,

    /// Active network attachments (container_id -> attachments)
    attachments: Arc<Mutex<HashMap<String, Vec<NetworkAttachment>>>>,

    /// Default network to use
    default_network: Option<String>,
}

/// The `CNI_CONTAINERID` for a pod sandbox the kubelet names by `id` (the
/// pod name): 64 hex digits, the shape CRI runtimes pass. Plugins derive
/// interface names from it — Cilium's temporary peer is `tmp` + its first
/// five characters, so a pod name with a `:` or `.` there (`web` → `web:e`
/// of `web:eth0`) became an invalid interface name ("unable to create veth
/// pair: invalid argument"). Deterministic, so ADD, CHECK and DEL agree.
pub fn cni_container_id(id: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(id.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

impl CniRuntime {
    /// Create a new CNI runtime
    pub fn new(plugin_paths: Vec<PathBuf>, config_dir: PathBuf) -> Result<Self, CniError> {
        let mut plugin_manager = CniPluginManager::new(plugin_paths);
        plugin_manager.discover_plugins()?;

        let config_manager = CniConfigManager::new(config_dir);

        Ok(Self {
            plugin_manager: Arc::new(Mutex::new(plugin_manager)),
            config_manager,
            attachments: Arc::new(Mutex::new(HashMap::new())),
            default_network: None,
        })
    }

    /// Set the default network to use
    pub fn with_default_network(mut self, network: String) -> Self {
        self.default_network = Some(network);
        self
    }

    /// Setup network for a container (ADD operation)
    pub fn setup_network(
        &self,
        container_id: &str,
        netns: &str,
        ifname: &str,
        network_name: Option<&str>,
    ) -> Result<CniResult, CniError> {
        self.setup_network_with_args(container_id, netns, ifname, network_name, None)
    }

    /// Setup network for a container (ADD operation) with `CNI_ARGS`
    /// (`K8S_POD_NAMESPACE=…;K8S_POD_NAME=…`, as the CRI runtimes pass them).
    pub fn setup_network_with_args(
        &self,
        container_id: &str,
        netns: &str,
        ifname: &str,
        network_name: Option<&str>,
        args: Option<&str>,
    ) -> Result<CniResult, CniError> {
        info!(
            "Setting up network for container {} in netns {}",
            container_id, netns
        );

        // Validate inputs
        if container_id.is_empty() {
            return Err(CniError::new(
                ErrorCode::InvalidEnvironmentVariables,
                "Container ID cannot be empty".to_string(),
            ));
        }

        if netns.is_empty() {
            return Err(CniError::new(
                ErrorCode::InvalidEnvironmentVariables,
                "Network namespace cannot be empty".to_string(),
            ));
        }

        // Check if netns exists
        if !Path::new(netns).exists() {
            return Err(CniError::new(
                ErrorCode::InvalidEnvironmentVariables,
                format!("Network namespace {} does not exist", netns),
            ));
        }

        // Get network configuration
        let network = self.get_network_config(network_name)?;

        // Execute ADD command. A plugin the network names but the last scan
        // did not see (installed after start, e.g. by a CNI agent's pod) is
        // looked for again before giving up.
        let mut plugin_manager = self.plugin_manager.lock().unwrap();
        if network
            .plugins
            .iter()
            .any(|p| !plugin_manager.has_plugin(&p.plugin_type))
        {
            plugin_manager.discover_plugins()?;
        }
        let result = plugin_manager.execute_network(
            CniCommand::Add,
            &network,
            &cni_container_id(container_id),
            netns,
            ifname,
            args,
        )?;

        // Store attachment
        let attachment = NetworkAttachment {
            container_id: container_id.to_string(),
            netns: netns.to_string(),
            ifname: ifname.to_string(),
            network: network.name.clone(),
            result: result.clone(),
        };

        let mut attachments = self.attachments.lock().unwrap();
        attachments
            .entry(container_id.to_string())
            .or_default()
            .push(attachment);

        info!(
            "Network setup complete for container {}, IP: {:?}",
            container_id,
            result.primary_ip()
        );

        Ok(result)
    }

    /// [`Self::setup_network_with_args`] for the async callers (the kubelet's
    /// pod start): the plugin runs on the blocking pool. Waited on from a
    /// worker thread it stopped every other task of the process — on a
    /// one-CPU node (one worker) the API server too, which tunnr-cni was
    /// waiting for: 10 s per pod. See `a_slow_plugin_does_not_stall_the_runtime`.
    pub async fn setup_network_async(
        self: &Arc<Self>,
        container_id: String,
        netns: String,
        ifname: String,
        network_name: Option<String>,
        args: Option<String>,
    ) -> Result<CniResult, CniError> {
        let cni = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            cni.setup_network_with_args(
                &container_id,
                &netns,
                &ifname,
                network_name.as_deref(),
                args.as_deref(),
            )
        })
        .await
        .unwrap_or_else(|e| {
            Err(CniError::new(
                ErrorCode::IoFailure,
                format!("the CNI ADD task failed: {e}"),
            ))
        })
    }

    /// [`Self::teardown_network`] for the async callers.
    pub async fn teardown_network_async(
        self: &Arc<Self>,
        container_id: String,
        netns: String,
        ifname: String,
        network_name: Option<String>,
    ) -> Result<(), CniError> {
        let cni = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            cni.teardown_network(&container_id, &netns, &ifname, network_name.as_deref())
        })
        .await
        .unwrap_or_else(|e| {
            Err(CniError::new(
                ErrorCode::IoFailure,
                format!("the CNI DEL task failed: {e}"),
            ))
        })
    }

    /// Teardown network for a container (DEL operation)
    pub fn teardown_network(
        &self,
        container_id: &str,
        netns: &str,
        ifname: &str,
        network_name: Option<&str>,
    ) -> Result<(), CniError> {
        info!(
            "Tearing down network for container {} in netns {}",
            container_id, netns
        );

        // Get network configuration
        let network = self.get_network_config(network_name)?;

        // Execute DEL command
        let plugin_manager = self.plugin_manager.lock().unwrap();
        plugin_manager.execute_network(
            CniCommand::Del,
            &network,
            &cni_container_id(container_id),
            netns,
            ifname,
            None,
        )?;

        // Remove attachment
        let mut attachments = self.attachments.lock().unwrap();
        if let Some(container_attachments) = attachments.get_mut(container_id) {
            container_attachments.retain(|a| a.network != network.name);
            if container_attachments.is_empty() {
                attachments.remove(container_id);
            }
        }

        info!("Network teardown complete for container {}", container_id);

        Ok(())
    }

    /// Check network configuration for a container (CHECK operation)
    pub fn check_network(
        &self,
        container_id: &str,
        netns: &str,
        ifname: &str,
        network_name: Option<&str>,
    ) -> Result<(), CniError> {
        debug!(
            "Checking network for container {} in netns {}",
            container_id, netns
        );

        // Get network configuration
        let network = self.get_network_config(network_name)?;

        // Skip check if disabled in config
        if network.disable_check == Some(true) {
            debug!("Check disabled for network {}", network.name);
            return Ok(());
        }

        // Execute CHECK command
        let plugin_manager = self.plugin_manager.lock().unwrap();
        plugin_manager.execute_network(
            CniCommand::Check,
            &network,
            &cni_container_id(container_id),
            netns,
            ifname,
            None,
        )?;

        debug!("Network check passed for container {}", container_id);

        Ok(())
    }

    /// Teardown all networks for a container
    pub fn teardown_all_networks(&self, container_id: &str) -> Result<(), CniError> {
        info!("Tearing down all networks for container {}", container_id);

        let attachments = {
            let attachments_lock = self.attachments.lock().unwrap();
            attachments_lock
                .get(container_id)
                .cloned()
                .unwrap_or_default()
        };

        for attachment in attachments {
            if let Err(e) = self.teardown_network(
                container_id,
                &attachment.netns,
                &attachment.ifname,
                Some(&attachment.network),
            ) {
                warn!(
                    "Failed to teardown network {} for container {}: {}",
                    attachment.network, container_id, e
                );
            }
        }

        Ok(())
    }

    /// Get network attachments for a container
    pub fn get_attachments(&self, container_id: &str) -> Vec<NetworkAttachment> {
        let attachments = self.attachments.lock().unwrap();
        attachments.get(container_id).cloned().unwrap_or_default()
    }

    /// Get the primary IP address for a container
    pub fn get_container_ip(&self, container_id: &str) -> Option<String> {
        let attachments = self.attachments.lock().unwrap();
        attachments
            .get(container_id)
            .and_then(|atts| atts.first())
            .and_then(|att| att.result.primary_ip())
            .map(|ip| ip.to_string())
    }

    /// Reload plugin discovery
    pub fn reload_plugins(&self) -> Result<(), CniError> {
        info!("Reloading CNI plugins");
        let mut plugin_manager = self.plugin_manager.lock().unwrap();
        plugin_manager.discover_plugins()
    }

    /// Get network configuration by name or use default
    fn get_network_config(
        &self,
        network_name: Option<&str>,
    ) -> Result<NetworkConfigList, CniError> {
        if let Some(name) = network_name {
            self.config_manager.get_config(name)
        } else if let Some(default) = &self.default_network {
            self.config_manager.get_config(default)
        } else {
            self.config_manager.get_default_config()
        }
    }

    /// List available networks
    pub fn list_networks(&self) -> Result<Vec<String>, CniError> {
        let configs = self.config_manager.load_configs()?;
        Ok(configs.into_iter().map(|c| c.name).collect())
    }

    /// Get statistics about active attachments
    pub fn get_stats(&self) -> NetworkStats {
        let attachments = self.attachments.lock().unwrap();
        NetworkStats {
            total_containers: attachments.len(),
            total_attachments: attachments.values().map(|v| v.len()).sum(),
        }
    }
}

/// Network statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub total_containers: usize,
    pub total_attachments: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn cni_container_ids_are_64_hex_and_stable() {
        let a = cni_container_id("web");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, cni_container_id("web"));
        assert_ne!(a, cni_container_id("web2"));
    }

    #[test]
    fn test_cni_runtime_creation() {
        let temp_plugin_dir = TempDir::new().unwrap();
        let temp_config_dir = TempDir::new().unwrap();

        let runtime = CniRuntime::new(
            vec![temp_plugin_dir.path().to_path_buf()],
            temp_config_dir.path().to_path_buf(),
        );

        assert!(runtime.is_ok());
    }

    #[test]
    fn test_default_network() {
        let temp_plugin_dir = TempDir::new().unwrap();
        let temp_config_dir = TempDir::new().unwrap();

        let runtime = CniRuntime::new(
            vec![temp_plugin_dir.path().to_path_buf()],
            temp_config_dir.path().to_path_buf(),
        )
        .unwrap()
        .with_default_network("test-network".to_string());

        assert_eq!(runtime.default_network, Some("test-network".to_string()));
    }

    #[test]
    fn test_get_stats() {
        let temp_plugin_dir = TempDir::new().unwrap();
        let temp_config_dir = TempDir::new().unwrap();

        let runtime = CniRuntime::new(
            vec![temp_plugin_dir.path().to_path_buf()],
            temp_config_dir.path().to_path_buf(),
        )
        .unwrap();

        let stats = runtime.get_stats();
        assert_eq!(stats.total_containers, 0);
        assert_eq!(stats.total_attachments, 0);
    }

    #[test]
    fn test_setup_network_validation() {
        let temp_plugin_dir = TempDir::new().unwrap();
        let temp_config_dir = TempDir::new().unwrap();

        let runtime = CniRuntime::new(
            vec![temp_plugin_dir.path().to_path_buf()],
            temp_config_dir.path().to_path_buf(),
        )
        .unwrap();

        // Test with empty container ID
        let result = runtime.setup_network("", "/var/run/netns/test", "eth0", None);
        assert!(result.is_err());

        // Test with empty netns
        let result = runtime.setup_network("container1", "", "eth0", None);
        assert!(result.is_err());
    }

    fn runtime_with_slow_plugin(dir: &std::path::Path, secs: u32) -> Arc<CniRuntime> {
        use std::os::unix::fs::PermissionsExt as _;
        let bin = dir.join("bin");
        let conf = dir.join("net.d");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&conf).unwrap();
        let plugin = bin.join("slow");
        std::fs::write(
            &plugin,
            format!("#!/bin/sh\nsleep {secs}\necho '{{\"cniVersion\":\"1.0.0\",\"ips\":[{{\"address\":\"10.1.0.2/32\"}}]}}'\n"),
        )
        .unwrap();
        std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            conf.join("10-slow.conflist"),
            r#"{"cniVersion":"1.0.0","name":"slow","plugins":[{"type":"slow"}]}"#,
        )
        .unwrap();
        Arc::new(CniRuntime::new(vec![bin], conf).unwrap())
    }

    /// A plugin that takes a second must not stop the other tasks of the
    /// runtime: the all-in-one's API server shares it, and a one-CPU node
    /// has one worker thread. With the plugin waited on from the worker, a
    /// node took 10 s per pod (tunnr-cni waits for PID 1, which waits for
    /// the stalled API server).
    #[tokio::test(flavor = "current_thread")]
    async fn a_slow_plugin_does_not_stall_the_runtime() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = TempDir::new().unwrap();
        let cni = runtime_with_slow_plugin(dir.path(), 1);
        let netns = dir.path().join("ns");
        std::fs::write(&netns, "").unwrap();
        let ticks = Arc::new(AtomicUsize::new(0));
        let t = ticks.clone();
        let ticker = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                t.fetch_add(1, Ordering::SeqCst);
            }
        });
        let r = cni
            .setup_network_async(
                "pod-a".into(),
                netns.to_string_lossy().into_owned(),
                "eth0".into(),
                None,
                Some("K8S_POD_NAMESPACE=default;K8S_POD_NAME=a".into()),
            )
            .await;
        assert!(r.is_ok(), "{r:?}");
        let n = ticks.load(Ordering::SeqCst);
        ticker.abort();
        assert!(
            n >= 5,
            "the runtime ticked {n} times during the plugin's second (stalled)"
        );
        assert_eq!(cni.get_container_ip("pod-a").as_deref(), Some("10.1.0.2"));
        let r = cni
            .teardown_network_async(
                "pod-a".into(),
                netns.to_string_lossy().into_owned(),
                "eth0".into(),
                None,
            )
            .await;
        assert!(r.is_ok(), "{r:?}");
        assert!(cni.get_container_ip("pod-a").is_none());
    }

    fn net_dir(files: &[(&str, &str)]) -> TempDir {
        let d = TempDir::new().unwrap();
        for (file, name) in files {
            std::fs::write(
                d.path().join(file),
                format!(r#"{{"cniVersion":"1.0.0","name":"{name}","type":"bridge"}}"#),
            )
            .unwrap();
        }
        d
    }

    /// R6: the kubelet preferred CNI network `rusternetes` and failed every
    /// pod ('Network configuration rusternetes not found') on a node whose
    /// only config is another CNI's (ovn-kubernetes writes
    /// 10-ovn-kubernetes.conf). A preferred name that is not there falls
    /// back to the first config in lexical order, as upstream runtimes do.
    #[test]
    fn a_missing_preferred_network_falls_back_to_the_first_config() {
        let plugins = TempDir::new().unwrap();
        let conf = net_dir(&[("10-ovn-kubernetes.conf", "ovn-kubernetes")]);
        let rt = CniRuntime::new(vec![plugins.path().into()], conf.path().into())
            .unwrap()
            .with_default_network("rusternetes".to_string());
        assert_eq!(rt.get_network_config(None).unwrap().name, "ovn-kubernetes");
    }

    #[test]
    fn the_default_config_is_the_first_in_lexical_order() {
        let plugins = TempDir::new().unwrap();
        for _ in 0..5 {
            let conf = net_dir(&[
                ("99-z.conf", "z"),
                ("05-a.conf", "a"),
                ("50-m.conflist", "m"),
                ("10-b.conf", "b"),
            ]);
            let rt = CniRuntime::new(vec![plugins.path().into()], conf.path().into()).unwrap();
            assert_eq!(rt.get_network_config(None).unwrap().name, "a");
        }
    }

    #[test]
    fn a_preferred_network_that_is_there_wins() {
        let plugins = TempDir::new().unwrap();
        let conf = net_dir(&[("05-a.conf", "a"), ("10-ovn-kubernetes.conf", "ovn-kubernetes")]);
        let rt = CniRuntime::new(vec![plugins.path().into()], conf.path().into())
            .unwrap()
            .with_default_network("ovn-kubernetes".to_string());
        assert_eq!(rt.get_network_config(None).unwrap().name, "ovn-kubernetes");
    }
}
