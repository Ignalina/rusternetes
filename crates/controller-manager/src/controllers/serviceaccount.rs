use anyhow::Result;
use futures::StreamExt;
use rusternetes_common::auth::{ServiceAccountClaims, TokenManager};
use rusternetes_common::resources::{Namespace, Secret, ServiceAccount};
use rusternetes_common::types::{ObjectMeta, TypeMeta};
use rusternetes_storage::{build_key, build_prefix, extract_key, Storage, WorkQueue};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// ServiceAccountController automatically creates default ServiceAccounts in new namespaces
/// and manages ServiceAccount tokens.
///
/// Responsibilities:
/// 1. Create "default" ServiceAccount in each namespace
/// 2. Create ServiceAccount tokens as Secrets, signed with the cluster's
///    service-account key (rusternetes_common::auth::cluster_token_manager);
///    without that key no token Secret is created (never an unsigned token)
/// 3. Handle ServiceAccount deletion and cleanup
pub struct ServiceAccountController<S: Storage> {
    storage: Arc<S>,
    tokens: Option<Arc<TokenManager>>,
}

impl<S: Storage + 'static> ServiceAccountController<S> {
    pub fn new(storage: Arc<S>) -> Self {
        let tokens = rusternetes_common::auth::cluster_token_manager();
        if tokens.is_none() {
            warn!("No service-account key in this process: ServiceAccount token Secrets are left to the API server");
        }
        Self { storage, tokens }
    }

    /// Watch-based run loop. Watches for serviceaccount changes and
    /// periodically resyncs every 30s.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let queue = WorkQueue::new();

        let worker_queue = queue.clone();
        let worker_self = Arc::clone(&self);
        tokio::spawn(async move {
            worker_self.worker(worker_queue).await;
        });

        loop {
            self.enqueue_all(&queue).await;

            let prefix = build_prefix("serviceaccounts", None);
            let watch_result = self.storage.watch(&prefix).await;
            let mut watch = match watch_result {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("Failed to establish watch: {}, retrying", e);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let mut resync = tokio::time::interval(std::time::Duration::from_secs(30));
            resync.tick().await;

            let mut watch_broken = false;
            while !watch_broken {
                tokio::select! {
                    event = watch.next() => {
                        match event {
                            Some(Ok(ev)) => {
                                let key = extract_key(&ev);
                                queue.add(key).await;
                            }
                            Some(Err(e)) => {
                                tracing::warn!("Watch error: {}, reconnecting", e);
                                watch_broken = true;
                            }
                            None => {
                                tracing::warn!("Watch stream ended, reconnecting");
                                watch_broken = true;
                            }
                        }
                    }
                    _ = resync.tick() => {
                        self.enqueue_all(&queue).await;
                    }
                }
            }
        }
    }

    /// Main reconciliation loop - ensures all namespaces have default ServiceAccounts
    async fn worker(&self, queue: WorkQueue) {
        while let Some(key) = queue.get().await {
            let parts: Vec<&str> = key.splitn(3, '/').collect();
            let (ns, name) = match parts.len() {
                3 => (parts[1], parts[2]),
                _ => {
                    queue.done(&key).await;
                    continue;
                }
            };
            // Skip namespaces that are being deleted — don't create SAs
            // in terminating namespaces (fights with namespace controller)
            let ns_key = build_key("namespaces", None, ns);
            if let Ok(namespace) = self.storage.get::<Namespace>(&ns_key).await {
                if namespace.metadata.deletion_timestamp.is_some() {
                    queue.forget(&key).await;
                    queue.done(&key).await;
                    continue;
                }
            }
            // Ensure the default service account exists in this namespace
            if let Err(e) = self.ensure_default_serviceaccount(ns).await {
                tracing::error!("Failed to ensure default SA in {}: {}", ns, e);
            }
            // Reconcile the specific service account
            match self.reconcile_serviceaccount(ns, name).await {
                Ok(()) => queue.forget(&key).await,
                Err(e) => {
                    tracing::error!("Failed to reconcile {}: {}", key, e);
                    queue.requeue_rate_limited(key.clone()).await;
                }
            }
            queue.done(&key).await;
        }
    }

    async fn enqueue_all(&self, queue: &WorkQueue) {
        // Enqueue all existing service accounts
        match self
            .storage
            .list::<ServiceAccount>("/registry/serviceaccounts/")
            .await
        {
            Ok(items) => {
                for item in &items {
                    let ns = item.metadata.namespace.as_deref().unwrap_or("");
                    let key = format!("serviceaccounts/{}/{}", ns, item.metadata.name);
                    queue.add(key).await;
                }
            }
            Err(e) => {
                tracing::error!("Failed to list serviceaccounts for enqueue: {}", e);
            }
        }
        // Also ensure default SA in all namespaces
        match self
            .storage
            .list::<Namespace>("/registry/namespaces/")
            .await
        {
            Ok(namespaces) => {
                for ns in &namespaces {
                    if ns.metadata.deletion_timestamp.is_none() {
                        let key = format!("serviceaccounts/{}/default", ns.metadata.name);
                        queue.add(key).await;
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to list namespaces for SA enqueue: {}", e);
            }
        }
    }

    #[allow(dead_code)]
    pub async fn reconcile_all(&self) -> Result<()> {
        debug!("Starting service account reconciliation");

        // List all namespaces
        let namespaces: Vec<Namespace> = self.storage.list("/registry/namespaces/").await?;

        for namespace in namespaces {
            let ns_name = &namespace.metadata.name;

            // Skip namespaces being deleted
            if namespace.metadata.deletion_timestamp.is_some() {
                continue;
            }

            if let Err(e) = self.ensure_default_serviceaccount(ns_name).await {
                error!(
                    "Failed to ensure default ServiceAccount in namespace {}: {}",
                    ns_name, e
                );
            }
        }

        Ok(())
    }

    /// Ensure the "default" ServiceAccount exists in a namespace
    async fn ensure_default_serviceaccount(&self, namespace: &str) -> Result<()> {
        let sa_name = "default";
        let sa_key = build_key("serviceaccounts", Some(namespace), sa_name);

        // Check if default ServiceAccount already exists
        match self.storage.get::<ServiceAccount>(&sa_key).await {
            Ok(_) => {
                debug!(
                    "Default ServiceAccount already exists in namespace {}",
                    namespace
                );
                return Ok(());
            }
            Err(rusternetes_common::Error::NotFound(_)) => {
                // ServiceAccount doesn't exist, create it
            }
            Err(e) => return Err(e.into()),
        }

        info!("Creating default ServiceAccount in namespace {}", namespace);

        // Create the default ServiceAccount
        let service_account = ServiceAccount {
            type_meta: TypeMeta {
                kind: "ServiceAccount".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: ObjectMeta {
                name: sa_name.to_string(),
                generate_name: None,
                generation: None,
                managed_fields: None,
                namespace: Some(namespace.to_string()),
                uid: String::new(),
                resource_version: None,
                deletion_grace_period_seconds: None,
                finalizers: None,
                owner_references: None,
                creation_timestamp: None,
                deletion_timestamp: None,
                labels: None,
                annotations: None,
            },
            secrets: None,
            image_pull_secrets: None,
            automount_service_account_token: Some(true),
        };

        match self.storage.create(&sa_key, &service_account).await {
            Ok(_) => {}
            Err(rusternetes_common::Error::AlreadyExists(_)) => {
                // Another reconciliation created it — this is fine
                debug!(
                    "Default ServiceAccount already exists in namespace {}",
                    namespace
                );
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }

        // Create a token Secret for the ServiceAccount
        self.create_token_secret(namespace, sa_name).await?;

        info!("Created default ServiceAccount in namespace {}", namespace);
        Ok(())
    }

    /// Create a token Secret for a ServiceAccount
    async fn create_token_secret(&self, namespace: &str, sa_name: &str) -> Result<()> {
        let secret_name = format!("{}-token", sa_name);
        let secret_key = build_key("secrets", Some(namespace), &secret_name);

        if self.tokens.is_none() {
            return Ok(());
        }
        // Check if token secret already exists
        if self.storage.get::<Secret>(&secret_key).await.is_ok() {
            debug!(
                "Token secret already exists for ServiceAccount {}/{}",
                namespace, sa_name
            );
            return Ok(());
        }

        debug!(
            "Creating token secret for ServiceAccount {}/{}",
            namespace, sa_name
        );

        // Get the ServiceAccount to retrieve its UID
        let sa_key = build_key("serviceaccounts", Some(namespace), sa_name);
        let sa: ServiceAccount = self.storage.get(&sa_key).await?;
        let sa_uid = &sa.metadata.uid;

        // Generate a JWT token (or fallback to simple token if no signing key)
        let token = self.generate_token(namespace, sa_name, sa_uid)?;

        let mut annotations = HashMap::new();
        annotations.insert(
            "kubernetes.io/service-account.name".to_string(),
            sa_name.to_string(),
        );
        annotations.insert(
            "kubernetes.io/service-account.uid".to_string(),
            sa_uid.clone(),
        );

        let secret = Secret {
            type_meta: TypeMeta {
                kind: "Secret".to_string(),
                api_version: "v1".to_string(),
            },
            metadata: ObjectMeta {
                name: secret_name.clone(),
                generate_name: None,
                generation: None,
                managed_fields: None,
                namespace: Some(namespace.to_string()),
                uid: String::new(),
                resource_version: None,
                deletion_grace_period_seconds: None,
                finalizers: None,
                owner_references: None,
                creation_timestamp: None,
                deletion_timestamp: None,
                labels: None,
                annotations: Some(annotations),
            },
            secret_type: Some("kubernetes.io/service-account-token".to_string()),
            data: {
                let mut data = HashMap::new();
                // Secret data is raw bytes (not base64 encoded - that's done on serialization)
                data.insert("token".to_string(), token.as_bytes().to_vec());
                // Add namespace and ca.crt (empty for now)
                data.insert("namespace".to_string(), namespace.as_bytes().to_vec());
                data.insert("ca.crt".to_string(), Vec::new());
                Some(data)
            },
            string_data: None,
            immutable: None,
        };

        match self.storage.create(&secret_key, &secret).await {
            Ok(_) => {
                info!(
                    "Created token secret {} for ServiceAccount {}/{}",
                    secret_name, namespace, sa_name
                );
            }
            Err(rusternetes_common::Error::AlreadyExists(_)) => {
                debug!("Token secret already exists for {}/{}", namespace, sa_name);
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }

    /// A ServiceAccount token signed with the cluster's key (the API
    /// server's issuer and audience). `Err` without the key.
    fn generate_token(&self, namespace: &str, sa_name: &str, sa_uid: &str) -> Result<String> {
        let tm = self
            .tokens
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no service-account key: no token for {namespace}/{sa_name}"))?;
        let claims = ServiceAccountClaims::new(sa_name.to_string(), namespace.to_string(), sa_uid.to_string(), 24 * 365);
        Ok(tm.generate_token(claims)?)
    }

    /// Reconcile a specific ServiceAccount (called when a SA is created/updated)
    pub async fn reconcile_serviceaccount(&self, namespace: &str, sa_name: &str) -> Result<()> {
        debug!("Reconciling ServiceAccount {}/{}", namespace, sa_name);

        let sa_key = build_key("serviceaccounts", Some(namespace), sa_name);

        // Get the ServiceAccount
        let sa: ServiceAccount = match self.storage.get(&sa_key).await {
            Ok(sa) => sa,
            Err(rusternetes_common::Error::NotFound(_)) => {
                // ServiceAccount was deleted, nothing to do
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        // If SA is being deleted, clean up tokens
        if sa.metadata.deletion_timestamp.is_some() {
            return self.cleanup_serviceaccount_tokens(namespace, sa_name).await;
        }

        // Ensure the SA has a token
        self.create_token_secret(namespace, sa_name).await?;

        Ok(())
    }

    /// Clean up token secrets when a ServiceAccount is deleted
    async fn cleanup_serviceaccount_tokens(&self, namespace: &str, sa_name: &str) -> Result<()> {
        info!(
            "Cleaning up tokens for ServiceAccount {}/{}",
            namespace, sa_name
        );

        // List all secrets in the namespace
        let prefix = build_prefix("secrets", Some(namespace));
        let secrets: Vec<Secret> = self.storage.list(&prefix).await?;

        // Find and delete secrets associated with this ServiceAccount
        for secret in secrets {
            if let Some(annotations) = &secret.metadata.annotations {
                if let Some(sa) = annotations.get("kubernetes.io/service-account.name") {
                    if sa == sa_name {
                        let secret_key =
                            build_key("secrets", Some(namespace), &secret.metadata.name);
                        match self.storage.delete(&secret_key).await {
                            Ok(_) => {
                                info!(
                                    "Deleted token secret {} for ServiceAccount {}/{}",
                                    secret.metadata.name, namespace, sa_name
                                );
                            }
                            Err(e) => {
                                error!(
                                    "Failed to delete token secret {}: {}",
                                    secret.metadata.name, e
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusternetes_storage::memory::MemoryStorage;

    #[tokio::test]
    async fn test_serviceaccount_controller_creation() {
        let storage = Arc::new(MemoryStorage::new());
        let _controller = ServiceAccountController::new(storage);
    }

    #[test]
    fn without_the_cluster_key_no_token_is_made() {
        let storage = Arc::new(MemoryStorage::new());
        let controller = ServiceAccountController::new(storage);
        // Never an unsigned placeholder token.
        assert!(controller.generate_token("default", "default", "test-uid-123").is_err());
    }
}
