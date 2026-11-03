//! Integration tests for ServiceAccountController

use rusternetes_common::resources::{
    namespace::{NamespaceSpec, NamespaceStatus},
    Namespace, Secret, ServiceAccount,
};
use rusternetes_common::types::{ObjectMeta, TypeMeta};
use rusternetes_controller_manager::controllers::serviceaccount::ServiceAccountController;
use rusternetes_storage::{build_key, memory::MemoryStorage, Storage};
use std::sync::Arc;

/// The cluster's service-account key in this process (the controller signs
/// token Secrets with it; without one it makes none).
fn with_cluster_key() {
    rusternetes_common::auth::install_cluster_token_manager(Arc::new(
        rusternetes_common::auth::TokenManager::new_random(),
    ));
}

#[tokio::test]
async fn test_serviceaccount_controller_creation() {
    let storage = Arc::new(MemoryStorage::new());
    let _controller = ServiceAccountController::new(storage);
}

#[tokio::test]
async fn test_serviceaccount_creates_default_in_namespace() {
    with_cluster_key();
    let storage = Arc::new(MemoryStorage::new());
    let controller = ServiceAccountController::new(storage.clone());

    // Create a test namespace
    let namespace = Namespace {
        type_meta: TypeMeta {
            kind: "Namespace".to_string(),
            api_version: "v1".to_string(),
        },
        metadata: ObjectMeta {
            name: "test-sa-namespace".to_string(),
            namespace: None,
            uid: uuid::Uuid::new_v4().to_string(),
            resource_version: None,
            deletion_grace_period_seconds: None,
            finalizers: None,
            owner_references: None,
            creation_timestamp: Some(chrono::Utc::now()),
            deletion_timestamp: None,
            labels: None,
            annotations: None,
            generate_name: None,
            generation: None,
            managed_fields: None,
        },
        spec: Some(NamespaceSpec { finalizers: None }),
        status: Some(NamespaceStatus {
            phase: Some(rusternetes_common::types::Phase::Active),
            conditions: None,
        }),
    };

    let ns_key = build_key("namespaces", None, "test-sa-namespace");
    storage.create(&ns_key, &namespace).await.unwrap();

    // Reconcile should create default ServiceAccount
    controller.reconcile_all().await.unwrap();

    // Verify default ServiceAccount was created
    let sa_key = build_key("serviceaccounts", Some("test-sa-namespace"), "default");
    let sa: ServiceAccount = storage.get(&sa_key).await.unwrap();
    assert_eq!(sa.metadata.name, "default");
    assert_eq!(sa.metadata.namespace.as_ref().unwrap(), "test-sa-namespace");

    // No long-lived token Secret (pods get bound tokens through TokenRequest).
    let secret_key = build_key("secrets", Some("test-sa-namespace"), "default-token");
    assert!(storage.get::<Secret>(&secret_key).await.is_err());

    // Clean up
    storage.delete(&sa_key).await.unwrap();
    storage.delete(&ns_key).await.unwrap();
}

#[tokio::test]
async fn test_serviceaccount_does_not_recreate_existing() {
    let storage = Arc::new(MemoryStorage::new());
    let controller = ServiceAccountController::new(storage.clone());

    // Create a namespace
    let namespace = Namespace {
        type_meta: TypeMeta {
            kind: "Namespace".to_string(),
            api_version: "v1".to_string(),
        },
        metadata: ObjectMeta {
            name: "test-existing-sa".to_string(),
            namespace: None,
            uid: uuid::Uuid::new_v4().to_string(),
            resource_version: None,
            deletion_grace_period_seconds: None,
            finalizers: None,
            owner_references: None,
            creation_timestamp: Some(chrono::Utc::now()),
            deletion_timestamp: None,
            labels: None,
            annotations: None,
            generate_name: None,
            generation: None,
            managed_fields: None,
        },
        spec: Some(NamespaceSpec { finalizers: None }),
        status: Some(NamespaceStatus {
            phase: Some(rusternetes_common::types::Phase::Active),
            conditions: None,
        }),
    };

    let ns_key = build_key("namespaces", None, "test-existing-sa");
    storage.create(&ns_key, &namespace).await.unwrap();

    // Create default ServiceAccount manually
    let service_account = ServiceAccount {
        type_meta: TypeMeta {
            kind: "ServiceAccount".to_string(),
            api_version: "v1".to_string(),
        },
        metadata: ObjectMeta {
            name: "default".to_string(),
            namespace: Some("test-existing-sa".to_string()),
            uid: uuid::Uuid::new_v4().to_string(),
            resource_version: None,
            deletion_grace_period_seconds: None,
            finalizers: None,
            owner_references: None,
            creation_timestamp: Some(chrono::Utc::now()),
            deletion_timestamp: None,
            labels: None,
            annotations: None,
            generate_name: None,
            generation: None,
            managed_fields: None,
        },
        secrets: None,
        image_pull_secrets: None,
        automount_service_account_token: Some(true),
    };

    let sa_key = build_key("serviceaccounts", Some("test-existing-sa"), "default");
    storage.create(&sa_key, &service_account).await.unwrap();

    // Reconcile should not recreate
    controller.reconcile_all().await.unwrap();

    // ServiceAccount should still exist with same UID
    let retrieved: ServiceAccount = storage.get(&sa_key).await.unwrap();
    assert_eq!(retrieved.metadata.uid, service_account.metadata.uid);

    // Clean up
    storage.delete(&sa_key).await.unwrap();
    storage.delete(&ns_key).await.unwrap();
}

#[tokio::test]
async fn test_serviceaccount_token_contains_required_fields() {
    with_cluster_key();
    let storage = Arc::new(MemoryStorage::new());
    let controller = ServiceAccountController::new(storage.clone());

    // Create a namespace
    let namespace = Namespace {
        type_meta: TypeMeta {
            kind: "Namespace".to_string(),
            api_version: "v1".to_string(),
        },
        metadata: ObjectMeta {
            name: "test-token-fields".to_string(),
            namespace: None,
            uid: uuid::Uuid::new_v4().to_string(),
            resource_version: None,
            deletion_grace_period_seconds: None,
            finalizers: None,
            owner_references: None,
            creation_timestamp: Some(chrono::Utc::now()),
            deletion_timestamp: None,
            labels: None,
            annotations: None,
            generate_name: None,
            generation: None,
            managed_fields: None,
        },
        spec: Some(NamespaceSpec { finalizers: None }),
        status: Some(NamespaceStatus {
            phase: Some(rusternetes_common::types::Phase::Active),
            conditions: None,
        }),
    };

    let ns_key = build_key("namespaces", None, "test-token-fields");
    storage.create(&ns_key, &namespace).await.unwrap();

    // Reconcile: the default ServiceAccount, no token Secret.
    controller.reconcile_all().await.unwrap();
    assert!(storage
        .get::<Secret>(&build_key(
            "secrets",
            Some("test-token-fields"),
            "default-token"
        ))
        .await
        .is_err());

    // A token Secret a user asks for is filled: token (signed with the
    // cluster's key) and namespace.
    let mut req = Secret::new("default-legacy", "test-token-fields")
        .with_type("kubernetes.io/service-account-token");
    req.metadata.annotations = Some(std::collections::HashMap::from([(
        "kubernetes.io/service-account.name".to_string(),
        "default".to_string(),
    )]));
    let secret_key = build_key("secrets", Some("test-token-fields"), "default-legacy");
    storage.create(&secret_key, &req).await.unwrap();
    controller
        .reconcile_serviceaccount("test-token-fields", "default")
        .await
        .unwrap();
    let secret: Secret = storage.get(&secret_key).await.unwrap();
    let data = secret.data.as_ref().unwrap();
    assert!(data.contains_key("token"));
    assert!(data.contains_key("namespace"));

    // The token is signed with the cluster's key.
    let token = data.get("token").unwrap();
    let tm = rusternetes_common::auth::cluster_token_manager().unwrap();
    let claims = tm
        .validate_token(std::str::from_utf8(token).unwrap())
        .unwrap();
    assert_eq!(
        claims.sub,
        "system:serviceaccount:test-token-fields:default"
    );

    // Namespace should match
    let namespace_bytes = data.get("namespace").unwrap();
    let namespace_str = String::from_utf8(namespace_bytes.clone()).unwrap();
    assert_eq!(namespace_str, "test-token-fields");

    // Clean up
    let sa_key = build_key("serviceaccounts", Some("test-token-fields"), "default");
    storage.delete(&sa_key).await.unwrap();
    storage.delete(&secret_key).await.unwrap();
    storage.delete(&ns_key).await.unwrap();
}

#[tokio::test]
async fn test_serviceaccount_skips_terminating_namespaces() {
    let storage = Arc::new(MemoryStorage::new());
    let controller = ServiceAccountController::new(storage.clone());

    // Create a namespace that's being deleted
    let namespace = Namespace {
        type_meta: TypeMeta {
            kind: "Namespace".to_string(),
            api_version: "v1".to_string(),
        },
        metadata: ObjectMeta {
            name: "test-terminating".to_string(),
            namespace: None,
            uid: uuid::Uuid::new_v4().to_string(),
            resource_version: None,
            deletion_grace_period_seconds: None,
            finalizers: None,
            owner_references: None,
            creation_timestamp: Some(chrono::Utc::now()),
            deletion_timestamp: Some(chrono::Utc::now()), // Being deleted
            labels: None,
            annotations: None,
            generate_name: None,
            generation: None,
            managed_fields: None,
        },
        spec: Some(NamespaceSpec { finalizers: None }),
        status: Some(NamespaceStatus {
            phase: Some(rusternetes_common::types::Phase::Terminating),
            conditions: None,
        }),
    };

    let ns_key = build_key("namespaces", None, "test-terminating");
    storage.create(&ns_key, &namespace).await.unwrap();

    // Reconcile should skip terminating namespace
    controller.reconcile_all().await.unwrap();

    // ServiceAccount should NOT be created
    let sa_key = build_key("serviceaccounts", Some("test-terminating"), "default");
    let result = storage.get::<ServiceAccount>(&sa_key).await;
    assert!(result.is_err()); // Should not exist

    // Clean up
    storage.delete(&ns_key).await.unwrap();
}
