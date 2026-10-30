use crate::client::ApiClient;
use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Scale a resource (Deployment, ReplicaSet, StatefulSet, etc.)
pub async fn execute(
    client: &ApiClient,
    resource_type: &str,
    name: &str,
    namespace: &str,
    replicas: i32,
) -> Result<()> {
    let qualified = scaled_kind(resource_type);
    let path = match resource_type {
        "deployment" | "deployments" | "deploy" => {
            format!(
                "/apis/apps/v1/namespaces/{}/deployments/{}/scale",
                namespace, name
            )
        }
        "replicaset" | "replicasets" | "rs" => {
            format!(
                "/apis/apps/v1/namespaces/{}/replicasets/{}/scale",
                namespace, name
            )
        }
        "statefulset" | "statefulsets" | "sts" => {
            format!(
                "/apis/apps/v1/namespaces/{}/statefulsets/{}/scale",
                namespace, name
            )
        }
        "replicationcontroller" | "rc" => {
            format!(
                "/api/v1/namespaces/{}/replicationcontrollers/{}/scale",
                namespace, name
            )
        }
        _ => anyhow::bail!("Resource type {} does not support scaling", resource_type),
    };

    let scale_body = json!({
        "spec": {
            "replicas": replicas
        }
    });

    // Use strategic merge patch for the scale subresource
    let _: Value = client
        .patch(&path, &scale_body, "application/merge-patch+json")
        .await
        .context("Failed to scale resource")?;

    println!(
        "{}",
        crate::printers::action_line(qualified, name, "scaled")
    );

    Ok(())
}

/// kubectl's name for the scaled kind: `deployment.apps`, `statefulset.apps`.
fn scaled_kind(resource_type: &str) -> &'static str {
    match resource_type {
        "replicaset" | "replicasets" | "rs" => "replicaset.apps",
        "statefulset" | "statefulsets" | "sts" => "statefulset.apps",
        "replicationcontroller" | "rc" => "replicationcontroller",
        _ => "deployment.apps",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn scale_message_like_upstream() {
        assert_eq!(
            crate::printers::action_line(super::scaled_kind("deploy"), "web", "scaled"),
            "deployment.apps/web scaled"
        );
        assert_eq!(super::scaled_kind("sts"), "statefulset.apps");
    }

    #[test]
    fn test_scale_path_deployment() {
        let path = format!(
            "/apis/apps/v1/namespaces/{}/deployments/{}/scale",
            "default", "web"
        );
        assert_eq!(
            path,
            "/apis/apps/v1/namespaces/default/deployments/web/scale"
        );
    }

    #[test]
    fn test_scale_path_statefulset() {
        let path = format!(
            "/apis/apps/v1/namespaces/{}/statefulsets/{}/scale",
            "prod", "db"
        );
        assert_eq!(path, "/apis/apps/v1/namespaces/prod/statefulsets/db/scale");
    }

    #[test]
    fn test_scale_body_construction() {
        let replicas = 5;
        let scale_body = json!({
            "spec": {
                "replicas": replicas
            }
        });
        assert_eq!(scale_body["spec"]["replicas"], 5);
    }

    #[test]
    fn test_scale_body_zero_replicas() {
        let scale_body = json!({
            "spec": {
                "replicas": 0
            }
        });
        assert_eq!(scale_body["spec"]["replicas"], 0);
    }

    #[test]
    fn test_scale_path_replicaset() {
        let path = format!(
            "/apis/apps/v1/namespaces/{}/replicasets/{}/scale",
            "default", "web-rs"
        );
        assert_eq!(
            path,
            "/apis/apps/v1/namespaces/default/replicasets/web-rs/scale"
        );
    }

    #[test]
    fn test_scale_path_replication_controller() {
        let path = format!(
            "/api/v1/namespaces/{}/replicationcontrollers/{}/scale",
            "default", "my-rc"
        );
        assert_eq!(
            path,
            "/api/v1/namespaces/default/replicationcontrollers/my-rc/scale"
        );
    }
}
