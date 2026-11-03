//! RuntimeClass handlers on the youki backend.
//!
//! A pod's RuntimeClass names a handler (`spec.handler`). On this backend a
//! handler is a node-local policy file, `<handlers dir>/<handler>.json`
//! (`$KUBELET_YOUKI_HANDLERS`, default `/etc/rusternetes/handlers`), applied
//! to each of the pod's containers before its OCI spec is written, plus an
//! optional result hook the shim calls once the container has exited:
//!
//! ```json
//! { "readonlyRootfs": true,
//!   "writable": ["/out"],
//!   "capabilities": [],
//!   "noNewPrivileges": true,
//!   "network": "none",
//!   "seccomp": "RuntimeDefault",
//!   "imageSeccompDir": "heimdall",
//!   "requireImageDigest": true,
//!   "resultSocket": "/run/heimdall/k8s.sock" }
//! ```
//!
//! * `readonlyRootfs`: the root is mounted read-only;
//! * `writable`: bind mounts (the pod's volumes) whose container path is
//!   listed stay writable, every other bind becomes read-only;
//! * `capabilities`: the container's whole capability set (`[]`: none);
//! * `noNewPrivileges`: always set;
//! * `network: "none"`: a fresh network namespace (loopback only) instead
//!   of the pod's;
//! * `seccomp`: the profile when nothing else names one (`RuntimeDefault`);
//! * `imageSeccompDir`: the profile shipped with the image, pinned by the
//!   image's digest: `<seccomp profile root>/<dir>/<digest hex>.json`; when
//!   it exists it is the container's profile, over the pod's own;
//! * `requireImageDigest`: the image must be named `name@sha256:<hex>`;
//! * `resultSocket`: after the container exits the shim sends a
//!   [`ResultRequest`] there (one JSON object, then end of stream) and
//!   appends the answer to the container's log.
//!
//! An unknown handler, or a handler file that does not parse, refuses the
//! container (`CreateContainerError`).

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::backend::ContainerConfig;
use crate::seccomp::Seccomp;

/// A handler's policy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Handler {
    #[serde(default)]
    pub readonly_rootfs: bool,
    #[serde(default)]
    pub writable: Vec<String>,
    #[serde(default)]
    pub capabilities: Option<Vec<String>>,
    #[serde(default)]
    pub no_new_privileges: bool,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub seccomp: Option<String>,
    #[serde(default)]
    pub image_seccomp_dir: Option<String>,
    #[serde(default)]
    pub require_image_digest: bool,
    #[serde(default)]
    pub result_socket: Option<PathBuf>,
}

/// One writable volume of the container: where it is inside and on the host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Volume {
    pub destination: String,
    pub source: String,
}

/// What the handler applied, as the shim tells the result hook.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Applied {
    pub readonly_rootfs: bool,
    pub capabilities: Option<Vec<String>>,
    pub no_new_privileges: bool,
    pub network: String,
    /// `"Unconfined"`, `"RuntimeDefault"` or `"Localhost <path>"`.
    pub seccomp: String,
    /// SHA-256 of the Localhost profile's bytes (lower-case hex).
    pub seccomp_profile_sha256: Option<String>,
    /// The profile came with the image (`imageSeccompDir`).
    pub seccomp_from_image: bool,
}

/// What the kubelet leaves in the container's directory (`handler.json`)
/// for the shim.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub handler: String,
    pub result_socket: Option<PathBuf>,
    pub image: String,
    /// `sha256:<hex>` when the image is named by digest.
    pub image_digest: Option<String>,
    pub writable: Vec<Volume>,
    pub applied: Applied,
}

/// What the shim sends the result hook after the container exited.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultRequest {
    pub container: String,
    pub record: Record,
    pub exit_code: Option<i64>,
    pub signal: Option<i32>,
    pub started_unix: i64,
    pub finished_unix: i64,
}

/// The file `handler.json` in a container's directory.
pub const RECORD_FILE: &str = "handler.json";

/// The handlers directory.
pub fn handlers_dir() -> PathBuf {
    std::env::var_os("KUBELET_YOUKI_HANDLERS")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/rusternetes/handlers"))
}

fn dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// The handler `name` from `dir`.
pub fn load(dir: &Path, name: &str) -> Result<Handler> {
    if !dns_label(name) {
        bail!("CreateContainerError: runtime handler {name:?} is not a DNS label");
    }
    let path = dir.join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path).map_err(|e| {
        anyhow::anyhow!(
            "CreateContainerError: no runtime handler {name:?} on this node ({}: {e})",
            path.display()
        )
    })?;
    serde_json::from_str(&text).map_err(|e| {
        anyhow::anyhow!(
            "CreateContainerError: runtime handler {name:?}: {}: {e}",
            path.display()
        )
    })
}

/// `name@sha256:<64 hex>` -> `sha256:<hex>`.
pub fn image_digest(image: &str) -> Option<String> {
    let (_, d) = image.rsplit_once('@')?;
    let hex = d.strip_prefix("sha256:")?;
    (hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    .then(|| d.to_string())
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// Apply `h` (named `name`) to a container's config; the record for the shim.
/// `seccomp_root` is the kubelet's seccomp profile root.
pub fn apply(
    name: &str,
    h: &Handler,
    config: &mut ContainerConfig,
    seccomp_root: &Path,
) -> Result<Record> {
    let image = config.image.clone().unwrap_or_default();
    let digest = image_digest(&image);
    if h.require_image_digest && digest.is_none() {
        bail!(
            "CreateContainerConfigError: runtime handler {name:?} runs only images pinned by digest (name@sha256:<hex>), not {image:?}"
        );
    }
    let hc = config.host_config.get_or_insert_with(Default::default);
    let mut applied = Applied::default();

    if h.readonly_rootfs {
        hc.readonly_rootfs = Some(true);
    }
    applied.readonly_rootfs = hc.readonly_rootfs == Some(true);

    // The pod's volumes: read-only unless listed as writable.
    let mut writable = Vec::new();
    if let Some(binds) = hc.binds.as_mut() {
        for b in binds.iter_mut() {
            let parts: Vec<&str> = b.split(':').collect();
            let (src, dst) = match parts.as_slice() {
                [s, d] | [s, d, _] => (s.to_string(), d.to_string()),
                _ => bail!("CreateContainerError: invalid bind {b:?}"),
            };
            if h.writable.iter().any(|w| *w == dst) {
                *b = format!("{src}:{dst}");
                writable.push(Volume {
                    destination: dst,
                    source: src,
                });
            } else {
                *b = format!("{src}:{dst}:ro");
            }
        }
    }
    // tmpfs mounts stay (scratch space inside the container only).

    if let Some(caps) = &h.capabilities {
        hc.cap_drop = Some(vec!["ALL".to_string()]);
        hc.cap_add = Some(caps.clone()).filter(|c| !c.is_empty());
        hc.privileged = Some(false);
        applied.capabilities = Some(caps.clone());
    }
    if h.no_new_privileges {
        let opts = hc.security_opt.get_or_insert_with(Vec::new);
        if !opts.iter().any(|o| o.starts_with("no-new-privileges")) {
            opts.push("no-new-privileges".to_string());
        }
        hc.privileged = Some(false);
    }
    applied.no_new_privileges = hc
        .security_opt
        .iter()
        .flatten()
        .any(|o| o.starts_with("no-new-privileges"));
    match h.network.as_deref() {
        None => {}
        Some("none") => hc.network_mode = Some("none".to_string()),
        Some(other) => {
            bail!(
                "CreateContainerError: runtime handler {name:?}: unknown network {other:?} (none)"
            )
        }
    }
    applied.network = hc.network_mode.clone().unwrap_or_default();

    // Seccomp: the image's own profile, else the pod's, else the handler's.
    let from_image = match (&h.image_seccomp_dir, &digest) {
        (Some(dir), Some(d)) => {
            let path = seccomp_root
                .join(dir)
                .join(format!("{}.json", d.trim_start_matches("sha256:")));
            match std::fs::read_to_string(&path) {
                Ok(profile) => Some(Seccomp::Localhost { path, profile }),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => bail!(
                    "CreateContainerError: cannot load seccomp profile {:?}: {e}",
                    path.display().to_string()
                ),
            }
        }
        _ => None,
    };
    applied.seccomp_from_image = from_image.is_some();
    if let Some(s) = from_image {
        hc.seccomp = Some(s);
    } else if matches!(hc.seccomp, None | Some(Seccomp::Unconfined)) {
        match h.seccomp.as_deref() {
            None => {}
            Some("RuntimeDefault") => hc.seccomp = Some(Seccomp::RuntimeDefault),
            Some(other) => bail!(
                "CreateContainerError: runtime handler {name:?}: unknown seccomp {other:?} (RuntimeDefault)"
            ),
        }
    }
    let (s, sum) = match &hc.seccomp {
        None | Some(Seccomp::Unconfined) => ("Unconfined".to_string(), None),
        Some(Seccomp::RuntimeDefault) => (
            "RuntimeDefault".to_string(),
            Some(sha256_hex(crate::seccomp::RUNTIME_DEFAULT.as_bytes())),
        ),
        Some(Seccomp::Localhost { path, profile }) => (
            format!("Localhost {}", path.display()),
            Some(sha256_hex(profile.as_bytes())),
        ),
    };
    applied.seccomp = s;
    applied.seccomp_profile_sha256 = sum;

    Ok(Record {
        handler: name.to_string(),
        result_socket: h.result_socket.clone(),
        image,
        image_digest: digest,
        writable,
        applied,
    })
}

/// The pod's handler (`host_config.runtime_handler`) applied to `config`;
/// the record to leave in the container's directory, `None` without a handler.
/// Handlers come from `handlers`, Localhost profiles from `seccomp_root`.
pub fn prepare(
    config: &mut ContainerConfig,
    handlers: &Path,
    seccomp_root: &Path,
) -> Result<Option<Record>> {
    let Some(name) = config
        .host_config
        .as_ref()
        .and_then(|h| h.runtime_handler.clone())
        .filter(|h| !h.is_empty())
    else {
        return Ok(None);
    };
    let h = load(handlers, &name)?;
    apply(&name, &h, config, seccomp_root).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::HostConfig;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn heimdall() -> Handler {
        serde_json::from_str(
            r#"{"readonlyRootfs": true, "writable": ["/out"], "capabilities": [],
                "noNewPrivileges": true, "network": "none", "seccomp": "RuntimeDefault",
                "imageSeccompDir": "heimdall", "requireImageDigest": true,
                "resultSocket": "/run/heimdall/k8s.sock"}"#,
        )
        .unwrap()
    }

    fn config(image: &str) -> ContainerConfig {
        ContainerConfig {
            image: Some(image.to_string()),
            host_config: Some(HostConfig {
                binds: Some(vec![
                    "/v/in:/in:ro".into(),
                    "/v/out:/out".into(),
                    "/v/data:/data".into(),
                ]),
                network_mode: Some("ns:/var/run/netns/x".into()),
                cap_add: Some(vec!["NET_ADMIN".into()]),
                privileged: Some(true),
                seccomp: Some(Seccomp::Unconfined),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn the_heimdall_policy_locks_the_container_down() {
        let d = tempfile::tempdir().unwrap();
        let mut c = config(&format!("docker.io/library/busybox@{DIGEST}"));
        let r = apply("heimdall", &heimdall(), &mut c, d.path()).unwrap();
        let hc = c.host_config.unwrap();
        assert_eq!(hc.readonly_rootfs, Some(true));
        assert_eq!(
            hc.binds.unwrap(),
            vec!["/v/in:/in:ro", "/v/out:/out", "/v/data:/data:ro"]
        );
        assert_eq!(hc.cap_drop, Some(vec!["ALL".to_string()]));
        assert_eq!(hc.cap_add, None);
        assert_eq!(hc.privileged, Some(false));
        assert!(hc
            .security_opt
            .unwrap()
            .contains(&"no-new-privileges".to_string()));
        assert_eq!(hc.network_mode.as_deref(), Some("none"));
        // An Unconfined pod still runs filtered under this handler.
        assert_eq!(hc.seccomp, Some(Seccomp::RuntimeDefault));
        assert_eq!(r.image_digest.as_deref(), Some(DIGEST));
        assert_eq!(
            r.writable,
            vec![Volume {
                destination: "/out".into(),
                source: "/v/out".into()
            }]
        );
        assert_eq!(r.applied.seccomp, "RuntimeDefault");
        assert!(!r.applied.seccomp_from_image);
        assert_eq!(
            r.result_socket,
            Some(PathBuf::from("/run/heimdall/k8s.sock"))
        );
    }

    #[test]
    fn the_profile_pinned_with_the_image_digest_wins() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("heimdall")).unwrap();
        let body = r#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}"#;
        let p = d
            .path()
            .join("heimdall")
            .join(format!("{}.json", DIGEST.trim_start_matches("sha256:")));
        std::fs::write(&p, body).unwrap();
        let mut c = config(&format!("busybox@{DIGEST}"));
        c.host_config.as_mut().unwrap().seccomp = Some(Seccomp::RuntimeDefault);
        let r = apply("heimdall", &heimdall(), &mut c, d.path()).unwrap();
        assert_eq!(
            c.host_config.unwrap().seccomp,
            Some(Seccomp::Localhost {
                path: p.clone(),
                profile: body.into()
            })
        );
        assert!(r.applied.seccomp_from_image);
        assert_eq!(r.applied.seccomp, format!("Localhost {}", p.display()));
        assert_eq!(r.applied.seccomp_profile_sha256.unwrap().len(), 64);
    }

    #[test]
    fn an_image_named_by_tag_is_refused_when_a_digest_is_required() {
        let d = tempfile::tempdir().unwrap();
        let mut c = config("busybox:1.37");
        let e = apply("heimdall", &heimdall(), &mut c, d.path())
            .unwrap_err()
            .to_string();
        assert!(e.starts_with("CreateContainerConfigError:"), "{e}");
        assert!(e.contains("pinned by digest"), "{e}");
    }

    #[test]
    fn an_unknown_handler_refuses_the_container_by_name() {
        let d = tempfile::tempdir().unwrap();
        let e = load(d.path(), "heimdall").unwrap_err().to_string();
        assert!(
            e.starts_with("CreateContainerError: no runtime handler \"heimdall\""),
            "{e}"
        );
        let e = load(d.path(), "../x").unwrap_err().to_string();
        assert!(e.contains("not a DNS label"), "{e}");
    }

    #[test]
    fn a_handler_file_with_an_unknown_field_is_refused() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("x.json"),
            r#"{"readonlyRootfs":true,"landlock":true}"#,
        )
        .unwrap();
        assert!(load(d.path(), "x").is_err());
        std::fs::write(d.path().join("y.json"), r#"{"readonlyRootfs":true}"#).unwrap();
        assert!(load(d.path(), "y").unwrap().readonly_rootfs);
    }

    #[test]
    fn digests_are_read_only_from_a_full_sha256_reference() {
        assert_eq!(
            image_digest(&format!("a/b@{DIGEST}")).as_deref(),
            Some(DIGEST)
        );
        assert_eq!(image_digest("a/b:1"), None);
        assert_eq!(image_digest("a/b@sha256:abc"), None);
        assert_eq!(
            image_digest(&format!(
                "a/b@{}",
                DIGEST.to_uppercase().replace("SHA256", "sha256")
            )),
            None
        );
    }

    #[test]
    fn prepare_applies_the_pods_handler_and_nothing_without_one() {
        let d = tempfile::tempdir().unwrap();
        let handlers = d.path().join("handlers");
        std::fs::create_dir_all(&handlers).unwrap();
        std::fs::write(
            handlers.join("heimdall.json"),
            serde_json::to_string(&heimdall()).unwrap(),
        )
        .unwrap();
        // No handler: the config is untouched.
        let mut plain = config(&format!("busybox@{DIGEST}"));
        let before = format!("{plain:?}");
        assert_eq!(prepare(&mut plain, &handlers, d.path()).unwrap(), None);
        assert_eq!(format!("{plain:?}"), before);
        // The heimdall handler: locked down, and a record for the shim.
        let mut c = config(&format!("busybox@{DIGEST}"));
        c.host_config.as_mut().unwrap().runtime_handler = Some("heimdall".into());
        let r = prepare(&mut c, &handlers, d.path())
            .unwrap()
            .expect("a record");
        assert_eq!(r.handler, "heimdall");
        assert_eq!(c.host_config.unwrap().network_mode.as_deref(), Some("none"));
        // A handler this node does not have refuses the container.
        let mut c = config(&format!("busybox@{DIGEST}"));
        c.host_config.as_mut().unwrap().runtime_handler = Some("gvisor".into());
        let e = prepare(&mut c, &handlers, d.path())
            .unwrap_err()
            .to_string();
        assert!(e.contains("no runtime handler \"gvisor\""), "{e}");
    }
}
