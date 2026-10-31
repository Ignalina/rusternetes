// Encryption at rest for the store (kube-apiserver `--encryption-provider-config`).
//
// The Kubernetes model: an `EncryptionConfiguration` lists, per resource, an
// ordered list of providers. The FIRST provider encrypts every write; every
// provider is tried on a read, by the prefix the stored value carries. A value
// is stored as
//
//     k8s:enc:aesgcm:v1:<key name>:<12-byte nonce><ciphertext + 16-byte tag>
//
// (AES-256-GCM, a random nonce per write, the storage key as additional
// authenticated data, so a value moved to another key does not decrypt) —
// the byte layout of kube-apiserver's `aesgcm` provider. A value without the
// `k8s:enc:` prefix is plaintext: it is read only when `identity` is among the
// providers (a Secret written before encryption was turned on, or by an
// `identity`-first config while encryption is turned off again).
//
// Key rotation, as in Kubernetes: (1) add the new key SECOND on every API
// server and restart them (all can read it); (2) move it FIRST and restart
// (writes use it); (3) rewrite every Secret (`kubectl get secrets -A -o json |
// kubectl replace -f -`); (4) drop the old key. [`EncryptionTransformer::is_current`]
// tells whether a stored value is already under the write provider.

use aes_gcm::{
    aead::{Aead, KeyInit, Nonce, Payload},
    Aes256Gcm, Key,
};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

/// Every encrypted value starts with this.
pub const ENCRYPTED_PREFIX: &[u8] = b"k8s:enc:";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// `apiserver.config.k8s.io/v1` `EncryptionConfiguration` (YAML or JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub kind: String,
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub resources: Vec<ResourceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub resources: Vec<String>,
    pub providers: Vec<ProviderConfig>,
}

/// One provider entry. Only `aesgcm` and `identity` are implemented; the
/// others are refused when the config is loaded, never silently replaced by
/// `identity`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aesgcm: Option<KeysConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aescbc: Option<KeysConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secretbox: Option<KeysConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysConfig {
    pub keys: Vec<KeyConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    pub name: String,
    /// The key, base64 (32 bytes: AES-256).
    pub secret: String,
}

impl EncryptionConfig {
    /// Parse YAML (or JSON, which is YAML).
    pub fn parse(text: &str) -> Result<Self> {
        let c: EncryptionConfig =
            serde_yaml::from_str(text).context("EncryptionConfiguration")?;
        if c.kind != "EncryptionConfiguration" {
            bail!("kind {:?}: expected EncryptionConfiguration", c.kind);
        }
        if !matches!(
            c.api_version.as_str(),
            "apiserver.config.k8s.io/v1" | "apiserver.k8s.io/v1"
        ) {
            bail!(
                "apiVersion {:?}: expected apiserver.config.k8s.io/v1",
                c.api_version
            );
        }
        Ok(c)
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| path.to_string())?;
        Self::parse(&text).with_context(|| path.to_string())
    }

    /// A config that encrypts `resources` with AES-GCM under `keys` (name,
    /// 32-byte key; the first encrypts) and still reads plaintext.
    pub fn aesgcm(resources: &[&str], keys: &[(&str, &[u8; 32])]) -> Self {
        EncryptionConfig {
            kind: "EncryptionConfiguration".into(),
            api_version: "apiserver.config.k8s.io/v1".into(),
            resources: vec![ResourceConfig {
                resources: resources.iter().map(|r| r.to_string()).collect(),
                providers: vec![
                    ProviderConfig {
                        aesgcm: Some(KeysConfig {
                            keys: keys
                                .iter()
                                .map(|(n, k)| KeyConfig {
                                    name: n.to_string(),
                                    secret: general_purpose::STANDARD.encode(k),
                                })
                                .collect(),
                        }),
                        ..ProviderConfig::empty()
                    },
                    ProviderConfig {
                        identity: Some(serde_json::json!({})),
                        ..ProviderConfig::empty()
                    },
                ],
            }],
        }
    }
}

impl ProviderConfig {
    fn empty() -> Self {
        ProviderConfig {
            aesgcm: None,
            aescbc: None,
            secretbox: None,
            kms: None,
            identity: None,
        }
    }
}

/// A provider that encrypts or decrypts.
pub trait EncryptionProvider: Send + Sync {
    /// The prefix a value this provider wrote starts with (`identity`: none).
    fn prefix(&self) -> &[u8];
    /// `data` (the plaintext) for the storage key `key`, prefix included.
    fn encrypt(&self, key: &str, data: &[u8]) -> Result<Vec<u8>>;
    /// The plaintext of `stored` (prefix included).
    fn decrypt(&self, key: &str, stored: &[u8]) -> Result<Vec<u8>>;
    fn name(&self) -> &str;
}

/// AES-256-GCM (kube-apiserver's `aesgcm` provider): a random 96-bit nonce
/// per write, the storage key authenticated with the value. Rotate a key well
/// before 2^32 writes under it.
pub struct AesGcmProvider {
    cipher: Aes256Gcm,
    key_name: String,
    prefix: Vec<u8>,
}

impl AesGcmProvider {
    pub fn new(key: &[u8], key_name: String) -> Result<Self> {
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow!("aesgcm key {key_name:?}: {} bytes, expected 32 (AES-256)", key.len()))?;
        if key_name.is_empty() || key_name.contains(':') {
            bail!("aesgcm key name {key_name:?}: must be non-empty and without ':'");
        }
        let cipher = Aes256Gcm::new(&Key::<Aes256Gcm>::from(key_array));
        let prefix = format!("k8s:enc:aesgcm:v1:{key_name}:").into_bytes();
        Ok(Self {
            cipher,
            key_name,
            prefix,
        })
    }

    pub fn from_base64(encoded_key: &str, key_name: String) -> Result<Self> {
        let key = general_purpose::STANDARD
            .decode(encoded_key.trim())
            .map_err(|e| anyhow!("aesgcm key {key_name:?}: not base64: {e}"))?;
        Self::new(&key, key_name)
    }

    pub fn generate_key() -> [u8; 32] {
        use aes_gcm::aead::Generate;
        Key::<Aes256Gcm>::generate().into()
    }
}

impl EncryptionProvider for AesGcmProvider {
    fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    fn encrypt(&self, key: &str, data: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::aead::Generate;
        let nonce: [u8; NONCE_LEN] = Nonce::<Aes256Gcm>::generate().into();
        let sealed = self
            .cipher
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: data,
                    aad: key.as_bytes(),
                },
            )
            .map_err(|e| anyhow!("aesgcm encrypt: {e}"))?;
        let mut out = Vec::with_capacity(self.prefix.len() + NONCE_LEN + sealed.len());
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    fn decrypt(&self, key: &str, stored: &[u8]) -> Result<Vec<u8>> {
        let body = stored
            .strip_prefix(self.prefix.as_slice())
            .ok_or_else(|| anyhow!("not written with aesgcm key {:?}", self.key_name))?;
        if body.len() < NONCE_LEN + TAG_LEN {
            bail!("aesgcm value too short ({} bytes)", body.len());
        }
        let nonce: [u8; NONCE_LEN] = body[..NONCE_LEN].try_into().expect("checked length");
        self.cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &body[NONCE_LEN..],
                    aad: key.as_bytes(),
                },
            )
            .map_err(|_| {
                anyhow!(
                    "aesgcm key {:?} does not open the value at {key} (wrong key, or the value was altered or moved)",
                    self.key_name
                )
            })
    }

    fn name(&self) -> &str {
        &self.key_name
    }
}

/// No encryption: writes plaintext, reads any value without the
/// `k8s:enc:` prefix.
pub struct IdentityProvider;

impl EncryptionProvider for IdentityProvider {
    fn prefix(&self) -> &[u8] {
        b""
    }

    fn encrypt(&self, _key: &str, data: &[u8]) -> Result<Vec<u8>> {
        Ok(data.to_vec())
    }

    fn decrypt(&self, _key: &str, stored: &[u8]) -> Result<Vec<u8>> {
        Ok(stored.to_vec())
    }

    fn name(&self) -> &str {
        "identity"
    }
}

/// The providers of one resource: the first writes, all read.
struct Chain {
    providers: Vec<Arc<dyn EncryptionProvider>>,
}

impl Chain {
    fn write(&self) -> &Arc<dyn EncryptionProvider> {
        &self.providers[0]
    }

    /// The provider that wrote `stored`.
    fn reader(&self, key: &str, stored: &[u8]) -> Result<&Arc<dyn EncryptionProvider>> {
        if stored.starts_with(ENCRYPTED_PREFIX) {
            self.providers
                .iter()
                .find(|p| !p.prefix().is_empty() && stored.starts_with(p.prefix()))
                .ok_or_else(|| {
                    let end = stored
                        .iter()
                        .enumerate()
                        .filter(|(_, b)| **b == b':')
                        .nth(4)
                        .map_or(stored.len().min(64), |(i, _)| i + 1);
                    anyhow!(
                        "{key}: written by {:?}, which no configured provider reads (a removed key?)",
                        String::from_utf8_lossy(&stored[..end])
                    )
                })
        } else {
            self.providers
                .iter()
                .find(|p| p.prefix().is_empty())
                .ok_or_else(|| anyhow!("{key}: stored unencrypted, and identity is not among the providers"))
        }
    }
}

/// The storage-side transformer: encrypts values on their way into the store
/// and decrypts them on their way out, per resource, from the storage key.
#[derive(Default)]
pub struct EncryptionTransformer {
    /// resource (`secrets`) -> its chain; `*` = every resource.
    resources: HashMap<String, Arc<Chain>>,
    all: Option<Arc<Chain>>,
}

impl EncryptionTransformer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_file(path: &str) -> Result<Self> {
        Self::from_config(EncryptionConfig::from_file(path)?)
    }

    pub fn from_config(config: EncryptionConfig) -> Result<Self> {
        let mut t = Self::new();
        for (i, rc) in config.resources.iter().enumerate() {
            if rc.providers.is_empty() {
                bail!("resources[{i}]: no providers");
            }
            let mut providers: Vec<Arc<dyn EncryptionProvider>> = Vec::new();
            for (j, p) in rc.providers.iter().enumerate() {
                let set = [
                    p.aesgcm.is_some(),
                    p.aescbc.is_some(),
                    p.secretbox.is_some(),
                    p.kms.is_some(),
                    p.identity.is_some(),
                ]
                .iter()
                .filter(|x| **x)
                .count();
                if set != 1 {
                    bail!("resources[{i}].providers[{j}]: exactly one provider per entry");
                }
                if let Some(k) = &p.aesgcm {
                    if k.keys.is_empty() {
                        bail!("resources[{i}].providers[{j}]: aesgcm without keys");
                    }
                    for kc in &k.keys {
                        let pr = AesGcmProvider::from_base64(&kc.secret, kc.name.clone())?;
                        if providers.iter().any(|x| x.prefix() == pr.prefix()) {
                            bail!("aesgcm key name {:?} twice", kc.name);
                        }
                        providers.push(Arc::new(pr));
                    }
                } else if p.identity.is_some() {
                    providers.push(Arc::new(IdentityProvider));
                } else {
                    let which = if p.aescbc.is_some() {
                        "aescbc"
                    } else if p.secretbox.is_some() {
                        "secretbox"
                    } else {
                        "kms"
                    };
                    bail!("resources[{i}].providers[{j}]: the {which} provider is not implemented (use aesgcm); refusing rather than storing plaintext");
                }
            }
            let chain = Arc::new(Chain { providers });
            for r in &rc.resources {
                if r == "*.*" {
                    t.all.get_or_insert_with(|| chain.clone());
                    continue;
                }
                if r.starts_with('*') {
                    bail!("resources[{i}]: {r:?}: only exact resources and \"*.*\" are supported");
                }
                // `deployments.apps` -> `deployments` (storage keys carry no group).
                let name = r.split('.').next().unwrap_or(r).to_string();
                // The first entry naming a resource wins (as in Kubernetes).
                t.resources.entry(name).or_insert_with(|| chain.clone());
            }
        }
        info!(
            "Encryption at rest: {} resource(s){}: {}",
            t.resources.len(),
            if t.all.is_some() { " + every other" } else { "" },
            t.resources
                .iter()
                .map(|(r, c)| format!("{r} writes with {}", c.write().name()))
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok(t)
    }

    /// The resource of a storage key: `/registry/secrets/ns/name` -> `secrets`.
    pub fn resource_of_key(key: &str) -> Option<&str> {
        key.strip_prefix("/registry/")?.split('/').next().filter(|r| !r.is_empty())
    }

    fn chain(&self, key: &str) -> Option<&Arc<Chain>> {
        let r = Self::resource_of_key(key)?;
        self.resources.get(r).or(self.all.as_ref())
    }

    /// Is the value at `key` transformed at all?
    pub fn applies(&self, key: &str) -> bool {
        self.chain(key).is_some()
    }

    /// The bytes to store for `data` at `key`.
    pub fn encode(&self, key: &str, data: &[u8]) -> Result<Vec<u8>> {
        match self.chain(key) {
            Some(c) => c.write().encrypt(key, data),
            None => Ok(data.to_vec()),
        }
    }

    /// The plaintext of the bytes stored at `key`.
    pub fn decode(&self, key: &str, stored: &[u8]) -> Result<Vec<u8>> {
        match self.chain(key) {
            Some(c) => c.reader(key, stored)?.decrypt(key, stored),
            None => Ok(stored.to_vec()),
        }
    }

    /// The plaintext, or `None` when `key` is not transformed (the stored
    /// bytes are the plaintext).
    pub fn decode_if(&self, key: &str, stored: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.chain(key) {
            Some(c) => c.reader(key, stored)?.decrypt(key, stored).map(Some),
            None => Ok(None),
        }
    }

    /// Was `stored` written by the provider that writes now (nothing to
    /// rewrite after a rotation)?
    pub fn is_current(&self, key: &str, stored: &[u8]) -> bool {
        match self.chain(key) {
            Some(c) => {
                let w = c.write();
                if w.prefix().is_empty() {
                    !stored.starts_with(ENCRYPTED_PREFIX)
                } else {
                    stored.starts_with(w.prefix())
                }
            }
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: &str = "/registry/secrets/default/db";

    fn t(cfg: &str) -> EncryptionTransformer {
        EncryptionTransformer::from_config(EncryptionConfig::parse(cfg).unwrap()).unwrap()
    }

    fn b64(k: &[u8; 32]) -> String {
        general_purpose::STANDARD.encode(k)
    }

    fn cfg(keys: &[(&str, [u8; 32])], identity: bool) -> String {
        let mut y = String::from("apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: [secrets]\n  providers:\n  - aesgcm:\n      keys:\n");
        for (n, k) in keys {
            y.push_str(&format!("      - name: {n}\n        secret: {}\n", b64(k)));
        }
        if identity {
            y.push_str("  - identity: {}\n");
        }
        y
    }

    #[test]
    fn a_secret_is_stored_as_aesgcm_ciphertext_and_reads_back() {
        let k1 = AesGcmProvider::generate_key();
        let tr = t(&cfg(&[("k1", k1)], true));
        let plain = br#"{"kind":"Secret","data":{"password":"aHVudGVyMg=="}}"#;
        let stored = tr.encode(S, plain).unwrap();
        assert!(stored.starts_with(b"k8s:enc:aesgcm:v1:k1:"), "{:?}", String::from_utf8_lossy(&stored));
        assert!(!stored.windows(8).any(|w| w == b"aHVudGVy"), "the plaintext shows");
        assert_eq!(stored.len(), b"k8s:enc:aesgcm:v1:k1:".len() + 12 + plain.len() + 16);
        assert_eq!(tr.decode(S, &stored).unwrap(), plain);
        // A fresh nonce per write.
        assert_ne!(tr.encode(S, plain).unwrap(), stored);
        // Other resources pass through.
        assert_eq!(tr.encode("/registry/pods/default/p", b"{}").unwrap(), b"{}");
        assert_eq!(tr.decode("/registry/configmaps/default/c", b"{}").unwrap(), b"{}");
        assert!(tr.applies(S) && !tr.applies("/registry/pods/default/p"));
    }

    #[test]
    fn the_value_is_bound_to_its_key() {
        let tr = t(&cfg(&[("k1", AesGcmProvider::generate_key())], true));
        let stored = tr.encode(S, b"{}").unwrap();
        let e = tr.decode("/registry/secrets/default/other", &stored).unwrap_err();
        assert!(e.to_string().contains("does not open"), "{e}");
        let mut flipped = stored.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(tr.decode(S, &flipped).is_err());
    }

    #[test]
    fn plaintext_written_before_encryption_reads_only_with_identity_listed() {
        let k1 = AesGcmProvider::generate_key();
        let with = t(&cfg(&[("k1", k1)], true));
        assert_eq!(with.decode(S, br#"{"old":1}"#).unwrap(), br#"{"old":1}"#);
        assert!(!with.is_current(S, br#"{"old":1}"#), "plaintext is to be rewritten");
        let without = t(&cfg(&[("k1", k1)], false));
        let e = without.decode(S, br#"{"old":1}"#).unwrap_err();
        assert!(e.to_string().contains("identity"), "{e}");
    }

    #[test]
    fn rotation_new_key_second_then_first_then_old_dropped() {
        let (k1, k2) = (AesGcmProvider::generate_key(), AesGcmProvider::generate_key());
        let old = t(&cfg(&[("k1", k1)], true));
        let v1 = old.encode(S, b"{\"v\":1}").unwrap();
        // 1. k2 added second: still writes k1, reads both.
        let step1 = t(&cfg(&[("k1", k1), ("k2", k2)], true));
        assert!(step1.encode(S, b"{}").unwrap().starts_with(b"k8s:enc:aesgcm:v1:k1:"));
        // 2. k2 first: writes k2, reads k1's values; k1's are not current.
        let step2 = t(&cfg(&[("k2", k2), ("k1", k1)], true));
        assert_eq!(step2.decode(S, &v1).unwrap(), b"{\"v\":1}");
        assert!(!step2.is_current(S, &v1));
        // 3. The rewrite: read, write again.
        let v2 = step2.encode(S, &step2.decode(S, &v1).unwrap()).unwrap();
        assert!(v2.starts_with(b"k8s:enc:aesgcm:v1:k2:") && step2.is_current(S, &v2));
        // 4. k1 dropped: the rewritten value reads, one left behind does not.
        let step4 = t(&cfg(&[("k2", k2)], true));
        assert_eq!(step4.decode(S, &v2).unwrap(), b"{\"v\":1}");
        let e = step4.decode(S, &v1).unwrap_err();
        assert!(e.to_string().contains("k8s:enc:aesgcm:v1:k1:"), "{e}");
    }

    #[test]
    fn decrypting_again_identity_first_reads_ciphertext_writes_plaintext() {
        let k1 = AesGcmProvider::generate_key();
        let on = t(&cfg(&[("k1", k1)], true));
        let v = on.encode(S, b"{}").unwrap();
        let off = t(&format!(
            "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: [secrets]\n  providers:\n  - identity: {{}}\n  - aesgcm:\n      keys:\n      - name: k1\n        secret: {}\n",
            b64(&k1)
        ));
        assert_eq!(off.decode(S, &v).unwrap(), b"{}");
        assert_eq!(off.encode(S, b"{}").unwrap(), b"{}");
        assert!(!off.is_current(S, &v));
    }

    #[test]
    fn unimplemented_providers_and_bad_keys_are_refused() {
        let head = "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: [secrets]\n  providers:\n";
        for p in [
            "  - secretbox:\n      keys:\n      - name: a\n        secret: AAAA\n",
            "  - aescbc:\n      keys:\n      - name: a\n        secret: AAAA\n",
            "  - kms:\n      name: x\n      endpoint: unix:///x\n",
            "  - aesgcm:\n      keys:\n      - name: a\n        secret: c2hvcnQ=\n",
            "  - aesgcm:\n      keys: []\n",
        ] {
            let c = EncryptionConfig::parse(&format!("{head}{p}")).unwrap();
            assert!(EncryptionTransformer::from_config(c).is_err(), "accepted: {p}");
        }
        assert!(EncryptionConfig::parse("apiVersion: v1\nkind: ConfigMap\nresources: []\n").is_err());
    }

    #[test]
    fn group_suffix_and_every_resource() {
        let k = b64(&AesGcmProvider::generate_key());
        let tr = t(&format!("apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: [configmaps, deployments.apps]\n  providers:\n  - aesgcm:\n      keys:\n      - name: a\n        secret: {k}\n  - identity: {{}}\n"));
        assert!(tr.applies("/registry/configmaps/kube-system/x"));
        assert!(tr.applies("/registry/deployments/default/d"));
        assert!(!tr.applies(S));
        let all = t(&format!("apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n- resources: ['*.*']\n  providers:\n  - aesgcm:\n      keys:\n      - name: a\n        secret: {k}\n  - identity: {{}}\n"));
        assert!(all.applies(S) && all.applies("/registry/pods/a/b"));
        assert!(!all.applies("/rusternetes/leader/control-plane"), "not a resource key");
    }

    #[test]
    fn the_builder_writes_a_config_kubernetes_reads() {
        let k = AesGcmProvider::generate_key();
        let c = EncryptionConfig::aesgcm(&["secrets"], &[("k1", &k)]);
        let y = serde_yaml::to_string(&c).unwrap();
        assert!(y.contains("aesgcm:") && y.contains("identity: {}"), "{y}");
        let tr = EncryptionTransformer::from_config(EncryptionConfig::parse(&y).unwrap()).unwrap();
        assert!(tr.encode(S, b"{}").unwrap().starts_with(b"k8s:enc:aesgcm:v1:k1:"));
    }
}
