//! Encryption at rest (`--encryption-provider-config`) in the two backends a
//! tunnr control plane runs: the embedded redb store and etcd (here a served
//! tunnr-etcd, as in the HA control plane). A Secret's stored bytes are
//! `k8s:enc:aesgcm:v1:<key>:` ciphertext; every read (get, list, watch) gives
//! the plaintext back; a Secret stored before encryption was on still reads,
//! and a rewrite encrypts it; a key rotation leaves no value the new key set
//! cannot read once everything is rewritten.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use rusternetes_common::encryption::{AesGcmProvider, EncryptionConfig, EncryptionTransformer};
use rusternetes_storage::etcd::EtcdStorage;
use rusternetes_storage::redb::RedbStorage;
use rusternetes_storage::{Storage, StorageBackend, WatchEvent};
use serde_json::json;

const CANARY: &str = "c2VjcmV0LWNhbmFyeS0xMjM0NQ=="; // base64 "secret-canary-12345"
const KEY: &str = "/registry/secrets/default/db";

fn secret(name: &str, value: &str) -> serde_json::Value {
    json!({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
        "metadata": {"name": name, "namespace": "default"}, "data": {"password": value}})
}

fn transformer(keys: &[(&str, &[u8; 32])]) -> Arc<EncryptionTransformer> {
    Arc::new(EncryptionTransformer::from_config(EncryptionConfig::aesgcm(&["secrets"], keys)).unwrap())
}

fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

async fn redb(name: &str) -> RedbStorage {
    let p = std::env::temp_dir().join(format!("rn-enc-{}-{name}.redb", std::process::id()));
    let _ = std::fs::remove_file(&p);
    RedbStorage::new(p.to_str().unwrap()).await.unwrap()
}

#[tokio::test]
async fn redb_a_secret_is_ciphertext_at_rest_and_plaintext_to_every_reader() {
    let mut s = redb("at-rest").await;
    s.set_encryption(transformer(&[("k1", &AesGcmProvider::generate_key())]));
    let mut w = s.watch("/registry/secrets/").await.unwrap();
    let made: serde_json::Value = s.create(KEY, &secret("db", CANARY)).await.unwrap();
    assert_eq!(made["data"]["password"], CANARY);
    let raw = s.store().get(KEY).unwrap().value;
    assert!(raw.starts_with(b"k8s:enc:aesgcm:v1:k1:"), "{:?}", String::from_utf8_lossy(&raw));
    assert!(!contains(&raw, CANARY), "the canary is in the stored bytes");
    let got: serde_json::Value = Storage::get(&s, KEY).await.unwrap();
    assert_eq!(got["data"]["password"], CANARY);
    assert_eq!(got["metadata"]["resourceVersion"], made["metadata"]["resourceVersion"]);
    let all: Vec<serde_json::Value> = Storage::list(&s, "/registry/secrets/").await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["data"]["password"], CANARY);
    match tokio::time::timeout(Duration::from_secs(2), w.next()).await.unwrap().unwrap().unwrap() {
        WatchEvent::Added(k, v) => {
            assert_eq!(k, KEY);
            assert!(v.contains(CANARY), "{v}");
        }
        other => panic!("{other:?}"),
    }
    // A Pod is stored as JSON, as before.
    let pod = json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "p", "namespace": "default"}});
    let _: serde_json::Value = s.create("/registry/pods/default/p", &pod).await.unwrap();
    assert!(s.store().get("/registry/pods/default/p").unwrap().value.starts_with(b"{"));
}

#[tokio::test]
async fn redb_a_plaintext_secret_from_before_reads_and_a_rewrite_encrypts_it() {
    let mut s = redb("migrate").await;
    // Written before encryption was turned on.
    s.store().create(KEY, secret("db", CANARY).to_string().as_bytes()).unwrap();
    let t = transformer(&[("k1", &AesGcmProvider::generate_key())]);
    s.set_encryption(t.clone());
    let old: serde_json::Value = Storage::get(&s, KEY).await.unwrap();
    assert_eq!(old["data"]["password"], CANARY);
    assert!(!t.is_current(KEY, &s.store().get(KEY).unwrap().value));
    // The rewrite (kubectl replace): the same object written again.
    let _: serde_json::Value = s.update(KEY, &old).await.unwrap();
    let raw = s.store().get(KEY).unwrap().value;
    assert!(raw.starts_with(b"k8s:enc:aesgcm:v1:k1:") && !contains(&raw, CANARY));
    assert!(t.is_current(KEY, &raw));
}

#[tokio::test]
async fn redb_rotation_add_second_then_first_rewrite_then_drop_the_old() {
    let (k1, k2) = (AesGcmProvider::generate_key(), AesGcmProvider::generate_key());
    let mut s = redb("rotate").await;
    s.set_encryption(transformer(&[("k1", &k1)]));
    let _: serde_json::Value = s.create(KEY, &secret("db", CANARY)).await.unwrap();
    s.set_encryption(transformer(&[("k1", &k1), ("k2", &k2)]));
    let v: serde_json::Value = Storage::get(&s, KEY).await.unwrap();
    s.set_encryption(transformer(&[("k2", &k2), ("k1", &k1)]));
    let _: serde_json::Value = s.update(KEY, &v).await.unwrap();
    assert!(s.store().get(KEY).unwrap().value.starts_with(b"k8s:enc:aesgcm:v1:k2:"));
    s.set_encryption(transformer(&[("k2", &k2)]));
    let v: serde_json::Value = Storage::get(&s, KEY).await.unwrap();
    assert_eq!(v["data"]["password"], CANARY);
    // Not rewritten = not readable once its key is gone: named, not garbage.
    s.store().put("/registry/secrets/default/left", &transformer(&[("k1", &k1)]).encode("/registry/secrets/default/left", b"{}").unwrap()).unwrap();
    let e = Storage::get::<serde_json::Value>(&s, "/registry/secrets/default/left").await.unwrap_err();
    assert!(e.to_string().contains("k8s:enc:aesgcm:v1:k1:"), "{e}");
}

#[tokio::test]
async fn backends_without_encryption_support_refuse_the_config() {
    let t = transformer(&[("k1", &AesGcmProvider::generate_key())]);
    assert!(StorageBackend::new_memory().with_encryption(t).is_err());
}

/// A served tunnr-etcd (plaintext, in-process), the HA control plane's road.
async fn served_as(name: &str) -> (String, tunnr_etcd::Store) {
    let p = std::env::temp_dir().join(format!("rn-enc-etcd-{}-{name}.redb", std::process::id()));
    let _ = std::fs::remove_file(&p);
    let store = tunnr_etcd::Store::open(p, tunnr_etcd::Options { fsync: false, ..tunnr_etcd::Options::main() }).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let opts = tunnr_etcd::server::ServeOptions { client_url: url.clone(), ..Default::default() };
    let s = store.clone();
    tokio::spawn(async move { tunnr_etcd::server::serve(s, l, opts, std::future::pending()).await.unwrap() });
    (url, store)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn etcd_a_secret_is_ciphertext_in_the_store_and_plaintext_to_every_reader() {
    let (url, store) = served_as("at-rest").await;
    let mut s = EtcdStorage::new(vec![url.clone()]).await.unwrap();
    s.set_encryption(transformer(&[("k1", &AesGcmProvider::generate_key())]));
    let mut w = s.watch("/registry/secrets/").await.unwrap();
    let made: serde_json::Value = s.create(KEY, &secret("db", CANARY)).await.unwrap();
    assert_eq!(made["data"]["password"], CANARY);
    let raw = store.get(KEY).unwrap().value;
    assert!(raw.starts_with(b"k8s:enc:aesgcm:v1:k1:") && !contains(&raw, CANARY), "{:?}", String::from_utf8_lossy(&raw));
    let mut got: serde_json::Value = Storage::get(&s, KEY).await.unwrap();
    assert_eq!(got["data"]["password"], CANARY);
    got["data"]["password"] = "bmV3".into();
    let _: serde_json::Value = s.update(KEY, &got).await.unwrap();
    let raw = store.get(KEY).unwrap().value;
    assert!(raw.starts_with(b"k8s:enc:aesgcm:v1:k1:") && !contains(&raw, "bmV3"));
    let all: Vec<serde_json::Value> = Storage::list(&s, "/registry/secrets/").await.unwrap();
    assert_eq!(all[0]["data"]["password"], "bmV3");
    let mut seen = Vec::new();
    for _ in 0..2 {
        match tokio::time::timeout(Duration::from_secs(3), w.next()).await.unwrap().unwrap().unwrap() {
            WatchEvent::Added(_, v) | WatchEvent::Modified(_, v) => seen.push(v),
            other => panic!("{other:?}"),
        }
    }
    assert!(seen[0].contains(CANARY) && seen[1].contains("bmV3"), "{seen:?}");
    s.delete(KEY).await.unwrap();
    match tokio::time::timeout(Duration::from_secs(3), w.next()).await.unwrap().unwrap().unwrap() {
        WatchEvent::Deleted(_, v) => assert!(v.contains("bmV3"), "{v}"),
        other => panic!("{other:?}"),
    }
    // A process without the config is told what it is reading, not handed garbage.
    let _: serde_json::Value = s.create(KEY, &secret("db", CANARY)).await.unwrap();
    let plain = EtcdStorage::new(vec![url]).await.unwrap();
    let e = Storage::get::<serde_json::Value>(&plain, KEY).await.unwrap_err();
    assert!(e.to_string().contains("--encryption-provider-config"), "{e}");
}

/// After `promote` (k2 first, k1 still read): the pass rewrites every Secret
/// not under k2 — k1 ones and plaintext from before — counts them, leaves the
/// rest alone, and a second pass (a restart, a resume) finds nothing to do.
async fn reencrypt_case(s: &StorageBackend, raw: &dyn Fn(&str) -> Vec<u8>, put_raw: &dyn Fn(&str, &[u8])) {
    let (k1, k2) = (AesGcmProvider::generate_key(), AesGcmProvider::generate_key());
    let old = transformer(&[("k1", &k1)]);
    for n in ["a", "b", "c"] {
        let k = format!("/registry/secrets/default/{n}");
        put_raw(&k, &old.encode(&k, secret(n, CANARY).to_string().as_bytes()).unwrap());
    }
    put_raw("/registry/secrets/default/legacy", secret("legacy", CANARY).to_string().as_bytes());
    put_raw("/registry/pods/default/p", b"{\"kind\":\"Pod\",\"metadata\":{\"name\":\"p\"}}");
    let new = transformer(&[("k2", &k2), ("k1", &k1)]);
    let s = s.clone_with_encryption(new.clone()).unwrap();
    let r = s.reencrypt().await.unwrap();
    assert_eq!((r.scanned, r.rewritten, r.conflicts), (4, 4, 0), "{r:?}");
    assert_eq!(r.write, "aesgcm:k2");
    assert_eq!(r.census_line(), "aesgcm:k2=4");
    for n in ["a", "b", "c", "legacy"] {
        let k = format!("/registry/secrets/default/{n}");
        let v = raw(&k);
        assert!(v.starts_with(b"k8s:enc:aesgcm:v1:k2:"), "{n}: {:?}", String::from_utf8_lossy(&v[..30.min(v.len())]));
        let got: serde_json::Value = Storage::get(&s, &k).await.unwrap();
        assert_eq!(got["data"]["password"], CANARY);
    }
    assert!(raw("/registry/pods/default/p").starts_with(b"{"), "a Pod is not touched");
    let again = s.reencrypt().await.unwrap();
    assert_eq!((again.scanned, again.rewritten), (4, 0), "idempotent: {again:?}");
    let cm = again.configmap("cp1", "2026-11-01T09:00:00Z");
    assert_eq!(cm["metadata"]["name"], "rusternetes-encryption-census");
    assert_eq!(cm["metadata"]["namespace"], "kube-system");
    assert_eq!(cm["data"]["write"], "aesgcm:k2");
    assert_eq!(cm["data"]["census"], "aesgcm:k2=4");
    assert_eq!(cm["data"]["by"], "cp1");
}

#[tokio::test]
async fn redb_reencrypt_after_promote_rewrites_all_not_under_the_first_key() {
    let s = redb("reenc").await;
    let store = s.store().clone();
    let b = StorageBackend::Redb(s);
    let st = store.clone();
    reencrypt_case(&b, &move |k| store.get(k).unwrap().value.to_vec(), &move |k, v| {
        st.put(k, v).unwrap();
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn etcd_reencrypt_after_promote_rewrites_all_not_under_the_first_key() {
    let (url, store) = served_as("reenc").await;
    let b = StorageBackend::Etcd(EtcdStorage::new(vec![url]).await.unwrap());
    let st = store.clone();
    reencrypt_case(&b, &move |k| store.get(k).unwrap().value.to_vec(), &move |k, v| {
        st.put(k, v).unwrap();
    })
    .await;
}
