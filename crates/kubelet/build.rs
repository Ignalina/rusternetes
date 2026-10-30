fn main() {
    // The youki (libcontainer) version linked, for the Node's
    // nodeInfo.containerRuntimeVersion (`youki://<version>`), from the
    // workspace lock.
    let lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    let v = std::fs::read_to_string(&lock)
        .ok()
        .and_then(|l| {
            let at = l.find("name = \"libcontainer\"\nversion = \"")?;
            let rest = &l[at + "name = \"libcontainer\"\nversion = \"".len()..];
            Some(rest[..rest.find('"')?].to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=RUSTERNETES_YOUKI_VERSION={v}");
    // CSI spec v1.13.0 (github.com/container-storage-interface/spec, Apache-2.0,
    // see proto/csi/LICENSE) and the kubelet plugin registration API v1
    // (k8s.io/kubelet pkg/apis/pluginregistration/v1, Apache-2.0).
    tonic_build::configure()
        .compile_protos(
            &["proto/csi/csi.proto", "proto/pluginregistration/api.proto"],
            &["proto/csi", "proto/pluginregistration"],
        )
        .expect("Failed to compile CSI protos");
}
