//! R3: what a stock client-go sends with `ContentType:
//! application/vnd.kubernetes.protobuf` (ovn-kubernetes hardcodes it for
//! every typed client) must decode to the same object as its JSON.
//!
//! The fixtures under `tests/fixtures/protobuf/` are written by
//! `tests/fixtures/protobuf/pbgen/main.go` (k8s.io/api of ovn-kubernetes
//! v1.4.0's vendor tree, the protobuf serializer client-go uses): for each
//! object a `<name>.pb` request body and the `<name>.json` of the same
//! object.
use rusternetes_api_server::protobuf::ProtoRegistry;
use serde_json::Value;
use std::path::PathBuf;

fn fixture(name: &str) -> (Vec<u8>, Value) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/protobuf");
    let pb = std::fs::read(dir.join(format!("{name}.pb"))).unwrap();
    let json =
        serde_json::from_slice(&std::fs::read(dir.join(format!("{name}.json"))).unwrap()).unwrap();
    (pb, json)
}

/// Go's JSON leaves zero values out or writes them as null / {} / []:
/// compare what is set.
fn prune(v: Value) -> Option<Value> {
    match v {
        Value::Null => None,
        Value::Object(m) => {
            let m: serde_json::Map<String, Value> = m
                .into_iter()
                .filter_map(|(k, v)| prune(v).map(|v| (k, v)))
                .collect();
            (!m.is_empty()).then_some(Value::Object(m))
        }
        Value::Array(a) => {
            let a: Vec<Value> = a.into_iter().filter_map(prune).collect();
            (!a.is_empty()).then_some(Value::Array(a))
        }
        Value::String(s) if s.is_empty() => None,
        Value::Bool(false) => None,
        Value::Number(n) if n.as_f64() == Some(0.0) => None,
        v => Some(v),
    }
}

fn check(name: &str) {
    let (pb, want) = fixture(name);
    let got = ProtoRegistry::new()
        .decode_k8s_resource(&pb)
        .unwrap_or_else(|| panic!("{name}: the protobuf body did not decode"));
    let got: Value = serde_json::from_slice(&got).unwrap();
    let (got, want) = (prune(got), prune(want));
    assert_eq!(
        got,
        want,
        "{name}: decoded protobuf differs from the object's JSON\n got: {}\nwant: {}",
        serde_json::to_string_pretty(&got).unwrap(),
        serde_json::to_string_pretty(&want).unwrap()
    );
}

#[test]
fn a_node_written_in_protobuf_decodes_whole() {
    check("node");
}

#[test]
fn a_core_v1_event_written_in_protobuf_decodes_whole() {
    check("event-core");
}

#[test]
fn an_events_k8s_io_v1_event_written_in_protobuf_decodes_whole() {
    check("event-events");
}

#[test]
fn a_lease_written_in_protobuf_decodes_whole() {
    check("lease");
}

/// The decoded Node is one Rusternetes stores and reads back: no null where
/// its types want a string (the spike's undecodable /registry/nodes/cp).
#[test]
fn a_node_from_protobuf_round_trips_through_the_stored_type() {
    let (pb, _) = fixture("node");
    let got = ProtoRegistry::new().decode_k8s_resource(&pb).unwrap();
    let node: rusternetes_common::resources::Node = serde_json::from_slice(&got).unwrap();
    let stored = serde_json::to_vec(&node).unwrap();
    let _: rusternetes_common::resources::Node = serde_json::from_slice(&stored).unwrap();
}
