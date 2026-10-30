//! Table printers that match upstream kubectl (k8s.io/kubernetes
//! pkg/printers/internalversion and the CLI's tabwriter): the same columns,
//! the same wording and the same alignment (minimum width 6, padding 3, the
//! last column unpadded).
//!
//! The printers read the server's JSON as is ([`serde_json::Value`]), so a
//! field the typed structs do not know still prints.

use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A table to render: a header row and the rows, one cell per column.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// How a table is printed.
#[derive(Debug, Clone, Default)]
pub struct PrintOptions {
    pub wide: bool,
    pub show_labels: bool,
    /// Prefix a NAMESPACE column (`--all-namespaces`).
    pub with_namespace: bool,
}

/// The resources the printers know, by any of kubectl's names for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Pod,
    Deployment,
    Service,
    Endpoints,
    Node,
    Namespace,
    Event,
}

impl Kind {
    pub fn parse(resource: &str) -> Option<Self> {
        Some(match resource {
            "pod" | "pods" | "po" => Kind::Pod,
            "deployment" | "deployments" | "deploy" | "deployment.apps" | "deployments.apps" => {
                Kind::Deployment
            }
            "service" | "services" | "svc" => Kind::Service,
            "endpoints" | "endpoint" | "ep" => Kind::Endpoints,
            "node" | "nodes" | "no" => Kind::Node,
            "namespace" | "namespaces" | "ns" => Kind::Namespace,
            "event" | "events" | "ev" => Kind::Event,
            _ => return None,
        })
    }

    pub fn namespaced(self) -> bool {
        !matches!(self, Kind::Node | Kind::Namespace)
    }

    /// The collection's API path, in `namespace` (or across all namespaces
    /// when `None`, or cluster-scoped).
    pub fn list_path(self, namespace: Option<&str>) -> String {
        let (prefix, plural) = match self {
            Kind::Pod => ("/api/v1", "pods"),
            Kind::Deployment => ("/apis/apps/v1", "deployments"),
            Kind::Service => ("/api/v1", "services"),
            Kind::Endpoints => ("/api/v1", "endpoints"),
            Kind::Node => ("/api/v1", "nodes"),
            Kind::Namespace => ("/api/v1", "namespaces"),
            Kind::Event => ("/api/v1", "events"),
        };
        match namespace {
            Some(ns) if self.namespaced() => format!("{}/namespaces/{}/{}", prefix, ns, plural),
            _ => format!("{}/{}", prefix, plural),
        }
    }

    pub fn kind_name(self) -> &'static str {
        match self {
            Kind::Pod => "Pod",
            Kind::Deployment => "Deployment",
            Kind::Service => "Service",
            Kind::Endpoints => "Endpoints",
            Kind::Node => "Node",
            Kind::Namespace => "Namespace",
            Kind::Event => "Event",
        }
    }

    pub fn api_version(self) -> &'static str {
        match self {
            Kind::Deployment => "apps/v1",
            _ => "v1",
        }
    }

    fn headers(self, wide: bool) -> Vec<&'static str> {
        let mut h = match self {
            Kind::Pod => vec!["NAME", "READY", "STATUS", "RESTARTS", "AGE"],
            Kind::Deployment => vec!["NAME", "READY", "UP-TO-DATE", "AVAILABLE", "AGE"],
            Kind::Service => vec![
                "NAME",
                "TYPE",
                "CLUSTER-IP",
                "EXTERNAL-IP",
                "PORT(S)",
                "AGE",
            ],
            Kind::Endpoints => vec!["NAME", "ENDPOINTS", "AGE"],
            Kind::Node => vec!["NAME", "STATUS", "ROLES", "AGE", "VERSION"],
            Kind::Namespace => vec!["NAME", "STATUS", "AGE"],
            Kind::Event if wide => vec![
                "LAST SEEN",
                "TYPE",
                "REASON",
                "OBJECT",
                "SUBOBJECT",
                "SOURCE",
                "MESSAGE",
                "FIRST SEEN",
                "COUNT",
                "NAME",
            ],
            Kind::Event => vec!["LAST SEEN", "TYPE", "REASON", "OBJECT", "MESSAGE"],
        };
        if wide {
            match self {
                Kind::Pod => h.extend(["IP", "NODE", "NOMINATED NODE", "READINESS GATES"]),
                Kind::Deployment => h.extend(["CONTAINERS", "IMAGES", "SELECTOR"]),
                Kind::Service => h.push("SELECTOR"),
                Kind::Node => h.extend([
                    "INTERNAL-IP",
                    "EXTERNAL-IP",
                    "OS-IMAGE",
                    "KERNEL-VERSION",
                    "CONTAINER-RUNTIME",
                ]),
                _ => {}
            }
        }
        h
    }

    fn row(self, o: &Value, now: DateTime<Utc>, wide: bool) -> Vec<String> {
        match self {
            Kind::Pod => pod_row(o, now, wide),
            Kind::Deployment => deployment_row(o, now, wide),
            Kind::Service => service_row(o, now, wide),
            Kind::Endpoints => vec![name(o), format_endpoints(o), age(o, now)],
            Kind::Node => node_row(o, now, wide),
            Kind::Namespace => vec![name(o), s(o, "/status/phase"), age(o, now)],
            Kind::Event => event_row(o, now, wide),
        }
    }
}

/// The table for `items` of `kind`.
pub fn table(kind: Kind, items: &[Value], opts: &PrintOptions, now: DateTime<Utc>) -> Table {
    let mut headers: Vec<String> = kind
        .headers(opts.wide)
        .into_iter()
        .map(String::from)
        .collect();
    if opts.with_namespace {
        headers.insert(0, "NAMESPACE".into());
    }
    if opts.show_labels {
        headers.push("LABELS".into());
    }
    let rows = items
        .iter()
        .map(|o| {
            let mut r = kind.row(o, now, opts.wide);
            if opts.with_namespace {
                r.insert(0, s(o, "/metadata/namespace"));
            }
            if opts.show_labels {
                r.push(labels(o));
            }
            r
        })
        .collect();
    Table { headers, rows }
}

/// Render like Go's `text/tabwriter` as kubectl sets it up: each column is
/// as wide as its widest cell plus 3 spaces (at least 6); the last column is
/// not padded.
pub fn render(t: &Table, no_headers: bool) -> String {
    let mut lines: Vec<&Vec<String>> = Vec::new();
    if !no_headers {
        lines.push(&t.headers);
    }
    lines.extend(t.rows.iter());
    let cols = lines.iter().map(|l| l.len()).max().unwrap_or(0);
    let mut widths = vec![0usize; cols];
    for l in &lines {
        for (i, c) in l.iter().enumerate() {
            if i + 1 < l.len() {
                widths[i] = widths[i].max((c.chars().count() + 3).max(6));
            }
        }
    }
    let mut out = String::new();
    for l in lines {
        for (i, c) in l.iter().enumerate() {
            out.push_str(c);
            if i + 1 < l.len() {
                for _ in c.chars().count()..widths[i] {
                    out.push(' ');
                }
            }
        }
        out.push('\n');
    }
    out
}

/// What kubectl prints for an empty list (on stderr).
pub fn no_resources(kind: Kind, namespace: Option<&str>) -> String {
    match namespace {
        Some(ns) if kind.namespaced() => format!("No resources found in {} namespace.", ns),
        _ => "No resources found".to_string(),
    }
}

/// `deployment.apps`, `pod`, `ingress.networking.k8s.io`: the lowercase
/// kind with the API group, as kubectl names an object in its messages.
pub fn qualified_kind(kind: &str, api_version: &str) -> String {
    let kind = kind.to_lowercase();
    match api_version.split_once('/') {
        Some((group, _)) if !group.is_empty() => format!("{}.{}", kind, group),
        _ => kind,
    }
}

/// `deployment.apps/web`: `-o name`, and the subject of `created`,
/// `configured`, `scaled`.
pub fn object_ref(o: &Value) -> String {
    format!(
        "{}/{}",
        qualified_kind(
            o.get("kind").and_then(Value::as_str).unwrap_or(""),
            o.get("apiVersion").and_then(Value::as_str).unwrap_or("")
        ),
        name(o)
    )
}

/// `deployment.apps/web scaled` and the like.
pub fn action_line(qualified: &str, name: &str, verb: &str) -> String {
    format!("{}/{} {}", qualified, name, verb)
}

/// `deployment.apps "web" deleted`.
pub fn deleted_line(qualified: &str, name: &str) -> String {
    format!("{} \"{}\" deleted", qualified, name)
}

/// The `-o json` text: Go's `json.MarshalIndent(obj, "", "    ")`.
pub fn to_json(v: &Value) -> String {
    use serde::Serialize;
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    v.serialize(&mut ser).expect("a JSON value serializes");
    String::from_utf8(buf).expect("JSON is UTF-8")
}

/// The object kubectl prints for `-o json|yaml` of a list: a `v1` `List`,
/// each item with its kind and apiVersion.
pub fn list_object(kind: Kind, items: &[Value]) -> Value {
    let items: Vec<Value> = items
        .iter()
        .map(|o| {
            let mut o = o.clone();
            if let Some(m) = o.as_object_mut() {
                m.entry("kind").or_insert_with(|| kind.kind_name().into());
                m.entry("apiVersion")
                    .or_insert_with(|| kind.api_version().into());
            }
            o
        })
        .collect();
    serde_json::json!({
        "apiVersion": "v1",
        "items": items,
        "kind": "List",
        "metadata": { "resourceVersion": "" }
    })
}

/// Go's `duration.HumanDuration`: `45s`, `2m5s`, `12m`, `3h20m`, `2d4h`, `400d`, `3y20d`.
pub fn human_duration(d: chrono::Duration) -> String {
    let seconds = d.num_seconds();
    if seconds < -1 {
        return "<invalid>".into();
    } else if seconds < 0 {
        return "0s".into();
    } else if seconds < 60 * 2 {
        return format!("{}s", seconds);
    }
    let minutes = seconds / 60;
    if minutes < 10 {
        let s = seconds % 60;
        return if s == 0 {
            format!("{}m", minutes)
        } else {
            format!("{}m{}s", minutes, s)
        };
    } else if minutes < 60 * 3 {
        return format!("{}m", minutes);
    }
    let hours = minutes / 60;
    if hours < 8 {
        let m = minutes % 60;
        return if m == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h{}m", hours, m)
        };
    } else if hours < 48 {
        return format!("{}h", hours);
    } else if hours < 24 * 8 {
        let h = hours % 24;
        return if h == 0 {
            format!("{}d", hours / 24)
        } else {
            format!("{}d{}h", hours / 24, h)
        };
    } else if hours < 24 * 365 * 2 {
        return format!("{}d", hours / 24);
    } else if hours < 24 * 365 * 8 {
        let dy = (hours / 24) % 365;
        return if dy == 0 {
            format!("{}y", hours / 24 / 365)
        } else {
            format!("{}y{}d", hours / 24 / 365, dy)
        };
    }
    format!("{}y", hours / 24 / 365)
}

/// `translateTimestampSince`: `<unknown>` for a missing time.
fn since(ts: Option<&str>, now: DateTime<Utc>) -> String {
    match ts.and_then(|t| DateTime::parse_from_rfc3339(t).ok()) {
        Some(t) => human_duration(now.signed_duration_since(t.with_timezone(&Utc))),
        None => "<unknown>".into(),
    }
}

fn age(o: &Value, now: DateTime<Utc>) -> String {
    since(
        o.pointer("/metadata/creationTimestamp")
            .and_then(Value::as_str),
        now,
    )
}

fn name(o: &Value) -> String {
    s(o, "/metadata/name")
}

/// The string at `ptr`, or empty.
fn s(o: &Value, ptr: &str) -> String {
    o.pointer(ptr)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn int(o: &Value, ptr: &str) -> i64 {
    o.pointer(ptr).and_then(Value::as_i64).unwrap_or(0)
}

fn or_none(v: String) -> String {
    if v.is_empty() {
        "<none>".into()
    } else {
        v
    }
}

fn arr<'a>(o: &'a Value, ptr: &str) -> &'a [Value] {
    o.pointer(ptr)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// `a=1,b=2` (sorted), or `<none>`.
fn label_map(m: Option<&Value>) -> String {
    let m: BTreeMap<&str, &str> = m
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.as_str(), v.as_str().unwrap_or("")))
                .collect()
        })
        .unwrap_or_default();
    or_none(
        m.iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn labels(o: &Value) -> String {
    label_map(o.pointer("/metadata/labels"))
}

fn pod_row(o: &Value, now: DateTime<Utc>, wide: bool) -> Vec<String> {
    let containers = arr(o, "/spec/containers").len();
    let mut restarts = 0;
    let mut ready = 0;
    let mut last_restart: Option<DateTime<Utc>> = None;
    let mut reason = s(o, "/status/phase");
    if !s(o, "/status/reason").is_empty() {
        reason = s(o, "/status/reason");
    }
    let note_restart = |c: &Value, last: &mut Option<DateTime<Utc>>| {
        if let Some(t) = c
            .pointer("/lastState/terminated/finishedAt")
            .and_then(Value::as_str)
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        {
            let t = t.with_timezone(&Utc);
            if last.map_or(true, |l| t > l) {
                *last = Some(t);
            }
        }
    };
    let exit_reason = |c: &Value, prefix: &str| -> String {
        let t = &c["state"]["terminated"];
        let r = t["reason"].as_str().unwrap_or("");
        if !r.is_empty() {
            format!("{}{}", prefix, r)
        } else if t["signal"].as_i64().unwrap_or(0) != 0 {
            format!("{}Signal:{}", prefix, t["signal"])
        } else {
            format!("{}ExitCode:{}", prefix, t["exitCode"].as_i64().unwrap_or(0))
        }
    };

    let mut initializing = false;
    let inits = arr(o, "/status/initContainerStatuses");
    let init_specs = arr(o, "/spec/initContainers").len();
    for (i, c) in inits.iter().enumerate() {
        restarts += c["restartCount"].as_i64().unwrap_or(0);
        note_restart(c, &mut last_restart);
        let term = c.pointer("/state/terminated");
        let waiting = c
            .pointer("/state/waiting/reason")
            .and_then(Value::as_str)
            .unwrap_or("");
        if let Some(t) = term {
            if t["exitCode"].as_i64().unwrap_or(0) == 0 {
                continue;
            }
            reason = exit_reason(c, "Init:");
        } else if !waiting.is_empty() && waiting != "PodInitializing" {
            reason = format!("Init:{}", waiting);
        } else {
            reason = format!("Init:{}/{}", i, init_specs);
        }
        initializing = true;
        break;
    }
    if !initializing {
        restarts = 0;
        let mut has_running = false;
        for c in arr(o, "/status/containerStatuses").iter().rev() {
            restarts += c["restartCount"].as_i64().unwrap_or(0);
            note_restart(c, &mut last_restart);
            let waiting = c
                .pointer("/state/waiting/reason")
                .and_then(Value::as_str)
                .unwrap_or("");
            let term = c.pointer("/state/terminated");
            let term_reason = term.and_then(|t| t["reason"].as_str()).unwrap_or("");
            if !waiting.is_empty() {
                reason = waiting.to_string();
            } else if !term_reason.is_empty() {
                reason = term_reason.to_string();
            } else if term.is_some() {
                reason = exit_reason(c, "");
            } else if c["ready"].as_bool() == Some(true) && c.pointer("/state/running").is_some() {
                has_running = true;
                ready += 1;
            }
        }
        if reason == "Completed" && has_running {
            let pod_ready = arr(o, "/status/conditions")
                .iter()
                .any(|c| c["type"] == "Ready" && c["status"] == "True");
            reason = if pod_ready { "Running" } else { "NotReady" }.into();
        }
    }
    if o.pointer("/metadata/deletionTimestamp")
        .map_or(false, |v| !v.is_null())
    {
        reason = if s(o, "/status/reason") == "NodeLost" {
            "Unknown".into()
        } else {
            "Terminating".into()
        };
    }
    let restarts = match last_restart {
        Some(t) => format!(
            "{} ({} ago)",
            restarts,
            human_duration(now.signed_duration_since(t))
        ),
        None => restarts.to_string(),
    };
    let mut row = vec![
        name(o),
        format!("{}/{}", ready, containers),
        reason,
        restarts,
        age(o, now),
    ];
    if wide {
        let gates = arr(o, "/spec/readinessGates");
        let gates = if gates.is_empty() {
            "<none>".to_string()
        } else {
            let conds = arr(o, "/status/conditions");
            let true_gates = gates
                .iter()
                .filter(|g| {
                    conds
                        .iter()
                        .any(|c| c["type"] == g["conditionType"] && c["status"] == "True")
                })
                .count();
            format!("{}/{}", true_gates, gates.len())
        };
        row.extend([
            or_none(s(o, "/status/podIP")),
            or_none(s(o, "/spec/nodeName")),
            or_none(s(o, "/status/nominatedNodeName")),
            gates,
        ]);
    }
    row
}

fn deployment_row(o: &Value, now: DateTime<Utc>, wide: bool) -> Vec<String> {
    let desired = o
        .pointer("/spec/replicas")
        .and_then(Value::as_i64)
        .unwrap_or(1);
    let mut row = vec![
        name(o),
        format!("{}/{}", int(o, "/status/readyReplicas"), desired),
        int(o, "/status/updatedReplicas").to_string(),
        int(o, "/status/availableReplicas").to_string(),
        age(o, now),
    ];
    if wide {
        let cs = arr(o, "/spec/template/spec/containers");
        let join = |f: &str| {
            cs.iter()
                .map(|c| c[f].as_str().unwrap_or("").to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        row.extend([
            join("name"),
            join("image"),
            label_selector(o.pointer("/spec/selector")),
        ]);
    }
    row
}

/// `metav1.FormatLabelSelector`.
fn label_selector(sel: Option<&Value>) -> String {
    let Some(sel) = sel.filter(|v| !v.is_null()) else {
        return "<none>".into();
    };
    let mut parts: Vec<String> = sel
        .get("matchLabels")
        .and_then(Value::as_object)
        .map(|m| {
            let m: BTreeMap<_, _> = m.iter().collect();
            m.into_iter()
                .map(|(k, v)| format!("{}={}", k, v.as_str().unwrap_or("")))
                .collect()
        })
        .unwrap_or_default();
    for e in sel
        .get("matchExpressions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let key = e["key"].as_str().unwrap_or("");
        let values: Vec<&str> = e["values"]
            .as_array()
            .map(|v| v.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        parts.push(match e["operator"].as_str().unwrap_or("") {
            "In" => format!("{} in ({})", key, values.join(",")),
            "NotIn" => format!("{} notin ({})", key, values.join(",")),
            "Exists" => key.to_string(),
            "DoesNotExist" => format!("!{}", key),
            op => format!("{} {} ({})", key, op, values.join(",")),
        });
    }
    if parts.is_empty() {
        "<none>".into()
    } else {
        parts.join(",")
    }
}

fn service_row(o: &Value, now: DateTime<Utc>, wide: bool) -> Vec<String> {
    let typ = {
        let t = s(o, "/spec/type");
        if t.is_empty() {
            "ClusterIP".to_string()
        } else {
            t
        }
    };
    let external_ips: Vec<String> = arr(o, "/spec/externalIPs")
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let external = match typ.as_str() {
        "ClusterIP" | "NodePort" => or_none(external_ips.join(",")),
        "LoadBalancer" => {
            let mut ips: Vec<String> = arr(o, "/status/loadBalancer/ingress")
                .iter()
                .filter_map(|i| {
                    i["ip"]
                        .as_str()
                        .or_else(|| i["hostname"].as_str())
                        .map(String::from)
                })
                .collect();
            ips.extend(external_ips);
            if ips.is_empty() {
                "<pending>".into()
            } else {
                ips.join(",")
            }
        }
        "ExternalName" => s(o, "/spec/externalName"),
        _ => "<unknown>".into(),
    };
    let ports: Vec<String> = arr(o, "/spec/ports")
        .iter()
        .map(|p| {
            let proto = p["protocol"].as_str().unwrap_or("TCP");
            let port = p["port"].as_i64().unwrap_or(0);
            match p["nodePort"].as_i64().filter(|n| *n != 0) {
                Some(np) => format!("{}:{}/{}", port, np, proto),
                None => format!("{}/{}", port, proto),
            }
        })
        .collect();
    let mut row = vec![
        name(o),
        typ,
        or_none(s(o, "/spec/clusterIP")),
        external,
        or_none(ports.join(",")),
        age(o, now),
    ];
    if wide {
        row.push(label_map(o.pointer("/spec/selector")));
    }
    row
}

/// `formatEndpoints`: up to three `ip:port`, then ` + N more...`.
fn format_endpoints(o: &Value) -> String {
    let subsets = arr(o, "/subsets");
    if subsets.is_empty() {
        return "<none>".into();
    }
    const MAX: usize = 3;
    let mut list: Vec<String> = Vec::new();
    let mut more = false;
    let mut count = 0;
    for ss in subsets {
        let addrs = arr(ss, "/addresses");
        let ports = arr(ss, "/ports");
        let ip = |a: &Value| a["ip"].as_str().unwrap_or("").to_string();
        if ports.is_empty() {
            count += addrs.len();
            for a in addrs {
                if list.len() == MAX {
                    more = true;
                    break;
                }
                list.push(ip(a));
            }
        } else {
            for p in ports {
                count += addrs.len();
                for a in addrs {
                    if list.len() == MAX {
                        more = true;
                        break;
                    }
                    let port = p["port"].as_i64().unwrap_or(0);
                    let host = ip(a);
                    list.push(if host.contains(':') {
                        format!("[{}]:{}", host, port)
                    } else {
                        format!("{}:{}", host, port)
                    });
                }
            }
        }
    }
    let ret = list.join(",");
    if more {
        format!("{} + {} more...", ret, count - MAX)
    } else {
        ret
    }
}

fn node_row(o: &Value, now: DateTime<Utc>, wide: bool) -> Vec<String> {
    let mut status: Vec<String> = Vec::new();
    if let Some(c) = arr(o, "/status/conditions")
        .iter()
        .find(|c| c["type"] == "Ready")
    {
        status.push(
            if c["status"] == "True" {
                "Ready"
            } else {
                "NotReady"
            }
            .into(),
        );
    }
    if status.is_empty() {
        status.push("Unknown".into());
    }
    if o.pointer("/spec/unschedulable").and_then(Value::as_bool) == Some(true) {
        status.push("SchedulingDisabled".into());
    }
    let mut roles = BTreeSet::new();
    if let Some(m) = o.pointer("/metadata/labels").and_then(Value::as_object) {
        for (k, v) in m {
            if let Some(r) = k.strip_prefix("node-role.kubernetes.io/") {
                if !r.is_empty() {
                    roles.insert(r.to_string());
                }
            } else if k == "kubernetes.io/role" {
                if let Some(v) = v.as_str().filter(|v| !v.is_empty()) {
                    roles.insert(v.to_string());
                }
            }
        }
    }
    let mut row = vec![
        name(o),
        status.join(","),
        or_none(roles.into_iter().collect::<Vec<_>>().join(",")),
        age(o, now),
        s(o, "/status/nodeInfo/kubeletVersion"),
    ];
    if wide {
        let addr = |t: &str| {
            or_none(
                arr(o, "/status/addresses")
                    .iter()
                    .find(|a| a["type"] == t)
                    .and_then(|a| a["address"].as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        };
        let unknown = |v: String| {
            if v.is_empty() {
                "<unknown>".to_string()
            } else {
                v
            }
        };
        row.extend([
            addr("InternalIP"),
            addr("ExternalIP"),
            unknown(s(o, "/status/nodeInfo/osImage")),
            unknown(s(o, "/status/nodeInfo/kernelVersion")),
            unknown(s(o, "/status/nodeInfo/containerRuntimeVersion")),
        ]);
    }
    row
}

fn event_row(o: &Value, now: DateTime<Utc>, wide: bool) -> Vec<String> {
    let ts = |p: &str| {
        o.pointer(p)
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
    };
    let first = match ts("/firstTimestamp") {
        Some(t) => since(Some(t), now),
        None => since(ts("/eventTime"), now),
    };
    let mut last = match ts("/lastTimestamp") {
        Some(t) => since(Some(t), now),
        None => first.clone(),
    };
    let mut count = int(o, "/count");
    if o.get("series").map_or(false, |v| !v.is_null()) {
        last = since(ts("/series/lastObservedTime"), now);
        count = int(o, "/series/count");
    } else if count == 0 {
        count = 1;
    }
    let kind = s(o, "/involvedObject/kind").to_lowercase();
    let obj_name = s(o, "/involvedObject/name");
    let target = if obj_name.is_empty() {
        kind
    } else {
        format!("{}/{}", kind, obj_name)
    };
    let message = s(o, "/message").trim().to_string();
    if wide {
        let source = {
            let (component, host) = (s(o, "/source/component"), s(o, "/source/host"));
            let (component, host) = if component.is_empty() {
                (s(o, "/reportingController"), s(o, "/reportingInstance"))
            } else {
                (component, host)
            };
            if host.is_empty() {
                component
            } else {
                format!("{}, {}", component, host)
            }
        };
        vec![
            last,
            s(o, "/type"),
            s(o, "/reason"),
            target,
            s(o, "/involvedObject/fieldPath"),
            source,
            message,
            first,
            count.to_string(),
            name(o),
        ]
    } else {
        vec![last, s(o, "/type"), s(o, "/reason"), target, message]
    }
}

#[cfg(test)]
mod tests {
    //! Expected text is what upstream kubectl v1.34 prints for the same
    //! objects (columns, wording, tabwriter spacing).
    use super::*;
    use serde_json::json;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-30T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn print(kind: Kind, items: &[Value], wide: bool) -> String {
        let opts = PrintOptions {
            wide,
            ..Default::default()
        };
        render(&table(kind, items, &opts, now()), false)
    }

    fn pod(name: &str, created: &str, status: Value) -> Value {
        json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": "default", "creationTimestamp": created},
            "spec": {"containers": [{"name": "web", "image": "busybox"}], "nodeName": "worker"},
            "status": status
        })
    }

    fn running() -> Value {
        json!({"phase": "Running", "podIP": "10.244.2.7",
               "containerStatuses": [{"name": "web", "ready": true, "restartCount": 0,
                                       "state": {"running": {"startedAt": "2026-10-30T11:55:00Z"}}}]})
    }

    #[test]
    fn human_duration_matches_go() {
        let d = chrono::Duration::seconds;
        assert_eq!(human_duration(d(-5)), "<invalid>");
        assert_eq!(human_duration(d(-1)), "0s");
        assert_eq!(human_duration(d(0)), "0s");
        assert_eq!(human_duration(d(119)), "119s");
        assert_eq!(human_duration(d(120)), "2m");
        assert_eq!(human_duration(d(125)), "2m5s");
        assert_eq!(human_duration(d(600)), "10m");
        assert_eq!(human_duration(d(3 * 3600)), "3h");
        assert_eq!(human_duration(d(3 * 3600 + 20 * 60)), "3h20m");
        assert_eq!(human_duration(d(30 * 3600)), "30h");
        assert_eq!(human_duration(d(52 * 3600)), "2d4h");
        assert_eq!(human_duration(d(48 * 3600)), "2d");
        assert_eq!(human_duration(d(400 * 86400)), "400d");
        assert_eq!(human_duration(d((365 * 3 + 20) * 86400)), "3y20d");
        assert_eq!(human_duration(d(365 * 10 * 86400)), "10y");
    }

    #[test]
    fn pods_like_upstream() {
        let pods = [
            pod("web-7d9c8b6f5-x2k4p", "2026-10-30T11:55:00Z", running()),
            pod(
                "pending-pod",
                "2026-10-30T11:59:30Z",
                json!({"phase": "Pending", "containerStatuses": [{"name": "web", "ready": false,
                       "restartCount": 0, "state": {"waiting": {"reason": "ContainerCreating"}}}]}),
            ),
        ];
        assert_eq!(
            print(Kind::Pod, &pods, false),
            "NAME                  READY   STATUS              RESTARTS   AGE\n\
             web-7d9c8b6f5-x2k4p   1/1     Running             0          5m\n\
             pending-pod           0/1     ContainerCreating   0          30s\n"
        );
    }

    #[test]
    fn pods_wide_like_upstream() {
        let pods = [pod("web", "2026-10-30T11:00:00Z", running())];
        assert_eq!(
            print(Kind::Pod, &pods, true),
            "NAME   READY   STATUS    RESTARTS   AGE   IP           NODE     NOMINATED NODE   READINESS GATES\n\
             web    1/1     Running   0          60m   10.244.2.7   worker   <none>           <none>\n"
        );
    }

    #[test]
    fn pod_restarts_crashloop_completed_terminating() {
        let crash = pod(
            "crash",
            "2026-10-30T10:00:00Z",
            json!({"phase": "Running", "containerStatuses": [{"name": "web", "ready": false,
                "restartCount": 4, "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                "lastState": {"terminated": {"exitCode": 1, "finishedAt": "2026-10-30T11:58:00Z"}}}]}),
        );
        let done = pod(
            "done",
            "2026-10-30T10:00:00Z",
            json!({"phase": "Succeeded", "containerStatuses": [{"name": "web", "ready": false,
                "restartCount": 0, "state": {"terminated": {"exitCode": 0, "reason": "Completed"}}}]}),
        );
        let mut gone = pod("gone", "2026-10-30T10:00:00Z", running());
        gone["metadata"]["deletionTimestamp"] = json!("2026-10-30T11:59:59Z");
        let init = {
            let mut p = pod(
                "init",
                "2026-10-30T11:59:00Z",
                json!({"phase": "Pending", "initContainerStatuses": [{"name": "i", "ready": false,
                    "restartCount": 0, "state": {"running": {}}}]}),
            );
            p["spec"]["initContainers"] = json!([{"name": "i"}]);
            p
        };
        assert_eq!(
            print(Kind::Pod, &[crash, done, gone, init], false),
            "NAME    READY   STATUS             RESTARTS     AGE\n\
             crash   0/1     CrashLoopBackOff   4 (2m ago)   120m\n\
             done    0/1     Completed          0            120m\n\
             gone    1/1     Terminating        0            120m\n\
             init    0/1     Init:0/1           0            60s\n"
        );
    }

    #[test]
    fn deployments_like_upstream() {
        let d = json!({
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": "web", "creationTimestamp": "2026-10-30T11:58:00Z"},
            "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "web"}},
                     "template": {"spec": {"containers": [{"name": "httpd", "image": "busybox:1.36"}]}}},
            "status": {"replicas": 3, "readyReplicas": 2, "updatedReplicas": 3, "availableReplicas": 2}
        });
        assert_eq!(
            print(Kind::Deployment, std::slice::from_ref(&d), false),
            "NAME   READY   UP-TO-DATE   AVAILABLE   AGE\n\
             web    2/3     3            2           2m\n"
        );
        assert_eq!(
            print(Kind::Deployment, &[d], true),
            "NAME   READY   UP-TO-DATE   AVAILABLE   AGE   CONTAINERS   IMAGES         SELECTOR\n\
             web    2/3     3            2           2m    httpd        busybox:1.36   app=web\n"
        );
    }

    #[test]
    fn services_like_upstream() {
        let svcs = [
            json!({"metadata": {"name": "kubernetes", "creationTimestamp": "2026-10-29T12:00:00Z"},
                   "spec": {"type": "ClusterIP", "clusterIP": "10.96.0.1",
                            "ports": [{"port": 443, "protocol": "TCP"}]}}),
            json!({"metadata": {"name": "webnp", "creationTimestamp": "2026-10-30T11:00:00Z"},
                   "spec": {"type": "NodePort", "clusterIP": "10.96.12.4", "selector": {"app": "web"},
                            "ports": [{"port": 8080, "nodePort": 30080, "protocol": "TCP"}]}}),
            json!({"metadata": {"name": "lb", "creationTimestamp": "2026-10-30T11:00:00Z"},
                   "spec": {"type": "LoadBalancer", "clusterIP": "10.96.3.3",
                            "ports": [{"port": 80, "nodePort": 31000, "protocol": "TCP"},
                                      {"port": 53, "nodePort": 31001, "protocol": "UDP"}]}}),
            json!({"metadata": {"name": "headless", "creationTimestamp": "2026-10-30T11:00:00Z"},
                   "spec": {"clusterIP": "None"}}),
        ];
        assert_eq!(
            print(Kind::Service, &svcs, false),
            "NAME         TYPE           CLUSTER-IP   EXTERNAL-IP   PORT(S)                     AGE\n\
             kubernetes   ClusterIP      10.96.0.1    <none>        443/TCP                     24h\n\
             webnp        NodePort       10.96.12.4   <none>        8080:30080/TCP              60m\n\
             lb           LoadBalancer   10.96.3.3    <pending>     80:31000/TCP,53:31001/UDP   60m\n\
             headless     ClusterIP      None         <none>        <none>                      60m\n"
        );
        assert!(print(Kind::Service, &svcs[1..2], true).ends_with("60m   app=web\n"));
    }

    #[test]
    fn endpoints_like_upstream() {
        let ep = |subsets: Value| {
            json!({"metadata": {"name": "web", "creationTimestamp": "2026-10-30T11:59:00Z"},
                   "subsets": subsets})
        };
        let many = ep(
            json!([{"addresses": [{"ip": "10.244.1.5"}, {"ip": "10.244.2.3"},
                                            {"ip": "10.244.2.4"}, {"ip": "10.244.1.9"}],
                              "ports": [{"port": 8080, "protocol": "TCP"}]}]),
        );
        let two = ep(
            json!([{"addresses": [{"ip": "10.244.1.5"}, {"ip": "10.244.2.3"}],
                             "ports": [{"port": 8080}]}]),
        );
        let none = ep(json!(null));
        let more = "10.244.1.5:8080,10.244.2.3:8080,10.244.2.4:8080 + 1 more...";
        let w = more.len() + 3;
        assert_eq!(
            print(Kind::Endpoints, &[two, many, none], false),
            format!(
                "NAME   {:<w$}AGE\nweb    {:<w$}60s\nweb    {:<w$}60s\nweb    {:<w$}60s\n",
                "ENDPOINTS", "10.244.1.5:8080,10.244.2.3:8080", more, "<none>"
            )
        );
    }

    #[test]
    fn nodes_like_upstream() {
        let node = |name: &str, ready: &str, labels: Value| {
            json!({"metadata": {"name": name, "creationTimestamp": "2026-10-30T09:00:00Z",
                                "labels": labels},
                   "status": {"conditions": [{"type": "MemoryPressure", "status": "False"},
                                             {"type": "Ready", "status": ready}],
                              "addresses": [{"type": "InternalIP", "address": "10.77.0.1"}],
                              "nodeInfo": {"kubeletVersion": "v1.35.0", "osImage": "tunnr",
                                           "kernelVersion": "6.18.2", "containerRuntimeVersion": "youki://0.5"}}})
        };
        let cp = node(
            "cp",
            "True",
            json!({"node-role.kubernetes.io/control-plane": ""}),
        );
        let mut worker = node("worker", "False", json!({}));
        worker["spec"] = json!({"unschedulable": true});
        let nodes = [cp, worker];
        assert_eq!(
            print(Kind::Node, &nodes, false),
            "NAME     STATUS                        ROLES           AGE   VERSION\n\
             cp       Ready                         control-plane   3h    v1.35.0\n\
             worker   NotReady,SchedulingDisabled   <none>          3h    v1.35.0\n"
        );
        assert_eq!(
            print(Kind::Node, &nodes[..1], true),
            "NAME   STATUS   ROLES           AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE   KERNEL-VERSION   CONTAINER-RUNTIME\n\
             cp     Ready    control-plane   3h    v1.35.0   10.77.0.1     <none>        tunnr      6.18.2           youki://0.5\n"
        );
        let unknown = json!({"metadata": {"name": "x"}});
        assert_eq!(
            table(Kind::Node, &[unknown], &PrintOptions::default(), now()).rows[0][1],
            "Unknown"
        );
    }

    #[test]
    fn namespaces_like_upstream() {
        let ns = |n: &str| {
            json!({"metadata": {"name": n, "creationTimestamp": "2026-10-29T12:00:00Z"},
                                  "status": {"phase": "Active"}})
        };
        assert_eq!(
            print(Kind::Namespace, &[ns("default"), ns("kube-system")], false),
            "NAME          STATUS   AGE\n\
             default       Active   24h\n\
             kube-system   Active   24h\n"
        );
    }

    #[test]
    fn events_like_upstream() {
        let ev = json!({
            "metadata": {"name": "web.1873a", "namespace": "default"},
            "involvedObject": {"kind": "Pod", "name": "web", "fieldPath": "spec.containers{web}"},
            "reason": "Pulled", "type": "Normal", "message": "Container image \"busybox\" already present on machine\n",
            "source": {"component": "kubelet", "host": "worker"},
            "firstTimestamp": "2026-10-30T11:50:00Z", "lastTimestamp": "2026-10-30T11:58:00Z", "count": 3
        });
        let scheduled = json!({
            "metadata": {"name": "web.1873b"},
            "involvedObject": {"kind": "Pod", "name": "web"},
            "reason": "Scheduled", "type": "Normal", "message": "Successfully assigned default/web to worker",
            "eventTime": "2026-10-30T11:59:00.000000Z", "reportingController": "default-scheduler"
        });
        assert_eq!(
            print(Kind::Event, &[ev.clone(), scheduled], false),
            "LAST SEEN   TYPE     REASON      OBJECT    MESSAGE\n\
             2m          Normal   Pulled      pod/web   Container image \"busybox\" already present on machine\n\
             60s         Normal   Scheduled   pod/web   Successfully assigned default/web to worker\n"
        );
        assert_eq!(
            print(Kind::Event, &[ev], true),
            "LAST SEEN   TYPE     REASON   OBJECT    SUBOBJECT              SOURCE            MESSAGE                                                FIRST SEEN   COUNT   NAME\n\
             2m          Normal   Pulled   pod/web   spec.containers{web}   kubelet, worker   Container image \"busybox\" already present on machine   10m          3       web.1873a\n"
        );
    }

    #[test]
    fn namespace_and_labels_columns() {
        let mut p = pod("web", "2026-10-30T11:55:00Z", running());
        p["metadata"]["labels"] = json!({"app": "web", "tier": "front"});
        let opts = PrintOptions {
            with_namespace: true,
            show_labels: true,
            ..Default::default()
        };
        assert_eq!(
            render(&table(Kind::Pod, &[p], &opts, now()), false),
            "NAMESPACE   NAME   READY   STATUS    RESTARTS   AGE   LABELS\n\
             default     web    1/1     Running   0          5m    app=web,tier=front\n"
        );
    }

    #[test]
    fn no_headers_and_empty() {
        let p = pod("web", "2026-10-30T11:55:00Z", running());
        assert_eq!(
            render(
                &table(Kind::Pod, &[p], &PrintOptions::default(), now()),
                true
            ),
            "web   1/1   Running   0     5m\n"
        );
        assert_eq!(
            no_resources(Kind::Pod, Some("default")),
            "No resources found in default namespace."
        );
        assert_eq!(
            no_resources(Kind::Node, Some("default")),
            "No resources found"
        );
    }

    #[test]
    fn names_and_messages_like_upstream() {
        let d = json!({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "web"}});
        assert_eq!(object_ref(&d), "deployment.apps/web");
        let p = json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "web"}});
        assert_eq!(object_ref(&p), "pod/web");
        assert_eq!(
            qualified_kind("Ingress", "networking.k8s.io/v1"),
            "ingress.networking.k8s.io"
        );
        assert_eq!(
            action_line("deployment.apps", "web", "scaled"),
            "deployment.apps/web scaled"
        );
        assert_eq!(
            deleted_line("deployment.apps", "web"),
            "deployment.apps \"web\" deleted"
        );
        assert_eq!(deleted_line("pod", "web"), "pod \"web\" deleted");
    }

    #[test]
    fn json_and_list_like_upstream() {
        let p = json!({"metadata": {"name": "web"}});
        let list = list_object(Kind::Pod, &[p]);
        assert_eq!(
            to_json(&list),
            "{\n    \"apiVersion\": \"v1\",\n    \"items\": [\n        {\n            \"apiVersion\": \"v1\",\n            \"kind\": \"Pod\",\n            \"metadata\": {\n                \"name\": \"web\"\n            }\n        }\n    ],\n    \"kind\": \"List\",\n    \"metadata\": {\n        \"resourceVersion\": \"\"\n    }\n}"
        );
        assert_eq!(
            serde_yaml::to_string(&list).unwrap(),
            "apiVersion: v1\nitems:\n- apiVersion: v1\n  kind: Pod\n  metadata:\n    name: web\nkind: List\nmetadata:\n  resourceVersion: ''\n"
        );
    }
}
