use anyhow::Result;
use aws_sdk_sqs::types::QueueAttributeName;
use colored::Colorize;
use petgraph::dot::{Config as DotConfig, Dot};
use petgraph::graph::{Graph, NodeIndex};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

/// A node in the trust graph.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize)]
pub enum Principal {
    Account(String),
    User(String),
    Role(String),
    Federated(String),
    Service(String),
    Wildcard,
    CanonicalUser(String),
}

impl Principal {
    pub fn label(&self) -> String {
        match self {
            Principal::Account(s) => format!("Account:{}", s),
            Principal::User(s) => format!("User:{}", s),
            Principal::Role(s) => format!("Role:{}", s),
            Principal::Federated(s) => format!("Federated:{}", s),
            Principal::Service(s) => format!("Service:{}", s),
            Principal::Wildcard => "Wildcard:*".to_string(),
            Principal::CanonicalUser(s) => format!("CanonicalUser:{}", s),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Principal::Account(_) => "Account",
            Principal::User(_) => "User",
            Principal::Role(_) => "Role",
            Principal::Federated(_) => "Federated",
            Principal::Service(_) => "Service",
            Principal::Wildcard => "Wildcard",
            Principal::CanonicalUser(_) => "CanonicalUser",
        }
    }

    pub fn id(&self) -> String {
        match self {
            Principal::Account(s)
            | Principal::User(s)
            | Principal::Role(s)
            | Principal::Federated(s)
            | Principal::Service(s)
            | Principal::CanonicalUser(s) => s.clone(),
            Principal::Wildcard => "*".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum EdgeKind {
    CanAssume,
    IsTrustedBy(String /* resource arn */),
}

impl EdgeKind {
    pub fn label(&self) -> String {
        match self {
            EdgeKind::CanAssume => "CanAssume".to_string(),
            EdgeKind::IsTrustedBy(arn) => format!("IsTrustedBy({})", arn),
        }
    }
}

/// Decode a percent-encoded string (e.g. `assume_role_policy_document`).
fn decode_policy(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"),
                16,
            ) {
                out.push(b as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn as_string_vec(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

/// Classify a (kind, value) pair into a Principal node.
fn principal_from_raw(kind: &str, value: &str) -> Principal {
    let v = value.trim().to_string();
    if v == "*" {
        return Principal::Wildcard;
    }
    match kind {
        "Service" => Principal::Service(v),
        "Federated" => Principal::Federated(v),
        "CanonicalUser" => Principal::CanonicalUser(v),
        "AWS" | "" => {
            if v.starts_with("arn:aws:iam::") && v.ends_with(":root") {
                // arn:aws:iam::123456789012:root → account
                let parts: Vec<&str> = v.split(':').collect();
                let acct = parts.get(4).map(|s| s.to_string()).unwrap_or(v.clone());
                Principal::Account(acct)
            } else if v.contains(":user/") {
                Principal::User(v)
            } else if v.contains(":role/") {
                Principal::Role(v)
            } else if v.chars().all(|c| c.is_ascii_digit()) && v.len() == 12 {
                Principal::Account(v)
            } else {
                // Best effort — treat unknown AWS principal as a "User"-style node.
                Principal::User(v)
            }
        }
        _ => Principal::User(v),
    }
}

/// Extract list of (kind, raw_value) Principal entries from a Statement.
fn collect_principal_entries(stmt: &Value) -> Vec<(String, String)> {
    if stmt
        .get("Effect")
        .and_then(|v| v.as_str())
        .unwrap_or("Allow")
        != "Allow"
    {
        return Vec::new();
    }

    let principal = match stmt.get("Principal") {
        Some(p) => p.clone(),
        None => return Vec::new(),
    };

    let mut entries: Vec<(String, String)> = Vec::new();
    match &principal {
        Value::String(s) => entries.push(("AWS".to_string(), s.clone())),
        Value::Object(map) => {
            for (k, v) in map.iter() {
                for raw in as_string_vec(v) {
                    entries.push((k.clone(), raw));
                }
            }
        }
        _ => {}
    }
    entries
}

/// Insert a Principal node into the graph; dedupe via the HashMap index.
fn get_or_insert(
    graph: &mut Graph<Principal, EdgeKind>,
    index: &mut HashMap<Principal, NodeIndex>,
    p: Principal,
) -> NodeIndex {
    if let Some(idx) = index.get(&p) {
        return *idx;
    }
    let idx = graph.add_node(p.clone());
    index.insert(p, idx);
    idx
}

/// Walk a policy document JSON string and return all (kind, raw) principal entries.
fn principals_in_policy(json_str: &str) -> Vec<(String, String)> {
    let value: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<(String, String)> = Vec::new();
    match value.get("Statement") {
        Some(Value::Array(stmts)) => {
            for s in stmts {
                out.extend(collect_principal_entries(s));
            }
        }
        Some(Value::Object(_)) => {
            out.extend(collect_principal_entries(value.get("Statement").unwrap()));
        }
        _ => {}
    }
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Build the full trust graph from IAM + resource policies. Errors are downgraded
/// to eprintln warnings — never panic on a single API failure.
pub async fn build_graph(factory: &ClientFactory) -> Graph<Principal, EdgeKind> {
    let mut graph: Graph<Principal, EdgeKind> = Graph::new();
    let mut index: HashMap<Principal, NodeIndex> = HashMap::new();

    // ---------- IAM roles: AssumeRolePolicyDocument ----------
    let iam = factory.iam();
    let mut paginator = iam.list_roles().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} list_roles failed: {}", "[-]".yellow(), e);
                break;
            }
        };
        for role in page.roles() {
            let role_arn = role.arn().to_string();
            let raw = match role.assume_role_policy_document() {
                Some(s) => s.to_string(),
                None => continue,
            };
            let decoded = decode_policy(&raw);
            let json_str = if decoded.trim_start().starts_with('{') {
                decoded
            } else {
                raw
            };

            let role_node =
                get_or_insert(&mut graph, &mut index, Principal::Role(role_arn.clone()));

            for (kind, raw_val) in principals_in_policy(&json_str) {
                let p = principal_from_raw(&kind, &raw_val);
                let p_node = get_or_insert(&mut graph, &mut index, p);
                graph.add_edge(p_node, role_node, EdgeKind::CanAssume);
            }
        }
    }

    // ---------- S3 bucket policies (global) ----------
    let s3 = factory.s3();
    match s3.list_buckets().send().await {
        Ok(resp) => {
            for bucket in resp.buckets() {
                let name = match bucket.name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let arn = format!("arn:aws:s3:::{}", name);
                match s3.get_bucket_policy().bucket(&name).send().await {
                    Ok(p) => {
                        if let Some(policy) = p.policy() {
                            let resource_node = get_or_insert(
                                &mut graph,
                                &mut index,
                                Principal::Account(arn.clone()),
                            );
                            for (kind, raw_val) in principals_in_policy(policy) {
                                let pp = principal_from_raw(&kind, &raw_val);
                                let pn = get_or_insert(&mut graph, &mut index, pp);
                                graph.add_edge(
                                    pn,
                                    resource_node,
                                    EdgeKind::IsTrustedBy(arn.clone()),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        let s = e.to_string();
                        if !s.contains("NoSuchBucketPolicy") && !s.contains("AccessDenied") {
                            eprintln!(
                                "{} s3 get_bucket_policy({}): {}",
                                "[-]".yellow(),
                                name,
                                s
                            );
                        }
                    }
                }
            }
        }
        Err(e) => eprintln!("{} s3 list_buckets failed: {}", "[-]".yellow(), e),
    }

    // ---------- Per-region: SNS / SQS / Lambda / Secrets ----------
    for region in &factory.regions {
        // SNS
        let sns = factory.sns(region);
        let mut sns_paginator = sns.list_topics().into_paginator().send();
        while let Some(page) = sns_paginator.next().await {
            let page = match page {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{} sns list_topics({}): {}", "[-]".yellow(), region, e);
                    break;
                }
            };
            for topic in page.topics() {
                let arn = match topic.topic_arn() {
                    Some(a) => a.to_string(),
                    None => continue,
                };
                match sns.get_topic_attributes().topic_arn(&arn).send().await {
                    Ok(resp) => {
                        if let Some(attrs) = resp.attributes() {
                            if let Some(policy) = attrs.get("Policy") {
                                let resource_node = get_or_insert(
                                    &mut graph,
                                    &mut index,
                                    Principal::Account(arn.clone()),
                                );
                                for (kind, raw_val) in principals_in_policy(policy) {
                                    let pp = principal_from_raw(&kind, &raw_val);
                                    let pn = get_or_insert(&mut graph, &mut index, pp);
                                    graph.add_edge(
                                        pn,
                                        resource_node,
                                        EdgeKind::IsTrustedBy(arn.clone()),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!(
                        "{} sns get_topic_attributes({}): {}",
                        "[-]".yellow(),
                        arn,
                        e
                    ),
                }
            }
        }

        // SQS
        let sqs = factory.sqs(region);
        let mut sqs_paginator = sqs.list_queues().into_paginator().send();
        while let Some(page) = sqs_paginator.next().await {
            let page = match page {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{} sqs list_queues({}): {}", "[-]".yellow(), region, e);
                    break;
                }
            };
            for url in page.queue_urls() {
                let arn = url.to_string();
                match sqs
                    .get_queue_attributes()
                    .queue_url(url)
                    .attribute_names(QueueAttributeName::Policy)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if let Some(attrs) = resp.attributes() {
                            if let Some(policy) = attrs.get(&QueueAttributeName::Policy) {
                                let resource_node = get_or_insert(
                                    &mut graph,
                                    &mut index,
                                    Principal::Account(arn.clone()),
                                );
                                for (kind, raw_val) in principals_in_policy(policy) {
                                    let pp = principal_from_raw(&kind, &raw_val);
                                    let pn = get_or_insert(&mut graph, &mut index, pp);
                                    graph.add_edge(
                                        pn,
                                        resource_node,
                                        EdgeKind::IsTrustedBy(arn.clone()),
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!(
                        "{} sqs get_queue_attributes({}): {}",
                        "[-]".yellow(),
                        arn,
                        e
                    ),
                }
            }
        }

        // Lambda
        let lambda = factory.lambda(region);
        let mut lambda_paginator = lambda.list_functions().into_paginator().send();
        while let Some(page) = lambda_paginator.next().await {
            let page = match page {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "{} lambda list_functions({}): {}",
                        "[-]".yellow(),
                        region,
                        e
                    );
                    break;
                }
            };
            for f in page.functions() {
                let name = match f.function_name() {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let arn = f
                    .function_arn()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| name.clone());
                match lambda.get_policy().function_name(&name).send().await {
                    Ok(p) => {
                        if let Some(policy) = p.policy() {
                            let resource_node = get_or_insert(
                                &mut graph,
                                &mut index,
                                Principal::Role(arn.clone()),
                            );
                            for (kind, raw_val) in principals_in_policy(policy) {
                                let pp = principal_from_raw(&kind, &raw_val);
                                let pn = get_or_insert(&mut graph, &mut index, pp);
                                graph.add_edge(
                                    pn,
                                    resource_node,
                                    EdgeKind::IsTrustedBy(arn.clone()),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        let s = e.to_string();
                        if s.contains("ResourceNotFound") {
                            continue;
                        }
                        eprintln!("{} lambda get_policy({}): {}", "[-]".yellow(), name, s);
                    }
                }
            }
        }

        // Secrets Manager
        let sm = factory.secretsmanager(region);
        let mut sm_paginator = sm.list_secrets().into_paginator().send();
        while let Some(page) = sm_paginator.next().await {
            let page = match page {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "{} secretsmanager list_secrets({}): {}",
                        "[-]".yellow(),
                        region,
                        e
                    );
                    break;
                }
            };
            for s in page.secret_list() {
                let id = match s.arn().or_else(|| s.name()) {
                    Some(v) => v.to_string(),
                    None => continue,
                };
                match sm.get_resource_policy().secret_id(&id).send().await {
                    Ok(p) => {
                        if let Some(policy) = p.resource_policy() {
                            let resource_node = get_or_insert(
                                &mut graph,
                                &mut index,
                                Principal::Account(id.clone()),
                            );
                            for (kind, raw_val) in principals_in_policy(policy) {
                                let pp = principal_from_raw(&kind, &raw_val);
                                let pn = get_or_insert(&mut graph, &mut index, pp);
                                graph.add_edge(
                                    pn,
                                    resource_node,
                                    EdgeKind::IsTrustedBy(id.clone()),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        let s_err = e.to_string();
                        if s_err.contains("ResourceNotFound") {
                            continue;
                        }
                        eprintln!(
                            "{} secretsmanager get_resource_policy({}): {}",
                            "[-]".yellow(),
                            id,
                            s_err
                        );
                    }
                }
            }
        }
    }

    graph
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[graph]".cyan().bold());

    // Caller account for the "external" count.
    let caller_account = match factory.sts().get_caller_identity().send().await {
        Ok(r) => r.account().unwrap_or_default().to_string(),
        Err(e) => {
            eprintln!("{} sts get_caller_identity failed: {}", "[-]".yellow(), e);
            String::new()
        }
    };

    let graph = build_graph(factory).await;

    // ---------- DOT output ----------
    let dot = Dot::with_config(&graph, &[DotConfig::EdgeNoLabel]);
    let mut dot_string = String::new();
    dot_string.push_str("digraph trust {\n");
    dot_string.push_str("  rankdir=LR;\n");
    dot_string.push_str("  node [shape=box, fontname=\"monospace\"];\n");
    for idx in graph.node_indices() {
        let p = &graph[idx];
        dot_string.push_str(&format!(
            "  n{} [label=\"{}\\n{}\"];\n",
            idx.index(),
            xml_escape(p.kind()),
            xml_escape(&p.id())
        ));
    }
    for e in graph.edge_indices() {
        if let Some((a, b)) = graph.edge_endpoints(e) {
            let kind = &graph[e];
            dot_string.push_str(&format!(
                "  n{} -> n{} [label=\"{}\"];\n",
                a.index(),
                b.index(),
                xml_escape(&kind.label())
            ));
        }
    }
    dot_string.push_str("}\n");
    // Also embed petgraph's native rendering as a comment for debug.
    dot_string.push_str(&format!("\n/* petgraph::Dot:\n{:?}\n*/\n", dot));
    output.loot_file("graph", "trust.dot", dot_string.as_bytes())?;

    // ---------- GraphML output ----------
    let mut gml = String::new();
    gml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    gml.push_str("<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n");
    gml.push_str("  <key id=\"kind\" for=\"node\" attr.name=\"kind\" attr.type=\"string\"/>\n");
    gml.push_str("  <key id=\"id\" for=\"node\" attr.name=\"id\" attr.type=\"string\"/>\n");
    gml.push_str("  <key id=\"label\" for=\"edge\" attr.name=\"label\" attr.type=\"string\"/>\n");
    gml.push_str("  <graph id=\"G\" edgedefault=\"directed\">\n");
    for idx in graph.node_indices() {
        let p = &graph[idx];
        gml.push_str(&format!(
            "    <node id=\"n{}\">\n      <data key=\"kind\">{}</data>\n      <data key=\"id\">{}</data>\n    </node>\n",
            idx.index(),
            xml_escape(p.kind()),
            xml_escape(&p.id())
        ));
    }
    for e in graph.edge_indices() {
        if let Some((a, b)) = graph.edge_endpoints(e) {
            let kind = &graph[e];
            gml.push_str(&format!(
                "    <edge source=\"n{}\" target=\"n{}\" label=\"{}\">\n      <data key=\"label\">{}</data>\n    </edge>\n",
                a.index(),
                b.index(),
                xml_escape(&kind.label()),
                xml_escape(&kind.label())
            ));
        }
    }
    gml.push_str("  </graph>\n</graphml>\n");
    output.loot_file("graph", "trust.graphml", gml.as_bytes())?;

    // ---------- JSON dump ----------
    let nodes_json: Vec<Value> = graph
        .node_indices()
        .map(|idx| {
            let p = &graph[idx];
            json!({
                "index": idx.index(),
                "kind": p.kind(),
                "id": p.id(),
            })
        })
        .collect();
    let edges_json: Vec<Value> = graph
        .edge_indices()
        .filter_map(|e| {
            graph.edge_endpoints(e).map(|(a, b)| {
                let k = &graph[e];
                let (kind, resource) = match k {
                    EdgeKind::CanAssume => ("CanAssume".to_string(), Value::Null),
                    EdgeKind::IsTrustedBy(arn) => {
                        ("IsTrustedBy".to_string(), Value::String(arn.clone()))
                    }
                };
                json!({
                    "source": a.index(),
                    "target": b.index(),
                    "kind": kind,
                    "resource": resource,
                })
            })
        })
        .collect();
    let dump = json!({
        "nodes": nodes_json,
        "edges": edges_json,
    });
    output.write_json("graph", &dump)?;

    // ---------- Summary stats ----------
    let node_count = graph.node_count();
    let edge_count = graph.edge_count();

    let mut roles_assumable_from_external_account: usize = 0;
    let mut wildcard_trusts: usize = 0;

    for idx in graph.node_indices() {
        if let Principal::Role(_) = graph[idx] {
            // inbound edges with EdgeKind::CanAssume
            for e in graph.edges_directed(idx, petgraph::Direction::Incoming) {
                if let EdgeKind::CanAssume = e.weight() {
                    let src = &graph[e.source()];
                    match src {
                        Principal::Wildcard => {
                            wildcard_trusts += 1;
                            roles_assumable_from_external_account += 1;
                        }
                        Principal::Account(acct) => {
                            if !caller_account.is_empty() && acct != &caller_account {
                                roles_assumable_from_external_account += 1;
                            }
                        }
                        Principal::User(arn) | Principal::Role(arn) => {
                            // Account in ARN slot 4
                            let parts: Vec<&str> = arn.split(':').collect();
                            if let Some(acct) = parts.get(4) {
                                if !caller_account.is_empty()
                                    && !acct.is_empty()
                                    && *acct != caller_account.as_str()
                                {
                                    roles_assumable_from_external_account += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    let headers = &[
        "NodeCount",
        "EdgeCount",
        "RolesAssumableFromExternalAccount",
        "WildcardTrusts",
    ];
    let table_rows = vec![vec![
        node_count.to_string(),
        edge_count.to_string(),
        roles_assumable_from_external_account.to_string(),
        wildcard_trusts.to_string(),
    ]];
    output.print_table(headers, &table_rows);
    output.write_table("graph-summary", headers, &table_rows)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}

// Pull in EdgeRef for `e.weight()` / `e.source()`.
use petgraph::visit::EdgeRef;
