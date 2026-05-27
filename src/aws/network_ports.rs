use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct NetworkPortRow {
    pub region: String,
    pub security_group_id: String,
    pub direction: String,
    pub protocol: String,
    pub port_range: String,
    pub source: String,
    pub attached_instances: usize,
}

#[derive(Clone)]
struct RegionData {
    region: String,
    rows: Vec<NetworkPortRow>,
    public_endpoints: Vec<(String, String, String)>, // (public_ip, port_range, source)
}

fn port_range_str(from: Option<i32>, to: Option<i32>, protocol: &str) -> String {
    match (from, to) {
        (Some(-1), _) | (_, Some(-1)) => "all".to_string(),
        (Some(f), Some(t)) if f == t => f.to_string(),
        (Some(f), Some(t)) => format!("{}-{}", f, t),
        _ => {
            if protocol == "-1" {
                "all".to_string()
            } else {
                "".to_string()
            }
        }
    }
}

fn protocol_str(p: Option<&str>) -> String {
    match p {
        Some("-1") => "all".to_string(),
        Some(s) => s.to_string(),
        None => "".to_string(),
    }
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[network-ports]".cyan().bold());
    let regions = factory.regions.clone();
    let sem = Arc::new(Semaphore::new(concurrency));
    let factory = Arc::new(factory.clone());

    let mut handles = vec![];
    for region in &regions {
        let region = region.clone();
        let factory = Arc::clone(&factory);
        let sem = Arc::clone(&sem);
        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let client = factory.ec2(&region);

            // Map of sg_id -> instance count
            let mut sg_instance_count: HashMap<String, usize> = HashMap::new();
            // Map of sg_id -> Vec<public_ip>
            let mut sg_public_ips: HashMap<String, Vec<String>> = HashMap::new();

            // Pull instances to map SG -> attached instances and public IPs.
            let mut inst_paginator = client.describe_instances().into_paginator().send();
            while let Some(page) = inst_paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for reservation in page.reservations() {
                    for inst in reservation.instances() {
                        let public_ip = inst.public_ip_address().map(|s| s.to_string());
                        for sg in inst.security_groups() {
                            if let Some(id) = sg.group_id() {
                                *sg_instance_count.entry(id.to_string()).or_insert(0) += 1;
                                if let Some(ip) = &public_ip {
                                    sg_public_ips
                                        .entry(id.to_string())
                                        .or_default()
                                        .push(ip.clone());
                                }
                            }
                        }
                    }
                }
            }

            // Pull network interfaces too in case of ELB/NAT etc.
            let mut eni_paginator = client.describe_network_interfaces().into_paginator().send();
            while let Some(page) = eni_paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for eni in page.network_interfaces() {
                    let public_ip = eni
                        .association()
                        .and_then(|a| a.public_ip())
                        .map(|s| s.to_string());
                    if let Some(ip) = public_ip {
                        for sg in eni.groups() {
                            if let Some(id) = sg.group_id() {
                                sg_public_ips
                                    .entry(id.to_string())
                                    .or_default()
                                    .push(ip.clone());
                            }
                        }
                    }
                }
            }

            let mut rows: Vec<NetworkPortRow> = vec![];
            let mut public_endpoints: Vec<(String, String, String)> = vec![];

            let mut sg_paginator = client.describe_security_groups().into_paginator().send();
            while let Some(page) = sg_paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for sg in page.security_groups() {
                    let sg_id = sg.group_id().unwrap_or("").to_string();
                    let attached = sg_instance_count.get(&sg_id).copied().unwrap_or(0);

                    for perm in sg.ip_permissions() {
                        let proto = protocol_str(perm.ip_protocol());
                        let port_range = port_range_str(perm.from_port(), perm.to_port(), &proto);

                        let mut sources: Vec<String> = vec![];
                        for r in perm.ip_ranges() {
                            if let Some(c) = r.cidr_ip() {
                                sources.push(c.to_string());
                            }
                        }
                        for r in perm.ipv6_ranges() {
                            if let Some(c) = r.cidr_ipv6() {
                                sources.push(c.to_string());
                            }
                        }
                        for p in perm.prefix_list_ids() {
                            if let Some(id) = p.prefix_list_id() {
                                sources.push(format!("pl:{}", id));
                            }
                        }
                        for u in perm.user_id_group_pairs() {
                            if let Some(id) = u.group_id() {
                                sources.push(format!("sg:{}", id));
                            }
                        }

                        for source in sources {
                            rows.push(NetworkPortRow {
                                region: region.clone(),
                                security_group_id: sg_id.clone(),
                                direction: "ingress".to_string(),
                                protocol: proto.clone(),
                                port_range: port_range.clone(),
                                source: source.clone(),
                                attached_instances: attached,
                            });
                            // Track public exposure
                            if let Some(ips) = sg_public_ips.get(&sg_id) {
                                for ip in ips {
                                    public_endpoints.push((
                                        ip.clone(),
                                        port_range.clone(),
                                        source.clone(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }

            RegionData {
                region,
                rows,
                public_endpoints,
            }
        });
        handles.push(handle);
    }

    let mut all_rows: Vec<NetworkPortRow> = vec![];
    let mut per_region: Vec<RegionData> = vec![];
    for h in handles {
        let data = h.await?;
        all_rows.extend(data.rows.clone());
        per_region.push(data);
    }

    let headers = &[
        "Region",
        "SecurityGroupId",
        "Direction",
        "Protocol",
        "PortRange",
        "Source",
        "AttachedInstances",
    ];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.security_group_id.clone(),
                r.direction.clone(),
                r.protocol.clone(),
                r.port_range.clone(),
                r.source.clone(),
                r.attached_instances.to_string(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("network-ports", headers, &display)?;
    output.write_csv("network-ports", &all_rows)?;
    output.write_json("network-ports", &all_rows)?;

    for rd in &per_region {
        if rd.public_endpoints.is_empty() {
            continue;
        }
        let mut body = String::new();
        for (ip, port, source) in &rd.public_endpoints {
            body.push_str(&format!("{}:{} from {}\n", ip, port, source));
        }
        output.loot_file(
            "network-ports",
            &format!("network-ports-{}.txt", rd.region),
            body,
        )?;
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
