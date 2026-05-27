use anyhow::Result;
use aws_sdk_iam::primitives::{DateTime, DateTimeFormat};
use colored::Colorize;
use serde::Serialize;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct PrincipalRow {
    #[serde(rename = "Type")]
    pub resource_type: String,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Arn")]
    pub arn: String,
    #[serde(rename = "CreateDate")]
    pub create_date: String,
}

fn fmt_dt(dt: &DateTime) -> String {
    dt.fmt(DateTimeFormat::DateTime)
        .unwrap_or_else(|_| dt.secs().to_string())
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    println!("\n{}", "[principals]".cyan().bold());

    let iam = factory.iam();

    let mut users: Vec<PrincipalRow> = Vec::new();
    let mut roles: Vec<PrincipalRow> = Vec::new();
    let mut groups: Vec<PrincipalRow> = Vec::new();

    // Users
    let mut paginator = iam.list_users().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} list_users failed: {}", "[-]".yellow(), e);
                break;
            }
        };
        for u in page.users() {
            users.push(PrincipalRow {
                resource_type: "User".to_string(),
                name: u.user_name().to_string(),
                arn: u.arn().to_string(),
                create_date: fmt_dt(u.create_date()),
            });
        }
    }

    // Roles
    let mut paginator = iam.list_roles().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} list_roles failed: {}", "[-]".yellow(), e);
                break;
            }
        };
        for r in page.roles() {
            roles.push(PrincipalRow {
                resource_type: "Role".to_string(),
                name: r.role_name().to_string(),
                arn: r.arn().to_string(),
                create_date: fmt_dt(r.create_date()),
            });
        }
    }

    // Groups
    let mut paginator = iam.list_groups().into_paginator().send();
    while let Some(page) = paginator.next().await {
        let page = match page {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{} list_groups failed: {}", "[-]".yellow(), e);
                break;
            }
        };
        for g in page.groups() {
            groups.push(PrincipalRow {
                resource_type: "Group".to_string(),
                name: g.group_name().to_string(),
                arn: g.arn().to_string(),
                create_date: fmt_dt(g.create_date()),
            });
        }
    }

    let mut all: Vec<PrincipalRow> = Vec::new();
    all.extend(users.iter().cloned());
    all.extend(roles.iter().cloned());
    all.extend(groups.iter().cloned());

    if all.is_empty() {
        println!("No IAM principals found (or insufficient permissions).");
        return Ok(());
    }

    let table_rows: Vec<Vec<String>> = all
        .iter()
        .map(|r| {
            vec![
                r.resource_type.clone(),
                r.name.clone(),
                r.arn.clone(),
                r.create_date.clone(),
            ]
        })
        .collect();

    let headers = &["Type", "Name", "Arn", "CreateDate"];
    output.print_table(headers, &table_rows);
    output.write_table("principals", headers, &table_rows)?;

    // Three CSV files (per spec)
    output.write_csv("principals-users", &users)?;
    output.write_csv("principals-roles", &roles)?;
    output.write_csv("principals-groups", &groups)?;

    // Combined JSON
    output.write_json("principals", &all)?;

    // Loot: ARNs grouped by type
    let mut loot = String::new();
    loot.push_str("# IAM Users\n");
    for u in &users {
        loot.push_str(&u.arn);
        loot.push('\n');
    }
    loot.push_str("\n# IAM Roles\n");
    for r in &roles {
        loot.push_str(&r.arn);
        loot.push('\n');
    }
    loot.push_str("\n# IAM Groups\n");
    for g in &groups {
        loot.push_str(&g.arn);
        loot.push('\n');
    }
    output.loot_commands("principals-arns", &loot)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
