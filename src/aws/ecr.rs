use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize, Clone)]
pub struct EcrRow {
    pub region: String,
    pub repo_name: String,
    pub repo_arn: String,
    pub image_count: usize,
    pub policy_exists: bool,
    pub image_tag_mutability: String,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[ecr]".cyan().bold());
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
            let client = factory.ecr(&region);
            let mut rows: Vec<EcrRow> = vec![];
            let mut policies: Vec<(String, String)> = vec![]; // (repo, policy_text)

            let mut repos: Vec<(String, String, String)> = vec![]; // (name, arn, tag_mutability)
            let mut paginator = client.describe_repositories().into_paginator().send();
            while let Some(page) = paginator.next().await {
                let page = match page {
                    Ok(p) => p,
                    Err(_) => break,
                };
                for r in page.repositories() {
                    let name = r.repository_name().unwrap_or("").to_string();
                    let arn = r.repository_arn().unwrap_or("").to_string();
                    let mutability = r
                        .image_tag_mutability()
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();
                    repos.push((name, arn, mutability));
                }
            }

            for (name, arn, mutability) in repos {
                // Count images.
                let mut image_count = 0usize;
                let mut img_paginator = client
                    .list_images()
                    .repository_name(&name)
                    .into_paginator()
                    .send();
                while let Some(page) = img_paginator.next().await {
                    let page = match page {
                        Ok(p) => p,
                        Err(_) => break,
                    };
                    image_count += page.image_ids().len();
                }

                // Policy probe.
                let mut policy_exists = false;
                match client
                    .get_repository_policy()
                    .repository_name(&name)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        if let Some(text) = resp.policy_text() {
                            policy_exists = true;
                            policies.push((name.clone(), text.to_string()));
                        }
                    }
                    Err(_) => {
                        // RepositoryPolicyNotFoundException — treat as None.
                    }
                }

                rows.push(EcrRow {
                    region: region.clone(),
                    repo_name: name,
                    repo_arn: arn,
                    image_count,
                    policy_exists,
                    image_tag_mutability: mutability,
                });
            }

            (rows, policies)
        });
        handles.push(handle);
    }

    let mut all_rows: Vec<EcrRow> = vec![];
    let mut all_policies: Vec<(String, String)> = vec![];
    for h in handles {
        let (rows, policies) = h.await?;
        all_rows.extend(rows);
        all_policies.extend(policies);
    }

    let headers = &[
        "Region",
        "RepoName",
        "RepoArn",
        "ImageCount",
        "PolicyExists",
        "ImageTagMutability",
    ];
    let display: Vec<Vec<String>> = all_rows
        .iter()
        .map(|r| {
            vec![
                r.region.clone(),
                r.repo_name.clone(),
                r.repo_arn.clone(),
                r.image_count.to_string(),
                if r.policy_exists { "yes".to_string() } else { "no".to_string() },
                r.image_tag_mutability.clone(),
            ]
        })
        .collect();
    output.print_table(headers, &display);
    output.write_table("ecr", headers, &display)?;
    output.write_csv("ecr", &all_rows)?;
    output.write_json("ecr", &all_rows)?;

    for (repo, policy) in &all_policies {
        let safe = repo.replace('/', "_");
        output.loot_file("ecr-policies", &format!("{}.json", safe), policy.as_bytes())?;
    }

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );
    Ok(())
}
