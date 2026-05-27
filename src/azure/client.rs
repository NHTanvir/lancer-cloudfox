use anyhow::{Context, Result};
use std::process::Command;

pub struct AzureClient {
    pub subscription_id: String,
    pub access_token: String,
    pub http: reqwest::Client,
}

impl AzureClient {
    pub fn new(subscription: Option<String>) -> Result<Self> {
        // Acquire token via az CLI
        let out = Command::new("az")
            .args([
                "account",
                "get-access-token",
                "--resource",
                "https://management.azure.com/",
                "--query",
                "accessToken",
                "--output",
                "tsv",
            ])
            .output()
            .context("Failed to invoke `az`. Install Azure CLI: https://aka.ms/azure-cli")?;
        if !out.status.success() {
            anyhow::bail!("`az account get-access-token` failed. Run `az login` first.");
        }
        let access_token = String::from_utf8(out.stdout)?.trim().to_string();

        // Subscription: argument > az default
        let subscription_id = match subscription {
            Some(s) => s,
            None => {
                let out = Command::new("az")
                    .args(["account", "show", "--query", "id", "--output", "tsv"])
                    .output()
                    .context("Failed to invoke `az`")?;
                if !out.status.success() {
                    anyhow::bail!("`az account show` failed. Run `az login` first.");
                }
                String::from_utf8(out.stdout)?.trim().to_string()
            }
        };

        Ok(Self {
            subscription_id,
            access_token,
            http: reqwest::Client::new(),
        })
    }

    pub fn auth_header(&self) -> (&'static str, String) {
        ("Authorization", format!("Bearer {}", self.access_token))
    }
}
