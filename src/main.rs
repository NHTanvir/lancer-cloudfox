use clap::{Parser, Subcommand};

mod aws;
mod azure;
mod cli;
mod gcp;
mod output;
mod tui;

use cli::aws::AwsCommand;

#[derive(Parser, Debug)]
#[command(
    name = "lancer-cloudfox",
    version,
    about = "Cloud situational awareness for pentesters — Rust clone of CloudFox"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "AWS commands")]
    Aws(cli::aws::AwsArgs),

    #[command(about = "Azure commands")]
    Azure(cli::azure::AzureArgs),

    #[command(about = "GCP commands")]
    Gcp(cli::gcp::GcpArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Aws(args) => {
            let factory = aws::client::ClientFactory::new(
                args.profile.as_deref(),
                args.regions.as_deref(),
            )
            .await?;

            let account_id = factory
                .sts()
                .get_caller_identity()
                .send()
                .await
                .ok()
                .and_then(|r| r.account().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown".to_string());

            let output = output::OutputWriter::new(&factory.profile, &account_id);
            let c = args.concurrency;

            match args.command {
                AwsCommand::Whoami           => aws::whoami::run(&factory, &output).await?,
                AwsCommand::Inventory        => aws::inventory::run(&factory, &output, c).await?,
                AwsCommand::Principals       => aws::principals::run(&factory, &output).await?,
                AwsCommand::Permissions      => aws::permissions::run(&factory, &output).await?,
                AwsCommand::RoleTrusts       => aws::role_trusts::run(&factory, &output).await?,
                AwsCommand::ResourceTrusts   => aws::resource_trusts::run(&factory, &output, c).await?,
                AwsCommand::IamSimulator     => aws::iam_simulator::run(&factory, &output).await?,
                AwsCommand::Buckets          => aws::buckets::run(&factory, &output).await?,
                AwsCommand::Secrets          => aws::secrets::run(&factory, &output, c).await?,
                AwsCommand::EnvVars          => aws::env_vars::run(&factory, &output, c).await?,
                AwsCommand::Instances        => aws::instances::run(&factory, &output, c).await?,
                AwsCommand::NetworkPorts     => aws::network_ports::run(&factory, &output, c).await?,
                AwsCommand::Lambda           => aws::lambda_fn::run(&factory, &output, c).await?,
                AwsCommand::Databases        => aws::databases::run(&factory, &output, c).await?,
                AwsCommand::Route53          => aws::route53::run(&factory, &output).await?,
                AwsCommand::Cloudformation   => aws::cloudformation::run(&factory, &output, c).await?,
                AwsCommand::Eks              => aws::eks::run(&factory, &output, c).await?,
                AwsCommand::Ecr              => aws::ecr::run(&factory, &output, c).await?,
                AwsCommand::Graph            => aws::graph::run(&factory, &output).await?,
                AwsCommand::Cape             => aws::cape::run(&factory, &output).await?,
                AwsCommand::AllChecks        => aws::all_checks::run(&factory, &output, c).await?,
                AwsCommand::CapeTui          => tui::cape::run(&factory, &output).await?,
            }
        }

        Command::Azure(args) => {
            let client = azure::client::AzureClient::new(args.subscription.clone())?;
            let output = output::OutputWriter::new_for("azure", &client.subscription_id);
            match args.command {
                cli::azure::AzureCommand::Whoami    => azure::whoami::run(&client, &output).await?,
                cli::azure::AzureCommand::Inventory => azure::inventory::run(&client, &output).await?,
                cli::azure::AzureCommand::Rbac      => azure::rbac::run(&client, &output).await?,
                cli::azure::AzureCommand::Storage   => azure::storage::run(&client, &output).await?,
                cli::azure::AzureCommand::Vms       => azure::vms::run(&client, &output).await?,
            }
        }

        Command::Gcp(args) => {
            let client = gcp::client::GcpClient::new(args.project.clone())?;
            let output = output::OutputWriter::new_for("gcp", &client.project);
            match args.command {
                cli::gcp::GcpCommand::Whoami          => gcp::whoami::run(&client, &output).await?,
                cli::gcp::GcpCommand::Inventory       => gcp::inventory::run(&client, &output).await?,
                cli::gcp::GcpCommand::Iam             => gcp::iam::run(&client, &output).await?,
                cli::gcp::GcpCommand::Serviceaccounts => gcp::serviceaccounts::run(&client, &output).await?,
                cli::gcp::GcpCommand::Privesc         => gcp::privesc::run(&client, &output).await?,
                cli::gcp::GcpCommand::Storage         => gcp::storage::run(&client, &output).await?,
                cli::gcp::GcpCommand::Gke             => gcp::gke::run(&client, &output).await?,
                cli::gcp::GcpCommand::Instances       => gcp::instances::run(&client, &output).await?,
                cli::gcp::GcpCommand::Functions       => gcp::functions::run(&client, &output).await?,
                cli::gcp::GcpCommand::Cloudrun        => gcp::cloudrun::run(&client, &output).await?,
                cli::gcp::GcpCommand::Secrets         => gcp::secrets::run(&client, &output).await?,
                cli::gcp::GcpCommand::Bigquery        => gcp::bigquery::run(&client, &output).await?,
                cli::gcp::GcpCommand::Cloudsql        => gcp::cloudsql::run(&client, &output).await?,
                cli::gcp::GcpCommand::Kms             => gcp::kms::run(&client, &output).await?,
            }
        }
    }

    Ok(())
}
