use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct AzureArgs {
    #[arg(long, global = true, help = "Azure subscription ID (defaults to active subscription)")]
    pub subscription: Option<String>,

    #[arg(long, global = true, help = "Max concurrent API calls", default_value = "10")]
    pub concurrency: usize,

    #[command(subcommand)]
    pub command: AzureCommand,
}

#[derive(Subcommand, Debug)]
pub enum AzureCommand {
    #[command(about = "Show current Azure identity")]
    Whoami,

    #[command(about = "Resource inventory across the subscription")]
    Inventory,

    #[command(about = "List role assignments and definitions (RBAC)")]
    Rbac,

    #[command(about = "Enumerate Storage accounts: keys, public access, containers")]
    Storage,

    #[command(about = "List VMs with NIC/public IP/identity info")]
    Vms,
}
