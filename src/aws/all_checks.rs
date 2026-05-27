use anyhow::Result;
use colored::Colorize;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

pub async fn run(factory: &ClientFactory, output: &OutputWriter, concurrency: usize) -> Result<()> {
    println!("\n{}", "[all-checks]".magenta().bold());
    println!("Running every read-only AWS subcommand sequentially.\n");

    let mut ok = 0usize;
    let mut failed: Vec<(String, String)> = vec![];
    let mut idx = 0usize;
    let total = 20usize;

    macro_rules! step {
        ($name:expr, $expr:expr) => {{
            idx += 1;
            let start = std::time::Instant::now();
            println!(
                "\n{} [{}/{}] {}",
                "==>".cyan().bold(),
                idx,
                total,
                ($name as &str).bold()
            );
            match $expr.await {
                Ok(()) => {
                    ok += 1;
                    println!(
                        "{} {} ({}s)",
                        "[ok]".green().bold(),
                        $name,
                        start.elapsed().as_secs()
                    );
                }
                Err(e) => {
                    failed.push(($name.to_string(), e.to_string()));
                    eprintln!("{} {}: {}", "[fail]".red().bold(), $name, e);
                }
            }
        }};
    }

    step!("whoami",          crate::aws::whoami::run(factory, output));
    step!("inventory",       crate::aws::inventory::run(factory, output, concurrency));
    step!("principals",      crate::aws::principals::run(factory, output));
    step!("permissions",     crate::aws::permissions::run(factory, output));
    step!("role-trusts",     crate::aws::role_trusts::run(factory, output));
    step!("resource-trusts", crate::aws::resource_trusts::run(factory, output, concurrency));
    step!("iam-simulator",   crate::aws::iam_simulator::run(factory, output));
    step!("buckets",         crate::aws::buckets::run(factory, output));
    step!("secrets",         crate::aws::secrets::run(factory, output, concurrency));
    step!("env-vars",        crate::aws::env_vars::run(factory, output, concurrency));
    step!("instances",       crate::aws::instances::run(factory, output, concurrency));
    step!("network-ports",   crate::aws::network_ports::run(factory, output, concurrency));
    step!("lambda",          crate::aws::lambda_fn::run(factory, output, concurrency));
    step!("databases",       crate::aws::databases::run(factory, output, concurrency));
    step!("route53",         crate::aws::route53::run(factory, output));
    step!("cloudformation",  crate::aws::cloudformation::run(factory, output, concurrency));
    step!("eks",             crate::aws::eks::run(factory, output, concurrency));
    step!("ecr",             crate::aws::ecr::run(factory, output, concurrency));
    step!("graph",           crate::aws::graph::run(factory, output));
    step!("cape",            crate::aws::cape::run(factory, output));

    println!(
        "\n{} {}/{} checks completed.",
        "[summary]".magenta().bold(),
        ok,
        total
    );
    if !failed.is_empty() {
        println!("{} failures:", failed.len());
        for (name, err) in &failed {
            println!("  - {}: {}", name, err);
        }
    }
    println!("Output directory: {}", output.base_dir().display());
    Ok(())
}
