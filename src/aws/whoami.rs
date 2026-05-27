use anyhow::Result;
use colored::Colorize;
use serde::Serialize;

use crate::aws::client::ClientFactory;
use crate::output::OutputWriter;

#[derive(Serialize)]
pub struct WhoamiRow {
    pub profile: String,
    pub account: String,
    pub user_id: String,
    pub arn: String,
}

pub async fn run(factory: &ClientFactory, output: &OutputWriter) -> Result<()> {
    let sts = factory.sts();
    let resp = sts.get_caller_identity().send().await?;

    let account = resp.account().unwrap_or("unknown").to_string();
    let user_id = resp.user_id().unwrap_or("unknown").to_string();
    let arn = resp.arn().unwrap_or("unknown").to_string();

    let row = WhoamiRow {
        profile: factory.profile.clone(),
        account: account.clone(),
        user_id: user_id.clone(),
        arn: arn.clone(),
    };

    println!("\n{}", "[whoami]".cyan().bold());
    output.print_table(
        &["Profile", "Account", "UserId", "ARN"],
        &[vec![
            factory.profile.clone(),
            account.clone(),
            user_id.clone(),
            arn.clone(),
        ]],
    );

    output.write_table(
        "whoami",
        &["Profile", "Account", "UserId", "ARN"],
        &[vec![
            factory.profile.clone(),
            account.clone(),
            user_id.clone(),
            arn.clone(),
        ]],
    )?;

    output.write_json("whoami", &row)?;

    let loot = format!(
        "# Identity\nProfile: {}\nAccount: {}\nUserId: {}\nARN: {}\n",
        factory.profile, account, user_id, arn
    );
    output.loot_commands("whoami-identity", &loot)?;

    println!(
        "\n{} Output written to: {}",
        "[+]".green().bold(),
        output.base_dir().display()
    );

    Ok(())
}
