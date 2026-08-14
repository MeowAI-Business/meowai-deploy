use clap::CommandFactory;
use cliclack::{log, note, spinner};

use crate::{
    cli::{Cli, Command, OnboardArgs},
    config::{DeploymentConfig, interactive_config},
    doctor,
    error::{AppError, Result},
};

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        None => print_help(),
        Some(Command::Doctor(args)) => doctor::run(&args).await,
        Some(Command::Onboard(args)) => run_onboard(&args).await,
        Some(Command::Sync) => not_ready("sync"),
        Some(Command::Status) => not_ready("status"),
        Some(Command::Rollback) => not_ready("rollback"),
        Some(Command::Logout) => not_ready("logout"),
    }
}

async fn run_onboard(args: &OnboardArgs) -> Result<()> {
    if let Some(path) = &args.write_config {
        DeploymentConfig::write_template(path)?;
        note("配置模板", format!("已写入非敏感配置到 {}", path.display()))
            .map_err(AppError::from_prompt)?;
        return Ok(());
    }
    if args.non_interactive && args.config.is_none() {
        return Err(AppError::InvalidConfig(
            "--non-interactive requires --config FILE".to_owned(),
        ));
    }
    let config = if args.non_interactive {
        let path = args.config.as_ref().expect("checked above");
        let mut config = DeploymentConfig::from_file(path)?;
        config.apply_cli_target(args);
        config.normalize();
        config.validate()?;
        config
    } else {
        interactive_config(args).await?
    };
    let mut config = config;
    config.resolve_passwords();

    note("部署预览", config.to_string()).map_err(AppError::from_prompt)?;
    note(
        "管理员凭证",
        format!(
            "New API     {} / {}\nUptime Kuma {} / {}\n\n请立即保存；凭证不会写入普通日志。",
            config.newapi_admin_username,
            config
                .newapi_admin_password
                .as_deref()
                .unwrap_or("<missing>"),
            config.kuma_admin_username,
            config.kuma_admin_password.as_deref().unwrap_or("<missing>")
        ),
    )
    .map_err(AppError::from_prompt)?;
    if args.dry_run {
        log::success("dry-run 完成：没有执行部署动作").map_err(AppError::from_prompt)?;
        return Ok(());
    }

    let progress = spinner();
    progress.start("检查 onboard 配置");
    tokio::time::sleep(std::time::Duration::from_millis(350)).await;
    progress.stop("CLI 骨架已就绪；实际部署能力尚未接入");
    Ok(())
}

fn not_ready(command: &str) -> Result<()> {
    Err(AppError::NotReady(command.to_owned()))
}

fn print_help() -> Result<()> {
    let mut command = Cli::command();
    command.print_help().map_err(AppError::from_prompt)?;
    println!();
    Ok(())
}
