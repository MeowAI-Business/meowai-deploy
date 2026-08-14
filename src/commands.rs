use clap::CommandFactory;
use cliclack::{log, note, spinner};

use crate::{
    cli::{Cli, Command, OnboardArgs},
    config::{DeploymentConfig, interactive_config},
    doctor,
    error::{AppError, Result},
    source::SourceClient,
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
    let credentials = config.source_credentials()?;
    progress.start("登录源站账号");
    let mut source = SourceClient::new(&config.source_url)?;
    let identity = source
        .authenticate(config.source_account_mode, &credentials)
        .await?;
    progress.stop("源站账号已验证");

    progress.start("读取源站分组");
    let catalog = source.groups().await?;
    progress.stop(format!("已读取 {} 个可见分组", catalog.groups.len()));

    progress.start("同步源站分组 Token");
    let token_sync = source
        .ensure_group_tokens(&config.deployment_id(), &catalog)
        .await?;
    progress.stop("源站分组 Token 已就绪");
    note(
        "源站资源",
        format!(
            "账号：{}\n分组：{}\nToken：新建 {}，复用 {}，修正 {}\n分组响应哈希：{}",
            identity.username,
            catalog.groups.len(),
            token_sync.created,
            token_sync.reused,
            token_sync.updated,
            catalog.response_sha256
        ),
    )
    .map_err(AppError::from_prompt)?;
    log::warning("源站适配已完成；下游容器部署将在后续流程接入").map_err(AppError::from_prompt)?;
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
