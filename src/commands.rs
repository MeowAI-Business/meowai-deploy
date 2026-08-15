use std::collections::BTreeSet;

use clap::CommandFactory;
use cliclack::{confirm, spinner};
use console::style;
use secrecy::ExposeSecret;

use crate::{
    cli::{Cli, Command, DeploymentArgs, OnboardArgs, RollbackArgs, SyncArgs},
    config::{DeploymentConfig, authenticate_source, interactive_config},
    doctor,
    error::{AppError, Result},
    source::SourceClient,
    state::unix_timestamp,
    storage::{self, CONFIG_FILE, SESSION_FILE},
    target::compose::DeploymentRuntime,
    target::kuma,
    target::newapi::NewApiClient,
};

pub async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        None => print_help(),
        Some(Command::Doctor(args)) => doctor::run(&args).await,
        Some(Command::Onboard(args)) => run_onboard(&args).await,
        Some(Command::Sync(args)) => run_sync(&args).await,
        Some(Command::Status(args)) => run_status(&args).await,
        Some(Command::Rollback(args)) => run_rollback(&args).await,
        Some(Command::Logout(args)) => run_logout(&args).await,
    }
}

async fn run_onboard(args: &OnboardArgs) -> Result<()> {
    if let Some(path) = &args.write_config {
        DeploymentConfig::write_template(path)?;
        print_message(
            "配置模板",
            &format!("已写入非敏感配置到 {}", path.display()),
        );
        return Ok(());
    }
    if args.non_interactive && args.config.is_none() {
        return Err(AppError::InvalidConfig(
            "--non-interactive requires --config FILE".to_owned(),
        ));
    }
    let (mut config, mut source, identity) = if let Some(path) = &args.config {
        let mut config = DeploymentConfig::from_file(path)?;
        config.apply_cli_target(args);
        config.normalize();
        config.resolve_passwords();
        config.validate()?;
        let (source, identity) = authenticate_source(&config).await?;
        (config, source, identity)
    } else {
        interactive_config(args).await?
    };
    config.resolve_passwords();
    ensure_compatible_current_deployment(&config)?;
    persist_source_session(&source)?;

    print_deployment_preview(&config);
    if args.dry_run {
        println!(
            "{} {}",
            style("✓").green(),
            style("dry-run 完成，没有执行部署动作").bold()
        );
        println!();
        return Ok(());
    }
    let confirmed = confirm("按以上配置开始部署？")
        .initial_value(true)
        .interact()
        .map_err(AppError::from_prompt)?;
    if !confirmed {
        return Err(AppError::Cancelled);
    }
    println!();

    let progress = spinner();
    progress.start("读取源站分组");
    let catalog = source.groups().await?;
    progress.stop(format!("已读取 {} 个可见分组", catalog.groups.len()));

    progress.start("读取源站价格配置");
    let source_pricing = source.pricing().await?;
    progress.stop("已读取并校验 8 个源站价格配置");

    progress.start("同步源站分组 Token");
    let token_sync = source
        .ensure_group_tokens(&config.deployment_id(), &catalog)
        .await?;
    progress.stop("源站分组 Token 已就绪");

    progress.start("准备源站 public status Key");
    let status_key = source.ensure_onboard_status_key().await?;
    progress.stop(if status_key.created {
        "源站 public status Key 已创建"
    } else {
        "源站 public status Key 已复用"
    });
    print_message(
        "源站资源",
        &format!(
            "账号：{}\n分组：{}\nToken：新建 {}，复用 {}，修正 {}\nstatus Key：{}\n分组响应哈希：{}",
            identity.username,
            catalog.groups.len(),
            token_sync.created,
            token_sync.reused,
            token_sync.updated,
            if status_key.created {
                "已创建"
            } else {
                "已复用"
            },
            catalog.response_sha256
        ),
    );

    progress.start("准备下游部署状态");
    let mut deployment = DeploymentRuntime::prepare(
        &config,
        identity.user_id,
        &catalog.response_sha256,
        status_key.metadata.id,
        status_key.key(),
    )?;
    progress.stop("下游部署状态已就绪");
    if deployment.credentials_should_display {
        print_message(
            "管理员凭证",
            &format!(
                "New API     {} / {}\nUptime Kuma {} / {}\n\n请立即保存；凭证不会写入普通日志。",
                config.newapi_admin_username,
                deployment.secrets.newapi_admin_password.expose_secret(),
                config.kuma_admin_username,
                deployment.secrets.kuma_admin_password.expose_secret()
            ),
        );
    }
    progress.start("部署 New API、PostgreSQL 和 Redis");
    deployment.deploy_base_stack(&config)?;
    progress.stop(format!(
        "基础服务已就绪，New API 端口 {}",
        deployment.state.newapi_port
    ));
    progress.start("初始化下游管理员和站点配置");
    let mut downstream = NewApiClient::connect(&deployment.executor, deployment.state.newapi_port)?;
    downstream
        .initialize_and_login(&config, &deployment.secrets.newapi_admin_password)
        .await?;
    downstream.configure_site(&config.website_name).await?;
    progress.stop("下游管理员已生成，站点配置已写入");

    progress.start("导入下游价格配置");
    let pricing_hashes = downstream.import_pricing(&source_pricing).await?;
    deployment.state.pricing_sha256 = pricing_hashes;
    deployment
        .state
        .mark_phase("pricing", "DONE", "8 个价格 option 已写入并回读一致");
    deployment.persist_state()?;
    progress.stop("8 个价格配置已校验");

    progress.start("同步下游分组渠道");
    let (channel_result, channels) = downstream
        .sync_channels(
            &config,
            &deployment.container_source_url,
            &catalog,
            &token_sync.bindings,
            &deployment.state.channels,
            true,
        )
        .await?;
    deployment.state.channels = channels;
    deployment.state.mark_phase(
        "channels",
        "DONE",
        format!(
            "渠道新建 {}，复用 {}，更新 {}",
            channel_result.created, channel_result.reused, channel_result.updated
        ),
    );
    deployment.persist_state()?;
    progress.stop(format!(
        "下游渠道已同步：新建 {}，复用 {}，更新 {}",
        channel_result.created, channel_result.reused, channel_result.updated
    ));
    progress.start("部署 Uptime Kuma 2.5.0");
    deployment.deploy_kuma(&config)?;
    progress.stop(format!(
        "Uptime Kuma 已就绪，端口 {}",
        deployment.state.kuma_port
    ));

    progress.start("克隆 public status 页面和监控");
    let manifest = source
        .onboard_status_manifest(&deployment.secrets.public_status_source_key)
        .await?;
    let deployment_id = config.deployment_id();
    let kuma_sync = kuma::sync_status_page(kuma::KumaSyncOptions {
        executor: &deployment.executor,
        container_name: &config.container_name,
        deployment_id: &deployment_id,
        website_name: &config.website_name,
        source_base_url: &deployment.container_source_url,
        status_key: &deployment.secrets.public_status_source_key,
        kuma_username: &config.kuma_admin_username,
        kuma_password: &deployment.secrets.kuma_admin_password,
        force: true,
        manifest: &manifest,
    })?;
    deployment.state.manifest_sha256 = kuma_sync.manifest_sha256;
    deployment.state.kuma_monitors = kuma_sync.monitors;
    deployment.state.mark_phase(
        "kuma",
        "DONE",
        format!(
            "status page {} and managed monitors synchronized",
            kuma_sync.page_slug
        ),
    );
    deployment.persist_state()?;
    progress.stop(format!(
        "已同步 {} 个 public status 监控",
        deployment.state.kuma_monitors.len()
    ));
    print_success("下游基础服务、管理员、价格、渠道和 public status 初始化完成");
    Ok(())
}

async fn run_sync(args: &SyncArgs) -> Result<()> {
    let mut config = load_deployment_config()?;
    config.resolve_passwords();
    let mut deployment = DeploymentRuntime::prepare(&config, 0, "", 0, None)?;
    let result = run_sync_inner(args, &config, &mut deployment).await;
    deployment.state.last_sync_at = unix_timestamp();
    deployment.state.last_sync_success = result.is_ok();
    let _ = deployment.persist_state();
    result
}

async fn run_sync_inner(
    args: &SyncArgs,
    config: &DeploymentConfig,
    deployment: &mut DeploymentRuntime,
) -> Result<()> {
    deployment.deploy_base_stack(config)?;
    let mut source = source_for_operation(config).await?;
    let identity = source
        .identity()
        .cloned()
        .ok_or_else(|| AppError::State("source session has no identity".to_owned()))?;
    if deployment.state.source_user_id != 0 && deployment.state.source_user_id != identity.user_id {
        return Err(AppError::State(format!(
            "deployment belongs to source user {}, not {}",
            deployment.state.source_user_id, identity.user_id
        )));
    }

    let catalog = source.groups().await?;
    let source_pricing = if args.pricing {
        Some(source.pricing().await?)
    } else {
        None
    };
    let active_group_ids = catalog
        .groups
        .iter()
        .map(|group| group.group_id.clone())
        .collect::<BTreeSet<_>>();
    let disabled_tokens = source
        .disable_removed_group_tokens(&config.deployment_id(), &active_group_ids)
        .await?;
    let token_sync = source
        .ensure_group_tokens(&config.deployment_id(), &catalog)
        .await?;
    let status_key = source.ensure_onboard_status_key().await?;
    if let Some(key) = status_key.key() {
        deployment.secrets.public_status_source_key = key.clone();
    }
    deployment.state.source_user_id = identity.user_id;
    deployment.state.source_group_sha256 = catalog.response_sha256.clone();
    deployment.state.status_key_id = status_key.metadata.id;
    deployment.persist(config)?;
    persist_source_session(&source)?;

    let mut downstream = NewApiClient::connect(&deployment.executor, deployment.state.newapi_port)?;
    downstream
        .initialize_and_login(config, &deployment.secrets.newapi_admin_password)
        .await?;
    let previous_channels = deployment.state.channels.clone();
    let (channel_result, mut channels) = downstream
        .sync_channels(
            config,
            &deployment.container_source_url,
            &catalog,
            &token_sync.bindings,
            &previous_channels,
            args.force,
        )
        .await?;
    let disabled_channels = downstream
        .disable_removed_channels(&previous_channels, &mut channels)
        .await?;
    deployment.state.channels = channels;
    if let Some(source_pricing) = &source_pricing {
        deployment.state.pricing_sha256 = downstream.import_pricing(source_pricing).await?;
        deployment
            .state
            .mark_phase("pricing", "DONE", "8 个价格 option 已重新导入并回读一致");
    }

    deployment.deploy_kuma(config)?;
    let manifest = source
        .onboard_status_manifest(&deployment.secrets.public_status_source_key)
        .await?;
    let deployment_id = config.deployment_id();
    let kuma_sync = kuma::sync_status_page(kuma::KumaSyncOptions {
        executor: &deployment.executor,
        container_name: &config.container_name,
        deployment_id: &deployment_id,
        website_name: &config.website_name,
        source_base_url: &deployment.container_source_url,
        status_key: &deployment.secrets.public_status_source_key,
        kuma_username: &config.kuma_admin_username,
        kuma_password: &deployment.secrets.kuma_admin_password,
        force: args.force,
        manifest: &manifest,
    })?;
    deployment.state.manifest_sha256 = kuma_sync.manifest_sha256;
    deployment.state.kuma_monitors = kuma_sync.monitors;
    deployment.state.mark_phase(
        "kuma",
        "DONE",
        format!("status page {} synchronized", kuma_sync.page_slug),
    );
    deployment.state.mark_phase(
        "sync",
        "DONE",
        format!(
            "groups {}, channels created {}, updated {}, reused {}, disabled {}, source tokens disabled {}, Kuma monitors {}",
            catalog.groups.len(),
            channel_result.created,
            channel_result.updated,
            channel_result.reused,
            disabled_channels,
            disabled_tokens,
            deployment.state.kuma_monitors.len()
        ),
    );
    deployment.persist(config)?;
    print_success(&format!(
        "同步完成：{} 个分组，渠道新建 {}、更新 {}、禁用 {}，Kuma {} 个监控",
        catalog.groups.len(),
        channel_result.created,
        channel_result.updated,
        disabled_channels,
        deployment.state.kuma_monitors.len()
    ));
    Ok(())
}

async fn run_status(_args: &DeploymentArgs) -> Result<()> {
    if !storage::exists(CONFIG_FILE)? {
        println!();
        println!("{}", style("尚未 onboard").yellow().bold());
        println!("{}", style("运行 meowai-deploy onboard 开始配置。").dim());
        println!();
        return Ok(());
    }
    let config = load_deployment_config()?;
    let deployment = DeploymentRuntime::prepare(&config, 0, "", 0, None)?;
    let compose = deployment
        .executor
        .compose(&config.container_name, &["ps", "--format", "json"])?;
    let compose_status = format_compose_status(&compose.stdout)?;
    let phases = deployment
        .state
        .phases
        .iter()
        .map(|(name, phase)| format!("{name}: {}", phase.status))
        .collect::<Vec<_>>()
        .join("\n");
    print_message(
        "部署状态",
        &format!(
            "目录：{}\nNew API：{}:{}\nUptime Kuma：{}:{}\n镜像：{}@{}\n最近同步：{}\n同步结果：{}\n\n阶段：\n{}\n\n容器：\n{}",
            deployment.state.directory,
            config.newapi_bind,
            deployment.state.newapi_port,
            config.kuma_bind,
            deployment.state.kuma_port,
            deployment.state.image,
            deployment.state.image_ref,
            deployment.state.last_sync_at,
            if deployment.state.last_sync_success {
                "成功"
            } else {
                "尚未成功"
            },
            phases,
            compose_status
        ),
    );
    Ok(())
}

async fn run_logout(_args: &DeploymentArgs) -> Result<()> {
    let removed = storage::remove(SESSION_FILE)?;
    print_success(if removed {
        "已删除 ~/.meowai-deploy/session.json；部署凭证和源站 Token 未撤销"
    } else {
        "当前没有已保存的源站登录会话"
    });
    Ok(())
}

async fn run_rollback(args: &RollbackArgs) -> Result<()> {
    if !args.yes {
        let confirmed = confirm("删除本次部署创建的下游容器、配置和数据？")
            .initial_value(false)
            .interact()
            .map_err(AppError::from_prompt)?;
        if !confirmed {
            return Err(AppError::Cancelled);
        }
    }
    if args.revoke_source && !args.yes {
        let confirmed = confirm("同时撤销源站分组 Token 和 public status Key？")
            .initial_value(false)
            .interact()
            .map_err(AppError::from_prompt)?;
        if !confirmed {
            return Err(AppError::Cancelled);
        }
    }

    let mut config = load_deployment_config()?;
    config.resolve_passwords();
    let deployment = DeploymentRuntime::prepare(&config, 0, "", 0, None)?;
    if args.revoke_source {
        let mut source = source_for_operation(&config).await?;
        let identity = source
            .identity()
            .cloned()
            .ok_or_else(|| AppError::State("source session has no identity".to_owned()))?;
        if deployment.state.source_user_id != 0
            && deployment.state.source_user_id != identity.user_id
        {
            return Err(AppError::State(
                "source account does not own this deployment".to_owned(),
            ));
        }
        let revoked_tokens = source
            .revoke_deployment_tokens(&deployment.state.deployment_id)
            .await?;
        source.revoke_onboard_status_key().await?;
        print_success(&format!(
            "已撤销源站资源：{} 个分组 Token 和 1 个 status Key",
            revoked_tokens
        ));
    }

    deployment
        .executor
        .compose(&config.container_name, &["down", "--remove-orphans"])?;
    deployment
        .executor
        .run_in_directory("rm -f secrets.env docker-compose.yml kuma-helper.js\nrm -rf data")?;
    storage::clear_deployment()?;
    print_success("下游 Compose 项目、配置和数据已清理");
    Ok(())
}

fn load_deployment_config() -> Result<DeploymentConfig> {
    let path = storage::directory()?.join(CONFIG_FILE);
    let mut config = DeploymentConfig::from_file(&path)?;
    config.normalize();
    config.validate()?;
    Ok(config)
}

fn ensure_compatible_current_deployment(config: &DeploymentConfig) -> Result<()> {
    if !storage::exists(CONFIG_FILE)? {
        return Ok(());
    }
    let existing = load_deployment_config()?;
    if existing.deployment_id() != config.deployment_id()
        || existing.source_username != config.source_username
    {
        return Err(AppError::State(
            "~/.meowai-deploy already manages another deployment; run rollback before onboarding a different site"
                .to_owned(),
        ));
    }
    Ok(())
}

async fn source_for_operation(config: &DeploymentConfig) -> Result<SourceClient> {
    if let Some(content) = storage::read(SESSION_FILE)? {
        let persisted = serde_json::from_slice(&content)
            .map_err(|error| AppError::State(format!("parse session.json: {error}")))?;
        return SourceClient::from_session(&config.source_url, persisted).map_err(AppError::from);
    }
    let (source, _) = authenticate_source(config).await?;
    persist_source_session(&source)?;
    Ok(source)
}

fn persist_source_session(source: &SourceClient) -> Result<()> {
    let session = source.export_session()?;
    let content = serde_json::to_vec_pretty(&session)
        .map_err(|error| AppError::State(format!("serialize session.json: {error}")))?;
    storage::write(SESSION_FILE, &content)
}

fn print_deployment_preview(config: &DeploymentConfig) {
    println!("{}", style("部署预览").bold());
    println!();
    print_field("网站", &config.website_name);
    print_field("容器", &config.container_name);
    print_field("安装目录", &config.directory.display().to_string());
    print_field("目标", &config.target_label());
    print_field("源站", &config.source_url);
    print_field("源站账号", &config.source_username);
    print_field(
        "New API",
        &format!("{}:{}", config.newapi_bind, config.newapi_port),
    );
    print_field(
        "Uptime Kuma",
        &format!("{}:{}", config.kuma_bind, config.kuma_port),
    );
    print_field("镜像", &format!("{}@{}", config.image, config.image_ref));
    println!();
}

fn print_field(label: &str, value: &str) {
    println!("  {}  {}", style(label).dim(), value);
}

fn print_message(title: &str, message: &str) {
    println!();
    println!("{}", style(title).bold());
    for line in message.lines() {
        println!("  {line}");
    }
    println!();
}

fn print_success(message: &str) {
    println!();
    println!("{} {}", style("✓").green(), style(message).bold());
    println!();
}

fn format_compose_status(raw: &[u8]) -> Result<String> {
    let raw = String::from_utf8_lossy(raw);
    let mut rows = Vec::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| AppError::Target(format!("decode Docker Compose status: {error}")))?;
        let name = value
            .get("Name")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let state = value
            .get("State")
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let health = value
            .get("Health")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let ports = value
            .get("Ports")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let state = if health.is_empty() {
            state.to_owned()
        } else {
            format!("{state}/{health}")
        };
        rows.push(if ports.is_empty() {
            format!("{name}: {state}")
        } else {
            format!("{name}: {state} · {ports}")
        });
    }
    if rows.is_empty() {
        Ok("没有运行中的容器".to_owned())
    } else {
        Ok(rows.join("\n"))
    }
}

fn print_help() -> Result<()> {
    let mut command = Cli::command();
    command.print_help().map_err(AppError::from_prompt)?;
    println!();
    Ok(())
}
