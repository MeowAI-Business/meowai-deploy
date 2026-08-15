use clap::CommandFactory;
use cliclack::{confirm, select};
use console::style;
use secrecy::ExposeSecret;

use crate::{
    application::{
        error::ApplicationError,
        manage::{
            ContainerStatus, SyncDeploymentRequest, clean_deployment, read_deployment_status,
            rollback_deployment, sync_deployment,
        },
        onboard::{
            DeploymentStateCheckpointStore, ProductionOnboardBackend, resume_onboard, start_onboard,
        },
        operation::{
            CancellationToken, EventSeverity, EventSink, OperationEvent, OperationEventKind,
            OperationStatus,
        },
    },
    cli::{CleanArgs, Cli, Command, DeploymentArgs, OnboardArgs, RollbackArgs, SyncArgs},
    config::{DeploymentConfig, authenticate_source, interactive_config, reauthenticate_source},
    doctor,
    error::{AppError, Result},
    source::{SourceClient, SourceError},
    state::{DOWNSTREAM_CLEANUP_PHASE, DeploymentState, unix_timestamp},
    storage::{self, CONFIG_FILE, CREDENTIALS_FILE, OPERATION_FILE, SESSION_FILE, STATE_FILE},
    updater,
};

struct CliEventSink;

impl EventSink for CliEventSink {
    fn emit(&self, event: OperationEvent) {
        match event.kind {
            OperationEventKind::StageStarted => print_action(&event.message),
            OperationEventKind::StageCompleted => print_done(&event.message),
            OperationEventKind::Message => match event.severity {
                EventSeverity::Debug => print_action(&event.message),
                EventSeverity::Info => print_done(&event.message),
                EventSeverity::Warning => print_message("提示", &event.message),
                EventSeverity::Error => print_message("失败", &event.message),
            },
            OperationEventKind::RecoverableFailure { .. }
            | OperationEventKind::FatalFailure { .. } => print_message("部署失败", &event.message),
            OperationEventKind::OperationCompleted => print_success(&event.message),
            OperationEventKind::OperationStarted
            | OperationEventKind::ProgressChanged { .. }
            | OperationEventKind::CredentialGenerated { .. }
            | OperationEventKind::OperationCancelled => {}
        }
    }
}

pub async fn run(cli: Cli) -> Result<()> {
    if !matches!(cli.command, Some(Command::Update(_))) {
        updater::check_periodically().await;
    }
    match cli.command {
        None => print_help(),
        Some(Command::Doctor(args)) => doctor::run(&args).await,
        Some(Command::Onboard(args)) => run_onboard(&args).await,
        Some(Command::Sync(args)) => run_sync(&args).await,
        Some(Command::Status(args)) => run_status(&args).await,
        Some(Command::Clean(args)) => run_clean(&args).await,
        Some(Command::Rollback(args)) => run_rollback(&args).await,
        Some(Command::Logout(args)) => run_logout(&args).await,
        Some(Command::Update(args)) => updater::run(&args).await,
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
    let existing_action = if args.config.is_none() && storage::exists(CONFIG_FILE)? {
        let action: String = select("检测到已保存的部署配置")
            .item(
                "resume".to_owned(),
                "继续上次部署",
                "使用上次表单、会话和已生成凭证",
            )
            .item(
                "replace".to_owned(),
                "清理当前部署并重新填写",
                "确认删除当前下游后部署新站点；保留账号级源站资源",
            )
            .initial_value("resume".to_owned())
            .interact()
            .map_err(AppError::from_prompt)?;
        println!();
        Some(action)
    } else {
        None
    };
    if existing_action.as_deref() == Some("replace") {
        clear_current_deployment_before_onboard().await?;
    }
    let resume_existing = existing_action.as_deref() == Some("resume");
    let (mut config, source, identity) = if resume_existing {
        let mut config = load_deployment_config()?;
        config.resolve_passwords();
        let source = source_for_operation(&config).await?;
        let identity = source
            .identity()
            .cloned()
            .ok_or_else(|| AppError::State("source session has no identity".to_owned()))?;
        (config, source, identity)
    } else if let Some(path) = &args.config {
        let mut config = DeploymentConfig::from_file(path)?;
        config.apply_cli_target(args);
        config.normalize();
        config.resolve_passwords();
        config.resolve_image_ref().await?;
        config.validate()?;
        let (source, identity) = authenticate_source(&config).await?;
        (config, source, identity)
    } else {
        interactive_config(args).await?
    };
    config.resolve_passwords();
    ensure_compatible_current_deployment(&config)?;
    persist_source_session(&source)?;
    let deployment_input = config.deployment_input();

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
    persist_deployment_config(&config)?;
    println!();

    let previous_checkpoint = if resume_existing {
        load_operation_checkpoint()?
    } else {
        None
    };
    let operation_id = format!("onboard-{}-{}", config.deployment_id(), unix_timestamp());
    let mut backend = ProductionOnboardBackend::new(config, source, identity);
    let mut checkpoint_store = DeploymentStateCheckpointStore;
    let mut result = match previous_checkpoint {
        Some(checkpoint)
            if matches!(
                checkpoint.status,
                OperationStatus::Running | OperationStatus::Failed
            ) =>
        {
            resume_onboard(
                &mut backend,
                &deployment_input,
                checkpoint,
                CliEventSink,
                &mut checkpoint_store,
            )
            .await
        }
        _ => {
            start_onboard(
                &mut backend,
                &deployment_input,
                operation_id,
                CliEventSink,
                &mut checkpoint_store,
            )
            .await
        }
    };
    if result
        .as_ref()
        .is_err_and(|error| error.code == "STATUS_KEY_CONTENT_UNAVAILABLE")
    {
        let confirmed = confirm(
            "源站已有公共状态密钥，但这台机器没有保存密钥内容。继续会生成新密钥，其他正在使用旧密钥的下游状态页会失效。是否继续？",
        )
        .initial_value(true)
        .interact()
        .map_err(AppError::from_prompt)?;
        if !confirmed {
            return Err(AppError::State(
                "未生成新公共状态密钥；旧密钥仍然有效，未作修改".to_owned(),
            ));
        }
        backend.allow_status_key_rotation();
        let checkpoint = load_operation_checkpoint()?.ok_or_else(|| {
            AppError::State("公共状态密钥恢复缺少 operation checkpoint".to_owned())
        })?;
        result = resume_onboard(
            &mut backend,
            &deployment_input,
            checkpoint,
            CliEventSink,
            &mut checkpoint_store,
        )
        .await;
    }
    let result = result.map_err(application_error)?;

    let credential_lines = result
        .credentials
        .iter()
        .map(|credential| {
            let label = match credential.kind.as_str() {
                "newapi_admin" => "New API    ",
                "kuma_admin" => "Uptime Kuma",
                _ => credential.kind.as_str(),
            };
            format!(
                "{label} {} / {}",
                credential.username,
                credential.password.expose_secret()
            )
        })
        .collect::<Vec<_>>();
    if !credential_lines.is_empty() {
        print_message(
            "管理员凭证",
            &format!(
                "{}\n\n请立即保存；凭证不会写入普通日志。",
                credential_lines.join("\n")
            ),
        );
    }
    tracing::debug!(
        operation_id = %result.operation_id,
        status = ?result.checkpoint.status,
        "onboard operation completed"
    );
    Ok(())
}

async fn run_sync(args: &SyncArgs) -> Result<()> {
    let mut config = load_deployment_config()?;
    config.resolve_passwords();
    let mut source = source_for_operation(&config).await?;
    let outcome = sync_deployment(
        &config,
        &mut source,
        SyncDeploymentRequest {
            include_pricing: args.pricing,
            force: args.force,
        },
        &CancellationToken::default(),
    )
    .await
    .map_err(application_error)?;
    print_success(&format!(
        "同步完成：{} 个分组，渠道新建 {}、更新 {}、禁用 {}，Kuma {} 个监控",
        outcome.group_count,
        outcome.channels_created,
        outcome.channels_updated,
        outcome.channels_disabled,
        outcome.kuma_monitor_count
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
    let status = read_deployment_status(&config, &CancellationToken::default())
        .map_err(application_error)?;
    let compose_status = format_container_status(&status.containers);
    let phases = status
        .phases
        .iter()
        .map(|(name, phase)| format!("{name}: {}", phase.status))
        .collect::<Vec<_>>()
        .join("\n");
    print_message(
        "部署状态",
        &format!(
            "目录：{}\nNew API：{}:{}\nUptime Kuma：{}:{}\n镜像：{}@{}\n最近同步：{}\n同步结果：{}\n\n阶段：\n{}\n\n容器：\n{}",
            status.directory,
            status.newapi_bind,
            status.newapi_port,
            status.kuma_bind,
            status.kuma_port,
            status.image,
            status.image_ref,
            status.last_sync_at,
            if status.last_sync_success {
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

async fn run_clean(args: &CleanArgs) -> Result<()> {
    if !args.yes {
        let confirmed =
            confirm("删除下游容器、生成配置和数据，但保留 onboard 配置、凭证和登录会话？")
                .initial_value(false)
                .interact()
                .map_err(AppError::from_prompt)?;
        if !confirmed {
            return Err(AppError::Cancelled);
        }
    }

    let mut config = load_deployment_config()?;
    config.resolve_passwords();
    clean_deployment(&config, &CancellationToken::default()).map_err(application_error)?;
    print_success("下游容器、生成配置和数据已清理；onboard 配置、凭证和登录会话已保留");
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
        let confirmed = confirm(
            "同时撤销这个源站账号的全部分组 Token 和公共状态密钥？这会让当前下游停止回源。",
        )
        .initial_value(false)
        .interact()
        .map_err(AppError::from_prompt)?;
        if !confirmed {
            return Err(AppError::Cancelled);
        }
    }

    let mut config = load_deployment_config()?;
    config.resolve_passwords();
    let mut source = if args.revoke_source {
        Some(source_for_operation(&config).await?)
    } else {
        None
    };
    let outcome = rollback_deployment(
        &config,
        source.as_mut(),
        args.revoke_source,
        &CancellationToken::default(),
    )
    .await
    .map_err(application_error)?;
    if outcome.source_status_key_revoked {
        print_success(&format!(
            "已撤销源站资源：{} 个分组 Token 和 1 个公共状态密钥",
            outcome.source_tokens_revoked
        ));
    }
    print_success("下游 Compose 项目、配置和数据已清理");
    Ok(())
}

fn load_saved_deployment_state() -> Result<Option<DeploymentState>> {
    storage::read(STATE_FILE)?
        .map(|content| {
            serde_json::from_slice(&content)
                .map_err(|error| AppError::State(format!("parse {STATE_FILE}: {error}")))
        })
        .transpose()
}

fn load_operation_checkpoint() -> Result<Option<crate::application::operation::OperationCheckpoint>>
{
    if let Some(content) = storage::read(OPERATION_FILE)? {
        let checkpoint = serde_json::from_slice(&content)
            .map_err(|error| AppError::State(format!("parse {OPERATION_FILE}: {error}")))?;
        return Ok(Some(checkpoint));
    }
    Ok(load_saved_deployment_state()?.and_then(|state| state.operation))
}

fn downstream_was_cleaned() -> Result<bool> {
    Ok(load_saved_deployment_state()?.is_some_and(|state| {
        state
            .phases
            .get(DOWNSTREAM_CLEANUP_PHASE)
            .is_some_and(|phase| phase.status == "DONE")
    }))
}

async fn clear_current_deployment_before_onboard() -> Result<()> {
    let has_state = storage::exists(STATE_FILE)?;
    let has_credentials = storage::exists(CREDENTIALS_FILE)?;
    if has_state && has_credentials {
        if downstream_was_cleaned()? {
            storage::clear_deployment()?;
            print_success("已清除保留的 onboard 配置，可以重新填写");
            return Ok(());
        }
        return run_rollback(&RollbackArgs {
            yes: false,
            revoke_source: false,
        })
        .await;
    }
    if has_state || has_credentials {
        return Err(AppError::State(
            "当前部署状态或凭证不完整，无法安全清理；请先检查 ~/.meowai-deploy".to_owned(),
        ));
    }
    let confirmed = confirm("删除当前未完成的 onboard 配置并重新填写？")
        .initial_value(false)
        .interact()
        .map_err(AppError::from_prompt)?;
    if !confirmed {
        return Err(AppError::Cancelled);
    }
    storage::clear_deployment()?;
    print_success("已清理未完成的 onboard 配置");
    Ok(())
}

fn load_deployment_config() -> Result<DeploymentConfig> {
    let path = storage::directory()?.join(CONFIG_FILE);
    let mut config = DeploymentConfig::from_file(&path)?;
    config.normalize();
    config.validate()?;
    Ok(config)
}

fn persist_deployment_config(config: &DeploymentConfig) -> Result<()> {
    let content = toml::to_string_pretty(config)
        .map_err(|error| AppError::State(format!("serialize deployment.toml: {error}")))?;
    storage::write(CONFIG_FILE, content.as_bytes())
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
        let mut source = SourceClient::from_session(&config.source_url, persisted)?;
        match source.validate_session().await {
            Ok(()) => {
                source.check_onboard_access().await?;
                persist_source_session(&source)?;
                return Ok(source);
            }
            Err(error) if is_source_authentication_error(&error) => {}
            Err(error) => return Err(error.into()),
        }
    }
    let (source, _) = if config.source_password.is_some() {
        authenticate_source(config).await?
    } else {
        reauthenticate_source(config).await?
    };
    persist_source_session(&source)?;
    Ok(source)
}

fn is_source_authentication_error(error: &SourceError) -> bool {
    match error {
        SourceError::AuthenticationRequired => true,
        SourceError::HttpStatus { status, .. } => {
            *status == reqwest::StatusCode::UNAUTHORIZED
                || *status == reqwest::StatusCode::FORBIDDEN
        }
        _ => false,
    }
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

fn print_action(message: &str) {
    println!("{} {}", style("→").cyan(), style(message).cyan());
}

fn print_done(message: &str) {
    println!("{} {}", style("✓").green(), message);
}

fn print_success(message: &str) {
    println!();
    println!("{} {}", style("✓").green(), style(message).bold());
    println!();
}

fn application_error(error: ApplicationError) -> AppError {
    if let Some(diagnostic) = &error.diagnostic {
        tracing::debug!(code = %error.code, diagnostic, "application operation failed");
    }
    error.into()
}

fn format_container_status(containers: &[ContainerStatus]) -> String {
    let rows = containers
        .iter()
        .map(|container| {
            let state = if container.health.is_empty() {
                container.state.clone()
            } else {
                format!("{}/{}", container.state, container.health)
            };
            if container.ports.is_empty() {
                format!("{}: {state}", container.name)
            } else {
                format!("{}: {state} · {}", container.name, container.ports)
            }
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        "没有运行中的容器".to_owned()
    } else {
        rows.join("\n")
    }
}

fn print_help() -> Result<()> {
    let mut command = Cli::command();
    command.print_help().map_err(AppError::from_prompt)?;
    println!();
    Ok(())
}
