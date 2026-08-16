use serde::Serialize;
use std::collections::BTreeSet;

use clap::CommandFactory;
use cliclack::{confirm, select, spinner};
use console::style;
use secrecy::ExposeSecret;

use crate::{
    cli::{CleanArgs, Cli, Command, DeploymentArgs, OnboardArgs, RollbackArgs, SyncArgs},
    config::{
        DeploymentConfig, Target, authenticate_source, interactive_config, reauthenticate_source,
    },
    doctor,
    error::{AppError, Result},
    lifecycle_outbox,
    source::{
        DeploymentMetadata, DeploymentRegistration, LifecycleReport, SourceClient, SourceError,
        StatusKeyProvision,
    },
    source_key_store,
    state::{DOWNSTREAM_CLEANUP_PHASE, DeploymentState, unix_timestamp},
    storage::{
        self, CONFIG_FILE, CREDENTIALS_FILE, DOWNSTREAM_CREDENTIALS_FILE, SESSION_FILE, STATE_FILE,
    },
    target::kuma,
    target::newapi::NewApiClient,
    target::{
        TargetExecutor,
        compose::{DeploymentRuntime, DeploymentSecrets},
    },
    updater,
};

pub async fn run(cli: Cli) -> Result<()> {
    match lifecycle_outbox::flush().await {
        Ok(sent) if sent > 0 => print_done(&format!("已补送 {sent} 条待处理生命周期事件")),
        Err(error) => eprintln!(
            "{}",
            style(format!("警告：待处理生命周期事件仍未送达：{error}")).yellow()
        ),
        _ => {}
    }
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
    let (mut config, mut source, identity) = if resume_existing {
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

    print_action("登记下游部署并写入控制面凭证");
    let registration_key = format!("reg_{}", crate::security::random_secret(32));
    let registration = source.register_deployment(&registration_key).await?;
    persist_downstream_registration(&config, &registration)?;
    source
        .report_lifecycle(
            &registration,
            "provisioning",
            "provisioning",
            "onboard started",
        )
        .await?;
    print_done("部署 ID、安装代次和四个控制面变量已安全写入本机及目标目录");

    print_action("读取源站分组");
    let catalog = source.groups().await?;
    print_done(&format!("已读取 {} 个可见分组", catalog.groups.len()));

    print_action("读取源站价格、计费、分组行为、首页、Seedance 和市场配置");
    let source_pricing = source.pricing().await?;
    print_done("源站价格、计费、分组行为、首页、Seedance 和市场配置已读取并校验");

    print_action("同步源站分组 Token");
    let token_sync = source.ensure_group_tokens(&catalog).await?;
    print_done("源站分组 Token 已就绪");

    print_action("准备源站公共状态密钥");
    let (status_key, shared_status_key) =
        resolve_source_status_key(&mut source, &config, identity.user_id).await?;
    print_done(if status_key.created {
        "源站公共状态密钥已创建"
    } else {
        "源站公共状态密钥已复用"
    });
    print_message(
        "源站资源",
        &format!(
            "账号：{}\n分组：{}\n分组 Token：新建 {}，复用 {}，修正 {}\n公共状态密钥：{}\n分组响应哈希：{}",
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

    print_action("准备下游部署状态");
    let mut deployment = DeploymentRuntime::prepare(
        &config,
        identity.user_id,
        &catalog.response_sha256,
        status_key.metadata.id,
        shared_status_key.as_ref(),
    )?;
    deployment.state.upstream_deployment_id = registration.deployment_id.clone();
    deployment.state.installation_generation = registration.installation_generation;
    deployment.state.control_plane_url = registration.control_plane_url.clone();
    deployment.persist_state()?;
    source_key_store::save(
        &config.source_url,
        identity.user_id,
        status_key.metadata.id,
        &deployment.secrets.public_status_source_key,
    )?;
    print_done("下游部署状态已就绪");
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
    print_action("安装目标主机更新服务");
    crate::target::updater::install(&deployment.executor, &config, deployment.state.newapi_port)?;
    print_done("已安装固定 digest 更新服务；不开放远程命令");
    deploy_base_stack_with_progress(&mut deployment, &config)?;
    print_action("初始化下游管理员和站点配置");
    let mut downstream = NewApiClient::connect(&deployment.executor, deployment.state.newapi_port)?;
    downstream
        .initialize_and_login(&config, &deployment.secrets.newapi_admin_password)
        .await?;
    downstream.configure_site(&config.website_name).await?;
    print_done("下游管理员已生成，站点配置已写入");

    print_action("导入价格、计费、分组行为、价格表、Seedance 和市场配置");
    let pricing_hashes = downstream.import_pricing(&source_pricing).await?;
    deployment.state.pricing_sha256 = pricing_hashes;
    deployment.state.mark_phase(
        "pricing",
        "DONE",
        "价格、计费、分组行为、价格表、Seedance 和市场配置已写入并回读一致",
    );
    deployment.persist_state()?;
    print_done("价格、计费、分组行为、价格表、Seedance 和市场配置已校验");

    print_action("同步下游分组渠道");
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
    print_done(&format!(
        "下游渠道已同步：新建 {}，复用 {}，更新 {}",
        channel_result.created, channel_result.reused, channel_result.updated
    ));
    deploy_kuma_with_progress(&mut deployment, &config)?;
    print_action("克隆公共状态页、分组和监控");
    let manifest = source
        .onboard_status_manifest(&deployment.secrets.public_status_source_key)
        .await?;
    let deployment_id = registration.deployment_id.clone();
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
    let public_status_url = kuma::internal_status_page_url(&kuma_sync.page_slug);
    downstream
        .configure_public_status_url(&public_status_url)
        .await?;
    deployment.state.mark_phase(
        "kuma",
        "DONE",
        format!(
            "status page {} and managed monitors synchronized",
            kuma_sync.page_slug
        ),
    );
    deployment.persist_state()?;
    print_done(&format!(
        "已同步 {} 个公共状态监控，公开状态页 {}",
        deployment.state.kuma_monitors.len(),
        public_status_url
    ));
    deployment.state.last_sync_at = unix_timestamp();
    deployment.state.last_sync_success = true;
    deployment.state.mark_phase(
        "onboard",
        "DONE",
        "base services, pricing, channels and public status initialized",
    );
    deployment.persist_state()?;
    persist_source_session(&source)?;
    source
        .update_deployment_metadata(
            &registration,
            &DeploymentMetadata {
                site_name: &config.website_name,
                container_name: &config.container_name,
                target_type: if matches!(config.target, Target::Local) {
                    "local"
                } else {
                    "ssh"
                },
                verified_primary_endpoint: "",
            },
        )
        .await?;
    source
        .report_lifecycle(&registration, "active", "active", "onboard completed")
        .await?;
    print_success("下游基础服务、管理员、价格、渠道和公共状态初始化完成");
    Ok(())
}

async fn run_sync(args: &SyncArgs) -> Result<()> {
    let mut config = load_deployment_config()?;
    config.resolve_passwords();
    let mut deployment = DeploymentRuntime::prepare(&config, 0, "", 0, None)?;
    let registration = load_downstream_registration()?.ok_or_else(|| {
        AppError::State(
            "missing upstream deployment registration; run onboard before sync".to_owned(),
        )
    })?;
    apply_authoritative_registration(&mut deployment.state, &registration)?;
    deployment.persist_state()?;
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
    deploy_base_stack_with_progress(deployment, config)?;
    let mut source = source_for_operation(config).await?;
    let identity = source
        .identity()
        .cloned()
        .ok_or_else(|| AppError::State("source session has no identity".to_owned()))?;
    if deployment.state.source_user_id != 0 && deployment.state.source_user_id != identity.user_id {
        return Err(AppError::State(format!(
            "当前部署属于源站用户 {}，与本次登录用户 {} 不一致",
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
        .disable_removed_group_tokens(&active_group_ids)
        .await?;
    let token_sync = source.ensure_group_tokens(&catalog).await?;
    let status_key = source.ensure_onboard_status_key().await?;
    if let Some(key) = status_key.key() {
        deployment.secrets.public_status_source_key = key.clone();
    } else if deployment.state.status_key_id != 0
        && deployment.state.status_key_id != status_key.metadata.id
    {
        deployment.secrets.public_status_source_key =
            source_key_store::load(&config.source_url, identity.user_id, status_key.metadata.id)?
                .ok_or_else(|| {
                AppError::State(
                    "源站公共状态密钥已更换，但这台机器没有保存新密钥内容；请运行 onboard 恢复"
                        .to_owned(),
                )
            })?;
    }
    source_key_store::save(
        &config.source_url,
        identity.user_id,
        status_key.metadata.id,
        &deployment.secrets.public_status_source_key,
    )?;
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
        deployment.state.mark_phase(
            "pricing",
            "DONE",
            "价格、计费、分组行为、价格表、Seedance 和市场配置已重新导入并回读一致",
        );
    }

    deploy_kuma_with_progress(deployment, config)?;
    let manifest = source
        .onboard_status_manifest(&deployment.secrets.public_status_source_key)
        .await?;
    let deployment_id = deployment.state.upstream_deployment_id.trim();
    if deployment_id.is_empty() {
        return Err(AppError::State(
            "upstream deployment registration has no deployment ID".to_owned(),
        ));
    }
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
    let public_status_url = kuma::internal_status_page_url(&kuma_sync.page_slug);
    downstream
        .configure_public_status_url(&public_status_url)
        .await?;
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
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
    executor.validate_access()?;
    let registration = load_downstream_registration()?;
    let mut cleanup_report_confirmed = true;
    if let Some(registration) = &registration {
        cleanup_report_confirmed = queue_lifecycle_report(
            registration,
            "cleanup_started",
            "cleanup_started",
            "clean started",
            true,
            args.yes,
        )
        .await?;
    }
    clean_downstream(&config, &executor)?;
    let mut removed_report_confirmed = true;
    if let Some(registration) = &registration {
        removed_report_confirmed = queue_lifecycle_report(
            registration,
            "removed",
            "removed",
            "clean completed",
            false,
            true,
        )
        .await?;
    }
    if let Some(mut state) = load_saved_deployment_state()? {
        state.mark_phase(
            DOWNSTREAM_CLEANUP_PHASE,
            "DONE",
            "downstream resources removed",
        );
        persist_deployment_state(&state)?;
    }
    if cleanup_report_confirmed && removed_report_confirmed {
        print_success(
            "下游容器、生成配置和数据已清理；上游已确认 removed，onboard 配置、凭证和登录会话已保留",
        );
    } else {
        print_success(
            "下游容器、生成配置和数据已清理；未送达的生命周期事件已加密排队，onboard 配置、凭证和登录会话已保留",
        );
    }
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
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
    executor.validate_access()?;
    let registration = load_downstream_registration()?;
    let mut cleanup_report_confirmed = true;
    if let Some(registration) = &registration {
        cleanup_report_confirmed = queue_lifecycle_report(
            registration,
            "cleanup_started",
            "cleanup_started",
            "rollback started",
            true,
            args.yes,
        )
        .await?;
    }
    let state = load_saved_deployment_state()?;
    if let Some(state) = &state {
        validate_cleanup_state(&config, &executor, state)?;
    }
    if args.revoke_source {
        let mut source = source_for_operation(&config).await?;
        let identity = source
            .identity()
            .cloned()
            .ok_or_else(|| AppError::State("source session has no identity".to_owned()))?;
        if state.as_ref().is_some_and(|state| {
            state.source_user_id != 0 && state.source_user_id != identity.user_id
        }) {
            return Err(AppError::State(
                "source account does not own this deployment".to_owned(),
            ));
        }
        let revoked_tokens = source.revoke_account_group_tokens().await?;
        source.revoke_onboard_status_key().await?;
        source_key_store::remove(&config.source_url, identity.user_id)?;
        print_success(&format!(
            "已撤销源站资源：{} 个分组 Token 和 1 个公共状态密钥",
            revoked_tokens
        ));
    } else if let (Some(state), Some(content)) = (state.as_ref(), storage::read(CREDENTIALS_FILE)?)
    {
        if state.source_user_id > 0 && state.status_key_id > 0 {
            let secrets = DeploymentSecrets::parse(&content)?;
            source_key_store::save(
                &config.source_url,
                state.source_user_id,
                state.status_key_id,
                &secrets.public_status_source_key,
            )?;
        }
    }

    clean_downstream(&config, &executor)?;
    let mut removed_report_confirmed = true;
    if let Some(registration) = &registration {
        removed_report_confirmed = queue_lifecycle_report(
            registration,
            "removed",
            "removed",
            "rollback completed",
            false,
            true,
        )
        .await?;
    }
    storage::clear_deployment()?;
    storage::remove(DOWNSTREAM_CREDENTIALS_FILE)?;
    if cleanup_report_confirmed && removed_report_confirmed {
        print_success("下游 Compose 项目、配置和数据已清理；上游已确认 removed");
    } else {
        print_success(
            "下游 Compose 项目、配置和数据已清理；未送达的生命周期事件已加密排队并保留最小重试材料",
        );
    }
    Ok(())
}

async fn queue_lifecycle_report(
    registration: &DeploymentRegistration,
    event_type: &str,
    state: &str,
    reason: &str,
    confirm_before_destructive_action: bool,
    preconfirmed: bool,
) -> Result<bool> {
    let report = LifecycleReport::new(event_type, state, reason);
    let event_id = lifecycle_outbox::enqueue(registration, report)?;
    match lifecycle_outbox::flush().await {
        Ok(_) => Ok(true),
        Err(error) => {
            eprintln!(
                "{}",
                style(format!(
                    "警告：上游暂时不可达，无法保证 {event_type} 已即时显示；事件已写入 0600 加密 outbox：{error}"
                ))
                .yellow()
            );
            if confirm_before_destructive_action && !preconfirmed {
                let confirmed = confirm("仍继续删除下游资源，并由后续 CLI 自动重试上报？")
                    .initial_value(false)
                    .interact()
                    .map_err(AppError::from_prompt)?;
                if !confirmed {
                    lifecycle_outbox::remove(&event_id)?;
                    return Err(AppError::Cancelled);
                }
            }
            Ok(false)
        }
    }
}

fn clean_downstream(config: &DeploymentConfig, executor: &TargetExecutor) -> Result<()> {
    executor.compose(&config.container_name, &["down", "--remove-orphans"])?;
    executor
		.run_in_directory("if command -v systemctl >/dev/null 2>&1 && [ \"$(id -u)\" -eq 0 ]; then systemctl disable --now meowai-deploy-updater.timer 2>/dev/null || true; rm -f /etc/systemd/system/meowai-deploy-updater.service /etc/systemd/system/meowai-deploy-updater.timer; systemctl daemon-reload || true; fi\nrm -f secrets.env downstream-credentials.env updater-credentials.env docker-compose.yml kuma-helper.js meowai-deploy-updater.sh meowai-deploy-updater.service meowai-deploy-updater.timer\nrm -rf data")?;
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

fn persist_deployment_state(state: &DeploymentState) -> Result<()> {
    let content = serde_json::to_vec_pretty(state)
        .map_err(|error| AppError::State(format!("serialize {STATE_FILE}: {error}")))?;
    storage::write(STATE_FILE, &content)
}

fn downstream_was_cleaned() -> Result<bool> {
    Ok(load_saved_deployment_state()?.is_some_and(|state| {
        state
            .phases
            .get(DOWNSTREAM_CLEANUP_PHASE)
            .is_some_and(|phase| phase.status == "DONE")
    }))
}

fn validate_cleanup_state(
    config: &DeploymentConfig,
    executor: &TargetExecutor,
    state: &DeploymentState,
) -> Result<()> {
    if state.deployment_id != config.deployment_id()
        || state.container_name != config.container_name
        || state.directory != config.directory.to_string_lossy()
    {
        return Err(AppError::State(
            "state.json 属于另一个部署，无法执行清理".to_owned(),
        ));
    }
    if state.target_fingerprint != executor.fingerprint()? {
        return Err(AppError::State(
            "目标主机与上次部署时不一致，无法执行清理".to_owned(),
        ));
    }
    Ok(())
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

#[derive(Serialize, serde::Deserialize)]

struct PersistedDownstreamCredentials {
    deployment_id: String,
    installation_generation: u32,
    control_plane_url: String,
    report_credential: String,
    pull_credential: String,
}

fn load_downstream_registration() -> Result<Option<DeploymentRegistration>> {
    let Some(content) = storage::read(DOWNSTREAM_CREDENTIALS_FILE)? else {
        return Ok(None);
    };
    let stored: PersistedDownstreamCredentials = serde_json::from_slice(&content)
        .map_err(|error| AppError::State(format!("parse downstream credentials: {error}")))?;
    Ok(Some(DeploymentRegistration {
        deployment_id: stored.deployment_id,
        installation_generation: stored.installation_generation,
        control_plane_url: stored.control_plane_url,
        report_credential: secrecy::SecretString::from(stored.report_credential),
        pull_credential: secrecy::SecretString::from(stored.pull_credential),
        heartbeat_interval_seconds: 60,
        snapshot_interval_seconds: 300,
        silent_updates_enabled: true,
        release_schema_version: "1".to_owned(),
    }))
}

fn apply_authoritative_registration(
    state: &mut DeploymentState,
    registration: &DeploymentRegistration,
) -> Result<()> {
    if !state.upstream_deployment_id.is_empty()
        && state.upstream_deployment_id != registration.deployment_id
    {
        return Err(AppError::State(
            "stored deployment state does not match the upstream registration".to_owned(),
        ));
    }
    state.upstream_deployment_id = registration.deployment_id.clone();
    state.installation_generation = registration.installation_generation;
    state.control_plane_url = registration.control_plane_url.clone();
    Ok(())
}

fn persist_downstream_registration(
    config: &DeploymentConfig,
    registration: &DeploymentRegistration,
) -> Result<()> {
    for (name, value) in [
        ("MEOWAI_DEPLOYMENT_ID", registration.deployment_id.as_str()),
        (
            "MEOWAI_CONTROL_PLANE_URL",
            registration.control_plane_url.as_str(),
        ),
        (
            "MEOWAI_REPORT_CREDENTIAL",
            registration.report_credential.expose_secret(),
        ),
        (
            "MEOWAI_PULL_CREDENTIAL",
            registration.pull_credential.expose_secret(),
        ),
        ("MEOWAI_CURRENT_IMAGE_DIGEST", config.image_ref.as_str()),
        ("MEOWAI_ALLOWED_IMAGE_REPOSITORY", config.image.as_str()),
        ("MEOWAI_CONTAINER_NAME", config.container_name.as_str()),
    ] {
        crate::security::validate_env_value(name, value)?;
    }
    let stored = PersistedDownstreamCredentials {
        deployment_id: registration.deployment_id.clone(),
        installation_generation: registration.installation_generation,
        control_plane_url: registration.control_plane_url.clone(),
        report_credential: registration.report_credential.expose_secret().to_owned(),
        pull_credential: registration.pull_credential.expose_secret().to_owned(),
    };
    let content = serde_json::to_vec_pretty(&stored)
        .map_err(|error| AppError::State(format!("serialize downstream credentials: {error}")))?;
    storage::write(DOWNSTREAM_CREDENTIALS_FILE, &content)?;
    write_target_downstream_credentials(config, registration)
}

fn write_target_downstream_credentials(
    config: &DeploymentConfig,
    registration: &DeploymentRegistration,
) -> Result<()> {
    let target = TargetExecutor::new(config.target.clone(), config.directory.clone());
    target.prepare()?;
    let target_content = format!(
        "MEOWAI_DEPLOYMENT_ID={}\nMEOWAI_INSTALLATION_GENERATION={}\nMEOWAI_CONTROL_PLANE_URL={}\nMEOWAI_REPORT_CREDENTIAL={}\nMEOWAI_PULL_CREDENTIAL={}\nMEOWAI_HEARTBEAT_INTERVAL_SECONDS={}\nMEOWAI_SNAPSHOT_INTERVAL_SECONDS={}\nMEOWAI_CURRENT_IMAGE_DIGEST={}\nMEOWAI_ALLOWED_IMAGE_REPOSITORY={}\nMEOWAI_CONTAINER_NAME={}\nMEOWAI_UPDATER_SOCKET_PATH=/run/meowai/updater.sock\n",
        registration.deployment_id,
        registration.installation_generation,
        registration.control_plane_url,
        registration.report_credential.expose_secret(),
        registration.pull_credential.expose_secret(),
        registration.heartbeat_interval_seconds,
        registration.snapshot_interval_seconds,
        config.image_ref,
        config.image,
        config.container_name,
    );
    target.write_file(
        "downstream-credentials.env",
        target_content.as_bytes(),
        true,
    )?;
    target.run_in_directory(
        r#"set -eu
file=downstream-credentials.env
test -s "$file"
mode=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file")
test "$mode" = 600
for key in MEOWAI_DEPLOYMENT_ID MEOWAI_INSTALLATION_GENERATION MEOWAI_CONTROL_PLANE_URL MEOWAI_REPORT_CREDENTIAL MEOWAI_PULL_CREDENTIAL MEOWAI_HEARTBEAT_INTERVAL_SECONDS MEOWAI_SNAPSHOT_INTERVAL_SECONDS MEOWAI_CURRENT_IMAGE_DIGEST MEOWAI_ALLOWED_IMAGE_REPOSITORY MEOWAI_CONTAINER_NAME MEOWAI_UPDATER_SOCKET_PATH; do
  count=$(grep -c "^${key}=..*" "$file" || true)
  test "$count" = 1
done"#,
    )?;
    Ok(())
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

async fn resolve_source_status_key(
    source: &mut SourceClient,
    config: &DeploymentConfig,
    source_user_id: i64,
) -> Result<(StatusKeyProvision, Option<secrecy::SecretString>)> {
    source_key_store::ensure_writable()?;
    let mut provision = source.ensure_onboard_status_key().await?;
    if let Some(key) = provision.key() {
        let key = key.clone();
        source_key_store::save(
            &config.source_url,
            source_user_id,
            provision.metadata.id,
            &key,
        )?;
        return Ok((provision, Some(key)));
    }
    if let Some(key) =
        source_key_store::load(&config.source_url, source_user_id, provision.metadata.id)?
    {
        return Ok((provision, Some(key)));
    }
    if current_deployment_has_status_key(source_user_id, provision.metadata.id)? {
        return Ok((provision, None));
    }

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
    source.revoke_onboard_status_key().await?;
    source_key_store::remove(&config.source_url, source_user_id)?;
    provision = source.ensure_onboard_status_key().await?;
    let key = provision
        .key()
        .cloned()
        .ok_or_else(|| AppError::State("源站生成新公共状态密钥后没有返回密钥内容".to_owned()))?;
    source_key_store::save(
        &config.source_url,
        source_user_id,
        provision.metadata.id,
        &key,
    )?;
    Ok((provision, Some(key)))
}

fn current_deployment_has_status_key(source_user_id: i64, status_key_id: i64) -> Result<bool> {
    if !storage::exists(CREDENTIALS_FILE)? {
        return Ok(false);
    }
    let Some(content) = storage::read(STATE_FILE)? else {
        return Ok(false);
    };
    let state: DeploymentState = serde_json::from_slice(&content)
        .map_err(|error| AppError::State(format!("parse {STATE_FILE}: {error}")))?;
    Ok(state.source_user_id == source_user_id && state.status_key_id == status_key_id)
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

fn deploy_base_stack_with_progress(
    deployment: &mut DeploymentRuntime,
    config: &DeploymentConfig,
) -> Result<()> {
    let progress = spinner();
    progress.start("正在准备 New API、PostgreSQL 和 Redis");
    match deployment.deploy_base_stack(config, |message| progress.set_message(message)) {
        Ok(()) => {
            progress.stop(format!(
                "基础服务已就绪，New API 端口 {}",
                deployment.state.newapi_port
            ));
            Ok(())
        }
        Err(error) => {
            progress.error("New API、PostgreSQL 和 Redis 部署失败");
            Err(error)
        }
    }
}

fn deploy_kuma_with_progress(
    deployment: &mut DeploymentRuntime,
    config: &DeploymentConfig,
) -> Result<()> {
    let progress = spinner();
    progress.start("正在准备 Uptime Kuma 2.5.0");
    match deployment.deploy_kuma(config, |message| progress.set_message(message)) {
        Ok(()) => {
            progress.stop(format!(
                "Uptime Kuma 已就绪，端口 {}",
                deployment.state.kuma_port
            ));
            Ok(())
        }
        Err(error) => {
            progress.error("Uptime Kuma 部署失败");
            Err(error)
        }
    }
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

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use secrecy::SecretString;

    use super::*;

    fn registration() -> DeploymentRegistration {
        DeploymentRegistration {
            deployment_id: "dep_target_credentials".to_owned(),
            installation_generation: 7,
            control_plane_url: "http://127.0.0.1:3004/api".to_owned(),
            report_credential: SecretString::from("report-secret"),
            pull_credential: SecretString::from("pull-secret"),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: true,
            release_schema_version: "1".to_owned(),
        }
    }

    #[test]
    fn target_credentials_are_private_and_read_back_complete() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut config = DeploymentConfig::default();
        config.directory = temporary.path().join("deployment");
        config.image_ref =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();

        write_target_downstream_credentials(&config, &registration())
            .expect("write target credentials");

        let path = config.directory.join("downstream-credentials.env");
        let metadata = fs::metadata(&path).expect("target credentials metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let content = fs::read_to_string(path).expect("read target credentials");
        for key in [
            "MEOWAI_DEPLOYMENT_ID",
            "MEOWAI_INSTALLATION_GENERATION",
            "MEOWAI_CONTROL_PLANE_URL",
            "MEOWAI_REPORT_CREDENTIAL",
            "MEOWAI_PULL_CREDENTIAL",
            "MEOWAI_HEARTBEAT_INTERVAL_SECONDS",
            "MEOWAI_SNAPSHOT_INTERVAL_SECONDS",
            "MEOWAI_CURRENT_IMAGE_DIGEST",
            "MEOWAI_ALLOWED_IMAGE_REPOSITORY",
            "MEOWAI_CONTAINER_NAME",
            "MEOWAI_UPDATER_SOCKET_PATH",
        ] {
            assert_eq!(
                content
                    .lines()
                    .filter(|line| line.starts_with(&format!("{key}=")))
                    .count(),
                1,
                "expected one non-empty {key} entry"
            );
            assert!(!content.contains(&format!("{key}=\n")));
        }
        assert!(content.contains("MEOWAI_UPDATER_SOCKET_PATH=/run/meowai/updater.sock\n"));
    }

    #[test]
    fn sync_uses_the_upstream_registration_as_the_authoritative_identity() {
        let mut state = DeploymentState {
            schema_version: 1,
            deployment_id: "local-derived-id".to_owned(),
            upstream_deployment_id: String::new(),
            installation_generation: 0,
            control_plane_url: String::new(),
            target_fingerprint: String::new(),
            container_name: String::new(),
            directory: String::new(),
            newapi_port: 0,
            kuma_port: 0,
            image: String::new(),
            image_ref: String::new(),
            image_digest: String::new(),
            source_user_id: 0,
            source_group_sha256: String::new(),
            status_key_id: 0,
            manifest_sha256: String::new(),
            pricing_sha256: Default::default(),
            channels: Default::default(),
            kuma_monitors: Default::default(),
            phases: Default::default(),
            last_sync_at: 0,
            last_sync_success: false,
        };
        let registration = registration();

        apply_authoritative_registration(&mut state, &registration)
            .expect("apply upstream registration");

        assert_eq!(state.deployment_id, "local-derived-id");
        assert_eq!(state.upstream_deployment_id, registration.deployment_id);
        assert_eq!(
            state.installation_generation,
            registration.installation_generation
        );
        assert_eq!(state.control_plane_url, registration.control_plane_url);
    }

    #[test]
    fn sync_rejects_a_registration_that_conflicts_with_persisted_upstream_identity() {
        let mut state = DeploymentState {
            schema_version: 1,
            deployment_id: "local-derived-id".to_owned(),
            upstream_deployment_id: "dep_original".to_owned(),
            installation_generation: 1,
            control_plane_url: String::new(),
            target_fingerprint: String::new(),
            container_name: String::new(),
            directory: String::new(),
            newapi_port: 0,
            kuma_port: 0,
            image: String::new(),
            image_ref: String::new(),
            image_digest: String::new(),
            source_user_id: 0,
            source_group_sha256: String::new(),
            status_key_id: 0,
            manifest_sha256: String::new(),
            pricing_sha256: Default::default(),
            channels: Default::default(),
            kuma_monitors: Default::default(),
            phases: Default::default(),
            last_sync_at: 0,
            last_sync_success: false,
        };

        let error = apply_authoritative_registration(&mut state, &registration())
            .expect_err("conflicting registration must be rejected");

        assert!(error.to_string().contains("does not match"));
        assert_eq!(state.upstream_deployment_id, "dep_original");
    }

    #[test]
    fn target_credentials_failure_leaves_no_partial_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let blocked = temporary.path().join("not-a-directory");
        fs::write(&blocked, b"blocked").expect("create blocking file");
        let mut config = DeploymentConfig::default();
        config.directory = blocked.clone();
        config.image_ref =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();

        assert!(write_target_downstream_credentials(&config, &registration()).is_err());
        assert!(!blocked.join("downstream-credentials.env").exists());
    }
}
