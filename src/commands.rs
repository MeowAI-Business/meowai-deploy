use clap::CommandFactory;
use cliclack::{confirm, select};
use console::style;
use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    application::{
        error::ApplicationError,
        manage::{ContainerStatus, clean_deployment, read_deployment_status, rollback_deployment},
        onboard::{
            DeploymentStateCheckpointStore, ProductionOnboardBackend, resume_onboard, start_onboard,
        },
        operation::{
            CancellationToken, EventSeverity, EventSink, OperationEvent, OperationEventKind,
            OperationStatus,
        },
    },
    bootstrap,
    cli::{CleanArgs, Cli, Command, DeploymentArgs, OnboardArgs, RollbackArgs, SyncArgs},
    config::{DeploymentConfig, authenticate_source, interactive_config, reauthenticate_source},
    doctor,
    error::{AppError, Result},
    lifecycle_outbox, platform,
    pricing::{MarginPreview, MarginRisk, PricingConfig},
    security::sha256_hex,
    source::{
        GroupCatalog, GroupTokenPlan, RemovedGroupTokenPlan, SourceClient, SourceError,
        StatusManifest,
    },
    state::{
        DOWNSTREAM_CLEANUP_PHASE, DeploymentState, SNAPSHOT_SCHEMA_VERSION, SyncSnapshot,
        load_snapshot, save_snapshot, unix_timestamp,
    },
    storage::{
        self, CONFIG_FILE, CREDENTIALS_FILE, DOWNSTREAM_LAST_SEEN_SNAPSHOT, LAST_APPLIED_SNAPSHOT,
        OPERATION_FILE, PRE_APPLY_SNAPSHOT, SESSION_FILE, SOURCE_LAST_SEEN_SNAPSHOT, STATE_FILE,
    },
    sync_plan::{
        FieldDiff, RiskLevel, SnapshotClassification, SourceSnapshotInput, SyncModule, SyncPlan,
        advance_last_applied, build_source_modules, checkpoint_last_applied, parse_modules,
        snapshot_from_modules, snapshots_match, update_snapshot_module,
    },
    target::compose::DeploymentRuntime,
    target::kuma,
    target::newapi::NewApiClient,
    updater, web,
};

#[cfg(test)]
use crate::source::DeploymentRegistration;

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
    match lifecycle_outbox::flush().await {
        Ok(sent) if sent > 0 => print_done(&format!("已补送 {sent} 条待处理生命周期事件")),
        Err(error) => eprintln!(
            "{}",
            style(format!("警告：待处理生命周期事件仍未送达：{error}")).yellow()
        ),
        _ => {}
    }
    if !matches!(cli.command, Some(Command::Update(_) | Command::Web(_))) {
        updater::check_periodically().await;
    }
    match cli.command {
        None if platform::should_launch_webui_without_args() => {
            web::run(&crate::cli::WebArgs {
                host: "0.0.0.0".parse().expect("valid default WebUI host"),
                port: 0,
                no_open: false,
                config: None,
            })
            .await
        }
        None => print_help(),
        Some(Command::Bootstrap(args)) => bootstrap::run(&args),
        Some(Command::Web(args)) => web::run(&args).await,
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
    let _operation_lock = storage::acquire_operation_lock()?;
    if let Some(path) = &args.write_config {
        DeploymentConfig::write_template(path)?;
        print_message(
            "配置模板",
            &format!("已写入非敏感配置到 {}", path.display()),
        );
        return Ok(());
    }
    doctor::preflight_onboard(args)?;
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
    let deployment_input = config.deployment_input();
    if load_saved_deployment_state()?
        .as_ref()
        .is_some_and(DeploymentState::downstream_is_initialized)
    {
        print_message(
            "已存在部署",
            "检测到下游已经完成初始化；onboard 将转入安全 sync，所有模块默认 No。",
        );
        let sync_args = SyncArgs {
            check: args.dry_run || args.non_interactive,
            details: false,
            apply: Vec::new(),
            pricing: false,
            force: false,
            plan_fingerprint: None,
        };
        return run_sync_loaded(&sync_args, &config).await;
    }

    print_action("读取源站分组");
    let catalog = source.groups().await?;
    print_done(&format!("已读取 {} 个可见分组", catalog.groups.len()));

    print_action("读取源站价格、计费、分组行为、首页、Seedance 和市场配置");
    let source_pricing = source.pricing().await?;
    print_done("源站价格、计费、分组行为、首页、Seedance 和市场配置已读取并校验");

    print_deployment_preview(&config);
    let group_margins = source_pricing.group_margin_previews(&catalog);
    let seedance_margins = source_pricing.seedance_margin_previews();
    print_margin_previews("普通分组预计额度毛利", &group_margins);
    print_margin_previews("Seedance 预计额度毛利", &seedance_margins);
    if group_margins
        .iter()
        .chain(&seedance_margins)
        .any(|preview| preview.risk == MarginRisk::Loss)
    {
        return Err(AppError::State(
            "默认下游售价低于当前采购价；请先在源站修正终端售价或采购策略".to_owned(),
        ));
    }
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
        .initial_value(false)
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
    // Registration, updater installation and lifecycle reporting are handled by the shared
    // application onboard backend. The CLI only renders its events.
    Ok(())
}

async fn run_sync(args: &SyncArgs) -> Result<()> {
    let _operation_lock = storage::acquire_operation_lock()?;
    if args.pricing {
        return Err(AppError::InvalidConfig(
            "--pricing 已废弃；请使用 --apply group_pricing,model_pricing,units,seedance,site 明确选择模块"
                .to_owned(),
        ));
    }
    parse_modules(&args.apply).map_err(AppError::InvalidConfig)?;
    let mut config = load_deployment_config()?;
    config.resolve_passwords();
    run_sync_loaded(args, &config).await
}

pub(crate) async fn run_sync_loaded(args: &SyncArgs, config: &DeploymentConfig) -> Result<()> {
    run_sync_loaded_with_credentials(args, config, None).await
}

pub(crate) async fn run_sync_loaded_with_credentials(
    args: &SyncArgs,
    config: &DeploymentConfig,
    ssh_password: Option<secrecy::SecretString>,
) -> Result<()> {
    run_sync_loaded_with_credentials_mode(args, config, ssh_password, true).await
}

pub(crate) async fn run_sync_loaded_with_web_credentials(
    args: &SyncArgs,
    config: &DeploymentConfig,
    ssh_password: Option<secrecy::SecretString>,
) -> Result<()> {
    run_sync_loaded_with_credentials_mode(args, config, ssh_password, false).await
}

async fn run_sync_loaded_with_credentials_mode(
    args: &SyncArgs,
    config: &DeploymentConfig,
    ssh_password: Option<secrecy::SecretString>,
    allow_prompt: bool,
) -> Result<()> {
    let mut deployment = DeploymentRuntime::load_existing_with_ssh_password(config, ssh_password)?;
    if let Some(registration) =
        crate::application::deployment_control::load_registration().map_err(application_error)?
    {
        crate::application::deployment_control::apply_registration(
            &mut deployment.state,
            &registration,
        )
        .map_err(application_error)?;
        deployment.persist_state()?;
    }
    let result = run_sync_inner(args, config, &mut deployment, allow_prompt).await;
    deployment.state.last_sync_at = unix_timestamp();
    deployment.state.last_sync_success =
        result.is_ok() || matches!(result, Err(AppError::SyncChangesDetected(_)));
    let _ = deployment.persist_state();
    result
}

struct SyncObservation {
    source_snapshot: SyncSnapshot,
    downstream_snapshot: SyncSnapshot,
    catalog: GroupCatalog,
    pricing: PricingConfig,
    token_plan: GroupTokenPlan,
    removed_tokens: Vec<RemovedGroupTokenPlan>,
    manifest: StatusManifest,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SyncPlanView {
    pub fingerprint: String,
    pub modules: Vec<SyncModuleView>,
    pub group_margins: Vec<MarginPreviewView>,
    pub seedance_margins: Vec<MarginPreviewView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SyncModuleView {
    pub module: SyncModule,
    pub label: &'static str,
    pub actionable: bool,
    pub conflict: bool,
    pub diffs: Vec<FieldDiff>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct MarginPreviewView {
    pub name: String,
    pub purchase: Option<f64>,
    pub sales: f64,
    pub margin_percent: Option<f64>,
    pub risk: &'static str,
}

pub(crate) async fn build_sync_plan_view(
    config: &DeploymentConfig,
    ssh_password: Option<secrecy::SecretString>,
) -> Result<SyncPlanView> {
    let mut deployment = DeploymentRuntime::load_existing_with_ssh_password(config, ssh_password)?;
    if let Some(registration) =
        crate::application::deployment_control::load_registration().map_err(application_error)?
    {
        crate::application::deployment_control::apply_registration(
            &mut deployment.state,
            &registration,
        )
        .map_err(application_error)?;
    }
    let mut source = source_for_operation_noninteractive(config).await?;
    let identity = source
        .identity()
        .ok_or_else(|| AppError::State("source session has no identity".to_owned()))?;
    if deployment.state.source_user_id != 0 && deployment.state.source_user_id != identity.user_id {
        return Err(AppError::State("当前源站账号不属于这个部署".to_owned()));
    }
    let mut downstream = NewApiClient::connect(&deployment.executor, deployment.state.newapi_port)?;
    downstream
        .login_existing(config, &deployment.secrets.newapi_admin_password)
        .await?;
    let observation =
        collect_sync_observation(&mut source, &downstream, config, &deployment).await?;
    save_snapshot(SOURCE_LAST_SEEN_SNAPSHOT, &observation.source_snapshot)?;
    save_snapshot(
        DOWNSTREAM_LAST_SEEN_SNAPSHOT,
        &observation.downstream_snapshot,
    )?;
    let plan = SyncPlan::new(
        observation.source_snapshot.clone(),
        observation.downstream_snapshot.clone(),
        load_snapshot(LAST_APPLIED_SNAPSHOT)?,
    );
    let actionable = plan.actionable_modules();
    let modules = SyncModule::ALL
        .into_iter()
        .map(|module| {
            let diffs = plan.diffs.get(&module).cloned().unwrap_or_default();
            SyncModuleView {
                module,
                label: module.label(),
                actionable: actionable.contains(&module),
                conflict: diffs
                    .iter()
                    .any(|diff| diff.classification == SnapshotClassification::Conflict),
                diffs,
            }
        })
        .collect();
    let (group_margins, seedance_margins) = current_margin_previews(&observation);
    Ok(SyncPlanView {
        fingerprint: plan.fingerprint(),
        modules,
        group_margins: group_margins
            .into_iter()
            .map(MarginPreviewView::from)
            .collect(),
        seedance_margins: seedance_margins
            .into_iter()
            .map(MarginPreviewView::from)
            .collect(),
    })
}

impl From<MarginPreview> for MarginPreviewView {
    fn from(value: MarginPreview) -> Self {
        let risk = match value.risk {
            MarginRisk::Profitable => "profitable",
            MarginRisk::ZeroMargin => "zero_margin",
            MarginRisk::Loss => "loss",
            MarginRisk::Unknown => "unknown",
        };
        Self {
            name: value.name,
            purchase: value.purchase,
            sales: value.sales,
            margin_percent: value.margin_percent,
            risk,
        }
    }
}

async fn run_sync_inner(
    args: &SyncArgs,
    config: &DeploymentConfig,
    deployment: &mut DeploymentRuntime,
    allow_prompt: bool,
) -> Result<()> {
    let mut source = source_for_operation_mode(config, allow_prompt).await?;
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
    let mut downstream = NewApiClient::connect(&deployment.executor, deployment.state.newapi_port)?;
    downstream
        .login_existing(config, &deployment.secrets.newapi_admin_password)
        .await?;

    print_action("只读读取源站、下游 New API 和 Kuma 当前状态");
    let observation =
        collect_sync_observation(&mut source, &downstream, config, deployment).await?;
    save_snapshot(SOURCE_LAST_SEEN_SNAPSHOT, &observation.source_snapshot)?;
    save_snapshot(
        DOWNSTREAM_LAST_SEEN_SNAPSHOT,
        &observation.downstream_snapshot,
    )?;
    let last_applied = load_snapshot(LAST_APPLIED_SNAPSHOT)?;
    let plan = SyncPlan::new(
        observation.source_snapshot.clone(),
        observation.downstream_snapshot.clone(),
        last_applied,
    );
    if let Some(expected) = args.plan_fingerprint.as_deref()
        && plan.fingerprint() != expected
    {
        return Err(AppError::State(
            "同步计划已经过期；源站、下游或本地基线已变化，请重新生成计划".to_owned(),
        ));
    }
    print_done("只读同步计划已生成；尚未执行任何远端写入");
    let (group_margins, seedance_margins) = current_margin_previews(&observation);
    let risk_status = margin_risk_status(&group_margins, &seedance_margins);
    print_margin_previews("普通分组当前额度毛利", &group_margins);
    print_margin_previews("Seedance 当前额度毛利", &seedance_margins);
    print_sync_plan(&plan, args.details);
    let mut last_applied = plan.last_applied.clone().unwrap_or_default();
    let converged_modules = plan.converged_modules();
    if !converged_modules.is_empty() {
        for module in &converged_modules {
            update_snapshot_module(
                &mut last_applied,
                *module,
                plan.downstream_value(*module).clone(),
            );
        }
        save_snapshot(LAST_APPLIED_SNAPSHOT, &last_applied)?;
        println!(
            "{} 已推进 {} 个双方同向变化模块的本地基线；远端零写入",
            style("✓").green(),
            converged_modules.len()
        );
        println!();
    }
    if !effective_sales_match_source(&plan, &BTreeSet::new(), false) {
        println!(
            "{}",
            style("[HIGH] 下游有效售价与源站终端价不同；首页价格表将默认保留，避免展示错误售价")
                .yellow()
                .bold()
        );
        println!();
    }

    let changed_modules = plan.actionable_modules();
    if args.check {
        deployment.state.mark_phase(
            "sync",
            "CHECKED",
            format!(
                "只读检查完成，{} 个模块存在差异；{risk_status}",
                changed_modules.len()
            ),
        );
        if changed_modules.is_empty() {
            print_success("只读检查完成，没有待处理差异");
            return Ok(());
        }
        return Err(AppError::SyncChangesDetected(changed_modules.len()));
    }

    let actionable = SyncModule::ALL
        .into_iter()
        .filter(|module| plan.source_value(*module) != plan.downstream_value(*module))
        .collect::<BTreeSet<_>>();
    let requested = parse_modules(&args.apply).map_err(AppError::InvalidConfig)?;
    let mut selected = BTreeSet::new();
    if !requested.is_empty() {
        selected.extend(requested.intersection(&actionable).copied());
        for module in requested.difference(&actionable) {
            println!(
                "{} {} 当前没有可应用的远端差异",
                style("-").dim(),
                module.label()
            );
        }
    } else {
        for module in SyncModule::ALL {
            if !actionable.contains(&module) {
                continue;
            }
            let confirmed = confirm(format!("应用{}变化？", module.label()))
                .initial_value(false)
                .interact()
                .map_err(AppError::from_prompt)?;
            if confirmed {
                selected.insert(module);
            }
        }
    }

    if selected.is_empty() {
        deployment.state.mark_phase(
            "sync",
            "DONE",
            format!("只读计划完成，未应用任何变更；{risk_status}"),
        );
        print_success("未应用任何变更；源站、下游和 Kuma 远端状态保持不变");
        return Ok(());
    }

    println!();
    println!("{}", style("最终执行计划").bold());
    print_field(
        "将应用",
        &selected
            .iter()
            .map(|module| module.label())
            .collect::<Vec<_>>()
            .join("、"),
    );
    print_field(
        "将保留",
        &SyncModule::ALL
            .into_iter()
            .filter(|module| !selected.contains(module))
            .map(SyncModule::label)
            .collect::<Vec<_>>()
            .join("、"),
    );
    if requested.is_empty() {
        let confirmed = confirm("应用以上已选择的变化？")
            .initial_value(false)
            .interact()
            .map_err(AppError::from_prompt)?;
        if !confirmed {
            deployment.state.mark_phase(
                "sync",
                "DONE",
                format!("最终确认选择 No，未应用任何变更；{risk_status}"),
            );
            print_success("未应用任何变更；源站、下游和 Kuma 远端状态保持不变");
            return Ok(());
        }
    }

    print_action("重新读取源站和下游，校验同步计划未过期");
    let fresh = collect_sync_observation(&mut source, &downstream, config, deployment).await?;
    ensure_snapshots_are_current(
        &observation.source_snapshot,
        &observation.downstream_snapshot,
        &fresh.source_snapshot,
        &fresh.downstream_snapshot,
    )?;
    print_done("同步计划仍然有效");

    let mut pre_apply = load_snapshot(PRE_APPLY_SNAPSHOT)?.unwrap_or_else(SyncSnapshot::new);
    let mut completed = Vec::new();
    for module in SyncModule::ALL {
        if !selected.contains(&module) {
            continue;
        }
        print_action(&format!("应用{}", module.label()));
        let result = apply_and_checkpoint_sync_module(
            module,
            args.force,
            &plan,
            &selected,
            &fresh,
            &mut source,
            &downstream,
            config,
            deployment,
            &mut last_applied,
            &mut pre_apply,
        )
        .await;
        match result {
            Ok(()) => completed.push(module),
            Err(error) => {
                deployment.state.mark_phase(
                    module.name(),
                    "FAILED",
                    format!("{}应用或回读失败", module.label()),
                );
                let _ = deployment.persist_state();
                let pending = SyncModule::ALL
                    .into_iter()
                    .filter(|candidate| {
                        selected.contains(candidate)
                            && *candidate != module
                            && !completed.contains(candidate)
                    })
                    .collect::<Vec<_>>();
                print_apply_summary(&completed, Some(module), &pending);
                return Err(error);
            }
        }
    }

    let final_observation =
        collect_sync_observation(&mut source, &downstream, config, deployment).await?;
    let (final_group_margins, final_seedance_margins) = current_margin_previews(&final_observation);
    let final_risk_status = margin_risk_status(&final_group_margins, &final_seedance_margins);
    save_snapshot(
        SOURCE_LAST_SEEN_SNAPSHOT,
        &final_observation.source_snapshot,
    )?;
    save_snapshot(
        DOWNSTREAM_LAST_SEEN_SNAPSHOT,
        &final_observation.downstream_snapshot,
    )?;
    deployment.state.source_user_id = identity.user_id;
    deployment.state.source_group_sha256 = final_observation.catalog.response_sha256;
    deployment.state.snapshot_schema_version = SNAPSHOT_SCHEMA_VERSION;
    deployment.state.mark_phase(
        "sync",
        "DONE",
        format!(
            "已应用 {} 个明确选择的模块；{final_risk_status}",
            selected.len()
        ),
    );
    deployment.persist_state()?;
    persist_source_session(&source)?;
    print_apply_summary(&completed, None, &[]);
    print_success(&format!(
        "同步完成：已应用 {} 个明确选择的模块",
        selected.len()
    ));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_and_checkpoint_sync_module(
    module: SyncModule,
    force: bool,
    plan: &SyncPlan,
    selected: &BTreeSet<SyncModule>,
    observation: &SyncObservation,
    source: &mut SourceClient,
    downstream: &NewApiClient,
    config: &DeploymentConfig,
    deployment: &mut DeploymentRuntime,
    last_applied: &mut SyncSnapshot,
    pre_apply: &mut SyncSnapshot,
) -> Result<()> {
    update_snapshot_module(
        pre_apply,
        module,
        observation
            .downstream_snapshot
            .modules
            .get(module.name())
            .map(|module| module.data.clone())
            .unwrap_or(Value::Null),
    );
    save_snapshot(PRE_APPLY_SNAPSHOT, pre_apply)?;
    apply_sync_module(
        module,
        force,
        plan,
        selected,
        observation,
        source,
        downstream,
        config,
        deployment,
    )
    .await?;
    let current_modules = read_downstream_modules(
        downstream,
        &observation.catalog,
        &observation.pricing,
        &observation.manifest,
        &observation.source_snapshot,
        config,
        deployment,
    )
    .await?;
    let current = snapshot_from_modules(current_modules);
    let current_value = current
        .modules
        .get(module.name())
        .map(|module| module.data.clone())
        .unwrap_or(Value::Null);
    let checkpoint = if matches!(module, SyncModule::Channels | SyncModule::Kuma) {
        current_value
    } else {
        checkpoint_last_applied(
            plan.baseline_value(module),
            plan.source_value(module),
            plan.downstream_value(module),
            &current_value,
            force,
        )
    };
    update_snapshot_module(last_applied, module, checkpoint);
    save_snapshot(LAST_APPLIED_SNAPSHOT, last_applied)?;
    save_snapshot(DOWNSTREAM_LAST_SEEN_SNAPSHOT, &current)?;
    deployment
        .state
        .last_applied_at
        .insert(module.name().to_owned(), unix_timestamp());
    deployment.state.snapshot_schema_version = SNAPSHOT_SCHEMA_VERSION;
    deployment.state.mark_phase(
        module.name(),
        "DONE",
        format!("{}已应用并回读", module.label()),
    );
    deployment.persist_state()?;
    print_done(&format!("{}已应用并保存快照", module.label()));
    Ok(())
}

async fn collect_sync_observation(
    source: &mut SourceClient,
    downstream: &NewApiClient,
    config: &DeploymentConfig,
    deployment: &DeploymentRuntime,
) -> Result<SyncObservation> {
    let catalog = source.groups().await?;
    let pricing = source.pricing().await?;
    let active_group_ids = catalog
        .groups
        .iter()
        .map(|group| group.group_id.clone())
        .collect::<BTreeSet<_>>();
    let token_plan = source.plan_group_tokens(&catalog).await?;
    let removed_tokens = source.plan_removed_group_tokens(&active_group_ids).await?;
    let manifest = source
        .onboard_status_manifest(&deployment.secrets.public_status_source_key)
        .await?;
    let deployment_id = config.deployment_id();
    let status_key_sha256 = sha256_hex(
        format!(
            "Bearer {}",
            deployment.secrets.public_status_source_key.expose_secret()
        )
        .as_bytes(),
    );
    let source_modules = build_source_modules(SourceSnapshotInput {
        catalog: &catalog,
        pricing: &pricing,
        token_plan: &token_plan,
        removed_tokens: &removed_tokens,
        manifest: &manifest,
        deployment_id: &deployment_id,
        website_name: &config.website_name,
        container_source_url: &deployment.container_source_url,
        status_key_sha256: &status_key_sha256,
    })?;
    let source_snapshot = snapshot_from_modules(source_modules);
    let downstream_modules = read_downstream_modules(
        downstream,
        &catalog,
        &pricing,
        &manifest,
        &source_snapshot,
        config,
        deployment,
    )
    .await?;
    Ok(SyncObservation {
        source_snapshot,
        downstream_snapshot: snapshot_from_modules(downstream_modules),
        catalog,
        pricing,
        token_plan,
        removed_tokens,
        manifest,
    })
}

async fn read_downstream_modules(
    downstream: &NewApiClient,
    catalog: &GroupCatalog,
    pricing: &PricingConfig,
    manifest: &StatusManifest,
    source_snapshot: &SyncSnapshot,
    config: &DeploymentConfig,
    deployment: &DeploymentRuntime,
) -> Result<BTreeMap<SyncModule, Value>> {
    let deployment_id = config.deployment_id();
    let managed_channel_tags = catalog
        .groups
        .iter()
        .map(|group| crate::target::newapi::channel_tag(&deployment_id, &group.group_id))
        .collect::<BTreeSet<_>>();
    let mut modules = downstream
        .read_managed_snapshot(pricing, &deployment_id, &managed_channel_tags)
        .await?;
    copy_source_fact(source_snapshot, &mut modules, SyncModule::Groups, "groups");
    copy_source_fact(
        source_snapshot,
        &mut modules,
        SyncModule::GroupPricing,
        "purchase",
    );
    copy_source_fact(
        source_snapshot,
        &mut modules,
        SyncModule::Seedance,
        "account_purchase",
    );
    let newapi_kuma = modules.remove(&SyncModule::Kuma).unwrap_or(Value::Null);
    let control_plane_deployment_id = if deployment.state.upstream_deployment_id.is_empty() {
        deployment_id.clone()
    } else {
        deployment.state.upstream_deployment_id.clone()
    };
    let mut kuma_snapshot = kuma::read_managed_snapshot(kuma::KumaSyncOptions {
        executor: &deployment.executor,
        container_name: &config.container_name,
        deployment_id: &control_plane_deployment_id,
        website_name: &config.website_name,
        source_base_url: &deployment.container_source_url,
        status_key: &deployment.secrets.public_status_source_key,
        kuma_username: &config.kuma_admin_username,
        kuma_password: &deployment.secrets.kuma_admin_password,
        force: false,
        manifest,
    })?;
    let public_status_url = newapi_kuma
        .get("console_setting.public_status_url")
        .cloned()
        .unwrap_or(Value::Null);
    kuma_snapshot
        .as_object_mut()
        .ok_or_else(|| AppError::State("Kuma snapshot must be an object".to_owned()))?
        .insert(
            "console_setting.public_status_url".to_owned(),
            public_status_url,
        );
    modules.insert(SyncModule::Kuma, kuma_snapshot);
    Ok(modules)
}

fn copy_source_fact(
    source: &SyncSnapshot,
    downstream: &mut BTreeMap<SyncModule, Value>,
    module: SyncModule,
    key: &str,
) {
    let value = source
        .modules
        .get(module.name())
        .and_then(|module| module.data.get(key))
        .cloned();
    if let (Some(value), Some(Value::Object(target))) = (value, downstream.get_mut(&module)) {
        target.insert(key.to_owned(), value);
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_sync_module(
    module: SyncModule,
    force: bool,
    plan: &SyncPlan,
    selected: &BTreeSet<SyncModule>,
    observation: &SyncObservation,
    source: &mut SourceClient,
    downstream: &NewApiClient,
    config: &DeploymentConfig,
    deployment: &mut DeploymentRuntime,
) -> Result<()> {
    match module {
        SyncModule::Channels => {
            let token_sync = source
                .apply_group_tokens(&observation.catalog, &observation.token_plan)
                .await?;
            let previous = deployment.state.channels.clone();
            let (_, mut channels) = downstream
                .sync_channels_with_pricing(
                    config,
                    &deployment.container_source_url,
                    &observation.catalog,
                    &token_sync.bindings,
                    &previous,
                    force,
                    Some(&observation.pricing),
                )
                .await?;
            downstream
                .disable_removed_channels(&previous, &mut channels)
                .await?;
            source
                .apply_removed_group_tokens(&observation.removed_tokens)
                .await?;
            deployment.state.channels = channels;
        }
        SyncModule::Kuma => {
            let local_deployment_id = config.deployment_id();
            let deployment_id = if deployment.state.upstream_deployment_id.is_empty() {
                local_deployment_id
            } else {
                deployment.state.upstream_deployment_id.clone()
            };
            let helper_force = force || !plan.has_downstream_drift(SyncModule::Kuma);
            let result = kuma::sync_status_page(kuma::KumaSyncOptions {
                executor: &deployment.executor,
                container_name: &config.container_name,
                deployment_id: &deployment_id,
                website_name: &config.website_name,
                source_base_url: &deployment.container_source_url,
                status_key: &deployment.secrets.public_status_source_key,
                kuma_username: &config.kuma_admin_username,
                kuma_password: &deployment.secrets.kuma_admin_password,
                force: helper_force,
                manifest: &observation.manifest,
            })?;
            let public_status_url = kuma::internal_status_page_url(&result.page_slug);
            downstream
                .configure_public_status_url(&public_status_url)
                .await?;
            deployment.state.manifest_sha256 = result.manifest_sha256;
            deployment.state.kuma_monitors = result.monitors;
        }
        module => {
            let (desired, pricing_table_preserved) =
                desired_module_value(module, plan, selected, force);
            if pricing_table_preserved {
                println!(
                    "{}",
                    style("[HIGH] 已保留下游首页价格表：当前有效售价未完全跟随源站终端价")
                        .yellow()
                        .bold()
                );
            }
            downstream
                .apply_snapshot_module(
                    module,
                    &config.deployment_id(),
                    &desired,
                    plan.downstream_value(module),
                )
                .await?;
        }
    }
    Ok(())
}

fn desired_module_value(
    module: SyncModule,
    plan: &SyncPlan,
    selected: &BTreeSet<SyncModule>,
    force: bool,
) -> (Value, bool) {
    let mut desired = advance_last_applied(
        plan.baseline_value(module),
        plan.source_value(module),
        plan.downstream_value(module),
        force,
    );
    if module != SyncModule::Site || effective_sales_match_source(plan, selected, force) {
        return (desired, false);
    }
    let Some(current_table) = plan
        .downstream_value(SyncModule::Site)
        .get("home_setting.pricing_table")
        .cloned()
    else {
        return (desired, false);
    };
    let Some(desired_object) = desired.as_object_mut() else {
        return (desired, false);
    };
    let changed = desired_object.get("home_setting.pricing_table") != Some(&current_table);
    desired_object.insert("home_setting.pricing_table".to_owned(), current_table);
    (desired, changed)
}

fn effective_sales_match_source(
    plan: &SyncPlan,
    selected: &BTreeSet<SyncModule>,
    force: bool,
) -> bool {
    [
        (SyncModule::GroupPricing, "GroupRatio"),
        (SyncModule::Seedance, "sales"),
    ]
    .into_iter()
    .all(|(module, key)| {
        let effective = if selected.contains(&module) {
            advance_last_applied(
                plan.baseline_value(module),
                plan.source_value(module),
                plan.downstream_value(module),
                force,
            )
        } else {
            plan.downstream_value(module).clone()
        };
        effective.get(key) == plan.source_value(module).get(key)
    })
}

fn ensure_snapshots_are_current(
    original_source: &SyncSnapshot,
    original_downstream: &SyncSnapshot,
    fresh_source: &SyncSnapshot,
    fresh_downstream: &SyncSnapshot,
) -> Result<()> {
    if snapshots_match(original_source, fresh_source)
        && snapshots_match(original_downstream, fresh_downstream)
    {
        return Ok(());
    }
    Err(AppError::State(
        "确认后源站或下游状态已变化；旧计划已拒绝应用，请重新运行 sync".to_owned(),
    ))
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
    let _operation_lock = storage::acquire_operation_lock()?;
    if args.config.is_none() && !storage::exists(CONFIG_FILE)? {
        print_success("没有已保存的部署配置，无需清理");
        return Ok(());
    }
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

    let mut config = load_config_path(args.config.as_deref())?;
    config.resolve_passwords();
    clean_deployment(&config, &CancellationToken::default())
        .await
        .map_err(application_error)?;
    print_success("下游容器、生成配置和数据已清理；onboard 配置、凭证和登录会话已保留");
    Ok(())
}

async fn run_rollback(args: &RollbackArgs) -> Result<()> {
    let _operation_lock = storage::acquire_operation_lock()?;
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

    let mut config = load_config_path(args.config.as_deref())?;
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
    print_success("下游 Compose 项目、配置和数据已清理；生命周期事件已由共享应用层处理");
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
            storage::clear_deployment_snapshots()?;
            crate::application::deployment_control::remove_registration()
                .map_err(application_error)?;
            print_success("已清除保留的 onboard 配置，可以重新填写");
            return Ok(());
        }
        return run_rollback(&RollbackArgs {
            yes: false,
            revoke_source: false,
            config: None,
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
    storage::clear_deployment_snapshots()?;
    crate::application::deployment_control::remove_registration().map_err(application_error)?;
    print_success("已清理未完成的 onboard 配置");
    Ok(())
}

pub(crate) fn load_deployment_config() -> Result<DeploymentConfig> {
    let path = storage::directory()?.join(CONFIG_FILE);
    let mut config = DeploymentConfig::from_file(&path)?;
    config.normalize();
    config.validate()?;
    Ok(config)
}

fn load_config_path(path: Option<&std::path::Path>) -> Result<DeploymentConfig> {
    let mut config = match path {
        Some(path) => DeploymentConfig::from_file(path)?,
        None => load_deployment_config()?,
    };
    config.normalize();
    config.validate()?;
    Ok(config)
}

pub(crate) fn persist_deployment_config(config: &DeploymentConfig) -> Result<()> {
    let content = toml::to_string_pretty(config)
        .map_err(|error| AppError::State(format!("serialize deployment.toml: {error}")))?;
    storage::write(CONFIG_FILE, content.as_bytes())
}

#[cfg(test)]
fn write_target_downstream_credentials(
    config: &DeploymentConfig,
    registration: &DeploymentRegistration,
) -> Result<()> {
    let executor =
        crate::target::TargetExecutor::new(config.target.clone(), config.directory.clone());
    crate::application::deployment_control::persist_registration(config, &executor, registration)
        .map_err(application_error)
}

#[cfg(test)]
fn apply_authoritative_registration(
    state: &mut DeploymentState,
    registration: &DeploymentRegistration,
) -> Result<()> {
    crate::application::deployment_control::apply_registration(state, registration)
        .map_err(application_error)
}

pub(crate) fn ensure_compatible_current_deployment(config: &DeploymentConfig) -> Result<()> {
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

pub(crate) async fn source_for_operation(config: &DeploymentConfig) -> Result<SourceClient> {
    source_for_operation_mode(config, true).await
}

pub(crate) async fn source_for_operation_noninteractive(
    config: &DeploymentConfig,
) -> Result<SourceClient> {
    source_for_operation_mode(config, false).await
}

async fn source_for_operation_mode(
    config: &DeploymentConfig,
    allow_prompt: bool,
) -> Result<SourceClient> {
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
    } else if !allow_prompt {
        return Err(SourceError::AuthenticationRequired.into());
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

pub(crate) fn persist_source_session(source: &SourceClient) -> Result<()> {
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

fn current_margin_previews(
    observation: &SyncObservation,
) -> (Vec<MarginPreview>, Vec<MarginPreview>) {
    let group_sales = observation
        .downstream_snapshot
        .modules
        .get(SyncModule::GroupPricing.name())
        .and_then(|module| module.data.get("GroupRatio"))
        .unwrap_or(&Value::Null);
    let seedance_sales = observation
        .downstream_snapshot
        .modules
        .get(SyncModule::Seedance.name())
        .and_then(|module| module.data.get("sales"))
        .unwrap_or(&Value::Null);
    (
        observation
            .pricing
            .group_margin_previews_with_downstream_sales(&observation.catalog, group_sales),
        observation
            .pricing
            .seedance_margin_previews_with_downstream_sales(seedance_sales),
    )
}

fn margin_risk_status(groups: &[MarginPreview], seedance: &[MarginPreview]) -> String {
    let losses = groups
        .iter()
        .chain(seedance)
        .filter(|preview| preview.risk == MarginRisk::Loss)
        .count();
    if losses == 0 {
        "未发现售价低于采购价".to_owned()
    } else {
        format!("CRITICAL 售价低于采购价 {losses} 项")
    }
}

fn print_apply_summary(
    completed: &[SyncModule],
    failed: Option<SyncModule>,
    not_executed: &[SyncModule],
) {
    println!();
    println!("{}", style("模块执行结果").bold());
    print_field(
        "已完成",
        &if completed.is_empty() {
            "无".to_owned()
        } else {
            completed
                .iter()
                .map(|module| module.label())
                .collect::<Vec<_>>()
                .join("、")
        },
    );
    print_field("失败", failed.map(SyncModule::label).unwrap_or("无"));
    print_field(
        "未执行",
        &if not_executed.is_empty() {
            "无".to_owned()
        } else {
            not_executed
                .iter()
                .map(|module| module.label())
                .collect::<Vec<_>>()
                .join("、")
        },
    );
    println!();
}

fn print_margin_previews(title: &str, previews: &[MarginPreview]) {
    if previews.is_empty() {
        return;
    }
    println!();
    println!("{}", style(title).bold());
    println!(
        "  {:<28} {:>10} {:>10} {:>10}  结论",
        "分组/模型", "采购价", "默认售价", "毛利率"
    );
    for preview in previews {
        let purchase = preview
            .purchase
            .map(|value| format!("{value:.4}"))
            .unwrap_or_else(|| "未知".to_owned());
        let margin = preview
            .margin_percent
            .map(|value| format!("{value:.2}%"))
            .unwrap_or_else(|| "未知".to_owned());
        let conclusion = match preview.risk {
            MarginRisk::Profitable => "默认有额度毛利",
            MarginRisk::ZeroMargin => "默认无额度毛利",
            MarginRisk::Loss => "CRITICAL 售价低于采购价",
            MarginRisk::Unknown => "采购价未知",
        };
        let line = format!(
            "  {:<28} {:>10} {:>10.4} {:>10}  {conclusion}",
            preview.name, purchase, preview.sales, margin
        );
        match preview.risk {
            MarginRisk::Profitable => println!("{}", style(line).green()),
            MarginRisk::ZeroMargin | MarginRisk::Unknown => {
                println!("{}", style(line).yellow())
            }
            MarginRisk::Loss => println!("{}", style(line).red().bold()),
        }
    }
    println!();
}

fn print_sync_plan(plan: &SyncPlan, details: bool) {
    println!();
    println!("{}", style("同步差异").bold());
    let changed = plan.changed_modules();
    if changed.is_empty() {
        println!("  {}", style("三方快照一致").green());
        println!();
        return;
    }
    for module in SyncModule::ALL {
        if !changed.contains(&module) {
            continue;
        }
        println!();
        println!("{}", style(module.label()).bold());
        let diffs = plan
            .diffs
            .get(&module)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let visible = if details {
            diffs.len()
        } else {
            diffs.len().min(12)
        };
        for diff in diffs.iter().take(visible) {
            print_sync_diff(diff, details);
        }
        if visible < diffs.len() {
            println!(
                "  {} 另有 {} 个字段；使用 sync --details 查看",
                style("...").dim(),
                diffs.len() - visible
            );
        }
    }
    println!();
}

fn print_sync_diff(diff: &FieldDiff, details: bool) {
    let classification = match diff.classification {
        SnapshotClassification::Unchanged => "无变化",
        SnapshotClassification::SourceChanged => "仅源站变化",
        SnapshotClassification::DownstreamChanged => "下游手动修改",
        SnapshotClassification::BothChangedToSame => "双方同向变化",
        SnapshotClassification::Conflict => "冲突",
        SnapshotClassification::UnknownBaseline => "无历史基线",
    };
    let risk = match diff.risk {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    };
    let line = format!("  [{risk}] {}  {classification}", diff.path);
    match diff.risk {
        RiskLevel::Critical => println!("{}", style(line).red().bold()),
        RiskLevel::High => println!("{}", style(line).yellow().bold()),
        RiskLevel::Medium => println!("{}", style(line).yellow()),
        RiskLevel::Low => println!("{line}"),
    }
    if details {
        print_field(
            "上次应用",
            &diff
                .last_applied
                .as_ref()
                .map(compact_json)
                .unwrap_or_else(|| "<无>".to_owned()),
        );
        print_field(
            "源站当前",
            &diff
                .source_current
                .as_ref()
                .map(compact_json)
                .unwrap_or_else(|| "<无>".to_owned()),
        );
        print_field(
            "下游当前",
            &diff
                .downstream_current
                .as_ref()
                .map(compact_json)
                .unwrap_or_else(|| "<无>".to_owned()),
        );
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "<无法序列化>".to_owned())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::DeploymentRegistration;
    use serde_json::json;

    fn pricing_table_plan() -> SyncPlan {
        let source = snapshot_from_modules(BTreeMap::from([
            (
                SyncModule::GroupPricing,
                json!({"GroupRatio": {"gpt-pro": 0.4}}),
            ),
            (
                SyncModule::Seedance,
                json!({"sales": [{"public_model": "seedance-2.0", "customer_rate_bps": 8300}]}),
            ),
            (
                SyncModule::Site,
                json!({
                    "home_setting.pricing_table": [{"model": "gpt-pro", "input": "new"}],
                    "home_setting.pricing_title": "new title"
                }),
            ),
        ]));
        let downstream = snapshot_from_modules(BTreeMap::from([
            (
                SyncModule::GroupPricing,
                json!({"GroupRatio": {"gpt-pro": 0.44}}),
            ),
            (
                SyncModule::Seedance,
                json!({"sales": [{"public_model": "seedance-2.0", "customer_rate_bps": 8300}]}),
            ),
            (
                SyncModule::Site,
                json!({
                    "home_setting.pricing_table": [{"model": "gpt-pro", "input": "old"}],
                    "home_setting.pricing_title": "old title"
                }),
            ),
        ]));
        let baseline = snapshot_from_modules(BTreeMap::from([
            (
                SyncModule::GroupPricing,
                json!({"GroupRatio": {"gpt-pro": 0.4}}),
            ),
            (
                SyncModule::Seedance,
                json!({"sales": [{"public_model": "seedance-2.0", "customer_rate_bps": 8300}]}),
            ),
            (
                SyncModule::Site,
                json!({
                    "home_setting.pricing_table": [{"model": "gpt-pro", "input": "old"}],
                    "home_setting.pricing_title": "old title"
                }),
            ),
        ]));
        SyncPlan::new(source, downstream, Some(baseline))
    }

    #[test]
    fn site_apply_preserves_table_when_effective_sales_are_local() {
        let plan = pricing_table_plan();
        let selected = BTreeSet::from([SyncModule::Site]);
        let (desired, preserved) = desired_module_value(SyncModule::Site, &plan, &selected, false);
        assert!(preserved);
        assert_eq!(
            desired["home_setting.pricing_table"],
            plan.downstream_value(SyncModule::Site)["home_setting.pricing_table"]
        );
        assert_eq!(desired["home_setting.pricing_title"], json!("new title"));
    }

    #[test]
    fn site_apply_can_follow_source_after_explicit_forced_sales_update() {
        let plan = pricing_table_plan();
        let selected = BTreeSet::from([SyncModule::GroupPricing, SyncModule::Site]);
        let (desired, preserved) = desired_module_value(SyncModule::Site, &plan, &selected, true);
        assert!(!preserved);
        assert_eq!(
            desired["home_setting.pricing_table"],
            plan.source_value(SyncModule::Site)["home_setting.pricing_table"]
        );
    }

    #[test]
    fn stale_source_or_downstream_snapshot_is_rejected() {
        let source = snapshot_from_modules(BTreeMap::from([(
            SyncModule::Groups,
            json!({"group": "old"}),
        )]));
        let downstream = source.clone();
        assert!(ensure_snapshots_are_current(&source, &downstream, &source, &downstream).is_ok());

        let fresh_source = snapshot_from_modules(BTreeMap::from([(
            SyncModule::Groups,
            json!({"group": "new"}),
        )]));
        let error = ensure_snapshots_are_current(&source, &downstream, &fresh_source, &downstream)
            .expect_err("stale plan must fail");
        assert!(error.to_string().contains("旧计划已拒绝应用"));
    }

    #[cfg(unix)]
    use std::{fs, os::unix::fs::PermissionsExt};

    use secrecy::SecretString;

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

    #[cfg(unix)]
    #[test]
    fn target_credentials_are_private_and_read_back_complete() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config = DeploymentConfig {
            directory: temporary.path().join("deployment"),
            image_ref: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            ..DeploymentConfig::default()
        };
        fs::create_dir_all(&config.directory).expect("create target directory");

        write_target_downstream_credentials(&config, &registration())
            .expect("write target credentials");

        let path = config.directory.join("downstream-credentials.env");
        let metadata = fs::metadata(&path).expect("target credentials metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        let executor =
            crate::target::TargetExecutor::new(config.target.clone(), config.directory.clone());
        let content = String::from_utf8(
            executor
                .run_in_directory("cat downstream-credentials.env")
                .expect("read target credentials through target executor")
                .stdout,
        )
        .expect("target credentials are UTF-8");
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
            operation: None,
            snapshot_schema_version: 0,
            last_applied_at: Default::default(),
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
            operation: None,
            snapshot_schema_version: 0,
            last_applied_at: Default::default(),
        };

        let error = apply_authoritative_registration(&mut state, &registration())
            .expect_err("conflicting registration must be rejected");

        assert!(error.to_string().contains("不一致") || error.to_string().contains("不匹配"));
        assert_eq!(state.upstream_deployment_id, "dep_original");
    }

    #[cfg(unix)]
    #[test]
    fn target_credentials_failure_leaves_no_partial_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let blocked = temporary.path().join("not-a-directory");
        fs::write(&blocked, b"blocked").expect("create blocking file");
        let config = DeploymentConfig {
            directory: blocked.clone(),
            image_ref: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            ..DeploymentConfig::default()
        };

        assert!(write_target_downstream_credentials(&config, &registration()).is_err());
        assert!(!blocked.join("downstream-credentials.env").exists());
    }
}
