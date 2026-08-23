//! Diagnostic-driven repair planning.
//!
//! The planner is deliberately pure with respect to a target: it only reads
//! local state and emits typed actions. Mutating handlers can be added without
//! weakening `--check`/`--plan` or allowing arbitrary shell from the source.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Duration,
};

use cliclack::confirm;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    cli::{RepairActionKind, RepairArgs},
    config::DeploymentConfig,
    error::{AppError, Result},
    security::sha256_hex,
    source::{
        DeploymentRegistration, RepairObservationRequest, RepairOperationRequest, SourceClient,
    },
    state::DeploymentState,
    storage::{
        self, CONFIG_FILE, DOWNSTREAM_CREDENTIALS_FILE, REPAIR_OPERATION_FILE,
        REPAIR_STATE_BACKUP_FILE, STATE_FILE,
    },
    target::{self, TargetExecutor},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepairDiagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub domain: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<RepairActionKind>,
    pub automatic: bool,
    #[serde(default)]
    pub evidence: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepairAction {
    pub kind: RepairActionKind,
    pub risk: String,
    pub automatic: bool,
    pub backup_level: String,
    pub requires_restart: Vec<String>,
    pub estimated_downtime_seconds: u32,
    pub preconditions: Vec<String>,
    pub postconditions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepairProtectionPolicy {
    pub backup_level: String,
    pub preserved_resources: Vec<String>,
    pub destructive_operations_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepairObservation {
    pub schema_version: u32,
    pub cli_schema: String,
    pub deployment_id: String,
    pub source_user_id: i64,
    pub local_generation: u32,
    pub config_present: bool,
    pub state_present: bool,
    pub registration_present: bool,
    pub target_directory_present: bool,
    pub target_credentials_present: bool,
    pub target_credentials_fingerprint: String,
    pub target_fingerprint: String,
    pub codes: Vec<String>,
    #[serde(default)]
    pub target: Option<target::repair::TargetObservation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepairPlan {
    pub schema_version: u32,
    pub operation_id: String,
    pub deployment_id: String,
    pub base_generation: u32,
    pub observation_fingerprint: String,
    pub plan_fingerprint: String,
    pub expires_at: i64,
    pub actions: Vec<RepairAction>,
    pub protection: RepairProtectionPolicy,
    pub verification: Vec<String>,
    pub manual_items: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepairOutcome {
    pub status: String,
    pub diagnostics: Vec<RepairDiagnostic>,
    pub plan: RepairPlan,
    #[serde(default)]
    pub journal: RepairJournal,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct RepairJournal {
    pub phase: String,
    #[serde(default)]
    pub source_operation_id: String,
    #[serde(default)]
    pub target_observation_fingerprint: String,
    #[serde(default)]
    pub backup: Option<target::repair::BackupManifest>,
    #[serde(default)]
    pub activated: bool,
    #[serde(default)]
    pub reporting_verified: bool,
    #[serde(default)]
    pub warning_code: String,
    #[serde(default)]
    pub local_state_backup: bool,
}

pub async fn run(args: &RepairArgs) -> Result<()> {
    // Read-only modes must not even create the local operation-lock file.
    let _lock = if args.check || args.plan {
        None
    } else {
        Some(storage::acquire_operation_lock()?)
    };
    let config = load_config(args.config.as_deref())?;
    let (mut observation, base_generation) = collect_observation(args.config.as_deref())?;
    let target_executor = config
        .as_ref()
        .map(|config| TargetExecutor::new(config.target.clone(), config.directory.clone()));
    if let (Some(config), Some(executor)) = (&config, &target_executor) {
        if let Ok(target_observation) = target::repair::observe(
            executor,
            &config.container_name,
            config.newapi_port,
            config.kuma_port,
        ) {
            observation.target = Some(target_observation.clone());
            if !target_observation.deployment_id.is_empty()
                && !observation.deployment_id.is_empty()
                && target_observation.deployment_id != observation.deployment_id
            {
                observation
                    .codes
                    .push("TARGET_DEPLOYMENT_ID_MISMATCH".to_owned());
            }
            if target_observation.installation_generation != 0
                && target_observation.installation_generation != observation.local_generation
                && !observation
                    .codes
                    .iter()
                    .any(|code| code == "LOCAL_OPERATION_INTERRUPTED")
            {
                observation
                    .codes
                    .push("TARGET_INSTALLATION_GENERATION_MISMATCH".to_owned());
            }
            if target_observation.directory_symlink {
                observation
                    .codes
                    .push("TARGET_DIRECTORY_SYMLINK".to_owned());
            }
            if !target_observation.compose_valid {
                let compose_code = target_observation
                    .files
                    .get("docker-compose.yml")
                    .is_some_and(|file| !file.exists);
                observation.codes.push(
                    if compose_code {
                        "TARGET_COMPOSE_MISSING"
                    } else {
                        "TARGET_COMPOSE_INVALID"
                    }
                    .to_owned(),
                );
            }
            if !target_observation.compose_project_name.is_empty()
                && target_observation.compose_project_name != config.container_name
            {
                observation.codes.push("TARGET_COMPOSE_DRIFT".to_owned());
            }
            // Managed drift detection (plan 6.4): render the managed Compose
            // from the local template and compare digests with the on-disk
            // file. Rendering never mutates the target; a failed local render
            // simply leaves drift detection to the other diagnostics.
            if target_observation.compose_valid
                && let Some(file) = target_observation.files.get("docker-compose.yml")
                && file.exists
                && !file.sha256.is_empty()
                && let Ok(runtime) =
                    crate::target::compose::DeploymentRuntime::load_existing_with_ssh_password(
                        config, None,
                    )
                && let Ok(rendered) =
                    crate::target::compose::render_managed_compose(config, &runtime)
                && sha256_hex(rendered.as_bytes()) != file.sha256
            {
                observation.codes.push("TARGET_COMPOSE_DRIFT".to_owned());
            }
            // A data-service failure is only a manual boundary when the
            // container is running but refuses queries (potential data-level
            // damage). A merely stopped managed container is a restartable
            // condition covered by TARGET_SERVICE_STOPPED (plan 6.7 allows
            // start/up for data services without touching volumes).
            let postgres_running = target_observation
                .services
                .get("postgres")
                .is_some_and(|service| service.state == "running");
            let redis_running = target_observation
                .services
                .get("redis")
                .is_some_and(|service| service.state == "running");
            if postgres_running && !target_observation.postgres_select_1 {
                observation
                    .codes
                    .push("TARGET_POSTGRES_UNHEALTHY".to_owned());
            }
            if redis_running && !target_observation.redis_ping {
                observation.codes.push("TARGET_REDIS_UNHEALTHY".to_owned());
            }
            if !target_observation.newapi_status {
                observation.codes.push("TARGET_NEWAPI_UNHEALTHY".to_owned());
            }
            if !target_observation.newapi_status_success {
                observation
                    .codes
                    .push("TARGET_NEWAPI_STATUS_NOT_READY".to_owned());
            }
            if !target_observation.local_health_status {
                observation
                    .codes
                    .push("TARGET_LOCAL_HEALTH_UNAVAILABLE".to_owned());
            }
            if !target_observation.kuma_status {
                observation.codes.push("TARGET_KUMA_UNHEALTHY".to_owned());
            }
            if let Some(newapi) = target_observation.services.get("new-api")
                && config.image_ref.starts_with("sha256:")
                && !newapi
                    .image_id
                    .contains(config.image_ref.trim_start_matches("sha256:"))
            {
                observation.codes.push("TARGET_IMAGE_DRIFT".to_owned());
            }
            if !target_observation.unknown_resources.is_empty() {
                observation
                    .codes
                    .push("TARGET_UNKNOWN_RESOURCES".to_owned());
            }
            augment_target_diagnostics(&mut observation.codes, &target_observation);
        } else {
            observation
                .codes
                .push("TARGET_OBSERVATION_UNAVAILABLE".to_owned());
        }
    }
    observation.codes.sort();
    observation.codes.dedup();
    // Source diagnose is read-only and safe in --check mode. Mutation APIs are
    // only reached from execute_plan after the explicit execution boundary.
    if let Some(config) = &config {
        match crate::application::deployment_control::load_registration_for(
            config,
            observation.source_user_id,
        ) {
            Ok(Some(registration)) => {
                match crate::commands::source_for_operation_noninteractive(config).await {
                    Ok(mut source) => {
                        if let Err(error) =
                            ensure_source_identity(&source, observation.source_user_id)
                        {
                            observation.codes.push(error.to_string());
                        } else {
                            let request = RepairObservationRequest {
                                schema_version: 1,
                                cli_schema: "2".to_owned(),
                                deployment_id: observation.deployment_id.clone(),
                                local_generation: observation.local_generation,
                                target_generation: observation
                                    .target
                                    .as_ref()
                                    .map(|target| target.installation_generation)
                                    .unwrap_or(observation.local_generation),
                                file_fingerprints: redacted_target_fingerprints(
                                    observation.target.as_ref(),
                                ),
                                services: redacted_target_services(observation.target.as_ref()),
                                capabilities: target_capabilities(observation.target.as_ref()),
                                requested_actions: args
                                    .actions
                                    .iter()
                                    .map(|kind| action_kind_name(*kind).to_owned())
                                    .collect(),
                            };
                            match source.repair_diagnose(&registration, &request).await {
                                Ok(receipt) => {
                                    if receipt.deployment_id != registration.deployment_id {
                                        observation
                                            .codes
                                            .push("CONTROL_GENERATION_DRIFT".to_owned());
                                    }
                                    if receipt.installation_generation != 0
                                        && observation.local_generation != 0
                                        && receipt.installation_generation
                                            != observation.local_generation
                                        && !observation
                                            .codes
                                            .iter()
                                            .any(|code| code == "LOCAL_OPERATION_INTERRUPTED")
                                    {
                                        observation
                                            .codes
                                            .push("CONTROL_GENERATION_DRIFT".to_owned());
                                    }
                                    observation.codes.extend(
                                        receipt
                                            .diagnostics
                                            .into_iter()
                                            .map(|diagnostic| diagnostic.code),
                                    );
                                }
                                Err(error) => {
                                    observation.codes.push(source_error_diagnostic_code(&error));
                                }
                            }
                        }
                    }
                    Err(error) => observation.codes.push(app_error_diagnostic_code(&error)),
                }
            }
            Ok(None) => observation
                .codes
                .push("LOCAL_REGISTRATION_MISSING".to_owned()),
            Err(error) => {
                observation
                    .codes
                    .push(if error.code == "DOWNSTREAM_CREDENTIALS_INVALID" {
                        "LOCAL_REGISTRATION_INVALID".to_owned()
                    } else {
                        "LOCAL_REGISTRATION_UNAVAILABLE".to_owned()
                    })
            }
        }
        observation.codes.sort();
        observation.codes.dedup();
    }
    let mut plan = build_plan(&observation, base_generation, &args.actions);
    if !args.actions.is_empty()
        && args.actions.iter().any(|kind| {
            *kind != RepairActionKind::ManualIntervention
                && !plan.actions.iter().any(|action| action.kind == *kind)
        })
    {
        return Err(AppError::State(
            "REPAIR_PLAN_INVALID: --actions 与当前诊断或动作依赖图不兼容".to_owned(),
        ));
    }
    let has_rotation = plan
        .actions
        .iter()
        .any(|action| action.kind == RepairActionKind::RotateInstallationCredentials);
    let has_release = plan
        .actions
        .iter()
        .any(|action| action.kind == RepairActionKind::ReconcileApprovedRelease);
    if has_rotation && has_release {
        plan.manual_items
            .push("CREDENTIAL_ROTATION_AND_RELEASE_REQUIRE_SEPARATE_OPERATIONS".to_owned());
    }
    if args.yes && plan.actions.iter().any(|action| !action.automatic) {
        plan.manual_items
            .push("NON_AUTOMATIC_ACTION_REQUIRES_INTERACTIVE_CONFIRMATION".to_owned());
    }
    if plan
        .actions
        .iter()
        .any(|action| action.backup_level == "B2")
        && !args.allow_data_migration
    {
        plan.manual_items
            .push("DATA_MIGRATION_AUTHORIZATION_REQUIRED".to_owned());
    }
    refresh_plan_fingerprint(&mut plan);
    if let Some(expected) = args.plan_fingerprint.as_deref()
        && !reviewed_plan_fingerprint_matches(&mut plan, expected, crate::state::unix_timestamp())
    {
        return Err(AppError::State(
            "REPAIR_PLAN_STALE: 当前目标事实已变化，请重新运行 repair --plan".to_owned(),
        ));
    }
    if args.plan_fingerprint.is_some() && plan.expires_at <= crate::state::unix_timestamp() {
        return Err(AppError::State(
            "REPAIR_PLAN_STALE: repair 计划已过期，请重新运行 repair --plan".to_owned(),
        ));
    }
    let mut status = if args.check {
        "diagnosed"
    } else if args.plan {
        "planned"
    } else if args.yes {
        if plan.manual_items.is_empty() && !plan.actions.is_empty() {
            "executing"
        } else if plan.manual_items.is_empty() {
            "succeeded"
        } else {
            "manual_required"
        }
    } else {
        "awaiting_confirmation"
    };
    if !args.check
        && !args.plan
        && status == "awaiting_confirmation"
        && !confirm("按以上 repair 计划执行？")
            .initial_value(false)
            .interact()
            .map_err(AppError::from_prompt)?
    {
        if let Some(config) = &config
            && let Ok(Some(registration)) =
                crate::application::deployment_control::load_registration_for(
                    config,
                    observation.source_user_id,
                )
        {
            let _ = queue_repair_event(
                &registration,
                "repair_aborted",
                "operation_aborted",
                "user declined repair plan",
            )
            .await;
        }
        return Err(AppError::Cancelled);
    }
    if !args.check
        && !args.plan
        && let Some(config) = &config
        && let Ok(Some(registration)) =
            crate::application::deployment_control::load_registration_for(
                config,
                observation.source_user_id,
            )
    {
        let _ = queue_repair_event(
            &registration,
            "repair_planned",
            "repair_planned",
            "diagnostic plan accepted",
        )
        .await;
    }
    if !args.check
        && !args.plan
        && matches!(status, "executing" | "awaiting_confirmation")
        && let Some(config) = config.as_ref()
        && let Some(expected) = observation.target.as_ref()
    {
        let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
        let current = target::repair::observe(
            &executor,
            &config.container_name,
            config.newapi_port,
            config.kuma_port,
        )
        .map_err(|_| AppError::State("REPAIR_PLAN_STALE: 目标事实重新采集失败".to_owned()))?;
        if current.fingerprint() != expected.fingerprint() {
            return Err(AppError::State(
                "REPAIR_PLAN_STALE: 执行前目标事实已变化，请重新生成 repair 计划".to_owned(),
            ));
        }
    }
    if args.yes && status == "manual_required" {
        plan.manual_items.push(
            "首版 CLI 只执行已实现的本地动作；需要上游 repair API 或人工确认的动作已停止"
                .to_owned(),
        );
        if let Some(config) = &config
            && let Ok(Some(registration)) =
                crate::application::deployment_control::load_registration_for(
                    config,
                    observation.source_user_id,
                )
        {
            let _ = queue_repair_event(
                &registration,
                "repair_manual_required",
                "manual_required",
                "repair action requires manual handling",
            )
            .await;
        }
    }
    if status == "awaiting_confirmation" && !plan.manual_items.is_empty() {
        status = "manual_required";
    }
    if (status == "executing" || status == "awaiting_confirmation") && !plan.actions.is_empty() {
        match execute_plan(&config, &observation, &plan, args.allow_data_migration).await {
            Ok((executed, execution_status)) => {
                plan = executed;
                status = execution_status;
            }
            Err(error) => {
                let code = repair_error_code(&error);
                plan.manual_items.push(code.clone());
                if let Some(config) = &config
                    && let Ok(Some(registration)) =
                        crate::application::deployment_control::load_registration_for(
                            config,
                            observation.source_user_id,
                        )
                {
                    let _ =
                        queue_repair_event(&registration, "repair_failed", "repair_failed", &code)
                            .await;
                }
                let mut journal = load_journal_for_plan(&plan.plan_fingerprint).unwrap_or_default();
                // A pre-activation failure whose source operation was already
                // aborted is settled: keep the aborted journal so the next
                // diagnosis replans from facts instead of resuming a dead
                // operation.
                if journal.phase != "aborted" {
                    journal.phase = "failed".to_owned();
                }
                journal.warning_code = code;
                let outcome = RepairOutcome {
                    status: journal.phase.clone(),
                    diagnostics: diagnostics_for(&observation),
                    plan,
                    journal,
                };
                persist_outcome(&outcome)?;
                if args.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json_output(&outcome)).unwrap()
                    );
                } else {
                    print_terminal(&outcome);
                }
                return Err(error);
            }
        }
    } else if status == "awaiting_confirmation" {
        status = "succeeded";
    }
    let mut journal = load_journal_for_plan(&plan.plan_fingerprint).unwrap_or_default();
    if journal.phase.is_empty() {
        journal.phase = status.to_owned();
    }
    let outcome = RepairOutcome {
        status: status.to_owned(),
        diagnostics: diagnostics_for(&observation),
        plan,
        journal,
    };
    // A read-only plan must not overwrite an interrupted/failed journal: doing
    // so would change the next diagnosis from resume to fresh execution and
    // invalidate the reviewed fingerprint.
    if !args.check && !args.plan {
        persist_outcome(&outcome)?;
    }
    if args.json {
        let bytes = serde_json::to_vec_pretty(&json_output(&outcome))
            .map_err(|error| AppError::State(format!("serialize repair plan: {error}")))?;
        println!("{}", String::from_utf8_lossy(&bytes));
    } else {
        print_terminal(&outcome);
    }
    if status == "manual_required" {
        return Err(AppError::State("REPAIR_MANUAL_REQUIRED".to_owned()));
    }
    Ok(())
}

fn augment_target_diagnostics(
    codes: &mut Vec<String>,
    target_observation: &target::repair::TargetObservation,
) {
    const REQUIRED_CREDENTIAL_KEYS: &[&str] = &[
        "MEOWAI_DEPLOYMENT_ID",
        "MEOWAI_INSTALLATION_GENERATION",
        "MEOWAI_CONTROL_PLANE_URL",
        "MEOWAI_REPORT_CREDENTIAL",
        "MEOWAI_PULL_CREDENTIAL",
        "MEOWAI_HEARTBEAT_INTERVAL_SECONDS",
        "MEOWAI_SNAPSHOT_INTERVAL_SECONDS",
        "MEOWAI_DEPLOYMENT_SCHEMA",
        "MEOWAI_UPDATER_SCHEMA",
        "MEOWAI_DATA_SCHEMA",
        "MEOWAI_CLI_SCHEMA",
        "MEOWAI_CONTAINER_NAME",
        "MEOWAI_NEWAPI_PORT",
        "MEOWAI_KUMA_PORT",
    ];
    match target_observation.files.get("downstream-credentials.env") {
        None => codes.push("TARGET_CREDENTIAL_FILE_MISSING".to_owned()),
        Some(file) if !file.exists => codes.push("TARGET_CREDENTIAL_FILE_MISSING".to_owned()),
        Some(file) => {
            if !file.regular || file.symlink {
                codes.push("TARGET_CREDENTIAL_FILE_INVALID".to_owned());
            }
            if REQUIRED_CREDENTIAL_KEYS.iter().any(|key| {
                file.keys
                    .get(*key)
                    .is_none_or(|value| value.count != 1 || !value.non_empty)
            }) {
                codes.push("TARGET_CREDENTIAL_KEYS_MISMATCH".to_owned());
            }
            if file.mode != "600" {
                codes.push("TARGET_FILE_PERMISSION_INVALID".to_owned());
            }
        }
    }
    match target_observation.files.get("secrets.env") {
        None => codes.push("TARGET_SECRET_FILE_INVALID".to_owned()),
        Some(file) if !file.exists => codes.push("TARGET_SECRET_FILE_INVALID".to_owned()),
        Some(file) => {
            if !file.regular || file.symlink {
                codes.push("TARGET_SECRET_FILE_INVALID".to_owned());
            }
            for key in ["POSTGRES_PASSWORD", "REDIS_PASSWORD"] {
                if file
                    .keys
                    .get(key)
                    .is_none_or(|value| value.count != 1 || !value.non_empty)
                {
                    codes.push("TARGET_SECRET_FILE_INVALID".to_owned());
                }
            }
            if file.mode != "600" {
                codes.push("TARGET_FILE_PERMISSION_INVALID".to_owned());
            }
        }
    }
    if let Some(file) = target_observation.files.get("updater-credentials.env") {
        if !file.exists || !file.regular || file.symlink {
            codes.push("TARGET_CREDENTIAL_FILE_INVALID".to_owned());
        }
        if file.mode != "600" {
            codes.push("TARGET_FILE_PERMISSION_INVALID".to_owned());
        }
    }
    if target_observation.agent_version.is_empty() || target_observation.agent_schema.is_empty() {
        codes.push("TARGET_AGENT_OUTDATED".to_owned());
    }
    // A binary that predates the repair protocol cannot generate the
    // target-applied proof required by a credential rotation. It is only
    // refreshed through the signed release engine, so surface it before any
    // rotation is attempted.
    if target_observation
        .files
        .get("bin/meowai-deploy-upgrade-agent")
        .is_some_and(|file| file.exists)
        && !target_observation.agent_proof_capable
    {
        codes.push("TARGET_AGENT_OUTDATED".to_owned());
    }
    if target_observation.disk_available_bytes > 0
        && target_observation.disk_available_bytes < 1024 * 1024 * 1024
    {
        codes.push("TARGET_DISK_INSUFFICIENT".to_owned());
    }
    if !target_observation.upgrade_agent_active || !target_observation.upgrade_timer_active {
        codes.push("TARGET_AGENT_UNHEALTHY".to_owned());
    }
    for (service, observation) in &target_observation.services {
        if !["postgres", "redis", "new-api", "uptime-kuma"].contains(&service.as_str()) {
            continue;
        }
        if observation.state != "running" {
            // A stopped managed container — including the data services — is
            // restartable with `start/up` while the pre/post data-identity
            // verification protects the mounts (plan 6.7).
            codes.push("TARGET_SERVICE_STOPPED".to_owned());
        } else if !observation.health.is_empty()
            && observation.health != "healthy"
            && service != "postgres"
            && service != "redis"
        {
            codes.push("TARGET_SERVICE_UNHEALTHY".to_owned());
        }
    }
    let postgres_running = target_observation
        .services
        .get("postgres")
        .is_some_and(|service| service.state == "running");
    let redis_running = target_observation
        .services
        .get("redis")
        .is_some_and(|service| service.state == "running");
    if (postgres_running && !target_observation.postgres_select_1)
        || (redis_running && !target_observation.redis_ping)
    {
        codes.push("TARGET_DEPENDENCY_UNHEALTHY".to_owned());
    }
    if !target_observation.newapi_status_success {
        codes.push("TARGET_NEWAPI_STATUS_NOT_READY".to_owned());
    }
    if !target_observation.local_health_status {
        codes.push("TARGET_LOCAL_HEALTH_UNAVAILABLE".to_owned());
    }
    for service in ["postgres", "redis", "new-api", "uptime-kuma"] {
        if !target_observation.services.contains_key(service) {
            codes.push(
                if matches!(service, "postgres" | "redis") {
                    "TARGET_DEPENDENCY_UNHEALTHY"
                } else {
                    "TARGET_SERVICE_STOPPED"
                }
                .to_owned(),
            );
        }
    }
    let agent_files_present = [
        "meowai-deploy-updater.sh",
        "meowai-deploy-updater.service",
        "meowai-deploy-updater.timer",
        "bin/meowai-deploy-upgrade-agent",
    ]
    .iter()
    .all(|path| {
        target_observation
            .files
            .get(*path)
            .is_some_and(|file| file.exists)
    });
    if !agent_files_present {
        codes.push("TARGET_AGENT_MISSING".to_owned());
    }
}

fn persist_outcome(outcome: &RepairOutcome) -> Result<()> {
    let journal = serde_json::to_vec_pretty(outcome)
        .map_err(|error| AppError::State(format!("serialize repair journal: {error}")))?;
    storage::write(REPAIR_OPERATION_FILE, &journal)
}

fn json_output(outcome: &RepairOutcome) -> Value {
    serde_json::json!({
        "schema_version": outcome.plan.schema_version,
        "operation_id": outcome.plan.operation_id,
        "status": outcome.status,
        "deployment_id": outcome.plan.deployment_id,
        "installation_generation": outcome.plan.base_generation,
        "diagnostics": outcome.diagnostics,
        "actions": outcome.plan.actions,
        "protection": outcome.plan.protection,
        "verification": outcome.plan.verification,
        "manual_items": outcome.plan.manual_items,
        "observation_fingerprint": outcome.plan.observation_fingerprint,
        "plan_fingerprint": outcome.plan.plan_fingerprint,
        "expires_at": outcome.plan.expires_at,
        "journal": {
            "phase": outcome.journal.phase,
            "source_operation_id": outcome.journal.source_operation_id,
            "target_observation_fingerprint": outcome.journal.target_observation_fingerprint,
            "activated": outcome.journal.activated,
            "reporting_verified": outcome.journal.reporting_verified,
            "local_state_backup": outcome.journal.local_state_backup,
            "warning_code": outcome.journal.warning_code,
        },
    })
}

fn load_journal_for_plan(plan_fingerprint: &str) -> Option<RepairJournal> {
    storage::read(REPAIR_OPERATION_FILE)
        .ok()
        .flatten()
        .and_then(|content| serde_json::from_slice::<RepairOutcome>(&content).ok())
        .filter(|outcome| {
            // Only one repair operation can be in flight (local and target
            // locks). Any non-terminal journal that references a source
            // operation must be adopted for resume even when the replanned
            // fingerprint differs, and an activated journal must never be
            // discarded by an early failure of a later attempt.
            outcome.plan.plan_fingerprint == plan_fingerprint
                || matches!(
                    outcome.status.as_str(),
                    "executing" | "failed_recoverable" | "installation_activated"
                )
                || (!outcome.journal.source_operation_id.is_empty()
                    && !matches!(
                        outcome.status.as_str(),
                        "succeeded"
                            | "succeeded_with_warning"
                            | "aborted"
                            | "diagnosed"
                            | "planned"
                    ))
        })
        .map(|outcome| outcome.journal)
}

fn repair_error_code(error: &AppError) -> String {
    let message = error.to_string();
    message
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .find(|part| {
            part.len() >= 6
                && part.len() <= 96
                && part.contains('_')
                && part.chars().all(|character| {
                    character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
                })
        })
        .unwrap_or("REPAIR_FAILED")
        .to_owned()
}

fn load_config(path: Option<&Path>) -> Result<Option<DeploymentConfig>> {
    let path = match path {
        Some(path) => path.to_owned(),
        None => storage::directory()?.join(CONFIG_FILE),
    };
    if !path.is_file() {
        return Ok(None);
    }
    let mut config = DeploymentConfig::from_file(&path)?;
    config.normalize();
    config.resolve_source_password();
    config.validate()?;
    Ok(Some(config))
}

async fn execute_plan(
    config: &Option<DeploymentConfig>,
    observation: &RepairObservation,
    plan: &RepairPlan,
    allow_data_migration: bool,
) -> Result<(RepairPlan, &'static str)> {
    let config = config
        .as_ref()
        .ok_or_else(|| AppError::State("LOCAL_CONFIG_OR_STATE_INVALID".to_owned()))?;
    let state_content = storage::read(STATE_FILE)?
        .ok_or_else(|| AppError::State("LOCAL_STATE_INVALID".to_owned()))?;
    let mut state: DeploymentState = serde_json::from_slice(&state_content)
        .map_err(|_| AppError::State("LOCAL_STATE_INVALID".to_owned()))?;
    storage::write(REPAIR_STATE_BACKUP_FILE, &state_content)?;
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
    let old_registration = match crate::application::deployment_control::load_registration_for(
        config,
        state.source_user_id,
    ) {
        Ok(Some(registration)) => registration,
        Ok(None) => recover_local_registration(config, &executor, &mut state).await?,
        Err(error) if error.code == "DOWNSTREAM_CREDENTIALS_INVALID" => {
            recover_local_registration(config, &executor, &mut state).await?
        }
        Err(error) => return Err(AppError::State(error.to_string())),
    };
    let _target_lock =
        target::repair::TargetOperationLock::acquire(&executor, "repair", &plan.operation_id)?;
    let _ = queue_repair_event(
        &old_registration,
        "repair_started",
        "repair_started",
        "plan accepted",
    )
    .await;
    for action in &plan.actions {
        let _ = queue_repair_event(
            &old_registration,
            "repair_action_started",
            "repair_action_started",
            action_kind_name(action.kind),
        )
        .await;
    }
    let rotates_credentials = plan
        .actions
        .iter()
        .any(|action| action.kind == RepairActionKind::RotateInstallationCredentials);
    let refresh_monitoring = plan
        .actions
        .iter()
        .any(|action| action.kind == RepairActionKind::RefreshMonitoring);
    if !rotates_credentials {
        let backup = if plan.protection.backup_level == "B1" || plan.protection.backup_level == "B2"
        {
            let target_observation = observation
                .target
                .as_ref()
                .ok_or_else(|| AppError::State("TARGET_OBSERVATION_UNAVAILABLE".to_owned()))?;
            Some(if plan.protection.backup_level == "B2" {
                target::repair::create_b2_backup(
                    &executor,
                    &plan.operation_id,
                    target_observation,
                    &config.container_name,
                )?
            } else {
                target::repair::create_b1_backup(&executor, &plan.operation_id, target_observation)?
            })
        } else {
            None
        };
        if refresh_monitoring {
            let mut source = crate::commands::source_for_operation_noninteractive(config).await?;
            let probe = source.repair_probe(&old_registration).await?;
            if probe.state == "failed" || probe.state == "not_configured" {
                let code = if probe.failure_code.is_empty() {
                    "PUBLIC_ENDPOINT_UNVERIFIED".to_owned()
                } else {
                    probe.failure_code
                };
                return Err(AppError::State(code));
            }
        }
        let has_release = plan
            .actions
            .iter()
            .any(|action| action.kind == RepairActionKind::ReconcileApprovedRelease);
        let local_actions: Vec<RepairAction> = plan
            .actions
            .iter()
            .filter(|action| action.kind != RepairActionKind::ReconcileApprovedRelease)
            .cloned()
            .collect();
        if let Err(error) = execute_local_actions(
            config,
            &executor,
            &old_registration,
            &RepairPlan {
                actions: local_actions,
                ..plan.clone()
            },
        ) {
            if let Some(backup) = &backup {
                let _ = target::repair::restore_b1_backup(&executor, &plan.operation_id, backup);
            }
            return Err(error);
        }
        if has_release {
            let mut registration = old_registration.clone();
            if let Err(error) = crate::upgrade::run_approved_release_for_repair(
                config,
                &mut registration,
                allow_data_migration,
            )
            .await
            {
                persist_execution_journal(
                    observation,
                    plan,
                    &RepairJournal {
                        phase: "failed_recoverable".to_owned(),
                        target_observation_fingerprint: observation
                            .target
                            .as_ref()
                            .map(|value| value.fingerprint())
                            .unwrap_or_default(),
                        backup: backup.clone(),
                        activated: true,
                        warning_code: repair_error_code(&error),
                        ..RepairJournal::default()
                    },
                )?;
                return Ok((plan.clone(), "failed_recoverable"));
            }
        }
        verify_local_action_results(
            config,
            &executor,
            observation.target.as_ref(),
            &plan.actions,
        )
        .await?;
        for action in &plan.actions {
            let _ = queue_repair_event(
                &old_registration,
                "repair_action_completed",
                "repair_action_completed",
                action_kind_name(action.kind),
            )
            .await;
        }
        persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "succeeded".to_owned(),
                target_observation_fingerprint: observation
                    .target
                    .as_ref()
                    .map(|value| value.fingerprint())
                    .unwrap_or_default(),
                ..RepairJournal::default()
            },
        )?;
        return Ok((plan.clone(), "succeeded"));
    }
    let mut source = crate::commands::source_for_operation_noninteractive(config).await?;
    ensure_source_identity(&source, state.source_user_id)?;
    let observation_request = RepairObservationRequest {
        schema_version: 1,
        cli_schema: "2".to_owned(),
        deployment_id: observation.deployment_id.clone(),
        local_generation: observation.local_generation,
        target_generation: observation
            .target
            .as_ref()
            .map(|target| target.installation_generation)
            .unwrap_or(observation.local_generation),
        file_fingerprints: redacted_target_fingerprints(observation.target.as_ref()),
        services: redacted_target_services(observation.target.as_ref()),
        capabilities: target_capabilities(observation.target.as_ref()),
        requested_actions: plan
            .actions
            .iter()
            .map(|action| action_kind_name(action.kind).to_owned())
            .collect(),
    };
    let source_diagnose = source
        .repair_diagnose(&old_registration, &observation_request)
        .await?;
    if source_diagnose.deployment_id != old_registration.deployment_id
        || (source_diagnose.installation_generation != 0
            && source_diagnose.installation_generation != old_registration.installation_generation)
            && !observation
                .codes
                .iter()
                .any(|code| code == "LOCAL_OPERATION_INTERRUPTED")
    {
        return Err(AppError::State("CONTROL_GENERATION_DRIFT".to_owned()));
    }
    let diagnostics =
        serde_json::to_value(diagnostics_for(observation)).unwrap_or(Value::Array(Vec::new()));
    let actions = serde_json::to_value(
        plan.actions
            .iter()
            .map(|action| {
                serde_json::json!({
                    "kind": action_kind_name(action.kind),
                    "risk": action.risk,
                    "automatic": action.automatic,
                    "backup_level": action.backup_level,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap_or(Value::Array(Vec::new()));
    let prior_journal = load_journal_for_plan(&plan.plan_fingerprint);
    // A journal that points at an aborted or expired source operation is
    // settled history, not a resume target; fall through to a fresh
    // operation in that case.
    let journal_operation = if let Some(journal) = &prior_journal
        && !journal.source_operation_id.is_empty()
    {
        let existing = source
            .repair_get_operation(&old_registration, &journal.source_operation_id)
            .await?;
        if existing.state == "operation_aborted"
            || existing.expires_at <= crate::state::unix_timestamp()
        {
            None
        } else {
            Some(existing)
        }
    } else {
        None
    };
    let operation = if let Some(operation) = journal_operation {
        operation
    } else {
        let idempotency_key = format!("{}-{}", plan.operation_id, plan.plan_fingerprint);
        let request = RepairOperationRequest {
            plan_fingerprint: plan.plan_fingerprint.clone(),
            observation_fingerprint: plan.observation_fingerprint.clone(),
            diagnostics,
            actions,
            backup_level: plan.protection.backup_level.clone(),
        };
        match source
            .repair_create_operation(&old_registration, &idempotency_key, &request)
            .await
        {
            Ok(operation) => operation,
            Err(error) if source_error_is_repair_conflict(&error) => {
                // The journal was lost but a live operation still exists on
                // the source. Adopt it for resume instead of failing; only
                // one operation can be pending per deployment.
                let now = crate::state::unix_timestamp();
                source
                    .repair_list_operations(&old_registration)
                    .await?
                    .into_iter()
                    .find(|operation| {
                        operation.expires_at > now
                            && !matches!(
                                operation.state.as_str(),
                                "succeeded" | "succeeded_with_warning" | "operation_aborted"
                            )
                    })
                    .ok_or(error)?
            }
            Err(error) => return Err(error.into()),
        }
    };
    let target_observation = observation
        .target
        .as_ref()
        .ok_or_else(|| AppError::State("TARGET_OBSERVATION_UNAVAILABLE".to_owned()))?;
    let mut backup = prior_journal
        .as_ref()
        // A backup manifest is bound to its operation id; never adopt one
        // recorded for a different (settled) operation.
        .filter(|journal| {
            journal.source_operation_id.is_empty()
                || journal.source_operation_id == operation.operation_id
        })
        .and_then(|journal| journal.backup.clone());
    // A kill at any later point must leave a resumable local journal that
    // points at the pending source operation (plan 12.3). Without it a rerun
    // could not find the pending operation and would attempt to create a
    // conflicting one.
    persist_execution_journal(
        observation,
        plan,
        &RepairJournal {
            phase: "executing".to_owned(),
            source_operation_id: operation.operation_id.clone(),
            target_observation_fingerprint: target_observation.fingerprint(),
            backup: backup.clone(),
            ..RepairJournal::default()
        },
    )?;
    if backup.is_none()
        && !matches!(
            operation.state.as_str(),
            "installation_activated"
                | "upstream_reporting_verified"
                | "public_probe_verified"
                | "succeeded"
                | "succeeded_with_warning"
                | "failed_recoverable"
        )
    {
        backup = Some(
            match target::repair::create_b1_backup(
                &executor,
                &operation.operation_id,
                target_observation,
            ) {
                Ok(backup) => backup,
                Err(error) => {
                    abort_and_settle(
                        &mut source,
                        &old_registration,
                        &operation.operation_id,
                        "REPAIR_BACKUP_FAILED",
                        observation,
                        plan,
                    )
                    .await;
                    return Err(error);
                }
            },
        );
        target::repair::write_journal(
            &executor,
            &operation.operation_id,
            "backup_completed",
            &serde_json::json!({
                "target_observation_fingerprint": target_observation.fingerprint()
            }),
        )?;
        let _ = queue_repair_event(
            &old_registration,
            "repair_backup_completed",
            "repair_backup_completed",
            "B1 backup completed",
        )
        .await;
        // Persist the fresh backup manifest for interruption recovery before
        // any mutation begins.
        persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "executing".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation.fingerprint(),
                backup: backup.clone(),
                ..RepairJournal::default()
            },
        )?;
    }
    let local_actions: Vec<RepairAction> = plan
        .actions
        .iter()
        .filter(|action| {
            matches!(
                action.kind,
                RepairActionKind::RepairManagedPermissions
                    | RepairActionKind::RepairUpgradeAgent
                    | RepairActionKind::RebuildManagedEnvironment
                    | RepairActionKind::ReconcileCompose
                    | RepairActionKind::ReconcileRegistrationIdentity
            )
        })
        .cloned()
        .collect();
    let pre_activation = matches!(
        operation.state.as_str(),
        "planned" | "credentials_prepared" | "target_applied" | "target_locally_verified"
    );
    if pre_activation
        && local_actions
            .iter()
            .any(|action| action.kind == RepairActionKind::RepairUpgradeAgent)
        && (target_observation
            .files
            .get("bin/meowai-deploy-upgrade-agent")
            .is_none_or(|file| !file.exists || !file.regular || file.symlink)
            || !target_observation.agent_proof_capable)
    {
        // A missing or pre-repair-protocol signed agent binary can only be
        // restored through the existing release engine. Do not synthesize or
        // copy an untrusted executable as part of a repair operation.
        let mut release_registration = old_registration.clone();
        if let Err(error) = crate::upgrade::run_approved_release_for_repair(
            config,
            &mut release_registration,
            allow_data_migration,
        )
        .await
        {
            let restored = backup.as_ref().map_or(Ok(()), |backup| {
                target::repair::restore_b1_backup(&executor, &operation.operation_id, backup)
            });
            abort_and_settle(
                &mut source,
                &old_registration,
                &operation.operation_id,
                "REPAIR_UPGRADE_AGENT_FAILED",
                observation,
                plan,
            )
            .await;
            if restored.is_err() {
                return Err(AppError::State("REPAIR_ROLLBACK_FAILED".to_owned()));
            }
            return Err(error);
        }
    }
    if pre_activation
        && !local_actions.is_empty()
        && let Err(error) = execute_local_actions(
            config,
            &executor,
            &old_registration,
            &RepairPlan {
                actions: local_actions,
                ..plan.clone()
            },
        )
    {
        let restored = backup.as_ref().map_or(Ok(()), |backup| {
            target::repair::restore_b1_backup(&executor, &operation.operation_id, backup)
        });
        abort_and_settle(
            &mut source,
            &old_registration,
            &operation.operation_id,
            "REPAIR_LOCAL_ACTION_FAILED",
            observation,
            plan,
        )
        .await;
        if restored.is_err() {
            return Err(AppError::State("REPAIR_ROLLBACK_FAILED".to_owned()));
        }
        return Err(error);
    }
    // Prepare encrypted pending credentials only after the required B1 backup
    // has completed. A backup/precondition failure must not leave pending
    // ciphertext behind on the source operation.
    let credentials = match source
        .repair_prepare(&old_registration, &operation.operation_id)
        .await
    {
        Ok(credentials) => credentials,
        Err(error) => {
            abort_and_settle(
                &mut source,
                &old_registration,
                &operation.operation_id,
                "REPAIR_PREPARE_FAILED",
                observation,
                plan,
            )
            .await;
            return Err(error.into());
        }
    };
    let _ = queue_repair_event(
        &old_registration,
        "repair_credentials_prepared",
        "repair_credentials_prepared",
        "pending credentials prepared",
    )
    .await;
    let target_observation_fingerprint = target_observation.fingerprint();
    let needs_target_apply = !matches!(
        operation.state.as_str(),
        "installation_activated"
            | "upstream_reporting_verified"
            | "public_probe_verified"
            | "succeeded"
            | "succeeded_with_warning"
            | "failed_recoverable"
    );
    let prepared_target = (|| -> Result<(String, &'static str)> {
        if !needs_target_apply {
            return Ok((String::new(), "resume"));
        }
        // The target-applied proof must come from the target agent or the
        // protected updater socket (plan 6.1/7.5); the CLI never computes it
        // from the in-memory secret. When the installed binary predates the
        // repair protocol, probe the full proof path with placeholder inputs
        // before stopping any service, so an incapable target fails cleanly
        // without downtime and without touching the environment file.
        if !target_observation.agent_proof_capable {
            target::repair::target_applied_proof_with_mode(
                &executor,
                "capability-probe",
                credentials.installation_generation,
                "capability-probe",
                &target_observation_fingerprint,
            )?;
        }
        let old_content =
            executor.run_in_directory("cat downstream-credentials.env 2>/dev/null || true")?;
        let mut values = managed_env_updates(config, &old_registration);
        values.insert(
            "MEOWAI_INSTALLATION_GENERATION",
            credentials.installation_generation.to_string(),
        );
        values.insert(
            "MEOWAI_REPORT_CREDENTIAL",
            credentials.report_credential.expose_secret().to_owned(),
        );
        values.insert(
            "MEOWAI_PULL_CREDENTIAL",
            credentials.pull_credential.expose_secret().to_owned(),
        );
        let new_content =
            complete_managed_env_file(&String::from_utf8_lossy(&old_content.stdout), values)?;
        executor.compose(&config.container_name, &["stop", "new-api"])?;
        target::repair::atomic_replace(
            &executor,
            &operation.operation_id,
            "downstream-credentials.env",
            new_content.as_bytes(),
            0o600,
        )?;
        executor.compose(&config.container_name, &["config"])?;
        target::repair::target_applied_proof_with_mode(
            &executor,
            &operation.operation_id,
            credentials.installation_generation,
            &credentials.target_challenge,
            &target_observation_fingerprint,
        )
    })();
    let (proof, proof_mode) = match prepared_target {
        Ok(proof) => proof,
        Err(error) => {
            let restored = backup.as_ref().map_or(Ok(()), |backup| {
                target::repair::restore_b1_backup(&executor, &operation.operation_id, backup)
            });
            let restarted = executor.compose(
                &config.container_name,
                &["up", "-d", "--no-deps", "new-api"],
            );
            abort_and_settle(
                &mut source,
                &old_registration,
                &operation.operation_id,
                "REPAIR_TARGET_APPLY_FAILED",
                observation,
                plan,
            )
            .await;
            if restored.is_err() || restarted.is_err() {
                return Err(AppError::State("REPAIR_ROLLBACK_FAILED".to_owned()));
            }
            return Err(error);
        }
    };
    target::repair::write_journal(
        &executor,
        &operation.operation_id,
        "target_proof_generated",
        &serde_json::json!({
            "target_applied_proof_mode": proof_mode,
            "target_observation_fingerprint": target_observation_fingerprint.clone(),
        }),
    )?;
    let activated = if needs_target_apply {
        match source
            .repair_activate(
                &old_registration,
                &operation.operation_id,
                &credentials.target_challenge,
                &proof,
                &target_observation_fingerprint,
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                // The HTTP response can be lost after the source commits the
                // activation. Read back the operation before deciding whether
                // it is safe to restore the old target credentials.
                match source
                    .repair_get_operation(&old_registration, &operation.operation_id)
                    .await
                {
                    Ok(receipt)
                        if matches!(
                            receipt.state.as_str(),
                            "installation_activated"
                                | "upstream_reporting_verified"
                                | "public_probe_verified"
                                | "succeeded"
                                | "succeeded_with_warning"
                                | "failed_recoverable"
                        ) =>
                    {
                        receipt
                    }
                    Ok(_) => {
                        if let Some(backup) = &backup {
                            let _ = target::repair::restore_b1_backup(
                                &executor,
                                &operation.operation_id,
                                backup,
                            );
                        }
                        let _ = executor.compose(
                            &config.container_name,
                            &["up", "-d", "--no-deps", "new-api"],
                        );
                        abort_and_settle(
                            &mut source,
                            &old_registration,
                            &operation.operation_id,
                            "REPAIR_ACTIVATION_FAILED",
                            observation,
                            plan,
                        )
                        .await;
                        return Err(error.into());
                    }
                    Err(_) => {
                        persist_execution_journal(
                            observation,
                            plan,
                            &RepairJournal {
                                phase: "failed_recoverable".to_owned(),
                                source_operation_id: operation.operation_id.clone(),
                                target_observation_fingerprint: target_observation_fingerprint
                                    .clone(),
                                backup: backup.clone(),
                                warning_code: "REPAIR_ACTIVATION_STATUS_UNKNOWN".to_owned(),
                                ..RepairJournal::default()
                            },
                        )?;
                        return Ok((plan.clone(), "failed_recoverable"));
                    }
                }
            }
        }
    } else {
        operation.clone()
    };
    target::repair::write_journal(
        &executor,
        &operation.operation_id,
        "installation_activated",
        &serde_json::json!({
            "target_observation_fingerprint": target_observation_fingerprint
        }),
    )?;
    let _ = queue_repair_event(
        &old_registration,
        "repair_installation_activated",
        "repair_installation_activated",
        "new installation activated",
    )
    .await;
    persist_execution_journal(
        observation,
        plan,
        &RepairJournal {
            phase: "installation_activated".to_owned(),
            source_operation_id: operation.operation_id.clone(),
            target_observation_fingerprint: target_observation_fingerprint.clone(),
            backup: backup.clone(),
            activated: true,
            ..RepairJournal::default()
        },
    )?;
    if executor
        .compose(
            &config.container_name,
            &["up", "-d", "--no-deps", "new-api"],
        )
        .is_err()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "REPAIR_NEWAPI_RESTART_FAILED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    if wait_for_newapi(&executor, config.newapi_port)
        .await
        .is_err()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "REPAIR_NEWAPI_STATUS_FAILED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    let after_observation = match target::repair::observe(
        &executor,
        &config.container_name,
        config.newapi_port,
        config.kuma_port,
    ) {
        Ok(value) => value,
        Err(_) => {
            let _ = persist_execution_journal(
                observation,
                plan,
                &RepairJournal {
                    phase: "failed_recoverable".to_owned(),
                    source_operation_id: operation.operation_id.clone(),
                    target_observation_fingerprint: target_observation_fingerprint.clone(),
                    backup: backup.clone(),
                    activated: true,
                    warning_code: "REPAIR_TARGET_OBSERVATION_FAILED".to_owned(),
                    ..RepairJournal::default()
                },
            );
            return Ok((plan.clone(), "failed_recoverable"));
        }
    };
    if target::repair::verify_resource_identity(
        &target_observation.data_paths,
        &after_observation.data_paths,
    )
    .is_err()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "PERSISTENT_RESOURCE_IDENTITY_CHANGED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    if target::repair::verify_volume_identity(
        &target_observation.volume_identities,
        &after_observation.volume_identities,
    )
    .is_err()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "PERSISTENT_RESOURCE_IDENTITY_CHANGED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    if target::repair::verify_service_mount_identity(
        &target_observation.services,
        &after_observation.services,
    )
    .is_err()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "PERSISTENT_RESOURCE_IDENTITY_CHANGED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    if !after_observation.postgres_select_1 || !after_observation.redis_ping {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "REPAIR_DATA_DEPENDENCY_UNHEALTHY".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    let registration = DeploymentRegistration {
        deployment_id: old_registration.deployment_id.clone(),
        installation_generation: activated.target_installation_generation,
        control_plane_url: old_registration.control_plane_url.clone(),
        report_credential: credentials.report_credential,
        pull_credential: credentials.pull_credential,
        heartbeat_interval_seconds: old_registration.heartbeat_interval_seconds,
        snapshot_interval_seconds: old_registration.snapshot_interval_seconds,
        silent_updates_enabled: old_registration.silent_updates_enabled,
        release_schema_version: old_registration.release_schema_version.clone(),
        release_manifest_public_key: old_registration.release_manifest_public_key.clone(),
        release_artifact_allowed_hosts: old_registration.release_artifact_allowed_hosts.clone(),
    };
    if crate::application::deployment_control::stage_registration_locally(
        config,
        state.source_user_id,
        &registration,
    )
    .is_err()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "REPAIR_LOCAL_REGISTRATION_STAGE_FAILED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    // New agents may support an immediate protected report request. A 404/
    // 501-style source response is an explicit compatibility fallback; it
    // never counts as reporting verification by itself.
    let _immediate_report_requested = source
        .repair_request_report(&registration, &operation.operation_id)
        .await
        .is_ok();
    state.installation_generation = registration.installation_generation;
    state.upstream_deployment_id = registration.deployment_id.clone();
    if storage::write(STATE_FILE, &serde_json::to_vec_pretty(&state).unwrap()).is_err()
        || crate::application::deployment_control::commit_staged_registration().is_err()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                warning_code: "REPAIR_LOCAL_STATE_PERSIST_FAILED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    // Reports queued under the revoked credentials can never be accepted and
    // would wedge the FIFO ahead of the new generation's repair events.
    let _ = crate::lifecycle_outbox::discard_stale_registration(&registration);
    let mut reporting_verified = false;
    let reporting_interval = u64::from(
        registration
            .heartbeat_interval_seconds
            .max(registration.snapshot_interval_seconds),
    );
    // Reporting verification may rely on the existing target timers when the
    // immediate report endpoint is unsupported. Allow two full intervals plus
    // a bounded startup grace period, while keeping a hard upper limit.
    let reporting_wait_seconds = reporting_interval
        .saturating_mul(2)
        .saturating_add(30)
        .clamp(60, 900);
    let reporting_attempts = (reporting_wait_seconds / 5).max(1);
    for _ in 0..reporting_attempts {
        let receipt = match source
            .repair_get_operation(&registration, &operation.operation_id)
            .await
        {
            Ok(receipt) => receipt,
            Err(_) => {
                let _ = persist_execution_journal(
                    observation,
                    plan,
                    &RepairJournal {
                        phase: "failed_recoverable".to_owned(),
                        source_operation_id: operation.operation_id.clone(),
                        target_observation_fingerprint: target_observation_fingerprint.clone(),
                        backup: backup.clone(),
                        activated: true,
                        warning_code: "REPAIR_REPORTING_STATUS_UNAVAILABLE".to_owned(),
                        ..RepairJournal::default()
                    },
                );
                return Ok((plan.clone(), "failed_recoverable"));
            }
        };
        if matches!(
            receipt.state.as_str(),
            "upstream_reporting_verified"
                | "public_probe_verified"
                | "succeeded"
                | "succeeded_with_warning"
        ) {
            reporting_verified = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    if !reporting_verified {
        let _ = source
            .repair_complete(
                &registration,
                &operation.operation_id,
                "failed_recoverable",
                "REPAIR_REPORTING_VERIFICATION_TIMEOUT",
            )
            .await;
        persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint,
                backup,
                activated: true,
                warning_code: "REPAIR_REPORTING_VERIFICATION_TIMEOUT".to_owned(),
                ..RepairJournal::default()
            },
        )?;
        return Ok((plan.clone(), "failed_recoverable"));
    }
    let _ = queue_repair_event(
        &registration,
        "repair_verification_completed",
        "repair_verification_completed",
        "upstream reporting verified",
    )
    .await;
    let (success, warning_code) = match source.repair_probe(&registration).await {
        Ok(probe) => {
            let success = probe.state == "completed" && probe.failure_code.is_empty();
            let warning = if success {
                String::new()
            } else if probe.failure_code.is_empty() {
                "PUBLIC_PROBE_FAILED".to_owned()
            } else {
                probe.failure_code
            };
            (success, warning)
        }
        Err(_) => (false, "REPAIR_PUBLIC_PROBE_UNAVAILABLE".to_owned()),
    };
    let final_status = if success {
        "succeeded"
    } else {
        "succeeded_with_warning"
    };
    // Reporting has already been verified. A public probe transport failure
    // is therefore a warning, not a reason to roll back the newly activated
    // credentials. Only failure to persist the terminal source state remains
    // recoverable.
    if let Err(_error) = source
        .repair_complete(
            &registration,
            &operation.operation_id,
            final_status,
            &warning_code,
        )
        .await
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "failed_recoverable".to_owned(),
                source_operation_id: operation.operation_id.clone(),
                target_observation_fingerprint: target_observation_fingerprint.clone(),
                backup: backup.clone(),
                activated: true,
                reporting_verified: true,
                warning_code: "REPAIR_SOURCE_COMPLETE_FAILED".to_owned(),
                ..RepairJournal::default()
            },
        );
        return Ok((plan.clone(), "failed_recoverable"));
    }
    let _ = queue_repair_event(
        &registration,
        if success {
            "repair_succeeded"
        } else {
            "repair_succeeded_with_warning"
        },
        if success {
            "repair_succeeded"
        } else {
            "repair_succeeded_with_warning"
        },
        if success {
            "repair completed"
        } else {
            if warning_code.is_empty() {
                "public probe warning"
            } else {
                &warning_code
            }
        },
    )
    .await;
    for action in &plan.actions {
        let _ = queue_repair_event(
            &registration,
            "repair_action_completed",
            "repair_action_completed",
            action_kind_name(action.kind),
        )
        .await;
    }
    let final_phase = if success {
        "succeeded"
    } else {
        "succeeded_with_warning"
    };
    persist_execution_journal(
        observation,
        plan,
        &RepairJournal {
            phase: final_phase.to_owned(),
            source_operation_id: operation.operation_id.clone(),
            target_observation_fingerprint,
            backup,
            activated: true,
            reporting_verified: true,
            ..RepairJournal::default()
        },
    )?;
    Ok((plan.clone(), final_phase))
}

async fn wait_for_newapi(executor: &TargetExecutor, port: u16) -> Result<String> {
    let mut last_error = None;
    for _ in 0..30 {
        match executor.newapi_version(port) {
            Ok(version) => return Ok(version),
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(last_error.unwrap_or_else(|| AppError::State("NEWAPI_STATUS_UNAVAILABLE".to_owned())))
}

async fn verify_local_action_results(
    config: &DeploymentConfig,
    executor: &TargetExecutor,
    before: Option<&target::repair::TargetObservation>,
    actions: &[RepairAction],
) -> Result<()> {
    let before =
        before.ok_or_else(|| AppError::State("TARGET_OBSERVATION_UNAVAILABLE".to_owned()))?;
    let after = target::repair::observe(
        executor,
        &config.container_name,
        config.newapi_port,
        config.kuma_port,
    )?;
    target::repair::verify_resource_identity(&before.data_paths, &after.data_paths)?;
    target::repair::verify_volume_identity(&before.volume_identities, &after.volume_identities)?;
    target::repair::verify_service_mount_identity(&before.services, &after.services)?;
    if !after.compose_valid {
        return Err(AppError::State("TARGET_COMPOSE_INVALID".to_owned()));
    }
    if !after.postgres_select_1 || !after.redis_ping {
        return Err(AppError::State("TARGET_DEPENDENCY_UNHEALTHY".to_owned()));
    }
    if !after.newapi_status_success {
        return Err(AppError::State("TARGET_NEWAPI_STATUS_NOT_READY".to_owned()));
    }
    if !after.kuma_status {
        return Err(AppError::State("TARGET_KUMA_UNHEALTHY".to_owned()));
    }
    if actions
        .iter()
        .any(|action| action.kind == RepairActionKind::RepairUpgradeAgent)
        && (!after.upgrade_agent_active || !after.upgrade_timer_active)
    {
        return Err(AppError::State("TARGET_AGENT_UNHEALTHY".to_owned()));
    }
    Ok(())
}

/// Match the control-plane URL recorded on the target against the configured
/// source URL and return the CLI-reachable registration form. The target env
/// holds the container-reachable alias (loopback rewritten to
/// `host.docker.internal`) and usually carries an `/api` suffix; older CLIs
/// wrote the bare source URL.
fn recovered_control_plane_url(source_url: &str, target_url: &str) -> Option<String> {
    let source_url = source_url.trim_end_matches('/');
    let cli_form = format!("{source_url}/api");
    let container_source = crate::target::compose::container_source_url(source_url)
        .unwrap_or_else(|_| source_url.to_owned());
    let container_source = container_source.trim_end_matches('/').to_owned();
    let container_form = format!("{container_source}/api");
    let target_url = target_url.trim_end_matches('/');
    if target_url == cli_form
        || target_url == container_form
        || target_url == source_url
        || target_url == container_source
    {
        Some(cli_form)
    } else {
        None
    }
}

async fn recover_local_registration(
    config: &DeploymentConfig,
    executor: &TargetExecutor,
    state: &mut DeploymentState,
) -> Result<DeploymentRegistration> {
    let output = executor
        .run_in_directory("cat downstream-credentials.env")
        .map_err(|_| AppError::State("LOCAL_REGISTRATION_MISSING".to_owned()))?;
    let content = String::from_utf8(output.stdout)
        .map_err(|_| AppError::State("TARGET_CREDENTIAL_FILE_INVALID".to_owned()))?;
    let values = crate::upgrade::parse_target_env(&content)?;
    let mut registration = crate::upgrade::registration_from_target_env_with_trust(&values, false)?;
    if registration.deployment_id.is_empty()
        || (!state.upstream_deployment_id.is_empty()
            && registration.deployment_id != state.upstream_deployment_id)
    {
        return Err(AppError::State(
            "LOCAL_REGISTRATION_CONTEXT_MISMATCH".to_owned(),
        ));
    }
    // The target env stores the container-reachable control-plane form (a
    // loopback source is rewritten to host.docker.internal) with an `/api`
    // suffix. Accept the known aliases of the configured source URL, and
    // store the CLI-reachable form in the recovered local registration.
    let Some(cli_control_plane) =
        recovered_control_plane_url(&config.source_url, &registration.control_plane_url)
    else {
        return Err(AppError::State("CONTROL_PLANE_CONTEXT_MISMATCH".to_owned()));
    };
    registration.control_plane_url = cli_control_plane;
    let mut source = crate::commands::source_for_operation_noninteractive(config).await?;
    ensure_source_identity(&source, state.source_user_id)?;
    let request = RepairObservationRequest {
        schema_version: 1,
        cli_schema: "2".to_owned(),
        deployment_id: registration.deployment_id.clone(),
        local_generation: state.installation_generation,
        target_generation: registration.installation_generation,
        file_fingerprints: serde_json::json!({"downstream_credentials": sha256_hex(content.as_bytes())}),
        services: serde_json::json!({}),
        capabilities: serde_json::json!({"registration_recovery": true}),
        requested_actions: vec!["reconcile_registration_identity".to_owned()],
    };
    let receipt = source.repair_diagnose(&registration, &request).await?;
    if receipt.deployment_id != registration.deployment_id
        || (receipt.installation_generation != 0
            && receipt.installation_generation != registration.installation_generation)
    {
        return Err(AppError::State("CONTROL_GENERATION_DRIFT".to_owned()));
    }
    crate::application::deployment_control::stage_registration_locally(
        config,
        state.source_user_id,
        &registration,
    )
    .map_err(|error| AppError::State(error.to_string()))?;
    crate::application::deployment_control::commit_staged_registration()
        .map_err(|error| AppError::State(error.to_string()))?;
    state.upstream_deployment_id = registration.deployment_id.clone();
    state.installation_generation = registration.installation_generation;
    storage::write(STATE_FILE, &serde_json::to_vec_pretty(state).unwrap())?;
    Ok(registration)
}

async fn queue_repair_event(
    registration: &DeploymentRegistration,
    event_type: &str,
    state: &str,
    reason: &str,
) -> Result<()> {
    crate::application::deployment_control::queue_lifecycle(registration, event_type, state, reason)
        .await
        .map(|_| ())
        .map_err(|error| AppError::State(error.to_string()))
}

/// Abort the pending source operation after a pre-activation failure and,
/// when the abort is accepted, settle the local journal as `aborted` so the
/// next diagnosis does not propose resuming an operation that no longer
/// exists upstream.
async fn abort_and_settle(
    source: &mut crate::source::SourceClient,
    registration: &DeploymentRegistration,
    operation_id: &str,
    error_code: &str,
    observation: &RepairObservation,
    plan: &RepairPlan,
) {
    if source
        .repair_abort(registration, operation_id, error_code)
        .await
        .is_ok()
    {
        let _ = persist_execution_journal(
            observation,
            plan,
            &RepairJournal {
                phase: "aborted".to_owned(),
                source_operation_id: operation_id.to_owned(),
                warning_code: error_code.to_owned(),
                ..RepairJournal::default()
            },
        );
        let _ = queue_repair_event(
            registration,
            "repair_aborted",
            "operation_aborted",
            error_code,
        )
        .await;
    }
}

fn persist_execution_journal(
    observation: &RepairObservation,
    plan: &RepairPlan,
    journal: &RepairJournal,
) -> Result<()> {
    let mut journal = journal.clone();
    journal.local_state_backup = storage::exists(REPAIR_STATE_BACKUP_FILE).unwrap_or(false);
    persist_outcome(&RepairOutcome {
        status: journal.phase.clone(),
        diagnostics: diagnostics_for(observation),
        plan: plan.clone(),
        journal,
    })
}

fn execute_local_actions(
    config: &DeploymentConfig,
    executor: &TargetExecutor,
    registration: &DeploymentRegistration,
    plan: &RepairPlan,
) -> Result<()> {
    for action in &plan.actions {
        match action.kind {
            RepairActionKind::ManualIntervention => {
                return Err(AppError::State("REPAIR_MANUAL_REQUIRED".to_owned()));
            }
            RepairActionKind::RestartManagedService => {
                let mut compose_args = vec!["up", "-d", "--no-deps"];
                let requested_services = action
                    .requires_restart
                    .iter()
                    .filter(|service| {
                        matches!(
                            service.as_str(),
                            "new-api" | "postgres" | "redis" | "uptime-kuma"
                        )
                    })
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let default_newapi = requested_services.is_empty();
                if default_newapi {
                    compose_args.push("new-api");
                } else {
                    compose_args.extend(requested_services);
                }
                executor.compose(&config.container_name, &compose_args)?;
                if action
                    .requires_restart
                    .iter()
                    .any(|service| service == "postgres")
                {
                    wait_for_local_check(|| {
                        executor
                            .run_in_directory(&format!(
                                "docker exec {}-postgres psql -U meowai -d newapi -tAc 'SELECT 1' >/dev/null",
                                config.container_name
                            ))
                            .map(|_| ())
                    })?;
                }
                if action
                    .requires_restart
                    .iter()
                    .any(|service| service == "redis")
                {
                    wait_for_local_check(|| {
                        executor
                            .run_in_directory(&format!(
                                "docker exec {}-redis sh -c 'redis-cli -a \"$REDIS_PASSWORD\" ping 2>/dev/null | grep -q PONG'",
                                config.container_name
                            ))
                            .map(|_| ())
                    })?;
                }
                if action
                    .requires_restart
                    .iter()
                    .any(|service| service == "new-api")
                    || default_newapi
                {
                    wait_for_local_check(|| {
                        executor.newapi_version(config.newapi_port).map(|_| ())
                    })?;
                }
                if action
                    .requires_restart
                    .iter()
                    .any(|service| service == "uptime-kuma")
                {
                    wait_for_local_check(|| {
                        executor
                            .run_in_directory(&format!(
                                "curl --fail --silent --show-error --max-time 5 http://127.0.0.1:{}/api/entry-page >/dev/null",
                                config.kuma_port
                            ))
                            .map(|_| ())
                    })?;
                }
            }
            RepairActionKind::RepairManagedPermissions => {
                executor.run_in_directory(
                    "set -eu\nfor file in secrets.env downstream-credentials.env updater-credentials.env; do [ ! -e \"$file\" ] || chmod 600 \"$file\"; done\n[ ! -e meowai-deploy-updater.sh ] || chmod 700 meowai-deploy-updater.sh\nfor file in meowai-deploy-updater.service meowai-deploy-updater.timer; do [ ! -e \"$file\" ] || chmod 644 \"$file\"; done\n[ ! -e run ] || chmod 700 run\n[ ! -e data ] || chmod 700 data\n[ ! -S run/updater.sock ] || chmod 600 run/updater.sock",
                )?;
            }
            RepairActionKind::RepairUpgradeAgent => {
                target::updater::install(executor, config, config.newapi_port)?;
            }
            RepairActionKind::RebuildManagedEnvironment => {
                let current = executor
                    .run_in_directory("cat downstream-credentials.env 2>/dev/null || true")?;
                let updates = managed_env_updates(config, registration);
                let content =
                    complete_managed_env_file(&String::from_utf8_lossy(&current.stdout), updates)?;
                target::repair::atomic_replace(
                    executor,
                    &plan.operation_id,
                    "downstream-credentials.env",
                    content.as_bytes(),
                    0o600,
                )?;
                let secrets = executor.run_in_directory("cat secrets.env 2>/dev/null || true")?;
                if !secrets.stdout.is_empty() {
                    let parsed = crate::target::compose::DeploymentSecrets::parse(&secrets.stdout)?;
                    let rendered = crate::target::compose::render_managed_secrets(&parsed);
                    target::repair::atomic_replace(
                        executor,
                        &plan.operation_id,
                        "secrets.env",
                        rendered.as_bytes(),
                        0o600,
                    )?;
                }
                executor.compose(&config.container_name, &["config"])?;
                executor.compose(
                    &config.container_name,
                    &["up", "-d", "--no-deps", "new-api"],
                )?;
            }
            RepairActionKind::ReconcileCompose => {
                let runtime =
                    crate::target::compose::DeploymentRuntime::load_existing_with_ssh_password(
                        config, None,
                    )?;
                let compose = crate::target::compose::render_managed_compose(config, &runtime)?;
                target::repair::atomic_replace(
                    executor,
                    &plan.operation_id,
                    "docker-compose.yml",
                    compose.as_bytes(),
                    0o644,
                )?;
                executor.compose(&config.container_name, &["config"])?;
                executor.compose(&config.container_name, &["up", "-d"])?;
            }
            RepairActionKind::ReconcileRegistrationIdentity => {
                let target = executor.run_in_directory("cat downstream-credentials.env")?;
                let values =
                    crate::upgrade::parse_target_env(&String::from_utf8_lossy(&target.stdout))?;
                let target_registration =
                    crate::upgrade::registration_from_target_env_with_trust(&values, false)?;
                if target_registration.deployment_id != registration.deployment_id
                    || target_registration.installation_generation
                        != registration.installation_generation
                {
                    return Err(AppError::State(
                        "CONTROL_GENERATION_DRIFT_MANUAL_REQUIRED".to_owned(),
                    ));
                }
            }
            RepairActionKind::ReconcileApprovedRelease => {
                // Executed by the async upgrade bridge in execute_plan.
            }
            RepairActionKind::RefreshMonitoring => {
                // The source-side probe is invoked by execute_plan where a live
                // authenticated client is available; this branch is a guard for
                // filtered local action execution.
            }
            RepairActionKind::RotateInstallationCredentials => unreachable!(),
        }
    }
    Ok(())
}

/// Wait for a restarted service to accept requests. Restart actions apply
/// `up -d` and must not fail just because the service needs a bounded amount
/// of startup time (plan 6.7: layered health checks follow restarts).
fn wait_for_local_check<F: FnMut() -> Result<()>>(mut check: F) -> Result<()> {
    let mut last_error = None;
    for _ in 0..30 {
        match check() {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(last_error.unwrap_or_else(|| AppError::State("TARGET_SERVICE_UNHEALTHY".to_owned())))
}

fn managed_env_updates<'a>(
    config: &'a DeploymentConfig,
    registration: &'a DeploymentRegistration,
) -> BTreeMap<&'a str, String> {
    let mut updates = BTreeMap::new();
    updates.insert("MEOWAI_DEPLOYMENT_ID", registration.deployment_id.clone());
    updates.insert(
        "MEOWAI_INSTALLATION_GENERATION",
        registration.installation_generation.to_string(),
    );
    updates.insert(
        "MEOWAI_CONTROL_PLANE_URL",
        target_control_plane_url(registration),
    );
    updates.insert(
        "MEOWAI_REPORT_CREDENTIAL",
        registration.report_credential.expose_secret().to_owned(),
    );
    updates.insert(
        "MEOWAI_PULL_CREDENTIAL",
        registration.pull_credential.expose_secret().to_owned(),
    );
    updates.insert(
        "MEOWAI_HEARTBEAT_INTERVAL_SECONDS",
        registration.heartbeat_interval_seconds.to_string(),
    );
    updates.insert(
        "MEOWAI_SNAPSHOT_INTERVAL_SECONDS",
        registration.snapshot_interval_seconds.to_string(),
    );
    updates.insert("MEOWAI_ALLOWED_IMAGE_REPOSITORY", config.image.clone());
    updates.insert("MEOWAI_CURRENT_IMAGE_DIGEST", config.image_ref.clone());
    updates.insert("MEOWAI_CONTAINER_NAME", config.container_name.clone());
    updates.insert("MEOWAI_NEWAPI_PORT", config.newapi_port.to_string());
    updates.insert("MEOWAI_KUMA_PORT", config.kuma_port.to_string());
    updates.insert(
        "MEOWAI_RELEASE_SCHEMA_VERSION",
        registration.release_schema_version.clone(),
    );
    updates
}

fn target_control_plane_url(registration: &DeploymentRegistration) -> String {
    crate::target::compose::container_source_url(&registration.control_plane_url)
        .unwrap_or_else(|_| registration.control_plane_url.clone())
}

fn update_env_file(content: &str, updates: &BTreeMap<&str, String>) -> Result<String> {
    for (key, value) in updates {
        crate::security::validate_env_value(key, value)?;
    }
    let mut seen = BTreeSet::new();
    let mut lines = Vec::new();
    for line in content.lines() {
        if let Some((key, _)) = line.split_once('=')
            && let Some(value) = updates.get(key)
        {
            if !seen.insert(key) {
                return Err(AppError::State(format!("duplicate managed env key {key}")));
            }
            lines.push(format!("{key}={value}"));
            continue;
        }
        lines.push(line.to_owned());
    }
    for (key, value) in updates {
        if seen.insert(key) {
            lines.push(format!("{key}={value}"));
        }
    }
    Ok(lines.join("\n") + "\n")
}

fn complete_managed_env_file(content: &str, mut updates: BTreeMap<&str, String>) -> Result<String> {
    let present = content
        .lines()
        .filter_map(|line| line.split_once('=').map(|(key, _)| key))
        .collect::<BTreeSet<_>>();
    for (key, value) in [
        ("MEOWAI_DEPLOYMENT_SCHEMA", "1".to_owned()),
        ("MEOWAI_UPDATER_SCHEMA", "1".to_owned()),
        ("MEOWAI_DATA_SCHEMA", "1".to_owned()),
        ("MEOWAI_CLI_SCHEMA", "2".to_owned()),
        ("CHECKER_PROXY_URL", "http://checker-proxy:8888".to_owned()),
        ("CHECKER_ENCRYPTION_KEY_ID", "1".to_owned()),
        ("CHECKER_FINGERPRINT_KEY_ID", "1".to_owned()),
        (
            "MEOWAI_UPDATER_SOCKET_PATH",
            "/run/meowai/updater.sock".to_owned(),
        ),
    ] {
        if !present.contains(key) {
            updates.insert(key, value);
        }
    }
    for key in ["CHECKER_ENCRYPTION_KEY", "CHECKER_FINGERPRINT_KEY"] {
        if !present.contains(key) {
            updates.insert(key, crate::security::random_secret(64));
        }
    }
    update_env_file(content, &updates)
}

fn restart_service_names(observation: &RepairObservation) -> Vec<String> {
    let mut services = observation
        .target
        .as_ref()
        .map(|target| {
            target
                .services
                .iter()
                .filter(|(_, service)| {
                    service.state != "running"
                        || (!service.health.is_empty() && service.health != "healthy")
                })
                .map(|(name, _)| name.clone())
                .filter(|name| {
                    matches!(
                        name.as_str(),
                        "new-api" | "postgres" | "redis" | "uptime-kuma"
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    services.sort();
    services.dedup();
    if services.is_empty() {
        services.push("new-api".to_owned());
    }
    services
}

fn action_kind_name(kind: RepairActionKind) -> &'static str {
    match kind {
        RepairActionKind::RotateInstallationCredentials => "rotate_installation_credentials",
        RepairActionKind::ManualIntervention => "manual_intervention",
        RepairActionKind::ReconcileRegistrationIdentity => "reconcile_registration_identity",
        RepairActionKind::RebuildManagedEnvironment => "rebuild_managed_environment",
        RepairActionKind::ReconcileCompose => "reconcile_compose",
        RepairActionKind::RepairUpgradeAgent => "repair_upgrade_agent",
        RepairActionKind::ReconcileApprovedRelease => "reconcile_approved_release",
        RepairActionKind::RestartManagedService => "restart_managed_service",
        RepairActionKind::RepairManagedPermissions => "repair_managed_permissions",
        RepairActionKind::RefreshMonitoring => "refresh_monitoring",
    }
}

pub fn collect_observation(
    config_path: Option<&std::path::Path>,
) -> Result<(RepairObservation, u32)> {
    let config_content = match config_path {
        Some(path) => fs::read(path).map_err(|source| AppError::ReadFile {
            path: path.to_owned(),
            source,
        })?,
        None => storage::read(CONFIG_FILE)?.unwrap_or_default(),
    };
    let config_present = !config_content.is_empty();
    let config = if config_present {
        std::str::from_utf8(&config_content)
            .ok()
            .and_then(|text| toml::from_str::<DeploymentConfig>(text).ok())
    } else {
        None
    };
    let state_content = storage::read(STATE_FILE)?.unwrap_or_default();
    let state = serde_json::from_slice::<DeploymentState>(&state_content).ok();
    let registration_content = storage::read(DOWNSTREAM_CREDENTIALS_FILE)?;
    let registration_present = registration_content.is_some();
    let registration_valid = registration_content
        .as_deref()
        .and_then(|content| serde_json::from_slice::<serde_json::Value>(content).ok())
        .is_some_and(|value| {
            value
                .get("deployment_id")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
                && value
                    .get("installation_generation")
                    .and_then(Value::as_u64)
                    .is_some_and(|v| v > 0)
                && value
                    .get("control_plane_url")
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
                && value
                    .get("report_credential")
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
                && value
                    .get("pull_credential")
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
        });
    let interrupted_operation = storage::read(REPAIR_OPERATION_FILE)?
        .and_then(|content| serde_json::from_slice::<RepairOutcome>(&content).ok())
        .is_some_and(|outcome| {
            // Resume-as-rotation only applies when the interrupted operation
            // actually involved installation credentials. A failed local-only
            // action (for example a service restart) is replanned from the
            // current facts and must not force a credential rotation.
            let rotation_involved =
                outcome.journal.activated
                    || !outcome.journal.source_operation_id.is_empty()
                    || outcome.plan.actions.iter().any(|action| {
                        action.kind == RepairActionKind::RotateInstallationCredentials
                    });
            if !rotation_involved {
                return false;
            }
            if matches!(
                outcome.status.as_str(),
                "succeeded" | "succeeded_with_warning" | "aborted" | "diagnosed" | "planned"
            ) {
                return false;
            }
            !matches!(
                outcome.journal.phase.as_str(),
                "" | "diagnosed" | "planned" | "succeeded" | "succeeded_with_warning" | "aborted"
            ) || matches!(outcome.status.as_str(), "executing" | "failed_recoverable")
        });
    let (directory, deployment_id, source_user_id, generation, target_fingerprint) =
        match (&config, &state) {
            (Some(config), Some(state)) => (
                Some(config.directory.clone()),
                state.upstream_deployment_id.clone(),
                state.source_user_id,
                state.installation_generation,
                state.target_fingerprint.clone(),
            ),
            (Some(config), None) => (
                Some(config.directory.clone()),
                String::new(),
                0,
                0,
                String::new(),
            ),
            (None, Some(state)) => (
                None,
                state.upstream_deployment_id.clone(),
                state.source_user_id,
                state.installation_generation,
                state.target_fingerprint.clone(),
            ),
            _ => (None, String::new(), 0, 0, String::new()),
        };
    let target_directory_present = match (&config, directory.as_ref()) {
        (Some(config), Some(_path))
            if matches!(config.target, crate::config::Target::Ssh { .. }) =>
        {
            true
        }
        (_, Some(path)) => path.is_dir(),
        _ => false,
    };
    let credentials_path = directory
        .as_ref()
        .map(|path| path.join("downstream-credentials.env"));
    let target_credentials_present = match (&config, credentials_path.as_ref()) {
        (Some(config), Some(_)) if matches!(config.target, crate::config::Target::Ssh { .. }) => {
            true
        }
        (_, Some(path)) => path.is_file(),
        _ => false,
    };
    let target_credentials_fingerprint = match (&config, credentials_path.as_ref()) {
        (Some(config), Some(_)) if matches!(config.target, crate::config::Target::Ssh { .. }) => {
            String::new()
        }
        (_, Some(path)) => fs::read(path)
            .ok()
            .map(|bytes| sha256_hex(&bytes))
            .unwrap_or_default(),
        _ => String::new(),
    };
    let mut codes = Vec::new();
    if !config_present {
        codes.push("LOCAL_CONFIG_MISSING".to_owned());
    }
    if config_present && state_content.is_empty() {
        codes.push("LOCAL_STATE_INVALID".to_owned());
    }
    if !registration_present {
        codes.push("LOCAL_REGISTRATION_MISSING".to_owned());
    } else if !registration_valid {
        codes.push("LOCAL_REGISTRATION_INVALID".to_owned());
    }
    if interrupted_operation {
        codes.push("LOCAL_OPERATION_INTERRUPTED".to_owned());
    }
    if directory.is_some() && !target_directory_present {
        codes.push("TARGET_DIRECTORY_MISSING".to_owned());
    }
    if directory.is_some() && target_directory_present && !target_credentials_present {
        codes.push("TARGET_CREDENTIAL_FILE_MISSING".to_owned());
    }
    Ok((
        RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id,
            source_user_id,
            local_generation: generation,
            config_present,
            state_present: !state_content.is_empty(),
            registration_present,
            target_directory_present,
            target_credentials_present,
            target_credentials_fingerprint,
            target_fingerprint,
            codes,
            target: None,
        },
        generation,
    ))
}

pub fn build_plan(
    observation: &RepairObservation,
    base_generation: u32,
    requested: &[RepairActionKind],
) -> RepairPlan {
    let requested: BTreeSet<_> = requested.iter().copied().collect();
    let mut actions: Vec<RepairAction> = Vec::new();
    let has = |kind: RepairActionKind| requested.is_empty() || requested.contains(&kind);
    let interrupted = observation
        .codes
        .iter()
        .any(|code| code == "LOCAL_OPERATION_INTERRUPTED");
    if interrupted
        && has(RepairActionKind::RotateInstallationCredentials)
        && !actions
            .iter()
            .any(|action| action.kind == RepairActionKind::RotateInstallationCredentials)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RotateInstallationCredentials,
            risk: "config".to_owned(),
            automatic: true,
            backup_level: "B1".to_owned(),
            requires_restart: vec!["new-api".to_owned()],
            estimated_downtime_seconds: 20,
            preconditions: vec!["resumable_operation_journal_present".to_owned()],
            postconditions: vec!["repair_operation_resumed".to_owned()],
        });
    }
    if observation.codes.iter().any(|code| {
        matches!(
            code.as_str(),
            "CONTROL_CREDENTIAL_CIPHERTEXT_UNREADABLE"
                | "CONTROL_INSTALLATION_MISSING"
                | "TARGET_CREDENTIAL_FILE_MISSING"
                | "TARGET_CREDENTIAL_FILE_INVALID"
                | "LOCAL_REGISTRATION_MISSING"
                | "LOCAL_REGISTRATION_INVALID"
                | "CONTROL_INSTALLATION_REVOKED"
        )
    }) && has(RepairActionKind::RotateInstallationCredentials)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RotateInstallationCredentials,
            risk: "config".to_owned(),
            automatic: true,
            backup_level: "B1".to_owned(),
            requires_restart: vec!["new-api".to_owned()],
            estimated_downtime_seconds: 20,
            preconditions: vec![
                "source_session_valid".to_owned(),
                "target_lock_acquired".to_owned(),
                "backup_completed".to_owned(),
                "data_identity_verified".to_owned(),
            ],
            postconditions: vec![
                "target_applied_proof_verified".to_owned(),
                "installation_activated".to_owned(),
                "new_generation_reported".to_owned(),
            ],
        });
    }
    if observation
        .codes
        .iter()
        .any(|code| matches!(code.as_str(), "TARGET_CREDENTIAL_KEYS_MISMATCH"))
        && has(RepairActionKind::RebuildManagedEnvironment)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RebuildManagedEnvironment,
            risk: "config".to_owned(),
            automatic: true,
            backup_level: "B1".to_owned(),
            requires_restart: vec!["new-api".to_owned()],
            estimated_downtime_seconds: 20,
            preconditions: vec![
                "registration_identity_verified".to_owned(),
                "compose_config_valid".to_owned(),
            ],
            postconditions: vec!["managed_environment_complete".to_owned()],
        });
    }
    if observation
        .codes
        .iter()
        .any(|code| code == "TARGET_IMAGE_DRIFT")
        && has(RepairActionKind::ReconcileApprovedRelease)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::ReconcileApprovedRelease,
            risk: "structural".to_owned(),
            automatic: false,
            backup_level: "B2".to_owned(),
            requires_restart: vec!["managed-services".to_owned()],
            estimated_downtime_seconds: 60,
            preconditions: vec![
                "signed_release_manifest_verified".to_owned(),
                "data_backup_completed".to_owned(),
            ],
            postconditions: vec!["approved_image_and_schema_applied".to_owned()],
        });
    }
    if observation
        .codes
        .iter()
        .any(|code| code == "TARGET_FILE_PERMISSION_INVALID")
        && has(RepairActionKind::RepairManagedPermissions)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RepairManagedPermissions,
            risk: "config".to_owned(),
            automatic: true,
            backup_level: "B1".to_owned(),
            requires_restart: Vec::new(),
            estimated_downtime_seconds: 0,
            preconditions: vec!["managed_paths_allowlisted".to_owned()],
            postconditions: vec!["managed_permissions_verified".to_owned()],
        });
    }
    if observation.codes.iter().any(|code| {
        matches!(
            code.as_str(),
            "TARGET_AGENT_MISSING" | "TARGET_AGENT_OUTDATED" | "TARGET_AGENT_UNHEALTHY"
        )
    }) && has(RepairActionKind::RepairUpgradeAgent)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RepairUpgradeAgent,
            risk: "structural".to_owned(),
            automatic: true,
            backup_level: "B1".to_owned(),
            requires_restart: vec!["updater".to_owned()],
            estimated_downtime_seconds: 0,
            preconditions: vec!["approved_agent_bundle_available".to_owned()],
            postconditions: vec!["agent_service_timer_healthy".to_owned()],
        });
    }
    if observation
        .codes
        .iter()
        .any(|code| code == "TARGET_SERVICE_STOPPED" || code == "TARGET_SERVICE_UNHEALTHY")
        && has(RepairActionKind::RestartManagedService)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RestartManagedService,
            risk: "service".to_owned(),
            automatic: true,
            backup_level: "B0".to_owned(),
            requires_restart: restart_service_names(observation),
            estimated_downtime_seconds: 30,
            preconditions: vec!["persistent_data_identity_verified".to_owned()],
            postconditions: vec!["required_services_healthy".to_owned()],
        });
    }
    if observation
        .codes
        .iter()
        .any(|code| code == "PUBLIC_ENDPOINT_UNVERIFIED")
        && has(RepairActionKind::RefreshMonitoring)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RefreshMonitoring,
            risk: "observe".to_owned(),
            automatic: true,
            backup_level: "B0".to_owned(),
            requires_restart: Vec::new(),
            estimated_downtime_seconds: 0,
            preconditions: vec!["source_session_valid".to_owned()],
            postconditions: vec!["reporting_and_probe_refreshed".to_owned()],
        });
    }
    let mut manual_items = Vec::new();
    if observation
        .codes
        .iter()
        .any(|code| code == "LOCAL_CONFIG_MISSING" || code == "LOCAL_STATE_INVALID")
    {
        manual_items.push("LOCAL_CONFIG_OR_STATE_INVALID".to_owned());
    }
    if observation.codes.iter().any(|code| {
        matches!(
            code.as_str(),
            "TARGET_COMPOSE_MISSING" | "TARGET_COMPOSE_INVALID" | "TARGET_COMPOSE_DRIFT"
        )
    }) && has(RepairActionKind::ReconcileCompose)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::ReconcileCompose,
            risk: "config".to_owned(),
            automatic: true,
            backup_level: "B1".to_owned(),
            requires_restart: vec!["managed-services".to_owned()],
            estimated_downtime_seconds: 30,
            preconditions: vec![
                "target_lock_acquired".to_owned(),
                "unknown_resources_absent".to_owned(),
                "data_identity_verified".to_owned(),
            ],
            postconditions: vec![
                "compose_config_valid".to_owned(),
                "persistent_mount_identity_unchanged".to_owned(),
            ],
        });
    }
    if observation.codes.iter().any(|code| {
        matches!(
            code.as_str(),
            "TARGET_NEWAPI_UNHEALTHY"
                | "TARGET_NEWAPI_STATUS_NOT_READY"
                | "TARGET_LOCAL_HEALTH_UNAVAILABLE"
                | "TARGET_KUMA_UNHEALTHY"
        )
    }) && has(RepairActionKind::RestartManagedService)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::RestartManagedService,
            risk: "service".to_owned(),
            automatic: true,
            backup_level: "B0".to_owned(),
            requires_restart: restart_service_names(observation),
            estimated_downtime_seconds: 20,
            preconditions: vec![
                "target_lock_acquired".to_owned(),
                "data_identity_verified".to_owned(),
            ],
            postconditions: vec![
                "newapi_status_success".to_owned(),
                "persistent_mount_identity_unchanged".to_owned(),
            ],
        });
    }
    if observation
        .codes
        .iter()
        .any(|code| code == "TARGET_INSTALLATION_GENERATION_MISMATCH")
        && !actions
            .iter()
            .any(|action| action.kind == RepairActionKind::RotateInstallationCredentials)
        && has(RepairActionKind::ReconcileRegistrationIdentity)
    {
        actions.push(RepairAction {
            kind: RepairActionKind::ReconcileRegistrationIdentity,
            risk: "config".to_owned(),
            automatic: false,
            backup_level: "B1".to_owned(),
            requires_restart: Vec::new(),
            estimated_downtime_seconds: 0,
            preconditions: vec!["authoritative_upstream_identity_available".to_owned()],
            postconditions: vec!["registration_identity_matches".to_owned()],
        });
    }
    // A single diagnostic can imply the same typed action through multiple
    // paths (for example an interrupted rotation plus a missing credential
    // file). Execute each action kind at most once so journals, events, and
    // plan fingerprints remain stable.
    let mut seen_actions = BTreeSet::new();
    actions.retain(|action| seen_actions.insert(action_kind_name(action.kind)));
    if observation.deployment_id.is_empty() && observation.registration_present {
        manual_items.push("LOCAL_REGISTRATION_CONTEXT_MISMATCH".to_owned());
    }
    if actions.is_empty() && manual_items.is_empty() && !observation.codes.is_empty() {
        manual_items.extend(observation.codes.iter().cloned());
    }
    if observation.codes.iter().any(|code| {
        code == "TARGET_UNKNOWN_RESOURCES"
            || code == "TARGET_DIRECTORY_SYMLINK"
            || code == "TARGET_DEPLOYMENT_ID_MISMATCH"
            || code == "TARGET_DISK_INSUFFICIENT"
            || code == "TARGET_DEPENDENCY_UNHEALTHY"
            || code == "TARGET_RESOURCE_UNOWNED"
            || code == "TARGET_SECRET_FILE_INVALID"
            || code == "DATA_SCHEMA_UNKNOWN"
            || code == "DATA_IDENTITY_CHANGED"
            || code == "DATA_REPAIR_MANUAL_REQUIRED"
            || code == "SOURCE_UNREACHABLE"
            || code == "SOURCE_REPAIR_API_INCOMPATIBLE"
            || code == "LOCAL_SESSION_REAUTH_REQUIRED"
            || code == "LOCAL_REGISTRATION_CONTEXT_MISMATCH"
            || code == "CONTROL_PLANE_CONTEXT_MISMATCH"
            || code == "CONTROL_GENERATION_DRIFT"
            || code == "CONTROL_REPAIR_OPERATION_CONFLICT"
            || code == "CONTROL_RELEASE_BLOCKED"
    }) {
        manual_items.push("TARGET_IDENTITY_OR_RESOURCE_BOUNDARY".to_owned());
    }
    if has(RepairActionKind::ManualIntervention)
        && (!manual_items.is_empty() || requested.contains(&RepairActionKind::ManualIntervention))
    {
        actions.push(RepairAction {
            kind: RepairActionKind::ManualIntervention,
            risk: "manual".to_owned(),
            automatic: false,
            backup_level: "B0".to_owned(),
            requires_restart: Vec::new(),
            estimated_downtime_seconds: 0,
            preconditions: vec!["operator_review_required".to_owned()],
            postconditions: vec!["manual_items_acknowledged".to_owned()],
        });
    }
    // Keep execution deterministic and respect dependencies between actions.
    // The planner may discover actions in diagnostic order, which is not an
    // execution order (for example service restart must follow compose).
    actions.sort_by_key(|action| match action.kind {
        RepairActionKind::RotateInstallationCredentials => 10,
        RepairActionKind::RebuildManagedEnvironment => 20,
        RepairActionKind::ReconcileRegistrationIdentity => 30,
        RepairActionKind::RepairManagedPermissions => 40,
        RepairActionKind::RepairUpgradeAgent => 50,
        RepairActionKind::ReconcileCompose => 60,
        RepairActionKind::ReconcileApprovedRelease => 70,
        RepairActionKind::RestartManagedService => 80,
        RepairActionKind::RefreshMonitoring => 90,
        RepairActionKind::ManualIntervention => 100,
    });
    let protection = RepairProtectionPolicy {
        backup_level: if actions.iter().any(|action| action.backup_level == "B2") {
            "B2".to_owned()
        } else if actions.is_empty() {
            "B0".to_owned()
        } else {
            "B1".to_owned()
        },
        preserved_resources: vec![
            "postgres-data".to_owned(),
            "redis-data".to_owned(),
            "newapi-data".to_owned(),
            "kuma-data".to_owned(),
        ],
        destructive_operations_allowed: false,
    };
    let verification = vec![
        "compose_config_valid".to_owned(),
        "persistent_mount_identity_unchanged".to_owned(),
        "postgres_select_1".to_owned(),
        "redis_ping".to_owned(),
        "newapi_status_success".to_owned(),
        "upstream_reporting_verified".to_owned(),
        "public_probe_independent".to_owned(),
    ];
    let observation_fingerprint = fingerprint_observation(observation);
    let requested_seed = requested
        .iter()
        .map(|kind| action_kind_name(*kind))
        .collect::<Vec<_>>()
        .join(",");
    let operation_seed = format!(
        "{}|{}|{}|{}",
        observation.deployment_id, base_generation, observation_fingerprint, requested_seed
    );
    let mut plan = RepairPlan {
        schema_version: 1,
        operation_id: format!(
            "repair_{}",
            sha256_hex(operation_seed.as_bytes())[..24].to_owned()
        ),
        deployment_id: observation.deployment_id.clone(),
        base_generation,
        observation_fingerprint,
        plan_fingerprint: String::new(),
        // Keep the expiry stable for a plan generated in the same hour so the
        // review fingerprint can be reproduced, while guaranteeing at least a
        // full hour of validity even for plans generated near an hour
        // boundary.
        expires_at: {
            let now = crate::state::unix_timestamp();
            (now / 3600 + 2) * 3600
        },
        actions,
        protection,
        verification,
        manual_items,
    };
    refresh_plan_fingerprint(&mut plan);
    plan
}

fn refresh_plan_fingerprint(plan: &mut RepairPlan) {
    let mut fingerprint_input = plan.clone();
    fingerprint_input.plan_fingerprint.clear();
    plan.plan_fingerprint = fingerprint(&fingerprint_input);
}

/// Match a freshly recomputed plan against a reviewed fingerprint. The plan
/// fingerprint deliberately covers the hourly-quantized expiry, so a plan
/// reviewed shortly before an hour boundary is reproduced by rolling the
/// expiry back one window — but only while that earlier expiry is still in
/// the future. On success the plan keeps the matched (reviewed) expiry.
fn reviewed_plan_fingerprint_matches(plan: &mut RepairPlan, expected: &str, now: i64) -> bool {
    if expected == plan.plan_fingerprint {
        return true;
    }
    let recomputed_expires_at = plan.expires_at;
    let earlier_window = recomputed_expires_at - 3600;
    if earlier_window > now {
        plan.expires_at = earlier_window;
        refresh_plan_fingerprint(plan);
        if expected == plan.plan_fingerprint {
            return true;
        }
    }
    plan.expires_at = recomputed_expires_at;
    refresh_plan_fingerprint(plan);
    false
}

fn diagnostics_for(observation: &RepairObservation) -> Vec<RepairDiagnostic> {
    observation
        .codes
        .iter()
        .map(|code| {
            let (domain, severity, summary, action, automatic) = match code.as_str() {
                "LOCAL_CONFIG_MISSING" => (
                    "local",
                    DiagnosticSeverity::Error,
                    "本地部署配置不存在",
                    None,
                    false,
                ),
                "LOCAL_STATE_INVALID" => (
                    "local",
                    DiagnosticSeverity::Error,
                    "本地部署状态缺失或无效",
                    None,
                    false,
                ),
                "LOCAL_REGISTRATION_MISSING" => (
                    "registration",
                    DiagnosticSeverity::Error,
                    "本地 registration 不存在",
                    Some(RepairActionKind::RotateInstallationCredentials),
                    true,
                ),
                "LOCAL_REGISTRATION_INVALID" => (
                    "registration",
                    DiagnosticSeverity::Error,
                    "本地 registration 文件格式或字段不完整",
                    Some(RepairActionKind::RotateInstallationCredentials),
                    true,
                ),
                "TARGET_DIRECTORY_MISSING" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "目标部署目录不存在",
                    None,
                    false,
                ),
                "TARGET_CREDENTIAL_FILE_MISSING" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "目标凭据文件不存在",
                    Some(RepairActionKind::RotateInstallationCredentials),
                    true,
                ),
                "TARGET_DIRECTORY_SYMLINK" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "目标部署目录是符号链接",
                    None,
                    false,
                ),
                "TARGET_COMPOSE_MISSING" | "TARGET_COMPOSE_INVALID" | "TARGET_COMPOSE_DRIFT" => (
                    "compose",
                    DiagnosticSeverity::Error,
                    "Compose 配置无法通过校验",
                    Some(RepairActionKind::ReconcileCompose),
                    true,
                ),
                "TARGET_CREDENTIAL_FILE_INVALID" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "目标凭据文件不是安全的普通文件",
                    Some(RepairActionKind::RotateInstallationCredentials),
                    true,
                ),
                "TARGET_CREDENTIAL_KEYS_MISMATCH" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "目标环境文件缺少必需键或包含无效密钥",
                    Some(RepairActionKind::RebuildManagedEnvironment),
                    true,
                ),
                "TARGET_SECRET_FILE_INVALID" => (
                    "data",
                    DiagnosticSeverity::Error,
                    "数据库凭据文件缺失或无效，无法安全自动重建",
                    Some(RepairActionKind::ManualIntervention),
                    false,
                ),
                "TARGET_FILE_PERMISSION_INVALID" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "受管文件权限不符合要求",
                    Some(RepairActionKind::RepairManagedPermissions),
                    true,
                ),
                "TARGET_AGENT_MISSING" | "TARGET_AGENT_OUTDATED" | "TARGET_AGENT_UNHEALTHY" => (
                    "agent",
                    DiagnosticSeverity::Warning,
                    "目标升级 agent 或 timer 不健康",
                    Some(RepairActionKind::RepairUpgradeAgent),
                    true,
                ),
                "TARGET_IMAGE_DRIFT" => (
                    "release",
                    DiagnosticSeverity::Warning,
                    "目标 NewAPI 镜像与受管批准 digest 不一致",
                    Some(RepairActionKind::ReconcileApprovedRelease),
                    false,
                ),
                "TARGET_SERVICE_STOPPED" | "TARGET_SERVICE_UNHEALTHY" => (
                    "service",
                    DiagnosticSeverity::Error,
                    "受管服务未运行或健康检查失败",
                    Some(RepairActionKind::RestartManagedService),
                    true,
                ),
                "TARGET_POSTGRES_UNHEALTHY" => (
                    "data",
                    DiagnosticSeverity::Error,
                    "PostgreSQL SELECT 1 未通过",
                    Some(RepairActionKind::RestartManagedService),
                    false,
                ),
                "TARGET_REDIS_UNHEALTHY" => (
                    "data",
                    DiagnosticSeverity::Error,
                    "Redis PING 未通过",
                    Some(RepairActionKind::RestartManagedService),
                    false,
                ),
                "TARGET_NEWAPI_UNHEALTHY"
                | "TARGET_NEWAPI_STATUS_NOT_READY"
                | "TARGET_LOCAL_HEALTH_UNAVAILABLE" => (
                    "service",
                    DiagnosticSeverity::Error,
                    "NewAPI /api/status 未通过",
                    Some(RepairActionKind::RestartManagedService),
                    true,
                ),
                "TARGET_KUMA_UNHEALTHY" => (
                    "service",
                    DiagnosticSeverity::Warning,
                    "Uptime Kuma 健康检查未通过",
                    Some(RepairActionKind::RestartManagedService),
                    true,
                ),
                "TARGET_UNKNOWN_RESOURCES" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "发现未归属的 Compose 资源，必须人工确认",
                    None,
                    false,
                ),
                "TARGET_DEPLOYMENT_ID_MISMATCH" => (
                    "identity",
                    DiagnosticSeverity::Error,
                    "目标机 deployment 身份与本地状态不一致",
                    None,
                    false,
                ),
                "TARGET_INSTALLATION_GENERATION_MISMATCH" => (
                    "identity",
                    DiagnosticSeverity::Error,
                    "目标机安装代次与本地状态不一致",
                    Some(RepairActionKind::ReconcileRegistrationIdentity),
                    false,
                ),
                "TARGET_OBSERVATION_UNAVAILABLE" => (
                    "target",
                    DiagnosticSeverity::Error,
                    "无法采集目标机结构化事实",
                    None,
                    false,
                ),
                "LOCAL_OPERATION_INTERRUPTED" => (
                    "local",
                    DiagnosticSeverity::Warning,
                    "存在未完成的 repair journal，需要恢复或重新规划",
                    None,
                    false,
                ),
                "PUBLIC_ENDPOINT_UNVERIFIED"
                | "PUBLIC_ENDPOINT_UNREACHABLE"
                | "PUBLIC_ENDPOINT_TLS_INVALID"
                | "PUBLIC_ENDPOINT_IDENTITY_MISMATCH" => (
                    "network",
                    DiagnosticSeverity::Warning,
                    "公网入口尚未完成独立验证",
                    Some(RepairActionKind::RefreshMonitoring),
                    true,
                ),
                "CONTROL_CRYPTO_SECRET_NOT_PERSISTENT" => (
                    "registration",
                    DiagnosticSeverity::Error,
                    "上游没有配置持久化 CRYPTO_SECRET",
                    Some(RepairActionKind::ManualIntervention),
                    false,
                ),
                "CONTROL_CREDENTIAL_CIPHERTEXT_UNREADABLE" | "CONTROL_INSTALLATION_MISSING" => (
                    "registration",
                    DiagnosticSeverity::Error,
                    "上游安装凭据无法读取，需要轮换安装代次",
                    Some(RepairActionKind::RotateInstallationCredentials),
                    true,
                ),
                "CONTROL_INSTALLATION_REVOKED" => (
                    "registration",
                    DiagnosticSeverity::Error,
                    "上游当前安装记录已撤销，需要轮换安装代次",
                    Some(RepairActionKind::RotateInstallationCredentials),
                    true,
                ),
                "DATA_ENCRYPTED_WITH_LOST_KEY" => (
                    "encryption",
                    DiagnosticSeverity::Warning,
                    "非安装业务密文可能因旧密钥丢失而不可恢复",
                    Some(RepairActionKind::ManualIntervention),
                    false,
                ),
                "TARGET_DISK_INSUFFICIENT" | "TARGET_DEPENDENCY_UNHEALTHY" => (
                    "data",
                    DiagnosticSeverity::Error,
                    "数据保护前置条件未满足",
                    Some(RepairActionKind::ManualIntervention),
                    false,
                ),
                "SOURCE_UNREACHABLE"
                | "SOURCE_REPAIR_API_INCOMPATIBLE"
                | "LOCAL_SESSION_REAUTH_REQUIRED" => (
                    "control",
                    DiagnosticSeverity::Error,
                    "控制面不可达或本地会话需要重新认证",
                    Some(RepairActionKind::ManualIntervention),
                    false,
                ),
                "LOCAL_REGISTRATION_UNAVAILABLE"
                | "CONTROL_GENERATION_DRIFT"
                | "CONTROL_REPAIR_OPERATION_CONFLICT"
                | "CONTROL_RELEASE_BLOCKED"
                | "CONTROL_GENERATION_DRIFT_MANUAL_REQUIRED"
                | "LOCAL_REGISTRATION_CONTEXT_MISMATCH"
                | "CONTROL_PLANE_CONTEXT_MISMATCH" => (
                    "registration",
                    DiagnosticSeverity::Error,
                    "控制面身份、操作冲突或发布授权不满足自动修复条件",
                    Some(RepairActionKind::ManualIntervention),
                    false,
                ),
                "TARGET_RESOURCE_UNOWNED"
                | "DATA_SCHEMA_UNKNOWN"
                | "DATA_IDENTITY_CHANGED"
                | "DATA_REPAIR_MANUAL_REQUIRED" => (
                    "data",
                    DiagnosticSeverity::Error,
                    "数据资源身份或 schema 无法安全确认，需要人工处理",
                    Some(RepairActionKind::ManualIntervention),
                    false,
                ),
                _ => (
                    "unknown",
                    DiagnosticSeverity::Warning,
                    "检测到未分类偏差",
                    None,
                    false,
                ),
            };
            RepairDiagnostic {
                code: code.clone(),
                severity,
                domain: domain.to_owned(),
                summary: summary.to_owned(),
                recommended_action: action,
                automatic,
                evidence: BTreeMap::new(),
            }
        })
        .collect()
}

fn source_error_is_repair_conflict(error: &crate::source::SourceError) -> bool {
    match error {
        crate::source::SourceError::HttpStatus { status, .. } => {
            *status == reqwest::StatusCode::CONFLICT
        }
        crate::source::SourceError::Api { message, .. } => {
            message.contains("CONTROL_REPAIR_OPERATION_CONFLICT")
        }
        _ => false,
    }
}

fn source_error_diagnostic_code(error: &crate::source::SourceError) -> String {
    match error {
        crate::source::SourceError::AuthenticationRequired
        | crate::source::SourceError::TwoFactorRequired
        | crate::source::SourceError::InvalidCredentials(_) => {
            "LOCAL_SESSION_REAUTH_REQUIRED".to_owned()
        }
        crate::source::SourceError::Transport { .. }
        | crate::source::SourceError::HttpStatus { .. }
        | crate::source::SourceError::RateLimited { .. } => "SOURCE_UNREACHABLE".to_owned(),
        crate::source::SourceError::InvalidResponse { .. }
        | crate::source::SourceError::Api { .. }
        | crate::source::SourceError::InvalidDeployment(_)
        | crate::source::SourceError::AmbiguousToken(_)
        | crate::source::SourceError::InvalidUrl(_) => "SOURCE_REPAIR_API_INCOMPATIBLE".to_owned(),
        _ => "SOURCE_UNREACHABLE".to_owned(),
    }
}

fn app_error_diagnostic_code(error: &AppError) -> String {
    match error {
        AppError::Source(source) => source_error_diagnostic_code(source),
        AppError::Message(message) if message.contains("认证") || message.contains("session") => {
            "LOCAL_SESSION_REAUTH_REQUIRED".to_owned()
        }
        _ => "SOURCE_UNREACHABLE".to_owned(),
    }
}

fn ensure_source_identity(source: &SourceClient, expected_user_id: i64) -> Result<()> {
    if expected_user_id == 0 {
        return Ok(());
    }
    let actual = source
        .identity()
        .ok_or_else(|| AppError::State("LOCAL_SESSION_REAUTH_REQUIRED".to_owned()))?;
    if actual.user_id != expected_user_id {
        return Err(AppError::State(
            "LOCAL_REGISTRATION_CONTEXT_MISMATCH".to_owned(),
        ));
    }
    Ok(())
}

fn fingerprint<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).expect("repair model serializes");
    format!("sha256:{}", sha256_hex(&bytes))
}

fn fingerprint_observation(observation: &RepairObservation) -> String {
    let mut normalized = observation.clone();
    if let Some(target) = normalized.target.as_mut() {
        *target = target.normalized_for_fingerprint();
    }
    fingerprint(&normalized)
}

fn redacted_target_fingerprints(target: Option<&target::repair::TargetObservation>) -> Value {
    let Some(target) = target else {
        return Value::Null;
    };
    serde_json::json!({
        "target": target.target_fingerprint,
        "compose": target.compose_fingerprint,
        "paths": target.data_paths.len(),
        "volumes": target.volume_identities.len(),
    })
}

fn target_capabilities(target: Option<&target::repair::TargetObservation>) -> Value {
    let Some(target) = target else {
        return Value::Null;
    };
    serde_json::json!({
        "agent_version": target.agent_version,
        "agent_schema": target.agent_schema,
        "updater_active": target.upgrade_agent_active,
        "timer_active": target.upgrade_timer_active,
    })
}

fn redacted_target_services(target: Option<&target::repair::TargetObservation>) -> Value {
    let Some(target) = target else {
        return Value::Null;
    };
    let services = target
        .services
        .iter()
        .map(|(name, service)| {
            (
                name.clone(),
                serde_json::json!({
                    "state": service.state,
                    "health": service.health,
                    "mount_count": service.mounts.len(),
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    Value::Object(services)
}

fn print_terminal(outcome: &RepairOutcome) {
    println!("诊断完成\n");
    println!("状态：{}", outcome.status);
    println!(
        "部署：{}",
        if outcome.plan.deployment_id.is_empty() {
            "<未识别>"
        } else {
            &outcome.plan.deployment_id
        }
    );
    println!("计划指纹：{}", outcome.plan.plan_fingerprint);
    if !outcome.plan.actions.is_empty() {
        println!("\n修复动作：");
        for action in &outcome.plan.actions {
            println!(
                "  - {:?} [{} / {}]",
                action.kind, action.risk, action.backup_level
            );
        }
    }
    println!("\n数据保护：PostgreSQL、Redis、NewAPI 数据和 Kuma 数据保持不变");
    if !outcome.plan.manual_items.is_empty() {
        println!("\n人工处理项：");
        for item in &outcome.plan.manual_items {
            println!("  - {item}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_fingerprint_is_stable_and_redacted() {
        let observation = RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id: "dep_test".to_owned(),
            source_user_id: 7,
            local_generation: 1,
            config_present: true,
            state_present: true,
            registration_present: false,
            target_directory_present: true,
            target_credentials_present: false,
            target_credentials_fingerprint: "".to_owned(),
            target_fingerprint: "target".to_owned(),
            codes: vec!["TARGET_CREDENTIAL_FILE_MISSING".to_owned()],
            target: None,
        };
        let plan = build_plan(&observation, 1, &[]);
        let encoded = serde_json::to_string(&plan).unwrap();
        assert!(!encoded.contains("secret-value"));
        assert_eq!(
            plan.plan_fingerprint,
            build_plan(&observation, 1, &[]).plan_fingerprint
        );
        assert_ne!(
            plan.operation_id,
            build_plan(
                &RepairObservation {
                    target_fingerprint: "changed-target".to_owned(),
                    ..observation.clone()
                },
                1,
                &[]
            )
            .operation_id
        );
        let mut changed = plan.clone();
        changed.manual_items.push("MANUAL_REVIEW".to_owned());
        let original_fingerprint = changed.plan_fingerprint.clone();
        refresh_plan_fingerprint(&mut changed);
        assert_ne!(original_fingerprint, changed.plan_fingerprint);
    }

    #[test]
    fn structural_release_uses_b2_and_is_a_distinct_action() {
        let observation = RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id: "dep_test".to_owned(),
            source_user_id: 7,
            local_generation: 1,
            config_present: true,
            state_present: true,
            registration_present: true,
            target_directory_present: true,
            target_credentials_present: true,
            target_credentials_fingerprint:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            target_fingerprint:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
            codes: vec![
                "TARGET_IMAGE_DRIFT".to_owned(),
                "TARGET_CREDENTIAL_FILE_MISSING".to_owned(),
            ],
            target: None,
        };
        let plan = build_plan(&observation, 1, &[]);
        assert_eq!(plan.protection.backup_level, "B2");
        assert!(
            plan.actions
                .iter()
                .any(|action| action.kind == RepairActionKind::ReconcileApprovedRelease)
        );
        assert!(
            plan.actions
                .iter()
                .any(|action| action.kind == RepairActionKind::RotateInstallationCredentials)
        );
    }

    #[test]
    fn duplicate_diagnostics_emit_each_action_once() {
        let observation = RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id: "dep_test".to_owned(),
            source_user_id: 7,
            local_generation: 1,
            config_present: true,
            state_present: true,
            registration_present: true,
            target_directory_present: true,
            target_credentials_present: false,
            target_credentials_fingerprint: String::new(),
            target_fingerprint: "target".to_owned(),
            codes: vec![
                "LOCAL_OPERATION_INTERRUPTED".to_owned(),
                "TARGET_CREDENTIAL_FILE_MISSING".to_owned(),
                "TARGET_SERVICE_STOPPED".to_owned(),
                "TARGET_SERVICE_UNHEALTHY".to_owned(),
            ],
            target: None,
        };
        let plan = build_plan(&observation, 1, &[]);
        let kinds: Vec<_> = plan.actions.iter().map(|action| action.kind).collect();
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == RepairActionKind::RotateInstallationCredentials)
                .count(),
            1
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == RepairActionKind::RestartManagedService)
                .count(),
            1
        );
    }

    #[test]
    fn action_plan_uses_allowed_risks_and_dependency_order() {
        let observation = RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id: "dep_test".to_owned(),
            source_user_id: 7,
            local_generation: 1,
            config_present: true,
            state_present: true,
            registration_present: true,
            target_directory_present: true,
            target_credentials_present: true,
            target_credentials_fingerprint: String::new(),
            target_fingerprint: "target".to_owned(),
            codes: vec![
                "TARGET_SERVICE_STOPPED".to_owned(),
                "TARGET_COMPOSE_DRIFT".to_owned(),
            ],
            target: None,
        };
        let plan = build_plan(&observation, 1, &[]);
        let risks = plan
            .actions
            .iter()
            .map(|action| action.risk.as_str())
            .collect::<Vec<_>>();
        assert!(risks.iter().all(|risk| matches!(
            *risk,
            "observe" | "config" | "service" | "structural" | "data" | "manual"
        )));
        let compose = plan
            .actions
            .iter()
            .position(|action| action.kind == RepairActionKind::ReconcileCompose)
            .unwrap();
        let restart = plan
            .actions
            .iter()
            .position(|action| action.kind == RepairActionKind::RestartManagedService)
            .unwrap();
        assert!(compose < restart);
    }

    #[test]
    fn explicit_manual_action_is_planned_and_non_automatic() {
        let observation = RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id: "dep_test".to_owned(),
            source_user_id: 7,
            local_generation: 1,
            config_present: true,
            state_present: true,
            registration_present: true,
            target_directory_present: true,
            target_credentials_present: true,
            target_credentials_fingerprint: String::new(),
            target_fingerprint: "target".to_owned(),
            codes: Vec::new(),
            target: None,
        };
        let plan = build_plan(&observation, 1, &[RepairActionKind::ManualIntervention]);
        let action = plan
            .actions
            .iter()
            .find(|action| action.kind == RepairActionKind::ManualIntervention)
            .unwrap();
        assert!(!action.automatic);
        assert_eq!(action.risk, "manual");
    }

    #[test]
    fn missing_control_installation_plans_credential_rotation() {
        let observation = RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id: "dep_test".to_owned(),
            source_user_id: 7,
            local_generation: 1,
            config_present: true,
            state_present: true,
            registration_present: true,
            target_directory_present: true,
            target_credentials_present: true,
            target_credentials_fingerprint: String::new(),
            target_fingerprint: "target".to_owned(),
            codes: vec!["CONTROL_INSTALLATION_MISSING".to_owned()],
            target: None,
        };
        let plan = build_plan(&observation, 1, &[]);
        assert_eq!(
            plan.actions
                .iter()
                .filter(|action| action.kind == RepairActionKind::RotateInstallationCredentials)
                .count(),
            1
        );
        assert!(
            !plan
                .actions
                .iter()
                .any(|action| action.kind == RepairActionKind::ReconcileRegistrationIdentity)
        );
    }

    #[test]
    fn managed_environment_rebuild_adds_required_metadata_and_checker_keys() {
        let registration = DeploymentRegistration {
            deployment_id: "dep_test".to_owned(),
            installation_generation: 2,
            control_plane_url: "http://source".to_owned(),
            report_credential: secrecy::SecretString::from("report"),
            pull_credential: secrecy::SecretString::from("pull"),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: false,
            release_schema_version: "1".to_owned(),
            release_manifest_public_key: String::new(),
            release_artifact_allowed_hosts: Vec::new(),
        };
        let config = DeploymentConfig {
            image_ref: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            ..DeploymentConfig::default()
        };
        let content = complete_managed_env_file(
            "MEOWAI_DEPLOYMENT_ID=old\n",
            managed_env_updates(&config, &registration),
        )
        .unwrap();
        assert!(content.contains("MEOWAI_INSTALLATION_GENERATION=2\n"));
        assert!(content.contains("CHECKER_ENCRYPTION_KEY="));
        assert!(content.contains("CHECKER_FINGERPRINT_KEY="));
        assert!(content.contains("MEOWAI_REPORT_CREDENTIAL=report\n"));
    }

    #[test]
    fn managed_environment_rewrites_loopback_control_plane_for_containers() {
        let registration = DeploymentRegistration {
            deployment_id: "dep_test".to_owned(),
            installation_generation: 2,
            control_plane_url: "http://127.0.0.1:39001/api".to_owned(),
            report_credential: secrecy::SecretString::from("report"),
            pull_credential: secrecy::SecretString::from("pull"),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: false,
            release_schema_version: "1".to_owned(),
            release_manifest_public_key: String::new(),
            release_artifact_allowed_hosts: Vec::new(),
        };
        let config = DeploymentConfig {
            image_ref: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            ..DeploymentConfig::default()
        };
        let content =
            complete_managed_env_file("", managed_env_updates(&config, &registration)).unwrap();
        assert!(
            content.contains("MEOWAI_CONTROL_PLANE_URL=http://host.docker.internal:39001/api\n")
        );
    }

    #[test]
    fn managed_environment_rebuild_preserves_existing_schema_versions() {
        let registration = DeploymentRegistration {
            deployment_id: "dep_test".to_owned(),
            installation_generation: 2,
            control_plane_url: "http://source".to_owned(),
            report_credential: secrecy::SecretString::from("report"),
            pull_credential: secrecy::SecretString::from("pull"),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: false,
            release_schema_version: "3".to_owned(),
            release_manifest_public_key: String::new(),
            release_artifact_allowed_hosts: Vec::new(),
        };
        let config = DeploymentConfig {
            image_ref: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
            ..DeploymentConfig::default()
        };
        let content = complete_managed_env_file(
            "MEOWAI_DEPLOYMENT_SCHEMA=7\nMEOWAI_UPDATER_SCHEMA=6\nMEOWAI_DATA_SCHEMA=5\nMEOWAI_CLI_SCHEMA=4\n",
            managed_env_updates(&config, &registration),
        )
        .unwrap();
        assert!(content.contains("MEOWAI_DEPLOYMENT_SCHEMA=7\n"));
        assert!(content.contains("MEOWAI_UPDATER_SCHEMA=6\n"));
        assert!(content.contains("MEOWAI_DATA_SCHEMA=5\n"));
        assert!(content.contains("MEOWAI_CLI_SCHEMA=4\n"));
    }

    #[test]
    fn env_replacement_rejects_duplicate_managed_keys_and_injection() {
        let mut updates = BTreeMap::new();
        updates.insert("MEOWAI_PULL_CREDENTIAL", "safe-value".to_owned());
        let duplicate = update_env_file(
            "MEOWAI_PULL_CREDENTIAL=old\nMEOWAI_PULL_CREDENTIAL=again\n",
            &updates,
        );
        assert!(duplicate.is_err());

        updates.insert("MEOWAI_PULL_CREDENTIAL", "safe\nEVIL=1".to_owned());
        assert!(update_env_file("", &updates).is_err());
    }

    #[test]
    fn repair_journal_is_secret_free_and_resumable() {
        let journal = RepairJournal {
            phase: "installation_activated".to_owned(),
            source_operation_id: "repair_source".to_owned(),
            target_observation_fingerprint: "sha256:target".to_owned(),
            activated: true,
            ..RepairJournal::default()
        };
        let encoded = serde_json::to_string(&journal).unwrap();
        assert!(encoded.contains("installation_activated"));
        assert!(!encoded.contains("credential"));
    }

    #[test]
    fn recovered_control_plane_url_accepts_known_aliases_only() {
        // Container-form alias with /api suffix (the normal target env form).
        assert_eq!(
            recovered_control_plane_url(
                "http://127.0.0.1:3004",
                "http://host.docker.internal:3004/api"
            )
            .as_deref(),
            Some("http://127.0.0.1:3004/api")
        );
        // CLI form with /api suffix.
        assert_eq!(
            recovered_control_plane_url(
                "https://source.example.com",
                "https://source.example.com/api/"
            )
            .as_deref(),
            Some("https://source.example.com/api")
        );
        // Legacy bare source URL.
        assert_eq!(
            recovered_control_plane_url(
                "https://source.example.com/",
                "https://source.example.com"
            )
            .as_deref(),
            Some("https://source.example.com/api")
        );
        // A different control plane must never be adopted.
        assert_eq!(
            recovered_control_plane_url(
                "https://source.example.com",
                "https://other.example.com/api"
            ),
            None
        );
        assert_eq!(
            recovered_control_plane_url(
                "http://127.0.0.1:3004",
                "http://host.docker.internal:3005/api"
            ),
            None
        );
    }

    #[test]
    fn pre_repair_agent_binary_is_diagnosed_as_outdated() {
        let mut target = target::repair::TargetObservation {
            compose_valid: true,
            postgres_select_1: true,
            redis_ping: true,
            newapi_status: true,
            newapi_status_success: true,
            local_health_status: true,
            kuma_status: true,
            upgrade_agent_active: true,
            upgrade_timer_active: true,
            agent_version: "1.2.5".to_owned(),
            agent_schema: "2".to_owned(),
            agent_proof_capable: false,
            ..target::repair::TargetObservation::default()
        };
        target.files.insert(
            "bin/meowai-deploy-upgrade-agent".to_owned(),
            target::repair::TargetFileObservation {
                exists: true,
                regular: true,
                mode: "755".to_owned(),
                ..target::repair::TargetFileObservation::default()
            },
        );
        let mut codes = Vec::new();
        augment_target_diagnostics(&mut codes, &target);
        assert!(codes.iter().any(|code| code == "TARGET_AGENT_OUTDATED"));
        target.agent_proof_capable = true;
        let mut capable_codes = Vec::new();
        augment_target_diagnostics(&mut capable_codes, &target);
        assert!(
            !capable_codes
                .iter()
                .any(|code| code == "TARGET_AGENT_OUTDATED")
        );
    }

    #[test]
    fn reviewed_fingerprint_matches_across_hour_boundary() {
        let observation = RepairObservation {
            schema_version: 1,
            cli_schema: "2".to_owned(),
            deployment_id: "dep_test".to_owned(),
            source_user_id: 7,
            local_generation: 1,
            config_present: true,
            state_present: true,
            registration_present: false,
            target_directory_present: true,
            target_credentials_present: false,
            target_credentials_fingerprint: String::new(),
            target_fingerprint: "target".to_owned(),
            codes: vec!["TARGET_CREDENTIAL_FILE_MISSING".to_owned()],
            target: None,
        };
        let reviewed = build_plan(&observation, 1, &[]);
        // Simulate a recomputation in the next hour window with unchanged
        // facts: only the expiry advanced by one window.
        let mut recomputed = reviewed.clone();
        recomputed.expires_at += 3600;
        refresh_plan_fingerprint(&mut recomputed);
        assert_ne!(recomputed.plan_fingerprint, reviewed.plan_fingerprint);
        let now = reviewed.expires_at - 1800;
        assert!(reviewed_plan_fingerprint_matches(
            &mut recomputed,
            &reviewed.plan_fingerprint,
            now
        ));
        // The matched plan keeps the reviewed expiry for the later check.
        assert_eq!(recomputed.expires_at, reviewed.expires_at);
        // A reviewed plan whose original expiry has passed must stay stale.
        let mut expired = reviewed.clone();
        expired.expires_at += 3600;
        refresh_plan_fingerprint(&mut expired);
        assert!(!reviewed_plan_fingerprint_matches(
            &mut expired,
            &reviewed.plan_fingerprint,
            reviewed.expires_at
        ));
        // A genuinely different plan is stale in every window.
        let mut drifted = build_plan(
            &RepairObservation {
                target_fingerprint: "changed".to_owned(),
                ..observation
            },
            1,
            &[],
        );
        assert!(!reviewed_plan_fingerprint_matches(
            &mut drifted,
            &reviewed.plan_fingerprint,
            now
        ));
    }
}
