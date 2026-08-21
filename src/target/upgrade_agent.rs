use serde::Deserialize;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
    sync::mpsc,
    thread,
    time::Duration,
};

use crate::{
    application::deployment_control,
    config::DeploymentConfig,
    error::{AppError, Result},
    source::{DeploymentRegistration, UpgradeTransitionReport, control_plane_client},
    state::DeploymentState,
    target::TargetExecutor,
    upgrade::{ManifestArtifact, ReleaseManifest, UpgradePlan},
};

#[derive(Clone, Debug)]
pub struct UpgradeAgentResult {
    pub operation_id: String,
    pub backup_id: String,
    pub image_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BundleManifest {
    bundle_schema: u32,
    release_id: String,
    deployment_schema: u32,
    files: Vec<BundleFile>,
    migration_steps: Vec<String>,
    #[serde(default)]
    compose_changes: Vec<BundleComposeChange>,
    #[serde(default)]
    env_changes: Vec<BundleEnvChange>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BundleFile {
    path: String,
    sha256: String,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BundleComposeChange {
    kind: String,
    name: String,
    action: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct BundleEnvChange {
    file: String,
    key: String,
    action: String,
}

struct ExtractedBundleFile {
    mode: u32,
    content: Vec<u8>,
}

struct ExtractedBundleArchive {
    manifest: Vec<u8>,
    files: BTreeMap<String, ExtractedBundleFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UpgradeJournal {
    operation_id: String,
    release_id: String,
    state: String,
    phase: String,
    backup_id: String,
    #[serde(default)]
    data_rollback_required: bool,
    updated_at: i64,
}

struct UpdaterPauseGuard {
    executor: TargetExecutor,
    active: bool,
}

struct TargetUpgradeLock {
    executor: TargetExecutor,
    token: String,
    stop: Option<mpsc::Sender<()>>,
    heartbeat: Option<thread::JoinHandle<()>>,
}

impl TargetUpgradeLock {
    fn acquire(executor: &TargetExecutor) -> Result<Self> {
        let token = crate::security::random_secret(32);
        let quoted_token = shell_quote(&token);
        executor.run_in_directory(&format!(
            r#"set -eu
lock=.meowai-upgrade.lock
token={quoted_token}
now=$(date +%s)
write_owner() {{
  printf '%s\n%s\n' "$token" "$now" > "$lock/owner.next-$token"
  chmod 600 "$lock/owner.next-$token"
  mv "$lock/owner.next-$token" "$lock/owner"
}}
if mkdir "$lock" 2>/dev/null; then
  chmod 700 "$lock"
  write_owner
  exit 0
fi
updated=$(sed -n '2p' "$lock/owner" 2>/dev/null || true)
case "$updated" in ''|*[!0-9]*) updated=0 ;; esac
if [ $((now - updated)) -le 900 ]; then
  echo 'another deployment upgrade is already running' >&2
  exit 1
fi
stale="$lock.stale-$token"
if ! mv "$lock" "$stale" 2>/dev/null; then
  echo 'deployment upgrade lock changed while reclaiming it' >&2
  exit 1
fi
rm -rf -- "$stale"
mkdir "$lock"
chmod 700 "$lock"
write_owner"#,
        ))?;
        let (stop, receiver) = mpsc::channel();
        let heartbeat_executor = executor.clone();
        let heartbeat_token = token.clone();
        let heartbeat = thread::spawn(move || {
            while receiver.recv_timeout(Duration::from_secs(30)).is_err() {
                let quoted_token = shell_quote(&heartbeat_token);
                let _ = heartbeat_executor.run_in_directory(&format!(
                    r#"set -eu
lock=.meowai-upgrade.lock
token={quoted_token}
[ "$(sed -n '1p' "$lock/owner" 2>/dev/null || true)" = "$token" ] || exit 0
now=$(date +%s)
printf '%s\n%s\n' "$token" "$now" > "$lock/owner.next-$token"
chmod 600 "$lock/owner.next-$token"
mv "$lock/owner.next-$token" "$lock/owner""#,
                ));
            }
        });
        Ok(Self {
            executor: executor.clone(),
            token,
            stop: Some(stop),
            heartbeat: Some(heartbeat),
        })
    }
}

impl Drop for TargetUpgradeLock {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.join();
        }
        let token = shell_quote(&self.token);
        let _ = self.executor.run_in_directory(&format!(
            r#"set -eu
lock=.meowai-upgrade.lock
token={token}
if [ "$(sed -n '1p' "$lock/owner" 2>/dev/null || true)" = "$token" ]; then
  rm -f -- "$lock/owner"
  rmdir "$lock" 2>/dev/null || true
fi"#,
        ));
    }
}

fn restore_updater_timer(executor: &TargetExecutor) -> Result<()> {
    executor
        .run_in_directory(
            "set -eu\nif [ -f /etc/systemd/system/meowai-deploy-updater.timer ]; then systemctl daemon-reload; systemctl enable --now meowai-deploy-updater.timer; fi",
        )
        .map(|_| ())
}

impl UpdaterPauseGuard {
    fn acquire(executor: &TargetExecutor, invoked_by_updater: bool) -> Result<Self> {
        executor.run_in_directory(if invoked_by_updater {
            "set -eu\nsystemctl stop meowai-deploy-updater.timer >/dev/null 2>&1 || true"
        } else {
            "set -eu\nsystemctl stop meowai-deploy-updater.timer meowai-deploy-updater.service >/dev/null 2>&1 || true"
        })?;
        Ok(Self {
            executor: executor.clone(),
            active: true,
        })
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for UpdaterPauseGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = restore_updater_timer(&self.executor);
        }
    }
}

pub async fn apply(
    config: &DeploymentConfig,
    state: &DeploymentState,
    registration: &DeploymentRegistration,
    manifest: &ReleaseManifest,
    artifact: &ManifestArtifact,
    artifact_bytes: &[u8],
    plan: &UpgradePlan,
    repair_updater: bool,
    invoked_by_updater: bool,
) -> Result<UpgradeAgentResult> {
    validate_data_migration_policy(manifest, invoked_by_updater)?;
    validate_migration_path(state, manifest)?;
    verify_artifact_bytes(artifact, artifact_bytes)?;
    let (operation_id, execution_mode, authorization_id) = if invoked_by_updater {
        if !plan.execution_authorized
            || plan.upgrade_authorization_id.is_empty()
            || plan.upgrade_operation_id.is_empty()
            || plan.upgrade_authorization_expires_at <= crate::state::unix_timestamp()
        {
            return Err(AppError::State(
                "结构性发布尚未获得有效的控制面自动执行授权".to_owned(),
            ));
        }
        validate_operation_id(&plan.upgrade_operation_id)?;
        (
            plan.upgrade_operation_id.clone(),
            "auto",
            plan.upgrade_authorization_id.as_str(),
        )
    } else {
        (
            format!("op_{}", crate::security::random_secret(24)),
            "manual",
            "",
        )
    };
    let backup_id = operation_id.clone();
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
    let _target_upgrade_lock = TargetUpgradeLock::acquire(&executor)?;
    let control_plane = control_plane_client(registration)?;

    recover_incomplete_operation(&executor, config, registration, manifest).await?;
    let resumes_prechecked_operation = read_journal(&executor)?.is_some_and(|journal| {
        journal.operation_id == operation_id && journal.state == "PRECHECKED"
    });

    let receipt = control_plane
        .report_upgrade_plan(
            registration,
            &operation_id,
            &manifest.release_id,
            match plan.decision {
                crate::upgrade::UpgradeDecision::Blocked => "blocked",
                crate::upgrade::UpgradeDecision::ImageOnly => "image_only",
                _ => "upgrade_required",
            },
            &plan.fingerprint,
            serde_json::to_value(&plan.current).map_err(|error| {
                AppError::State(format!("serialize current capability: {error}"))
            })?,
            serde_json::to_value(&plan.target).map_err(|error| {
                AppError::State(format!("serialize target capability: {error}"))
            })?,
            execution_mode,
            authorization_id,
        )
        .await?;
    if !receipt.accepted
        || receipt.operation_id != operation_id
        || receipt.release_id != manifest.release_id
        || (receipt.state != "PLANNED"
            && !(resumes_prechecked_operation && receipt.state == "PRECHECKED"))
        || receipt.plan_fingerprint != plan.fingerprint
        || receipt.execution_mode != execution_mode
        || receipt.authorization_id != authorization_id
    {
        return Err(AppError::State(
            "控制面升级计划回读与目标机执行上下文不一致".to_owned(),
        ));
    }
    journal_with_data_rollback(
        &executor,
        &operation_id,
        &manifest.release_id,
        "PLANNED",
        "PLANNED",
        "",
        manifest.rollback.data_rollback_required,
    )?;

    lifecycle(
        registration,
        "upgrade_discovered",
        "DISCOVERED",
        "结构性发布已发现",
    )
    .await;
    lifecycle(
        registration,
        "upgrade_planned",
        "PLANNED",
        "升级计划已由控制面记录",
    )
    .await;

    if let Err(error) = preflight(&executor, config, state, manifest) {
        journal(
            &executor,
            &operation_id,
            &manifest.release_id,
            "PRECHECK_FAILED",
            "PRECHECK_FAILED",
            "",
        )?;
        let _ = report_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "PRECHECK_FAILED",
                "PRECHECK_FAILED",
                "",
                "PRECHECK_FAILED",
                &error.to_string(),
            ),
        )
        .await;
        return Err(error);
    }
    let mut updater_pause = UpdaterPauseGuard::acquire(&executor, invoked_by_updater)?;
    report_transition(
        registration,
        transition(
            &operation_id,
            manifest,
            "PRECHECKED",
            "PRECHECKED",
            "",
            "",
            "",
        ),
    )
    .await?;
    journal(
        &executor,
        &operation_id,
        &manifest.release_id,
        "PRECHECKED",
        "PRECHECKED",
        "",
    )?;
    lifecycle(
        registration,
        "upgrade_prechecked",
        "PRECHECKED",
        "目标机预检通过",
    )
    .await;

    report_transition(
        registration,
        transition(
            &operation_id,
            manifest,
            "BACKUP_STARTED",
            "BACKUP_STARTED",
            &backup_id,
            "",
            "",
        ),
    )
    .await?;
    journal(
        &executor,
        &operation_id,
        &manifest.release_id,
        "BACKUP_STARTED",
        "BACKUP_STARTED",
        &backup_id,
    )?;
    lifecycle(
        registration,
        "backup_started",
        "BACKUP_STARTED",
        "开始创建完整部署备份",
    )
    .await;
    if let Err(error) = backup(
        &executor,
        config,
        &backup_id,
        &operation_id,
        &manifest.release_id,
    ) {
        journal(
            &executor,
            &operation_id,
            &manifest.release_id,
            "BACKUP_FAILED",
            "BACKUP_FAILED",
            &backup_id,
        )?;
        queue_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "BACKUP_FAILED",
                "BACKUP_FAILED",
                &backup_id,
                "BACKUP_FAILED",
                &error.to_string(),
            ),
        )
        .await?;
        return Err(error);
    }
    journal(
        &executor,
        &operation_id,
        &manifest.release_id,
        "BACKUP_VERIFIED",
        "BACKUP_VERIFIED",
        &backup_id,
    )?;
    require_queued_transition(
        registration,
        transition(
            &operation_id,
            manifest,
            "BACKUP_VERIFIED",
            "BACKUP_VERIFIED",
            &backup_id,
            "",
            "",
        ),
    )
    .await?;
    lifecycle(
        registration,
        "backup_succeeded",
        "BACKUP_VERIFIED",
        "部署备份已完成并通过校验",
    )
    .await;
    if repair_updater {
        lifecycle(
            registration,
            "updater_repair_started",
            "BACKUP_VERIFIED",
            "备份验证完成，开始修复目标机 updater 和 systemd 定时器",
        )
        .await;
        if let Err(error) =
            crate::target::updater::install_paused(&executor, config, config.newapi_port)
        {
            rollback_operation(
                &executor,
                config,
                registration,
                &manifest.release_id,
                &operation_id,
                &backup_id,
                manifest.rollback.data_rollback_required,
            )
            .await?;
            return Err(AppError::Target(format!(
                "修复目标机 updater 失败：{error}"
            )));
        }
        lifecycle(
            registration,
            "updater_repair_succeeded",
            "BACKUP_VERIFIED",
            "目标机 updater 和 systemd 定时器已修复",
        )
        .await;
    }
    let stage_dir = format!(".upgrade/{operation_id}");
    let bundle = match stage_bundle(&executor, &stage_dir, manifest, artifact, artifact_bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            journal(
                &executor,
                &operation_id,
                &manifest.release_id,
                "STAGE_FAILED",
                "STAGE_FAILED",
                &backup_id,
            )?;
            queue_transition(
                registration,
                transition(
                    &operation_id,
                    manifest,
                    "STAGE_FAILED",
                    "STAGE_FAILED",
                    &backup_id,
                    "STAGE_FAILED",
                    &error.to_string(),
                ),
            )
            .await?;
            return Err(error);
        }
    };
    if let Err(error) = prepare_environment_files(
        &executor,
        &stage_dir,
        config,
        registration,
        manifest,
        &bundle,
    ) {
        journal(
            &executor,
            &operation_id,
            &manifest.release_id,
            "STAGE_FAILED",
            "STAGE_FAILED",
            &backup_id,
        )?;
        queue_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "STAGE_FAILED",
                "STAGE_FAILED",
                &backup_id,
                "ENVIRONMENT_STAGE_FAILED",
                &error.to_string(),
            ),
        )
        .await?;
        return Err(error);
    }
    if let Err(error) = validate_compose_changes(&executor, config, &stage_dir, manifest, &bundle) {
        journal(
            &executor,
            &operation_id,
            &manifest.release_id,
            "STAGE_FAILED",
            "STAGE_FAILED",
            &backup_id,
        )?;
        queue_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "STAGE_FAILED",
                "STAGE_FAILED",
                &backup_id,
                "COMPOSE_CHANGE_VALIDATION_FAILED",
                &error.to_string(),
            ),
        )
        .await?;
        return Err(error);
    }
    journal(
        &executor,
        &operation_id,
        &manifest.release_id,
        "STAGED",
        "STAGED",
        &backup_id,
    )?;
    require_queued_transition(
        registration,
        transition(
            &operation_id,
            manifest,
            "STAGED",
            "STAGED",
            &backup_id,
            "",
            "",
        ),
    )
    .await?;
    lifecycle(
        registration,
        "upgrade_staged",
        "STAGED",
        "升级 artifact 已暂存并校验",
    )
    .await;

    if manifest.migration_plan.from < manifest.migration_plan.to {
        report_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "MIGRATION_STARTED",
                "MIGRATION_STARTED",
                &backup_id,
                "",
                "",
            ),
        )
        .await?;
        journal(
            &executor,
            &operation_id,
            &manifest.release_id,
            "MIGRATION_STARTED",
            "MIGRATION_STARTED",
            &backup_id,
        )?;
        lifecycle(
            registration,
            "migration_started",
            "MIGRATION_STARTED",
            "开始执行版本化迁移",
        )
        .await;
        if let Err(error) = run_migrations(&executor, &stage_dir, manifest, &bundle) {
            queue_transition(
                registration,
                transition(
                    &operation_id,
                    manifest,
                    "MIGRATION_FAILED",
                    "MIGRATION_FAILED",
                    &backup_id,
                    "MIGRATION_FAILED",
                    &error.to_string(),
                ),
            )
            .await?;
            rollback_operation(
                &executor,
                config,
                registration,
                &manifest.release_id,
                &operation_id,
                &backup_id,
                manifest.rollback.data_rollback_required,
            )
            .await?;
            return Err(error);
        }
        lifecycle(
            registration,
            "migration_succeeded",
            "SERVICES_SWITCHING",
            "版本化迁移已完成",
        )
        .await;
    }

    report_transition(
        registration,
        transition(
            &operation_id,
            manifest,
            "SERVICES_SWITCHING",
            "SERVICES_SWITCHING",
            &backup_id,
            "",
            "",
        ),
    )
    .await?;
    journal(
        &executor,
        &operation_id,
        &manifest.release_id,
        "SERVICES_SWITCHING",
        "SERVICES_SWITCHING",
        &backup_id,
    )?;
    if let Err(error) = switch_services(&executor, config, &stage_dir, &bundle) {
        queue_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "SWITCH_FAILED",
                "SWITCH_FAILED",
                &backup_id,
                "SWITCH_FAILED",
                &error.to_string(),
            ),
        )
        .await?;
        rollback_operation(
            &executor,
            config,
            registration,
            &manifest.release_id,
            &operation_id,
            &backup_id,
            manifest.rollback.data_rollback_required,
        )
        .await?;
        return Err(error);
    }
    journal(
        &executor,
        &operation_id,
        &manifest.release_id,
        "HEALTH_CHECKING",
        "HEALTH_CHECKING",
        &backup_id,
    )?;
    queue_transition(
        registration,
        transition(
            &operation_id,
            manifest,
            "HEALTH_CHECKING",
            "HEALTH_CHECKING",
            &backup_id,
            "",
            "",
        ),
    )
    .await?;
    lifecycle(
        registration,
        "upgrade_health_checking",
        "HEALTH_CHECKING",
        "开始全栈健康检查",
    )
    .await;
    if let Err(error) = health_check(&executor, config, manifest) {
        queue_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "HEALTH_FAILED",
                "HEALTH_FAILED",
                &backup_id,
                "HEALTH_FAILED",
                &error.to_string(),
            ),
        )
        .await?;
        let rollback_result = rollback_operation(
            &executor,
            config,
            registration,
            &manifest.release_id,
            &operation_id,
            &backup_id,
            manifest.rollback.data_rollback_required,
        )
        .await;
        lifecycle(
            registration,
            "health_check_failed",
            if rollback_result.is_ok() {
                "ROLLED_BACK"
            } else {
                "ROLLBACK_FAILED"
            },
            "健康检查失败，已执行回滚流程",
        )
        .await;
        rollback_result?;
        return Err(error);
    }
    if let Err(error) = activate_updater_timer(&executor) {
        queue_transition(
            registration,
            transition(
                &operation_id,
                manifest,
                "HEALTH_FAILED",
                "HEALTH_FAILED",
                &backup_id,
                "UPDATER_TIMER_ACTIVATION_FAILED",
                &error.to_string(),
            ),
        )
        .await?;
        let rollback_result = rollback_operation(
            &executor,
            config,
            registration,
            &manifest.release_id,
            &operation_id,
            &backup_id,
            manifest.rollback.data_rollback_required,
        )
        .await;
        lifecycle(
            registration,
            "updater_activation_failed",
            if rollback_result.is_ok() {
                "ROLLED_BACK"
            } else {
                "ROLLBACK_FAILED"
            },
            "目标机 updater timer 激活失败，已执行回滚流程",
        )
        .await;
        rollback_result?;
        return Err(error);
    }
    updater_pause.disarm();
    journal(
        &executor,
        &operation_id,
        &manifest.release_id,
        "COMMITTED",
        "COMMITTED",
        &backup_id,
    )?;
    queue_transition(
        registration,
        transition(
            &operation_id,
            manifest,
            "COMMITTED",
            "COMMITTED",
            &backup_id,
            "",
            "",
        ),
    )
    .await?;
    lifecycle(
        registration,
        "upgrade_succeeded",
        "COMMITTED",
        "完整 deployment upgrade 已完成",
    )
    .await;
    // Retention runs after the target has committed and the transition has
    // been durably recorded.  A housekeeping failure must not turn a
    // completed upgrade into a failed client invocation (nor cause a future
    // invocation to repeat it).  It is safe to leave extra verified backups
    // behind; the next successful upgrade will try retention again.
    if let Err(error) = prune_backups(&executor, manifest.rollback.retained_backup_count) {
        eprintln!("已提交升级的备份清理延后处理：{error}");
    }
    Ok(UpgradeAgentResult {
        operation_id,
        backup_id,
        image_digest: manifest.image_digest.clone(),
    })
}

pub async fn rollback_recorded(
    config: &DeploymentConfig,
    registration: &DeploymentRegistration,
    requested_operation_id: &str,
) -> Result<String> {
    validate_operation_id(requested_operation_id)?;
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
    let journal = read_journal(&executor)?.ok_or_else(|| {
        AppError::State("目标机没有可恢复的 deployment upgrade operation".to_owned())
    })?;
    if journal.operation_id != requested_operation_id || journal.backup_id.is_empty() {
        return Err(AppError::State(
            "请求的 operation 与目标机 upgrade journal 不一致".to_owned(),
        ));
    }
    rollback_operation(
        &executor,
        config,
        registration,
        &journal.release_id,
        &journal.operation_id,
        &journal.backup_id,
        journal.data_rollback_required,
    )
    .await?;
    Ok(journal.backup_id)
}

async fn recover_incomplete_operation(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    registration: &DeploymentRegistration,
    manifest: &ReleaseManifest,
) -> Result<()> {
    let Some(journal) = read_journal(executor)? else {
        return Ok(());
    };
    match journal.state.as_str() {
        "COMMITTED" | "ROLLED_BACK" => Ok(()),
        "PRECHECK_FAILED" | "BACKUP_FAILED" | "STAGE_FAILED" => {
            validate_operation_id(&journal.operation_id)?;
            let mut cleanup = format!(
                "set -eu\nrm -rf -- {}",
                shell_quote(&format!(".upgrade/{}", journal.operation_id))
            );
            if journal.state == "BACKUP_FAILED" && !journal.backup_id.is_empty() {
                cleanup.push_str(&format!(
                    "\nrm -rf -- {}",
                    shell_quote(&format!("backups/{}", journal.backup_id))
                ));
            }
            executor.run_in_directory(&cleanup)?;
            restore_updater_timer(executor)
        }
        "PLANNED" | "PRECHECKED" => {
            validate_operation_id(&journal.operation_id)?;
            executor.run_in_directory(&format!(
                "set -eu\nrm -rf -- {}",
                shell_quote(&format!(".upgrade/{}", journal.operation_id))
            ))?;
            restore_updater_timer(executor)
        }
        "BACKUP_STARTED" | "BACKUP_VERIFIED" | "STAGED" => {
            validate_operation_id(&journal.operation_id)?;
            let (failure_state, error_code, remove_backup) = if journal.state == "BACKUP_STARTED" {
                (
                    "BACKUP_FAILED",
                    "BACKUP_INTERRUPTED",
                    !journal.backup_id.is_empty(),
                )
            } else {
                ("STAGE_FAILED", "STAGE_INTERRUPTED", false)
            };
            let mut cleanup = format!(
                "set -eu\nrm -rf -- {}",
                shell_quote(&format!(".upgrade/{}", journal.operation_id))
            );
            if remove_backup {
                cleanup.push_str(&format!(
                    "\nrm -rf -- {}",
                    shell_quote(&format!("backups/{}", journal.backup_id))
                ));
            }
            executor.run_in_directory(&cleanup)?;
            journal_with_data_rollback(
                executor,
                &journal.operation_id,
                &journal.release_id,
                failure_state,
                failure_state,
                &journal.backup_id,
                journal.data_rollback_required,
            )?;
            restore_updater_timer(executor)?;
            require_queued_transition(
                registration,
                transition_release(
                    &journal.operation_id,
                    &journal.release_id,
                    failure_state,
                    failure_state,
                    &journal.backup_id,
                    error_code,
                    "升级在服务切换前中断；已清理暂存文件，当前业务服务保持不变",
                ),
            )
            .await?;
            Err(AppError::State(format!(
                "检测到服务切换前中断的 operation {}，已安全关闭；请创建新的升级授权后重试",
                journal.operation_id
            )))
        }
        "MIGRATION_STARTED" | "SERVICES_SWITCHING" | "HEALTH_CHECKING" | "MIGRATION_FAILED"
        | "SWITCH_FAILED" | "HEALTH_FAILED" | "ROLLBACK_STARTED" => {
            if journal.backup_id.is_empty() || journal.release_id != manifest.release_id {
                return Err(AppError::State(
                    "发现无法自动恢复的 upgrade journal，必须人工核对 release 和 backup".to_owned(),
                ));
            }
            rollback_operation(
                executor,
                config,
                registration,
                &journal.release_id,
                &journal.operation_id,
                &journal.backup_id,
                journal.data_rollback_required,
            )
            .await?;
            Ok(())
        }
        _ => Err(AppError::State(format!(
            "upgrade journal 状态 {} 需要人工介入",
            journal.state
        ))),
    }
}

fn read_journal(executor: &TargetExecutor) -> Result<Option<UpgradeJournal>> {
    let output = executor.run_in_directory(
        "set -eu\nif [ -f run/upgrade-status.json ]; then cat run/upgrade-status.json; fi",
    )?;
    if output.stdout.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&output.stdout)
        .map(Some)
        .map_err(|error| AppError::State(format!("parse upgrade journal: {error}")))
}

fn validate_operation_id(operation_id: &str) -> Result<()> {
    if operation_id.len() < 11
        || operation_id.len() > 95
        || !operation_id.starts_with("op_")
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(AppError::InvalidConfig(
            "upgrade operation id 无效".to_owned(),
        ));
    }
    Ok(())
}

fn transition(
    operation_id: &str,
    manifest: &ReleaseManifest,
    state: &str,
    phase: &str,
    backup_id: &str,
    error_code: &str,
    error_summary: &str,
) -> UpgradeTransitionReport {
    transition_release(
        operation_id,
        &manifest.release_id,
        state,
        phase,
        backup_id,
        error_code,
        error_summary,
    )
}

fn transition_release(
    operation_id: &str,
    release_id: &str,
    state: &str,
    phase: &str,
    backup_id: &str,
    error_code: &str,
    error_summary: &str,
) -> UpgradeTransitionReport {
    UpgradeTransitionReport {
        operation_id: operation_id.to_owned(),
        release_id: release_id.to_owned(),
        state: state.to_owned(),
        phase: phase.to_owned(),
        backup_id: backup_id.to_owned(),
        error_code: error_code.to_owned(),
        error_summary: error_summary.chars().take(255).collect(),
    }
}

async fn report_transition(
    registration: &DeploymentRegistration,
    report: UpgradeTransitionReport,
) -> Result<()> {
    control_plane_client(registration)?
        .report_upgrade_transition(registration, &report)
        .await?;
    Ok(())
}

async fn queue_transition(
    registration: &DeploymentRegistration,
    report: UpgradeTransitionReport,
) -> Result<bool> {
    deployment_control::queue_upgrade_transition(registration, report)
        .await
        .map_err(AppError::from)
}

async fn require_queued_transition(
    registration: &DeploymentRegistration,
    report: UpgradeTransitionReport,
) -> Result<()> {
    if queue_transition(registration, report).await? {
        return Ok(());
    }
    Err(AppError::State(
        "控制面状态暂时无法确认；当前阶段已安全记录，停止后续目标机变更".to_owned(),
    ))
}

async fn rollback_operation(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    registration: &DeploymentRegistration,
    release_id: &str,
    operation_id: &str,
    backup_id: &str,
    data_rollback_required: bool,
) -> Result<()> {
    let _ = queue_transition(
        registration,
        transition_release(
            operation_id,
            release_id,
            "ROLLBACK_STARTED",
            "ROLLBACK_STARTED",
            backup_id,
            "",
            "",
        ),
    )
    .await;
    journal(
        executor,
        operation_id,
        release_id,
        "ROLLBACK_STARTED",
        "ROLLBACK_STARTED",
        backup_id,
    )?;
    match rollback(executor, config, backup_id, data_rollback_required) {
        Ok(()) => {
            journal(
                executor,
                operation_id,
                release_id,
                "ROLLED_BACK",
                "ROLLED_BACK",
                backup_id,
            )?;
            queue_transition(
                registration,
                transition_release(
                    operation_id,
                    release_id,
                    "ROLLED_BACK",
                    "ROLLED_BACK",
                    backup_id,
                    "",
                    "",
                ),
            )
            .await?;
            lifecycle(
                registration,
                "rollback_succeeded",
                "ROLLED_BACK",
                "升级失败，已恢复备份",
            )
            .await;
            Ok(())
        }
        Err(error) => {
            journal(
                executor,
                operation_id,
                release_id,
                "ROLLBACK_FAILED",
                "ROLLBACK_FAILED",
                backup_id,
            )?;
            let _ = queue_transition(
                registration,
                transition_release(
                    operation_id,
                    release_id,
                    "ROLLBACK_FAILED",
                    "ROLLBACK_FAILED",
                    backup_id,
                    "ROLLBACK_FAILED",
                    &error.to_string(),
                ),
            )
            .await;
            Err(error)
        }
    }
}

fn verify_artifact_bytes(artifact: &ManifestArtifact, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 != artifact.size {
        return Err(AppError::State("升级 artifact size 校验失败".to_owned()));
    }
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != artifact.sha256 {
        return Err(AppError::State("升级 artifact SHA256 校验失败".to_owned()));
    }
    Ok(())
}

fn preflight(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    state: &DeploymentState,
    manifest: &ReleaseManifest,
) -> Result<()> {
    let diagnostics = String::from_utf8_lossy(&executor.remote_diagnostics()?.stdout).to_string();
    for required in [
        "os=Linux",
        "docker_daemon=pass",
        "compose=pass",
        "directory=pass",
    ] {
        if !diagnostics
            .lines()
            .any(|line| line.eq_ignore_ascii_case(required))
        {
            return Err(AppError::Target(format!("目标机预检失败：缺少 {required}")));
        }
    }
    if state.deployment_id.is_empty()
        || config.container_name.is_empty()
        || manifest.minimum_deployment_schema == 0
    {
        return Err(AppError::State(
            "升级预检发现部署身份或 manifest schema 无效".to_owned(),
        ));
    }
    let requires_systemd = manifest
        .required_capabilities
        .iter()
        .any(|capability| capability == "systemd");
    let requires_data_migration = manifest
        .migration_plan
        .steps
        .iter()
        .any(|step| step.starts_with("data-") && !is_noop_data_step(step));
    executor.run_in_directory(&format!(
        r#"set -eu
for command in docker curl sha256sum tar awk sed df stat; do command -v "$command" >/dev/null; done
{timeout_check}
docker compose version >/dev/null
docker info >/dev/null
docker compose --env-file secrets.env -p {project} -f docker-compose.yml config >/dev/null
available_kb=$(df -Pk . | awk 'NR==2 {{print $4}}')
[ "${{available_kb:-0}}" -ge 2097152 ]
available_inodes=$(df -Pi . | awk 'NR==2 {{print $4}}')
[ "${{available_inodes:-0}}" -ge 10000 ]
{systemd_check}"#,
        project = shell_quote(&config.container_name),
        timeout_check = if requires_data_migration {
            "command -v timeout >/dev/null"
        } else {
            ":"
        },
        systemd_check = if requires_systemd {
            "command -v systemctl >/dev/null\nsystemctl show-environment >/dev/null"
        } else {
            ":"
        }
    ))?;
    Ok(())
}

fn backup(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    backup_id: &str,
    operation_id: &str,
    release_id: &str,
) -> Result<()> {
    let dir = shell_quote(&format!("backups/{backup_id}"));
    let project = shell_quote(&config.container_name);
    let operation = shell_quote(operation_id);
    let release = shell_quote(release_id);
    let script = format!(
        r#"set -eu
mkdir -p {dir}
chmod 700 backups {dir}
mkdir -p {dir}/systemd {dir}/bin
for file in docker-compose.yml docker-compose.updater.yml secrets.env downstream-credentials.env updater-credentials.env meowai-deploy-updater.sh meowai-deploy-updater.service meowai-deploy-updater.timer; do
  if [ -f "$file" ]; then cp -p "$file" "{dir}/$file"; fi
done
if [ -f bin/meowai-deploy-upgrade-agent ]; then cp -p bin/meowai-deploy-upgrade-agent {dir}/bin/; fi
for unit in meowai-deploy-updater.service meowai-deploy-updater.timer; do
  if [ -f "/etc/systemd/system/$unit" ]; then cp -p "/etc/systemd/system/$unit" "{dir}/systemd/$unit"; fi
done
if [ -d run/migrations ]; then cp -a run/migrations "{dir}/migrations"; fi
printf '%s\n' {operation} > {dir}/operation-id
printf '%s\n' {release} > {dir}/release-id
docker inspect --format '{{{{.Config.Image}}}}|{{{{.State.Status}}}}|{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' {project} > {dir}/newapi-inspect-summary
docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U meowai -d newapi -Fc' > {dir}/postgres.dump
test -s {dir}/postgres.dump
docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T postgres pg_restore --list < {dir}/postgres.dump >/dev/null
docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning SAVE >/dev/null'
tar -czf {dir}/redis-data.tar.gz data/redis
tar -czf {dir}/kuma-data.tar.gz data/uptime-kuma
chmod 600 {dir}/postgres.dump {dir}/redis-data.tar.gz {dir}/kuma-data.tar.gz
(cd {dir} && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS && sha256sum -c SHA256SUMS >/dev/null)
"#
    );
    executor.run_in_directory(&script).map(|_| ())
}

fn prune_backups(executor: &TargetExecutor, retained: u32) -> Result<()> {
    let retained = retained.clamp(1, 10);
    executor
        .run_in_directory(&format!(
            // Only this agent's operation backups are managed by retention.
            // Existing operator-created archives (for example
            // `backups/release-*`) are intentionally retained untouched.
            "set -eu\nfind backups -mindepth 1 -maxdepth 1 -type d -name 'op_[A-Za-z0-9_-]*' -print | sort -r | awk 'NR>{retained}' | while IFS= read -r old; do case \"$old\" in backups/op_[A-Za-z0-9_-]*) rm -rf -- \"$old\" ;; *) exit 1 ;; esac; done"
        ))
        .map(|_| ())
}

fn stage_bundle(
    executor: &TargetExecutor,
    stage_dir: &str,
    manifest: &ReleaseManifest,
    _artifact: &ManifestArtifact,
    bytes: &[u8],
) -> Result<BundleManifest> {
    let mut archive = extract_archive_bytes(bytes)?;
    let bundle_manifest: BundleManifest = serde_json::from_slice(&archive.manifest)
        .map_err(|error| AppError::State(format!("bundle manifest JSON 无效：{error}")))?;
    validate_bundle_manifest(&bundle_manifest, manifest)?;
    let declared = bundle_manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<BTreeSet<_>>();
    let actual = archive.files.keys().cloned().collect::<BTreeSet<_>>();
    if actual != declared {
        return Err(AppError::State(
            "upgrade artifact 文件集合与 bundle manifest 不一致".to_owned(),
        ));
    }
    for file in &bundle_manifest.files {
        let extracted = archive
            .files
            .get(&file.path)
            .ok_or_else(|| AppError::State(format!("bundle 缺少声明文件：{}", file.path)))?;
        let sha256 = Sha256::digest(&extracted.content)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if extracted.mode != file.mode || sha256 != file.sha256 {
            return Err(AppError::State(format!(
                "bundle 文件权限或 SHA256 不匹配：{}",
                file.path
            )));
        }
    }
    let stage = shell_quote(stage_dir);
    executor.run_in_directory(&format!(
        "set -eu\nmkdir -p {stage}/files\nchmod 700 .upgrade {stage} {stage}/files"
    ))?;
    executor.write_file(
        &format!("{stage_dir}/files/bundle-manifest.json"),
        &archive.manifest,
        true,
    )?;
    for file in &bundle_manifest.files {
        let extracted = archive
            .files
            .remove(&file.path)
            .ok_or_else(|| AppError::State(format!("bundle 缺少声明文件：{}", file.path)))?;
        let relative = format!("{stage_dir}/files/{}", file.path);
        executor.write_file(&relative, &extracted.content, file.mode == 0o600)?;
        let file_path = shell_quote(&relative);
        executor.run_in_directory(&format!(
            "set -eu\nchmod {mode} {file_path}\ntest -f {file_path}",
            mode = format_args!("{:o}", file.mode)
        ))?;
    }
    Ok(bundle_manifest)
}

#[cfg(test)]
fn validate_archive_bytes(bytes: &[u8]) -> Result<()> {
    extract_archive_bytes(bytes).map(|_| ())
}

fn extract_archive_bytes(bytes: &[u8]) -> Result<ExtractedBundleArchive> {
    const MAX_ARCHIVE_BYTES: usize = 256 * 1024 * 1024;
    const MAX_UNPACKED_BYTES: u64 = 256 * 1024 * 1024;
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(AppError::State(
            "升级 artifact 超过 256 MiB 限制".to_owned(),
        ));
    }
    let decoder = zstd::stream::read::Decoder::new(Cursor::new(bytes))
        .map_err(|error| AppError::State(format!("升级 artifact zstd 解码失败：{error}")))?;
    let mut archive = tar::Archive::new(decoder);
    let allowed = [
        "bundle-manifest.json",
        "docker-compose.yml",
        "docker-compose.updater.yml",
        "secrets.env.patch",
        "downstream-credentials.env.patch",
        "meowai-deploy-upgrade-agent",
    ];
    let allowed = allowed.into_iter().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut manifest = None;
    let mut files = BTreeMap::new();
    let mut unpacked_bytes = 0_u64;
    let entries = archive
        .entries()
        .map_err(|error| AppError::State(format!("读取升级 artifact 目录失败：{error}")))?;
    for entry in entries {
        let mut entry = entry
            .map_err(|error| AppError::State(format!("读取升级 artifact 条目失败：{error}")))?;
        let path = entry
            .path()
            .map_err(|error| AppError::State(format!("读取升级 artifact 路径失败：{error}")))?;
        let path = path
            .to_str()
            .ok_or_else(|| AppError::State("升级 artifact 路径不是 UTF-8".to_owned()))?
            .to_owned();
        let allowed_path = allowed.contains(path.as_str()) || is_migration_script_path(&path);
        if !allowed_path || !seen.insert(path.clone()) {
            return Err(AppError::State(format!(
                "升级 artifact 条目不允许或重复：{path}"
            )));
        }
        if !entry.header().entry_type().is_file() {
            return Err(AppError::State(format!(
                "升级 artifact 只允许普通文件：{path}"
            )));
        }
        let size = entry
            .header()
            .size()
            .map_err(|error| AppError::State(format!("读取升级 artifact 大小失败：{error}")))?;
        unpacked_bytes = unpacked_bytes
            .checked_add(size)
            .filter(|total| *total <= MAX_UNPACKED_BYTES)
            .ok_or_else(|| AppError::State("升级 artifact 解包后超过 256 MiB 限制".to_owned()))?;
        let mode = entry
            .header()
            .mode()
            .map_err(|error| AppError::State(format!("读取升级 artifact 权限失败：{error}")))?
            & 0o777;
        let mut content = Vec::with_capacity(size as usize);
        entry
            .read_to_end(&mut content)
            .map_err(|error| AppError::State(format!("读取升级 artifact 内容失败：{error}")))?;
        if content.len() as u64 != size {
            return Err(AppError::State(format!(
                "升级 artifact 条目大小不一致：{path}"
            )));
        }
        if path == "bundle-manifest.json" {
            manifest = Some(content);
        } else {
            files.insert(path, ExtractedBundleFile { mode, content });
        }
    }
    let manifest = manifest
        .ok_or_else(|| AppError::State("升级 artifact 缺少 bundle-manifest.json".to_owned()))?;
    Ok(ExtractedBundleArchive { manifest, files })
}

fn validate_bundle_manifest(bundle: &BundleManifest, manifest: &ReleaseManifest) -> Result<()> {
    if bundle.bundle_schema != 1
        || bundle.release_id != manifest.release_id
        || bundle.deployment_schema != manifest.deployment_schema
        || bundle.migration_steps != manifest.migration_plan.steps
        || bundle.files.is_empty()
        || bundle.files.len() > 40
    {
        return Err(AppError::State(
            "bundle manifest 与签名 release manifest 不一致".to_owned(),
        ));
    }
    let allowed = [
        ("docker-compose.yml", 0o644),
        ("docker-compose.updater.yml", 0o644),
        ("secrets.env.patch", 0o600),
        ("downstream-credentials.env.patch", 0o600),
        ("meowai-deploy-upgrade-agent", 0o700),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for file in &bundle.files {
        let expected_mode = allowed
            .iter()
            .find(|(path, _)| *path == file.path)
            .map(|(_, mode)| *mode)
            .or_else(|| is_migration_script_path(&file.path).then_some(0o700))
            .ok_or_else(|| {
                AppError::State(format!("bundle 声明了不允许的目标文件：{}", file.path))
            })?;
        if file.mode != expected_mode
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !seen.insert(file.path.as_str())
        {
            return Err(AppError::State(format!(
                "bundle 文件声明无效：{}",
                file.path
            )));
        }
    }
    for required in ["docker-compose.yml", "meowai-deploy-upgrade-agent"] {
        if !seen.contains(required) {
            return Err(AppError::State(format!("bundle 缺少必需文件：{required}")));
        }
    }
    let mut compose_changes = std::collections::BTreeSet::new();
    for change in &bundle.compose_changes {
        if !matches!(change.kind.as_str(), "service" | "network" | "volume")
            || !matches!(change.action.as_str(), "add" | "remove" | "modify")
            || change.name.is_empty()
            || change.name.len() > 128
            || !change
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(AppError::State(format!(
                "bundle Compose 变更声明无效：{}",
                change.name
            )));
        }
        if !compose_changes.insert((change.kind.as_str(), change.name.as_str())) {
            return Err(AppError::State(format!(
                "bundle 重复声明 Compose 资源：{}:{}",
                change.kind, change.name
            )));
        }
        if change.action == "remove" {
            return Err(AppError::State(format!(
                "当前 agent 拒绝删除 Compose 资源：{}",
                change.name
            )));
        }
    }
    let mut env_changes = std::collections::BTreeSet::new();
    for change in &bundle.env_changes {
        if !matches!(
            change.file.as_str(),
            "secrets.env.patch" | "downstream-credentials.env.patch"
        ) || !matches!(
            change.action.as_str(),
            "add" | "preserve" | "replace" | "remove"
        ) || change.key.is_empty()
            || change.key.len() > 128
            || !change
                .key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(AppError::State(format!(
                "bundle 环境变量变更声明无效：{}:{}",
                change.file, change.key
            )));
        }
        if !env_changes.insert((change.file.as_str(), change.key.as_str())) {
            return Err(AppError::State(format!(
                "bundle 重复声明环境变量：{}:{}",
                change.file, change.key
            )));
        }
        if change.file == "downstream-credentials.env.patch"
            && matches!(
                change.key.as_str(),
                "MEOWAI_DEPLOYMENT_ID"
                    | "MEOWAI_INSTALLATION_GENERATION"
                    | "MEOWAI_CONTROL_PLANE_URL"
                    | "MEOWAI_REPORT_CREDENTIAL"
                    | "MEOWAI_PULL_CREDENTIAL"
                    | "MEOWAI_HEARTBEAT_INTERVAL_SECONDS"
                    | "MEOWAI_SNAPSHOT_INTERVAL_SECONDS"
                    | "MEOWAI_DEPLOYMENT_SCHEMA"
                    | "MEOWAI_UPDATER_SCHEMA"
                    | "MEOWAI_CLI_SCHEMA"
                    | "MEOWAI_DATA_SCHEMA"
                    | "MEOWAI_CURRENT_IMAGE_DIGEST"
                    | "MEOWAI_ALLOWED_IMAGE_REPOSITORY"
                    | "MEOWAI_CONTAINER_NAME"
                    | "MEOWAI_NEWAPI_PORT"
                    | "MEOWAI_KUMA_PORT"
                    | "MEOWAI_RELEASE_SCHEMA_VERSION"
                    | "MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY"
                    | "MEOWAI_RELEASE_ARTIFACT_ALLOWED_HOSTS"
                    | "MEOWAI_UPDATER_SOCKET_PATH"
            )
        {
            return Err(AppError::State(format!(
                "bundle 不得修改 agent 管理的 downstream key：{}",
                change.key
            )));
        }
    }
    for step in &manifest.migration_plan.steps {
        if step.starts_with("data-") && !is_noop_data_step(step) {
            let script = format!("migrations/{step}.sh");
            if !bundle.files.iter().any(|file| file.path == script) {
                return Err(AppError::State(format!(
                    "数据迁移步骤 {} 缺少签名 bundle 脚本 {}",
                    step, script
                )));
            }
        }
    }
    Ok(())
}

fn validate_data_migration_policy(
    manifest: &ReleaseManifest,
    invoked_by_updater: bool,
) -> Result<()> {
    let has_data_migration = manifest
        .migration_plan
        .steps
        .iter()
        .any(|step| step.starts_with("data-") && !is_noop_data_step(step));
    if has_data_migration && !manifest.rollback.data_rollback_required {
        return Err(AppError::State(
            "真实数据迁移必须声明 data_rollback_required=true".to_owned(),
        ));
    }
    if manifest.rollback.data_rollback_required && invoked_by_updater {
        return Err(AppError::State(
            "需要数据恢复保障的迁移不能由 timer 静默执行；请使用 CLI plan 和显式确认".to_owned(),
        ));
    }
    Ok(())
}

fn is_migration_script_path(path: &str) -> bool {
    let Some(step) = path.strip_prefix("migrations/") else {
        return false;
    };
    step.strip_suffix(".sh").is_some_and(|step| {
        !step.is_empty()
            && step.len() <= 96
            && step
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

fn run_migrations(
    executor: &TargetExecutor,
    stage_dir: &str,
    manifest: &ReleaseManifest,
    bundle: &BundleManifest,
) -> Result<()> {
    for step in &bundle.migration_steps {
        let marker = shell_quote(&format!("run/migrations/{step}.done"));
        executor.run_in_directory("set -eu\nmkdir -p run/migrations")?;
        if executor
            .run_in_directory(&format!("set -eu\ntest -f {marker}"))
            .is_ok()
        {
            continue;
        }
        match step.as_str() {
            step if is_sequential_deployment_step(step) => {
                verify_deployment_step(executor, stage_dir, step)?
            }
            step if is_noop_data_step(step) => {}
            step if step.starts_with("data-") => run_data_migration(executor, stage_dir, step)?,
            step if manifest.migration_plan.from == manifest.migration_plan.to => {
                return Err(AppError::State(format!(
                    "无需迁移的 manifest 包含步骤：{step}"
                )));
            }
            _ => {
                return Err(AppError::State(format!(
                    "当前 upgrade agent 不支持迁移步骤：{step}"
                )));
            }
        }
        executor.run_in_directory(&format!(
            "set -eu\nprintf '%s\\n' {} > {marker}\nchmod 600 {marker}",
            shell_quote(step),
            marker = marker
        ))?;
    }
    Ok(())
}

fn run_data_migration(executor: &TargetExecutor, stage_dir: &str, step: &str) -> Result<()> {
    let script = shell_quote(&format!("{stage_dir}/files/migrations/{step}.sh"));
    let output = executor.run_in_directory(&format!(
        r#"set -eu
test -x {script}
command -v timeout >/dev/null
set +e
timeout --signal=TERM --kill-after=30s 900s sh {script} >/dev/null 2>&1
status=$?
set -e
printf '%s' "$status""#,
        script = script
    ))?;
    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<i32>()
        .map_err(|_| AppError::State(format!("数据迁移步骤 {step} 未返回有效状态")))?;
    if status == 0 {
        Ok(())
    } else if matches!(status, 124 | 137 | 143) {
        Err(AppError::State(format!("数据迁移步骤 {step} 执行超时")))
    } else {
        Err(AppError::State(format!(
            "数据迁移步骤 {step} 失败，退出码 {status}"
        )))
    }
}

fn is_noop_data_step(step: &str) -> bool {
    let Some((from, to)) = step.strip_prefix("data-").and_then(parse_step_range) else {
        return false;
    };
    from == to
}

fn parse_step_range(value: &str) -> Option<(u32, u32)> {
    let (from, to) = value.split_once("-to-")?;
    Some((from.parse().ok()?, to.parse().ok()?))
}

fn is_sequential_deployment_step(step: &str) -> bool {
    step.strip_prefix("deployment-")
        .and_then(parse_step_range)
        .is_some_and(|(from, to)| to == from.saturating_add(1))
}

fn validate_migration_path(state: &DeploymentState, manifest: &ReleaseManifest) -> Result<()> {
    let mut current_data = state
        .data_schema
        .parse::<u32>()
        .map_err(|_| AppError::State("当前 data schema 不是有效整数".to_owned()))?;
    let current_deployment = state
        .deployment_schema
        .parse::<u32>()
        .map_err(|_| AppError::State("当前 deployment schema 不是有效整数".to_owned()))?;
    if current_deployment != manifest.migration_plan.from {
        return Err(AppError::State(format!(
            "当前 deployment schema {} 与 manifest migration 起点 {} 不一致",
            current_deployment, manifest.migration_plan.from
        )));
    }
    if manifest.migration_plan.from == manifest.migration_plan.to {
        if manifest
            .migration_plan
            .steps
            .iter()
            .any(|step| step.starts_with("deployment-"))
        {
            return Err(AppError::State(
                "deployment schema 不变时不得声明 deployment migration step".to_owned(),
            ));
        }
    }
    if manifest.migration_plan.steps.is_empty() {
        return Err(AppError::State(
            "deployment schema 变化时必须声明 migration step".to_owned(),
        ));
    }
    let mut deployment_version = manifest.migration_plan.from;
    for step in &manifest.migration_plan.steps {
        if let Some(range) = step.strip_prefix("deployment-").and_then(parse_step_range) {
            if range.0 != deployment_version || range.1 != range.0 + 1 {
                return Err(AppError::State(format!(
                    "deployment migration step {} 不连续",
                    step
                )));
            }
            deployment_version = range.1;
        } else if let Some(range) = step.strip_prefix("data-").and_then(parse_step_range) {
            if range.0 == range.1 {
                if range.0 != current_data {
                    return Err(AppError::State(format!(
                        "noop data migration step {} 与当前版本不匹配",
                        step
                    )));
                }
                continue;
            }
            if range.0 != current_data || range.1 != range.0 + 1 {
                return Err(AppError::State(format!(
                    "data migration step {} 必须从当前版本连续升级一个版本",
                    step
                )));
            }
            current_data = range.1;
        } else {
            return Err(AppError::State(format!(
                "migration step {} 使用了未知命名空间",
                step
            )));
        }
    }
    if deployment_version != manifest.migration_plan.to {
        return Err(AppError::State(
            "deployment migration steps 未覆盖到 manifest 目标版本".to_owned(),
        ));
    }
    if current_data < manifest.minimum_data_schema {
        return Err(AppError::State(format!(
            "migration steps 未覆盖 data schema {} -> {}",
            state.data_schema, manifest.minimum_data_schema
        )));
    }
    Ok(())
}

fn prepare_environment_files(
    executor: &TargetExecutor,
    stage_dir: &str,
    config: &DeploymentConfig,
    registration: &DeploymentRegistration,
    manifest: &ReleaseManifest,
    bundle: &BundleManifest,
) -> Result<()> {
    let files = shell_quote(&format!("{stage_dir}/files"));
    let deployment_schema = shell_quote(&manifest.deployment_schema.to_string());
    let updater_schema = shell_quote(&manifest.minimum_updater_schema.to_string());
    let cli_schema = shell_quote(&manifest.minimum_cli_schema.to_string());
    let data_schema = shell_quote(&manifest.minimum_data_schema.to_string());
    let image_digest = shell_quote(&manifest.image_digest);
    let deployment_id = shell_quote(&registration.deployment_id);
    let installation_generation = shell_quote(&registration.installation_generation.to_string());
    let control_plane_url = shell_quote(&registration.control_plane_url);
    let heartbeat_interval = shell_quote(&registration.heartbeat_interval_seconds.to_string());
    let snapshot_interval = shell_quote(&registration.snapshot_interval_seconds.to_string());
    let image_repository = shell_quote(&config.image);
    let container_name = shell_quote(&config.container_name);
    let newapi_port = shell_quote(&config.newapi_port.to_string());
    let kuma_port = shell_quote(&config.kuma_port.to_string());
    let release_schema = shell_quote(&registration.release_schema_version);
    let release_public_key = shell_quote(&registration.release_manifest_public_key);
    let artifact_hosts = shell_quote(&registration.release_artifact_allowed_hosts.join(","));
    let mut env_validation = String::new();
    for file in ["secrets.env.patch", "downstream-credentials.env.patch"] {
        let keys = bundle
            .env_changes
            .iter()
            .filter(|change| change.file == file)
            .map(|change| shell_quote(&change.key))
            .collect::<Vec<_>>();
        env_validation.push_str(&format!(
            "validate_patch {} {}\n",
            shell_quote(file),
            keys.join(" ")
        ));
    }
    let mut env_actions = String::new();
    for change in &bundle.env_changes {
        let target = if change.file == "secrets.env.patch" {
            shell_quote(&format!("{stage_dir}/merged-secrets.env"))
        } else {
            shell_quote(&format!("{stage_dir}/merged-downstream-credentials.env"))
        };
        let patch = shell_quote(&format!("{stage_dir}/files/{}", change.file));
        let key = shell_quote(&change.key);
        match change.action.as_str() {
            "add" => env_actions.push_str(&format!("add_key {} {} {}\n", target, patch, key)),
            "preserve" => {
                env_actions.push_str(&format!("preserve_key {} {} {}\n", target, patch, key))
            }
            "replace" => {
                env_actions.push_str(&format!("replace_key {} {} {}\n", target, patch, key))
            }
            "remove" => env_actions.push_str(&format!("remove_key {} {} {}\n", target, patch, key)),
            _ => {
                return Err(AppError::State(format!(
                    "不支持的环境变量 action：{}",
                    change.action
                )));
            }
        }
    }
    executor.run_in_directory(&format!(
        r#"set -eu
validate_patch() {{
  patch=$1
  shift
  [ -f "{files}/$patch" ] || return 0
  seen="{stage}/patch-$(basename "$patch").keys"
  : > "$seen"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) exit 1 ;; esac
    key=${{line%%=*}}
    case "$key" in *[!A-Z0-9_]*|'') exit 1 ;; esac
    ! grep -Fqx "$key" "$seen" || exit 1
    printf '%s\n' "$key" >> "$seen"
    allowed=false
    for candidate in "$@"; do [ "$candidate" = "$key" ] && allowed=true; done
    [ "$allowed" = true ] || exit 1
  done < "{files}/$patch"
}}
validate_env_file() {{
  target=$1
  seen=$2
  : > "$seen"
  test -f "$target"
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) exit 1 ;; esac
    key=${{line%%=*}}
    case "$key" in *[!A-Z0-9_]*|'') exit 1 ;; esac
    ! grep -Fqx "$key" "$seen" || exit 1
    printf '%s\n' "$key" >> "$seen"
  done < "$target"
}}
patch_line() {{
  patch=$1
  key=$2
  test -f "$patch"
  count=$(grep -c "^${{key}}=" "$patch" || true)
  [ "$count" = 1 ]
  grep "^${{key}}=" "$patch"
}}
set_line() {{
  file=$1
  key=$2
  line=$3
  tmp="$file.next"
  awk -F= -v key="$key" '$1 != key {{ print }}' "$file" > "$tmp"
  printf '%s\n' "$line" >> "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$file"
}}
add_key() {{
  target=$1
  patch=$2
  key=$3
  line=$(patch_line "$patch" "$key")
  if grep -q "^${{key}}=" "$target"; then
    # Replaying a partially applied bundle is safe only when the existing
    # managed value is exactly the value declared by the bundle.
    grep -Fxq "$line" "$target"
  else
    printf '%s\n' "$line" >> "$target"
  fi
}}
preserve_key() {{
  target=$1
  patch=$2
  key=$3
  grep -q "^${{key}}=" "$target"
  ! grep -q "^${{key}}=" "$patch" 2>/dev/null
}}
replace_key() {{
  target=$1
  patch=$2
  key=$3
  grep -q "^${{key}}=" "$target"
  line=$(patch_line "$patch" "$key")
  set_line "$target" "$key" "$line"
}}
remove_key() {{
  target=$1
  patch=$2
  key=$3
  grep -q "^${{key}}=" "$target"
  ! grep -q "^${{key}}=" "$patch" 2>/dev/null
  tmp="$target.next"
  awk -F= -v key="$key" '$1 != key {{ print }}' "$target" > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$target"
}}
set_key() {{
  file=$1
  key=$2
  value=$3
  set_line "$file" "$key" "$key=$value"
}}
{env_validation}
downstream="{stage}/merged-downstream-credentials.env"
secrets="{stage}/merged-secrets.env"
validate_env_file secrets.env "{stage}/current-secrets.keys"
validate_env_file downstream-credentials.env "{stage}/current-downstream-credentials.keys"
cp secrets.env "$secrets"
cp downstream-credentials.env "$downstream"
chmod 600 "$secrets" "$downstream"
cp "$secrets" "{stage}/secrets.env"
cp "$downstream" "{stage}/downstream-credentials.env"
if [ -f updater-credentials.env ]; then cp updater-credentials.env "{stage}/updater-credentials.env"; chmod 600 "{stage}/updater-credentials.env"; fi
{env_actions}
validate_env_file "$secrets" "{stage}/merged-secrets.keys"
validate_env_file "$downstream" "{stage}/merged-downstream-credentials.keys"
set_key "$downstream" MEOWAI_DEPLOYMENT_SCHEMA {deployment_schema}
set_key "$downstream" MEOWAI_UPDATER_SCHEMA {updater_schema}
set_key "$downstream" MEOWAI_CLI_SCHEMA {cli_schema}
set_key "$downstream" MEOWAI_DATA_SCHEMA {data_schema}
set_key "$downstream" MEOWAI_CURRENT_IMAGE_DIGEST {image_digest}
set_key "$downstream" MEOWAI_DEPLOYMENT_ID {deployment_id}
set_key "$downstream" MEOWAI_INSTALLATION_GENERATION {installation_generation}
set_key "$downstream" MEOWAI_CONTROL_PLANE_URL {control_plane_url}
set_key "$downstream" MEOWAI_HEARTBEAT_INTERVAL_SECONDS {heartbeat_interval}
set_key "$downstream" MEOWAI_SNAPSHOT_INTERVAL_SECONDS {snapshot_interval}
set_key "$downstream" MEOWAI_ALLOWED_IMAGE_REPOSITORY {image_repository}
set_key "$downstream" MEOWAI_CONTAINER_NAME {container_name}
set_key "$downstream" MEOWAI_NEWAPI_PORT {newapi_port}
set_key "$downstream" MEOWAI_KUMA_PORT {kuma_port}
set_key "$downstream" MEOWAI_RELEASE_SCHEMA_VERSION {release_schema}
set_key "$downstream" MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY {release_public_key}
set_key "$downstream" MEOWAI_RELEASE_ARTIFACT_ALLOWED_HOSTS {artifact_hosts}"#,
        stage = shell_quote(stage_dir),
        files = files,
        deployment_schema = deployment_schema,
        updater_schema = updater_schema,
        cli_schema = cli_schema,
        data_schema = data_schema,
        image_digest = image_digest,
        deployment_id = deployment_id,
        installation_generation = installation_generation,
        control_plane_url = control_plane_url,
        heartbeat_interval = heartbeat_interval,
        snapshot_interval = snapshot_interval,
        image_repository = image_repository,
        container_name = container_name,
        newapi_port = newapi_port,
        kuma_port = kuma_port,
        release_schema = release_schema,
        release_public_key = release_public_key,
        artifact_hosts = artifact_hosts,
        env_validation = env_validation,
        env_actions = env_actions,
    ))?;
    Ok(())
}

fn verify_deployment_step(executor: &TargetExecutor, stage_dir: &str, step: &str) -> Result<()> {
    if !is_sequential_deployment_step(step) {
        return Err(AppError::State(format!(
            "deployment migration step 不连续：{step}"
        )));
    }
    let files = shell_quote(&format!("{stage_dir}/files"));
    executor
        .run_in_directory(&format!(
            "set -eu\ntest -s {files}/docker-compose.yml\ntest -s {files}/meowai-deploy-upgrade-agent"
        ))
        .map(|_| ())
}

fn validate_compose_changes(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    stage_dir: &str,
    manifest: &ReleaseManifest,
    bundle: &BundleManifest,
) -> Result<()> {
    let project = shell_quote(&config.container_name);
    let current_file = shell_quote("docker-compose.yml");
    let staged_file = shell_quote(&format!("{stage_dir}/rendered-docker-compose.yml"));
    let current_env = shell_quote("secrets.env");
    let staged_env = shell_quote(&format!("{stage_dir}/merged-secrets.env"));
    render_staged_compose(executor, stage_dir, config, manifest)?;
    let current = executor.run_in_directory(&format!(
        "docker compose --env-file {current_env} -p {project} -f {current_file} config --format json"
    ))?;
    let staged = executor.run_in_directory(&format!(
        "set -eu\nvalidation_file=.meowai-compose-validation.yml\ntrap 'rm -f \"$validation_file\"' EXIT\ncp {staged_file} \"$validation_file\"\ndocker compose --env-file {staged_env} -p {project} -f \"$validation_file\" config --format json"
    ))?;
    let current: serde_json::Value = serde_json::from_slice(&current.stdout)
        .map_err(|error| AppError::State(format!("当前 Compose config JSON 无效：{error}")))?;
    let staged: serde_json::Value = serde_json::from_slice(&staged.stdout)
        .map_err(|error| AppError::State(format!("暂存 Compose config JSON 无效：{error}")))?;
    validate_compose_diff(&current, &staged, &bundle.compose_changes)
}

fn render_staged_compose(
    executor: &TargetExecutor,
    stage_dir: &str,
    config: &DeploymentConfig,
    manifest: &ReleaseManifest,
) -> Result<()> {
    let template = executor.run_in_directory(&format!(
        "cat {}",
        shell_quote(&format!("{stage_dir}/files/docker-compose.yml"))
    ))?;
    let mut document: serde_json::Value = serde_json::from_slice(&template.stdout)
        .map_err(|error| AppError::State(format!("bundle Compose 模板 JSON 无效：{error}")))?;
    let replacements = std::collections::BTreeMap::from([
        ("MEOWAI_CONTAINER_NAME", config.container_name.clone()),
        ("MEOWAI_NEWAPI_BIND", config.newapi_bind.clone()),
        ("MEOWAI_KUMA_BIND", config.kuma_bind.clone()),
        ("MEOWAI_NEWAPI_PORT", config.newapi_port.to_string()),
        ("MEOWAI_KUMA_PORT", config.kuma_port.to_string()),
        (
            "MEOWAI_IMAGE_REFERENCE",
            format!("{}@{}", manifest.image_repository, manifest.image_digest),
        ),
    ]);
    render_compose_value(&mut document, &replacements)?;
    let rendered = serde_json::to_vec_pretty(&document)
        .map_err(|error| AppError::State(format!("序列化 Compose 模板失败：{error}")))?;
    executor.write_file(
        &format!("{stage_dir}/rendered-docker-compose.yml"),
        &rendered,
        false,
    )
}

fn render_compose_value(
    value: &mut serde_json::Value,
    replacements: &std::collections::BTreeMap<&str, String>,
) -> Result<()> {
    match value {
        serde_json::Value::String(text) => {
            for (key, replacement) in replacements {
                *text = text.replace(&format!("${{{key}}}"), replacement);
            }
            if text.contains("${MEOWAI_") {
                return Err(AppError::State(format!(
                    "Compose 模板包含未知的 MeowAI 变量：{text}"
                )));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                render_compose_value(item, replacements)?;
            }
        }
        serde_json::Value::Object(object) => {
            for item in object.values_mut() {
                render_compose_value(item, replacements)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_compose_diff(
    current: &serde_json::Value,
    staged: &serde_json::Value,
    declared: &[BundleComposeChange],
) -> Result<()> {
    let mut expected = std::collections::BTreeMap::new();
    for change in declared {
        expected.insert(
            (change.kind.clone(), change.name.clone()),
            change.action.clone(),
        );
    }
    let mut actual = std::collections::BTreeMap::new();
    for (kind, field) in [
        ("service", "services"),
        ("network", "networks"),
        ("volume", "volumes"),
    ] {
        let empty = serde_json::Map::new();
        let old = current
            .get(field)
            .and_then(|value| value.as_object())
            .unwrap_or(&empty);
        let new = staged
            .get(field)
            .and_then(|value| value.as_object())
            .unwrap_or(&empty);
        for name in old.keys() {
            if !new.contains_key(name) {
                return Err(AppError::State(format!(
                    "当前 agent 拒绝删除 Compose 资源：{kind}:{name}"
                )));
            }
        }
        for (name, new_value) in new {
            let Some(old_value) = old.get(name) else {
                actual.insert((kind.to_owned(), name.clone()), "add".to_owned());
                continue;
            };
            let old_value = normalize_compose_resource(kind, old_value.clone());
            let new_value = normalize_compose_resource(kind, new_value.clone());
            if old_value != new_value {
                actual.insert((kind.to_owned(), name.clone()), "modify".to_owned());
            }
        }
    }
    for key in actual.keys() {
        if !expected.contains_key(key) {
            return Err(AppError::State(format!(
                "Compose 实际变更未在 bundle 中声明：{key:?}"
            )));
        }
    }
    for (key, action) in &expected {
        if actual.get(key) == Some(action) {
            continue;
        }
        let (kind, name) = key;
        let field = match kind.as_str() {
            "service" => "services",
            "network" => "networks",
            "volume" => "volumes",
            _ => unreachable!("validated Compose resource kind"),
        };
        let current_resource = current.get(field).and_then(|value| value.get(name));
        let staged_resource = staged.get(field).and_then(|value| value.get(name));
        if action != "remove"
            && current_resource.is_some()
            && staged_resource.is_some()
            && normalize_compose_resource(kind, current_resource.cloned().unwrap())
                == normalize_compose_resource(kind, staged_resource.cloned().unwrap())
        {
            // A retry may observe a resource that the bundle already applied.
            // Treat the declared no-op as idempotent while still rejecting
            // conflicting or undeclared changes above.
            continue;
        }
        return Err(AppError::State(format!(
            "Compose 实际变更与 bundle 声明不一致：expected={expected:?}, actual={actual:?}"
        )));
    }
    Ok(())
}

fn normalize_compose_resource(kind: &str, mut value: serde_json::Value) -> serde_json::Value {
    if kind == "service"
        && let Some(environment) = value
            .as_object_mut()
            .and_then(|object| object.get_mut("environment"))
            .and_then(|environment| environment.as_object_mut())
    {
        for value in environment.values_mut() {
            *value = serde_json::Value::String("<managed>".to_owned());
        }
    }
    value
}

fn switch_services(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    stage_dir: &str,
    bundle: &BundleManifest,
) -> Result<()> {
    let files = shell_quote(&format!("{stage_dir}/files"));
    let project = shell_quote(&config.container_name);
    let declared = bundle
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut install_commands = Vec::new();
    for (source, target, mode) in [
        (
            "docker-compose.updater.yml",
            "docker-compose.updater.yml",
            "0644",
        ),
        (
            "meowai-deploy-upgrade-agent",
            "bin/meowai-deploy-upgrade-agent",
            "0700",
        ),
    ] {
        if declared.contains(source) {
            install_commands.push(format!(
                "install -m {mode} {files}/{} {}",
                shell_quote(source),
                shell_quote(target)
            ));
        }
    }
    install_commands.push(format!(
        "install -m 0644 {}/rendered-docker-compose.yml docker-compose.yml",
        shell_quote(stage_dir)
    ));
    if !declared.contains("docker-compose.updater.yml") {
        install_commands.push("rm -f docker-compose.updater.yml".to_owned());
    }
    install_commands.push(format!(
        "install -m 0600 {}/merged-secrets.env secrets.env",
        shell_quote(stage_dir)
    ));
    install_commands.push(format!(
        "install -m 0600 {}/merged-downstream-credentials.env downstream-credentials.env",
        shell_quote(stage_dir)
    ));
    executor.run_in_directory(&format!(
        "set -eu\nmkdir -p bin\n{}\ndocker compose --env-file secrets.env -p {project} -f docker-compose.yml config >/dev/null\ndocker compose --env-file secrets.env -p {project} -f docker-compose.yml up -d --remove-orphans",
        install_commands.join("\n"),
        project = project
    ))?;
    crate::target::updater::install_paused(executor, config, config.newapi_port)?;
    executor
        .run_in_directory("set -eu\nsystemctl daemon-reload")
        .map(|_| ())
}

fn activate_updater_timer(executor: &TargetExecutor) -> Result<()> {
    executor.run_in_directory(
        "set -eu\nsystemctl enable --now meowai-deploy-updater.timer\nsystemctl is-enabled --quiet meowai-deploy-updater.timer\nsystemctl is-active --quiet meowai-deploy-updater.timer",
    )?;
    Ok(())
}

fn health_check(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    manifest: &ReleaseManifest,
) -> Result<()> {
    let project = shell_quote(&config.container_name);
    let newapi_timeout = manifest.health_policy.newapi_timeout_seconds.max(10);
    let dependency_timeout = manifest.health_policy.dependency_timeout_seconds.max(10);
    let expected_image = shell_quote(&format!(
        "{}@{}",
        manifest.image_repository, manifest.image_digest
    ));
    let heartbeat_age = manifest
        .health_policy
        .updater_heartbeat_max_age_seconds
        .max(30);
    executor.run_in_directory(&format!(
        r#"set -eu
deadline=$(( $(date +%s) + {dependency_timeout} ))
while :; do
  pg=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' {project}-postgres 2>/dev/null || true)
  redis=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' {project}-redis 2>/dev/null || true)
  kuma=$(docker inspect --format '{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{else}}}}none{{{{end}}}}' {project}-uptime-kuma 2>/dev/null || true)
  [ "$pg" = healthy ] && [ "$redis" = healthy ] && [ "$kuma" = healthy ] && break
  [ "$(date +%s)" -lt "$deadline" ] || exit 1
  sleep 2
done
deadline=$(( $(date +%s) + {newapi_timeout} ))
while :; do
  if curl --fail --silent --show-error --max-time 5 http://127.0.0.1:{newapi_port}/api/status >/dev/null && curl --fail --silent --show-error --max-time 5 http://127.0.0.1:{newapi_port}/api/setup >/dev/null; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] || exit 1
  sleep 2
done
configured=$(docker compose --env-file secrets.env -p {project} -f docker-compose.yml config --services | sort)
running=$(docker compose --env-file secrets.env -p {project} -f docker-compose.yml ps --services --status running | sort)
[ "$configured" = "$running" ]
[ "$(docker inspect --format '{{{{.Config.Image}}}}' {project})" = {expected_image} ]
systemctl cat meowai-deploy-updater.service >/dev/null
systemctl cat meowai-deploy-updater.timer >/dev/null
test -S run/updater.sock
test -s run/updater-status.json
updated_at=$(sed -n 's/.*"updated_at":[[:space:]]*\([0-9][0-9]*\).*/\1/p' run/updater-status.json | head -n 1)
[ -n "$updated_at" ]
[ $(( $(date +%s) - updated_at )) -le {heartbeat_age} ]
grep -q '^MEOWAI_DEPLOYMENT_ID=..*' downstream-credentials.env
grep -q '^MEOWAI_INSTALLATION_GENERATION=..*' downstream-credentials.env
grep -q '^MEOWAI_DEPLOYMENT_SCHEMA={deployment_schema}$' downstream-credentials.env
grep -q '^MEOWAI_UPDATER_SCHEMA={updater_schema}$' downstream-credentials.env
docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -U meowai -d newapi -Atqc "select 1"' | grep -qx 1
docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T redis sh -c 'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning ping' | grep -qx PONG
deadline=$(( $(date +%s) + {dependency_timeout} ))
while :; do
  if curl --fail --silent --show-error --max-time 5 http://127.0.0.1:{kuma_port}/api/entry-page >/dev/null; then break; fi
  [ "$(date +%s)" -lt "$deadline" ] || exit 1
  sleep 2
done"#,
        dependency_timeout = dependency_timeout,
        newapi_timeout = newapi_timeout,
        newapi_port = config.newapi_port,
        kuma_port = config.kuma_port,
        expected_image = expected_image,
        heartbeat_age = heartbeat_age,
        deployment_schema = manifest.deployment_schema,
        updater_schema = manifest.minimum_updater_schema,
    )).map(|_| ())
}

fn rollback(
    executor: &TargetExecutor,
    config: &DeploymentConfig,
    backup_id: &str,
    data_rollback_required: bool,
) -> Result<()> {
    let dir = shell_quote(&format!("backups/{backup_id}"));
    let project = shell_quote(&config.container_name);
    executor.run_in_directory(&format!(
        r#"set -eu
(cd {dir} && sha256sum -c SHA256SUMS >/dev/null)
docker compose --env-file secrets.env -p {project} -f docker-compose.yml stop new-api redis uptime-kuma >/dev/null 2>&1 || true
for file in docker-compose.yml docker-compose.updater.yml secrets.env downstream-credentials.env updater-credentials.env meowai-deploy-updater.sh meowai-deploy-updater.service meowai-deploy-updater.timer; do
  if [ -f {dir}/$file ]; then cp -p {dir}/$file "$file"; else rm -f "$file"; fi
done
mkdir -p bin
if [ -f {dir}/bin/meowai-deploy-upgrade-agent ]; then cp -p {dir}/bin/meowai-deploy-upgrade-agent bin/; else rm -f bin/meowai-deploy-upgrade-agent; fi
rm -rf run/migrations
if [ -d {dir}/migrations ]; then cp -a {dir}/migrations run/migrations; fi
for unit in meowai-deploy-updater.service meowai-deploy-updater.timer; do
  if [ -f {dir}/systemd/$unit ]; then install -m 0644 {dir}/systemd/$unit "/etc/systemd/system/$unit"; else rm -f "/etc/systemd/system/$unit"; fi
done
if [ "{restore_data}" = 1 ]; then
  rm -rf data/redis data/uptime-kuma
  tar -xzf {dir}/redis-data.tar.gz
  tar -xzf {dir}/kuma-data.tar.gz
fi
systemctl daemon-reload
docker compose --env-file secrets.env -p {project} -f docker-compose.yml up -d postgres redis uptime-kuma
deadline=$(( $(date +%s) + 120 ))
until docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_isready -U meowai -d newapi' >/dev/null; do [ "$(date +%s)" -lt "$deadline" ] || exit 1; sleep 2; done
if [ "{restore_data}" = 1 ]; then
  docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -U meowai -d newapi -v ON_ERROR_STOP=1 -c "drop schema public cascade; create schema public;"'
  docker compose --env-file secrets.env -p {project} -f docker-compose.yml exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_restore -U meowai -d newapi --no-owner --no-privileges' < {dir}/postgres.dump
fi
docker compose --env-file secrets.env -p {project} -f docker-compose.yml up -d --remove-orphans
if [ -f /etc/systemd/system/meowai-deploy-updater.timer ]; then systemctl enable --now meowai-deploy-updater.timer; fi"#,
        dir = dir,
        project = project,
        restore_data = if data_rollback_required { 1 } else { 0 }
    )).map(|_| ())
}

fn journal(
    executor: &TargetExecutor,
    operation_id: &str,
    release_id: &str,
    state: &str,
    phase: &str,
    backup_id: &str,
) -> Result<()> {
    let data_rollback_required = read_journal(executor)
        .ok()
        .flatten()
        .is_some_and(|value| value.data_rollback_required);
    journal_with_data_rollback(
        executor,
        operation_id,
        release_id,
        state,
        phase,
        backup_id,
        data_rollback_required,
    )
}

fn journal_with_data_rollback(
    executor: &TargetExecutor,
    operation_id: &str,
    release_id: &str,
    state: &str,
    phase: &str,
    backup_id: &str,
    data_rollback_required: bool,
) -> Result<()> {
    let content = serde_json::to_vec_pretty(&UpgradeJournal {
        operation_id: operation_id.to_owned(),
        release_id: release_id.to_owned(),
        state: state.to_owned(),
        phase: phase.to_owned(),
        backup_id: backup_id.to_owned(),
        data_rollback_required,
        updated_at: crate::state::unix_timestamp(),
    })
    .map_err(|error| AppError::State(format!("serialize upgrade journal: {error}")))?;
    executor.write_file("run/upgrade-status.json", &content, true)
}

async fn lifecycle(
    registration: &DeploymentRegistration,
    event_type: &str,
    state: &str,
    reason: &str,
) {
    let _ = deployment_control::queue_lifecycle(registration, event_type, state, reason).await;
}

fn shell_quote(value: &str) -> String {
    shell_escape::escape(value.into()).into_owned()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        BundleComposeChange, BundleEnvChange, BundleManifest, TargetUpgradeLock,
        prepare_environment_files, render_compose_value, run_migrations, validate_archive_bytes,
        validate_bundle_manifest, validate_compose_diff, validate_data_migration_policy,
        validate_migration_path,
    };
    use crate::{
        config::{DeploymentConfig, Target},
        source::DeploymentRegistration,
        state::DeploymentState,
        target::TargetExecutor,
        upgrade::{ManifestHealthPolicy, ManifestMigrationPlan, ManifestRollback, ReleaseManifest},
    };
    use secrecy::SecretString;
    use serde_json::json;

    fn change(kind: &str, name: &str, action: &str) -> BundleComposeChange {
        BundleComposeChange {
            kind: kind.to_owned(),
            name: name.to_owned(),
            action: action.to_owned(),
        }
    }

    fn state(deployment_schema: u32, data_schema: u32) -> DeploymentState {
        serde_json::from_value(json!({
            "schema_version": 1,
            "deployment_id": "deployment-test",
            "target_fingerprint": "target-test",
            "container_name": "newapi",
            "directory": "/tmp/newapi",
            "newapi_port": 3000,
            "kuma_port": 3001,
            "image": "image",
            "image_ref": "sha256:image",
            "deployment_schema": deployment_schema.to_string(),
            "data_schema": data_schema.to_string()
        }))
        .expect("deployment state")
    }

    fn config(directory: &std::path::Path) -> DeploymentConfig {
        DeploymentConfig {
            directory: directory.to_path_buf(),
            container_name: "newapi".to_owned(),
            image: "ghcr.io/example/newapi".to_owned(),
            newapi_port: 3100,
            kuma_port: 3101,
            ..DeploymentConfig::default()
        }
    }

    fn registration() -> DeploymentRegistration {
        DeploymentRegistration {
            deployment_id: "dep_test".to_owned(),
            installation_generation: 2,
            control_plane_url: "https://control.example/api".to_owned(),
            report_credential: SecretString::from("report"),
            pull_credential: SecretString::from("pull"),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: true,
            release_schema_version: "2".to_owned(),
            release_manifest_public_key: "public-key".to_owned(),
            release_artifact_allowed_hosts: vec!["assets.example".to_owned()],
        }
    }

    fn manifest(from: u32, to: u32, minimum_data_schema: u32, steps: &[&str]) -> ReleaseManifest {
        ReleaseManifest {
            manifest_schema: 1,
            release_id: "rel_test".to_owned(),
            channel: "stable".to_owned(),
            newapi_version: "2.0.0".to_owned(),
            image_repository: "ghcr.io/example/newapi".to_owned(),
            image_digest: "sha256:target".to_owned(),
            deployment_schema: to,
            minimum_deployment_schema: to,
            minimum_updater_schema: 2,
            minimum_cli_schema: 2,
            minimum_data_schema,
            upgrade_kind: "deployment_and_image".to_owned(),
            required_capabilities: vec!["linux".to_owned()],
            artifacts: Vec::new(),
            migration_plan: ManifestMigrationPlan {
                from,
                to,
                steps: steps.iter().map(|step| (*step).to_owned()).collect(),
            },
            health_policy: ManifestHealthPolicy {
                newapi_timeout_seconds: 120,
                dependency_timeout_seconds: 120,
                updater_heartbeat_max_age_seconds: 180,
            },
            rollback: ManifestRollback {
                supported: true,
                retained_backup_count: 3,
                data_rollback_required: false,
            },
            created_at: 1,
            expires_at: 2,
            signature: String::new(),
        }
    }

    fn archive(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).expect("zstd encoder");
        let mut builder = tar::Builder::new(encoder);
        for (path, entry_type, body) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o600);
            header.set_entry_type(*entry_type);
            header.set_path(path).expect("archive path");
            header.set_cksum();
            builder
                .append(&header, Cursor::new(*body))
                .expect("append archive entry");
        }
        let encoder = builder.into_inner().expect("finish tar");
        encoder.finish().expect("finish zstd")
    }

    fn traversal_archive() -> Vec<u8> {
        let encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).expect("zstd encoder");
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_path("bundle-manifest.json").expect("safe path");
        let raw = header.as_mut_bytes();
        raw[..100].fill(0);
        raw[..13].copy_from_slice(b"../escape.txt");
        header.set_cksum();
        builder
            .append(&header, Cursor::new(b"x"))
            .expect("append traversal entry");
        let encoder = builder.into_inner().expect("finish tar");
        encoder.finish().expect("finish zstd")
    }

    fn bundle(env_changes: Vec<BundleEnvChange>) -> BundleManifest {
        BundleManifest {
            bundle_schema: 1,
            release_id: "rel_test".to_owned(),
            deployment_schema: 2,
            files: Vec::new(),
            migration_steps: vec!["deployment-1-to-2".to_owned()],
            compose_changes: Vec::new(),
            env_changes,
        }
    }

    #[test]
    fn compose_diff_accepts_an_added_service() {
        let current = json!({"services": {"new-api": {"image": "old"}}});
        let staged = json!({"services": {
            "new-api": {"image": "old"},
            "worker": {"image": "worker:v2"}
        }});
        validate_compose_diff(&current, &staged, &[change("service", "worker", "add")])
            .expect("declared service addition");
    }

    #[test]
    fn compose_diff_accepts_a_real_service_change() {
        let current = json!({"services": {"new-api": {"image": "old", "ports": ["3000"]}}});
        let staged = json!({"services": {"new-api": {"image": "new", "ports": ["3000"]}}});
        validate_compose_diff(&current, &staged, &[change("service", "new-api", "modify")])
            .expect("declared service modification");
    }

    #[test]
    fn compose_diff_accepts_a_retry_when_declared_resources_are_already_applied() {
        let current = json!({"services": {
            "new-api": {"image": "new"},
            "upgrade-probe": {"image": "redis:7-alpine"}
        }});
        let staged = current.clone();
        validate_compose_diff(
            &current,
            &staged,
            &[
                change("service", "new-api", "modify"),
                change("service", "upgrade-probe", "modify"),
            ],
        )
        .expect("already-applied declared resources are idempotent");
    }

    #[test]
    fn compose_diff_ignores_secret_value_only_changes() {
        let current = json!({"services": {"new-api": {
            "image": "same",
            "environment": {"SESSION_SECRET": "old", "MODE": "prod"}
        }}});
        let staged = json!({"services": {"new-api": {
            "image": "same",
            "environment": {"SESSION_SECRET": "new", "MODE": "prod"}
        }}});
        validate_compose_diff(&current, &staged, &[])
            .expect("secret rotation is not compose change");
    }

    #[test]
    fn compose_diff_rejects_undeclared_modification_and_removal() {
        let current = json!({
            "services": {"new-api": {"image": "old"}, "worker": {"image": "old"}}
        });
        let modified = json!({
            "services": {"new-api": {"image": "new"}, "worker": {"image": "old"}}
        });
        assert!(validate_compose_diff(&current, &modified, &[]).is_err());
        let removed = json!({"services": {"new-api": {"image": "old"}}});
        assert!(validate_compose_diff(&current, &removed, &[]).is_err());
    }

    #[test]
    fn compose_template_renders_deployment_values_without_expanding_secrets() {
        let mut document: serde_json::Value =
            serde_json::from_str(include_str!("../../upgrade-bundle/docker-compose.yml"))
                .expect("compose template");
        let replacements = std::collections::BTreeMap::from([
            ("MEOWAI_CONTAINER_NAME", "customer-api".to_owned()),
            ("MEOWAI_NEWAPI_BIND", "127.0.0.1".to_owned()),
            ("MEOWAI_KUMA_BIND", "0.0.0.0".to_owned()),
            ("MEOWAI_NEWAPI_PORT", "3100".to_owned()),
            ("MEOWAI_KUMA_PORT", "3101".to_owned()),
            (
                "MEOWAI_IMAGE_REFERENCE",
                "ghcr.io/example/newapi@sha256:target".to_owned(),
            ),
        ]);
        render_compose_value(&mut document, &replacements).expect("render template");
        let rendered = serde_json::to_string(&document).expect("serialize compose");
        assert!(!rendered.contains("${MEOWAI_"));
        assert!(rendered.contains("customer-api-postgres"));
        assert!(rendered.contains("127.0.0.1:3100:3000"));
        assert!(rendered.contains("${POSTGRES_PASSWORD}"));
        assert!(rendered.contains("${SESSION_SECRET}"));
    }

    #[test]
    fn migration_path_rejects_missing_data_migration() {
        let error =
            validate_migration_path(&state(1, 1), &manifest(1, 2, 2, &["deployment-1-to-2"]))
                .expect_err("data schema below minimum must be rejected");
        assert!(error.to_string().contains("migration steps 未覆盖"));
    }

    #[test]
    fn migration_path_accepts_noop_data_step_without_downgrading() {
        validate_migration_path(
            &state(1, 5),
            &manifest(1, 2, 4, &["data-5-to-5", "deployment-1-to-2"]),
        )
        .expect("noop data step and deployment step");
    }

    #[cfg(unix)]
    #[test]
    fn deployment_migration_runtime_accepts_future_sequential_step() {
        let root = tempfile::tempdir().expect("target directory");
        let files = root.path().join(".upgrade/op_test/files");
        std::fs::create_dir_all(&files).expect("staging directory");
        std::fs::write(files.join("docker-compose.yml"), "{}\n").expect("staged Compose file");
        std::fs::write(files.join("meowai-deploy-upgrade-agent"), "agent\n").expect("staged agent");
        let executor = TargetExecutor::new(Target::Local, root.path().to_path_buf());
        let migration_manifest = manifest(2, 3, 1, &["deployment-2-to-3"]);
        let mut migration_bundle = bundle(Vec::new());
        migration_bundle.migration_steps = vec!["deployment-2-to-3".to_owned()];

        run_migrations(
            &executor,
            ".upgrade/op_test",
            &migration_manifest,
            &migration_bundle,
        )
        .expect("future sequential deployment migration");
        assert_eq!(
            std::fs::read_to_string(root.path().join("run/migrations/deployment-2-to-3.done"))
                .expect("migration marker"),
            "deployment-2-to-3\n"
        );
    }

    #[test]
    fn bundle_requires_real_script_for_non_noop_data_migration() {
        let migration_manifest = manifest(1, 2, 2, &["deployment-1-to-2", "data-1-to-2"]);
        let mut missing = bundle(Vec::new());
        missing.migration_steps = migration_manifest.migration_plan.steps.clone();
        assert!(validate_bundle_manifest(&missing, &migration_manifest).is_err());
        let mut complete = missing;
        complete.files.extend([
            super::BundleFile {
                path: "docker-compose.yml".to_owned(),
                sha256: "b".repeat(64),
                mode: 0o644,
            },
            super::BundleFile {
                path: "meowai-deploy-upgrade-agent".to_owned(),
                sha256: "c".repeat(64),
                mode: 0o700,
            },
        ]);
        complete.files.push(super::BundleFile {
            path: "migrations/data-1-to-2.sh".to_owned(),
            sha256: "a".repeat(64),
            mode: 0o700,
        });
        validate_bundle_manifest(&complete, &migration_manifest)
            .expect("data migration script is explicitly bundled");
    }

    #[test]
    fn data_migration_requires_restore_policy_and_manual_execution() {
        let mut value = manifest(1, 2, 2, &["deployment-1-to-2", "data-1-to-2"]);
        assert!(validate_data_migration_policy(&value, false).is_err());
        value.rollback.data_rollback_required = true;
        validate_data_migration_policy(&value, false)
            .expect("manual CLI may run a restorable data migration");
        assert!(validate_data_migration_policy(&value, true).is_err());
    }

    // The production data-migration runner intentionally uses GNU timeout,
    // which is part of the Linux target contract. Keep this integration test
    // on Linux so macOS's incompatible BSD timeout is not mistaken for a
    // migration failure.
    #[cfg(target_os = "linux")]
    #[test]
    fn data_migration_runtime_writes_marker_only_after_success() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("target directory");
        let migration_dir = root.path().join(".upgrade/op_test/files/migrations");
        std::fs::create_dir_all(&migration_dir).expect("migration directory");
        let script = migration_dir.join("data-1-to-2.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf 'business-secret'\nprintf 'private-row' >&2\nexit 23\n",
        )
        .expect("failing migration");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("migration mode");
        let executor = TargetExecutor::new(Target::Local, root.path().to_path_buf());
        let mut migration_manifest = manifest(1, 2, 2, &["data-1-to-2"]);
        migration_manifest.migration_plan.from = 1;
        migration_manifest.migration_plan.to = 2;
        let mut migration_bundle = bundle(Vec::new());
        migration_bundle.migration_steps = vec!["data-1-to-2".to_owned()];

        let error = run_migrations(
            &executor,
            ".upgrade/op_test",
            &migration_manifest,
            &migration_bundle,
        )
        .expect_err("failed migration must stop");
        assert!(error.to_string().contains("退出码 23"));
        assert!(!error.to_string().contains("business-secret"));
        assert!(!error.to_string().contains("private-row"));
        let marker = root.path().join("run/migrations/data-1-to-2.done");
        assert!(!marker.exists());

        std::fs::write(&script, "#!/bin/sh\nexit 0\n").expect("successful migration");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700))
            .expect("migration mode");
        run_migrations(
            &executor,
            ".upgrade/op_test",
            &migration_manifest,
            &migration_bundle,
        )
        .expect("successful migration");
        assert_eq!(
            std::fs::read_to_string(&marker).expect("migration marker"),
            "data-1-to-2\n"
        );

        std::fs::write(&script, "#!/bin/sh\nexit 99\n").expect("would fail if rerun");
        run_migrations(
            &executor,
            ".upgrade/op_test",
            &migration_manifest,
            &migration_bundle,
        )
        .expect("completed migration must be idempotent");
    }

    #[test]
    fn archive_validation_accepts_regular_allowlisted_files() {
        let bytes = archive(&[("bundle-manifest.json", tar::EntryType::Regular, b"{}")]);
        validate_archive_bytes(&bytes).expect("regular allowlisted archive");
    }

    #[test]
    fn archive_validation_rejects_links_duplicates_traversal_and_unknown_files() {
        for bytes in [
            archive(&[("bundle-manifest.json", tar::EntryType::Symlink, b"")]),
            archive(&[("bundle-manifest.json", tar::EntryType::Link, b"")]),
            archive(&[
                ("bundle-manifest.json", tar::EntryType::Regular, b"{}"),
                ("bundle-manifest.json", tar::EntryType::Regular, b"{}"),
            ]),
            traversal_archive(),
            archive(&[("unexpected.txt", tar::EntryType::Regular, b"x")]),
        ] {
            assert!(validate_archive_bytes(&bytes).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn environment_patch_applies_all_actions_and_preserves_empty_values() {
        let root = tempfile::tempdir().expect("target directory");
        std::fs::create_dir_all(root.path().join(".upgrade/op_test/files"))
            .expect("stage directory");
        std::fs::write(
            root.path().join("secrets.env"),
            "KEEP=old\nCHANGE=old\nREMOVE=old\nEMPTY=\n",
        )
        .expect("secrets env");
        std::fs::write(
            root.path().join("downstream-credentials.env"),
            "MEOWAI_DEPLOYMENT_ID=dep\nMEOWAI_INSTALLATION_GENERATION=1\n",
        )
        .expect("downstream env");
        std::fs::write(
            root.path().join(".upgrade/op_test/files/secrets.env.patch"),
            "EMPTY=\nCHANGE=new\n",
        )
        .expect("env patch");
        let executor = TargetExecutor::new(Target::Local, root.path().to_path_buf());
        let changes = vec![
            ("EMPTY", "add"),
            ("KEEP", "preserve"),
            ("CHANGE", "replace"),
            ("REMOVE", "remove"),
        ]
        .into_iter()
        .map(|(key, action)| BundleEnvChange {
            file: "secrets.env.patch".to_owned(),
            key: key.to_owned(),
            action: action.to_owned(),
        })
        .collect();

        prepare_environment_files(
            &executor,
            ".upgrade/op_test",
            &config(root.path()),
            &registration(),
            &manifest(1, 2, 1, &["deployment-1-to-2"]),
            &bundle(changes),
        )
        .expect("apply environment actions");

        let merged =
            std::fs::read_to_string(root.path().join(".upgrade/op_test/merged-secrets.env"))
                .expect("merged secrets");
        assert!(merged.contains("KEEP=old\n"));
        assert!(merged.contains("CHANGE=new\n"));
        assert!(merged.contains("EMPTY=\n"));
        assert!(!merged.contains("REMOVE="));
        let downstream = std::fs::read_to_string(
            root.path()
                .join(".upgrade/op_test/merged-downstream-credentials.env"),
        )
        .expect("merged downstream credentials");
        assert!(downstream.contains("MEOWAI_NEWAPI_PORT=3100\n"));
        assert!(downstream.contains("MEOWAI_KUMA_PORT=3101\n"));
        assert!(downstream.contains("MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY=public-key\n"));
        assert!(downstream.contains("MEOWAI_RELEASE_ARTIFACT_ALLOWED_HOSTS=assets.example\n"));
    }

    #[cfg(unix)]
    #[test]
    fn environment_patch_rejects_duplicate_and_undeclared_keys() {
        for (current, patch) in [
            ("DUP=one\nDUP=two\n", ""),
            ("KEEP=old\n", "UNDECLARED=value\n"),
        ] {
            let root = tempfile::tempdir().expect("target directory");
            std::fs::create_dir_all(root.path().join(".upgrade/op_test/files"))
                .expect("stage directory");
            std::fs::write(root.path().join("secrets.env"), current).expect("secrets env");
            std::fs::write(
                root.path().join("downstream-credentials.env"),
                "MEOWAI_DEPLOYMENT_ID=dep\n",
            )
            .expect("downstream env");
            std::fs::write(
                root.path().join(".upgrade/op_test/files/secrets.env.patch"),
                patch,
            )
            .expect("env patch");
            let executor = TargetExecutor::new(Target::Local, root.path().to_path_buf());
            assert!(
                prepare_environment_files(
                    &executor,
                    ".upgrade/op_test",
                    &config(root.path()),
                    &registration(),
                    &manifest(1, 2, 1, &["deployment-1-to-2"]),
                    &bundle(Vec::new()),
                )
                .is_err()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn environment_patch_rejects_conflicting_existing_add_key() {
        let root = tempfile::tempdir().expect("target directory");
        std::fs::create_dir_all(root.path().join(".upgrade/op_test/files"))
            .expect("stage directory");
        std::fs::write(root.path().join("secrets.env"), "FEATURE=old\n").expect("secrets env");
        std::fs::write(
            root.path().join("downstream-credentials.env"),
            "MEOWAI_DEPLOYMENT_ID=dep\n",
        )
        .expect("downstream env");
        std::fs::write(
            root.path().join(".upgrade/op_test/files/secrets.env.patch"),
            "FEATURE=new\n",
        )
        .expect("env patch");
        let executor = TargetExecutor::new(Target::Local, root.path().to_path_buf());
        let changes = vec![BundleEnvChange {
            file: "secrets.env.patch".to_owned(),
            key: "FEATURE".to_owned(),
            action: "add".to_owned(),
        }];
        assert!(
            prepare_environment_files(
                &executor,
                ".upgrade/op_test",
                &config(root.path()),
                &registration(),
                &manifest(1, 2, 1, &["deployment-1-to-2"]),
                &bundle(changes),
            )
            .is_err()
        );
    }

    #[test]
    fn bundle_manifest_rejects_agent_managed_environment_keys() {
        let mut candidate = bundle(vec![BundleEnvChange {
            file: "downstream-credentials.env.patch".to_owned(),
            key: "MEOWAI_DATA_SCHEMA".to_owned(),
            action: "replace".to_owned(),
        }]);
        candidate.files = [
            ("docker-compose.yml", 0o644),
            ("docker-compose.updater.yml", 0o644),
            ("meowai-deploy-upgrade-agent", 0o700),
        ]
        .into_iter()
        .map(|(path, mode)| super::BundleFile {
            path: path.to_owned(),
            sha256: "a".repeat(64),
            mode,
        })
        .collect();
        assert!(
            validate_bundle_manifest(&candidate, &manifest(1, 2, 1, &["deployment-1-to-2"]))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn upgrade_lock_rejects_active_owner_and_reclaims_expired_owner() {
        let root = tempfile::tempdir().expect("target directory");
        let executor = TargetExecutor::new(Target::Local, root.path().to_path_buf());
        let first = TargetUpgradeLock::acquire(&executor).expect("first lock");
        assert!(TargetUpgradeLock::acquire(&executor).is_err());
        drop(first);
        let second = TargetUpgradeLock::acquire(&executor).expect("lock after release");
        drop(second);

        std::fs::create_dir(root.path().join(".meowai-upgrade.lock")).expect("stale lock");
        std::fs::write(
            root.path().join(".meowai-upgrade.lock/owner"),
            "orphan\n1\n",
        )
        .expect("stale owner");
        let reclaimed = TargetUpgradeLock::acquire(&executor).expect("reclaim stale lock");
        drop(reclaimed);
        assert!(!root.path().join(".meowai-upgrade.lock").exists());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "upgrade_agent_e2e.rs"]
mod e2e_tests;
