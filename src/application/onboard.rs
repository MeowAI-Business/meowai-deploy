use std::{future::Future, pin::Pin};

use secrecy::SecretString;
use std::collections::BTreeSet;

use super::{
    error::{ApplicationError, ApplicationResult, ErrorCategory, app_error, source_error},
    input::DeploymentInput,
    operation::{
        CancellationToken, EventSink, OperationCheckpoint, OperationKind, OperationStage,
        OperationTracker, OperationTransitionError,
    },
    plan::{CancellationPolicy, DeploymentPlan, build_onboard_plan},
    source::{persist_source_session, read_source_resources},
    target::{DeploymentTargetProbeRequest, probe_deployment_target},
};

use crate::{
    config::DeploymentConfig,
    error::AppError,
    pricing::PricingConfig,
    source::{GroupCatalog, SourceClient, SourceIdentity, StatusKeyProvision, TokenSync},
    source_key_store,
    state::DeploymentState,
    storage::{self, OPERATION_FILE, STATE_FILE},
    target::newapi::NewApiClient,
    target::{compose::DeploymentRuntime, kuma},
};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StageOutput {
    pub message: String,
    pub progress: Option<(u64, u64)>,
    pub credential_kinds: Vec<String>,
}

#[derive(Debug)]
pub struct AdministratorCredential {
    pub kind: String,
    pub username: String,
    pub password: SecretString,
}

#[derive(Debug)]
pub struct OnboardOutcome {
    pub operation_id: String,
    pub checkpoint: OperationCheckpoint,
    pub credentials: Vec<AdministratorCredential>,
}

pub trait OnboardBackend: Send {
    fn prepare_resume<'a>(
        &'a mut self,
        _completed_stages: &'a BTreeSet<OperationStage>,
    ) -> BoxFuture<'a, ApplicationResult<()>> {
        Box::pin(async { Ok(()) })
    }

    fn run_stage<'a>(
        &'a mut self,
        stage: OperationStage,
        input: &'a DeploymentInput,
        cancellation: &'a CancellationToken,
        progress: &'a mut (dyn FnMut(&str) + Send),
    ) -> BoxFuture<'a, ApplicationResult<StageOutput>>;

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, ApplicationResult<Vec<AdministratorCredential>>>;
}

pub trait CheckpointStore: Send {
    fn save(&mut self, checkpoint: &OperationCheckpoint) -> ApplicationResult<()>;
}

#[derive(Clone, Default)]
pub struct OperationControl {
    cancellation: CancellationToken,
}

impl OperationControl {
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    pub fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

pub async fn start_onboard<B, S, P>(
    backend: &mut B,
    input: &DeploymentInput,
    operation_id: impl Into<String>,
    sink: S,
    store: &mut P,
) -> ApplicationResult<OnboardOutcome>
where
    B: OnboardBackend,
    S: EventSink,
    P: CheckpointStore,
{
    let control = OperationControl::default();
    start_onboard_with_control(backend, input, operation_id, sink, store, &control).await
}

pub async fn start_onboard_with_control<B, S, P>(
    backend: &mut B,
    input: &DeploymentInput,
    operation_id: impl Into<String>,
    sink: S,
    store: &mut P,
    control: &OperationControl,
) -> ApplicationResult<OnboardOutcome>
where
    B: OnboardBackend,
    S: EventSink,
    P: CheckpointStore,
{
    let plan = build_onboard_plan(input, operation_id.into()).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Validation,
            error.code.as_str(),
            error.message,
            error.retryable,
        )
        .with_field(error.field)
    })?;
    let mut tracker = OperationTracker::with_cancellation(
        plan.deployment_id.clone(),
        OperationKind::Onboard,
        sink,
        control.cancellation.clone(),
    );
    tracker.start("开始执行部署").map_err(operation_error)?;
    store_tracker(store, &tracker)?;
    execute_plan(backend, input, plan, &mut tracker, store).await
}

pub async fn resume_onboard<B, S, P>(
    backend: &mut B,
    input: &DeploymentInput,
    checkpoint: OperationCheckpoint,
    sink: S,
    store: &mut P,
) -> ApplicationResult<OnboardOutcome>
where
    B: OnboardBackend,
    S: EventSink,
    P: CheckpointStore,
{
    let control = OperationControl::default();
    resume_onboard_with_control(backend, input, checkpoint, sink, store, &control).await
}

pub async fn resume_onboard_with_control<B, S, P>(
    backend: &mut B,
    input: &DeploymentInput,
    mut checkpoint: OperationCheckpoint,
    sink: S,
    store: &mut P,
    control: &OperationControl,
) -> ApplicationResult<OnboardOutcome>
where
    B: OnboardBackend,
    S: EventSink,
    P: CheckpointStore,
{
    if checkpoint.kind != OperationKind::Onboard {
        return Err(ApplicationError::new(
            ErrorCategory::Conflict,
            "OPERATION_KIND_MISMATCH",
            "当前检查点不是部署操作，无法恢复",
            false,
        ));
    }
    let plan = build_onboard_plan(input, checkpoint.operation_id.clone()).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Validation,
            error.code.as_str(),
            error.message,
            error.retryable,
        )
        .with_field(error.field)
    })?;
    if checkpoint.status == super::operation::OperationStatus::Running {
        let interrupted_stage = checkpoint.current_stage.or_else(|| {
            plan.stages
                .iter()
                .map(|stage| stage.stage)
                .find(|stage| !checkpoint.completed_stages.contains(stage))
        });
        let interrupted_stage = interrupted_stage.ok_or_else(|| {
            ApplicationError::new(
                ErrorCategory::Conflict,
                "INTERRUPTED_STAGE_UNKNOWN",
                "无法确定上次部署中断的阶段",
                false,
            )
        })?;
        checkpoint
            .fail(
                interrupted_stage,
                "OPERATION_INTERRUPTED",
                "部署进程在该阶段中断，可从检查点继续",
                true,
            )
            .map_err(operation_error)?;
    }
    backend.prepare_resume(&checkpoint.completed_stages).await?;
    let mut tracker = OperationTracker::from_checkpoint_with_cancellation(
        checkpoint,
        sink,
        control.cancellation.clone(),
    );
    tracker.resume().map_err(operation_error)?;
    store_tracker(store, &tracker)?;
    execute_plan(backend, input, plan, &mut tracker, store).await
}

pub fn cancel_operation(control: &OperationControl) {
    control.cancel();
}

async fn execute_plan<B, S, P>(
    backend: &mut B,
    input: &DeploymentInput,
    plan: DeploymentPlan,
    tracker: &mut OperationTracker<S>,
    store: &mut P,
) -> ApplicationResult<OnboardOutcome>
where
    B: OnboardBackend,
    S: EventSink,
    P: CheckpointStore,
{
    for planned in plan.stages {
        if tracker
            .checkpoint()
            .completed_stages
            .contains(&planned.stage)
        {
            continue;
        }
        if let Err(error) = tracker.start_stage(planned.stage, stage_message(planned.stage)) {
            let error = operation_error(error);
            if error.category == ErrorCategory::Cancelled {
                tracker.cancel("已取消部署").map_err(operation_error)?;
                store_tracker(store, tracker)?;
            }
            return Err(error);
        }
        store_tracker(store, tracker)?;

        let cancellation = tracker.cancellation_token();
        let mut report_progress = |message: &str| tracker.message(planned.stage, message);
        let result = match planned.cancellation {
            CancellationPolicy::Immediate => {
                tokio::select! {
                    result = backend.run_stage(
                        planned.stage,
                        input,
                        &cancellation,
                        &mut report_progress,
                    ) => result,
                    _ = cancellation.cancelled() => Err(ApplicationError::new(
                        ErrorCategory::Cancelled,
                        "OPERATION_CANCELLED",
                        "操作已取消",
                        false,
                    )),
                }
            }
            CancellationPolicy::SafePoint | CancellationPolicy::NotInterruptible => {
                backend
                    .run_stage(planned.stage, input, &cancellation, &mut report_progress)
                    .await
            }
        };
        match result {
            Ok(output) => {
                if let Some((completed, total)) = output.progress {
                    tracker.progress(planned.stage, completed, total);
                }
                for kind in output.credential_kinds {
                    tracker.credential_generated(planned.stage, kind);
                }
                tracker
                    .complete_stage(planned.stage, output.message)
                    .map_err(operation_error)?;
                store_tracker(store, tracker)?;
                if cancellation.is_cancelled() {
                    tracker.cancel("已取消部署").map_err(operation_error)?;
                    store_tracker(store, tracker)?;
                    return Err(ApplicationError::new(
                        ErrorCategory::Cancelled,
                        "OPERATION_CANCELLED",
                        "操作已取消",
                        false,
                    ));
                }
            }
            Err(error) => {
                if error.category == ErrorCategory::Cancelled {
                    let _ = tracker.cancel("已取消部署");
                } else {
                    let _ = tracker.fail_current_error(&error);
                }
                store_tracker(store, tracker)?;
                return Err(error);
            }
        }
    }

    let credentials = backend.finish().await?;
    tracker.complete("部署已完成").map_err(operation_error)?;
    store_tracker(store, tracker)?;
    Ok(OnboardOutcome {
        operation_id: tracker.checkpoint().operation_id.clone(),
        checkpoint: tracker.checkpoint_owned(),
        credentials,
    })
}

fn store_tracker<P: CheckpointStore, S: EventSink>(
    store: &mut P,
    tracker: &OperationTracker<S>,
) -> ApplicationResult<()> {
    store.save(tracker.checkpoint())
}

fn operation_error(error: OperationTransitionError) -> ApplicationError {
    if matches!(error, OperationTransitionError::Cancelled) {
        ApplicationError::new(
            ErrorCategory::Cancelled,
            "OPERATION_CANCELLED",
            "操作已取消",
            false,
        )
    } else {
        ApplicationError::new(
            ErrorCategory::Conflict,
            "OPERATION_STATE_INVALID",
            error.to_string(),
            false,
        )
    }
}

fn stage_message(stage: OperationStage) -> &'static str {
    match stage {
        OperationStage::InputValidation => "校验部署输入",
        OperationStage::SourceConnectivity => "检查源站连接",
        OperationStage::SourceAuthentication => "验证源站账号",
        OperationStage::SourceApproval => "检查源站批准状态",
        OperationStage::TargetValidation => "检查下游目标",
        OperationStage::SourceResources => "准备源站资源",
        OperationStage::BaseServices => "启动基础服务",
        OperationStage::DownstreamInitialization => "初始化下游站点",
        OperationStage::PricingImport => "同步价格配置",
        OperationStage::ChannelSynchronization => "同步渠道",
        OperationStage::KumaSynchronization => "同步状态页",
        OperationStage::FinalVerification => "执行最终校验",
        OperationStage::Cleanup => "清理部署资源",
        OperationStage::Rollback => "回滚部署",
    }
}

pub struct DeploymentStateCheckpointStore;

impl CheckpointStore for DeploymentStateCheckpointStore {
    fn save(&mut self, checkpoint: &OperationCheckpoint) -> ApplicationResult<()> {
        let checkpoint_content = serde_json::to_vec_pretty(checkpoint).map_err(|error| {
            ApplicationError::new(
                ErrorCategory::Persistence,
                "CHECKPOINT_SERIALIZE_FAILED",
                "无法保存部署检查点",
                true,
            )
            .with_diagnostic(error.to_string())
        })?;
        storage::write(OPERATION_FILE, &checkpoint_content).map_err(persistence_error)?;
        let Some(content) = storage::read(STATE_FILE).map_err(persistence_error)? else {
            return Ok(());
        };
        let mut state: DeploymentState = serde_json::from_slice(&content).map_err(|error| {
            ApplicationError::new(
                ErrorCategory::Persistence,
                "CHECKPOINT_STATE_INVALID",
                "无法读取已保存的部署状态",
                false,
            )
            .with_diagnostic(error.to_string())
        })?;
        state.operation = Some(checkpoint.clone());
        let content = serde_json::to_vec_pretty(&state).map_err(|error| {
            ApplicationError::new(
                ErrorCategory::Persistence,
                "CHECKPOINT_SERIALIZE_FAILED",
                "无法保存部署检查点",
                true,
            )
            .with_diagnostic(error.to_string())
        })?;
        storage::write(STATE_FILE, &content).map_err(persistence_error)
    }
}

pub struct ProductionOnboardBackend {
    config: DeploymentConfig,
    source: SourceClient,
    identity: SourceIdentity,
    catalog: Option<GroupCatalog>,
    pricing: Option<PricingConfig>,
    token_sync: Option<TokenSync>,
    status_key: Option<StatusKeyProvision>,
    shared_status_key: Option<SecretString>,
    deployment: Option<DeploymentRuntime>,
    downstream: Option<NewApiClient>,
    credentials: Vec<AdministratorCredential>,
    allow_status_key_rotation: bool,
    ssh_password: Option<SecretString>,
}

impl ProductionOnboardBackend {
    pub fn new(config: DeploymentConfig, source: SourceClient, identity: SourceIdentity) -> Self {
        Self {
            config,
            source,
            identity,
            catalog: None,
            pricing: None,
            token_sync: None,
            status_key: None,
            shared_status_key: None,
            deployment: None,
            downstream: None,
            credentials: Vec::new(),
            allow_status_key_rotation: false,
            ssh_password: None,
        }
    }

    pub fn with_ssh_password(mut self, password: Option<SecretString>) -> Self {
        self.ssh_password = password;
        self
    }

    pub fn allow_status_key_rotation(&mut self) {
        self.allow_status_key_rotation = true;
    }

    fn deployment(&self) -> ApplicationResult<&DeploymentRuntime> {
        self.deployment.as_ref().ok_or_else(|| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "DEPLOYMENT_RUNTIME_MISSING",
                "部署运行时尚未准备完成",
                false,
            )
        })
    }

    fn deployment_mut(&mut self) -> ApplicationResult<&mut DeploymentRuntime> {
        self.deployment.as_mut().ok_or_else(|| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "DEPLOYMENT_RUNTIME_MISSING",
                "部署运行时尚未准备完成",
                false,
            )
        })
    }

    fn downstream(&self) -> ApplicationResult<&NewApiClient> {
        self.downstream.as_ref().ok_or_else(|| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "DOWNSTREAM_CLIENT_MISSING",
                "下游连接尚未准备完成",
                false,
            )
        })
    }

    async fn prepare_source_resources(
        &mut self,
        cancellation: &CancellationToken,
    ) -> ApplicationResult<StageOutput> {
        source_key_store::ensure_writable().map_err(app_error)?;
        let resources = read_source_resources(&mut self.source, cancellation).await?;
        let catalog = resources.catalog;
        let pricing = resources.pricing;
        let token_sync = resources.token_sync;
        let mut status_key = self
            .source
            .ensure_onboard_status_key()
            .await
            .map_err(source_error)?;
        let mut shared_status_key = if let Some(key) = status_key.key() {
            source_key_store::save(
                &self.config.source_url,
                self.identity.user_id,
                status_key.metadata.id,
                key,
            )
            .map_err(app_error)?;
            Some(key.clone())
        } else {
            source_key_store::load(
                &self.config.source_url,
                self.identity.user_id,
                status_key.metadata.id,
            )
            .map_err(app_error)?
        };

        if shared_status_key.is_none() && self.allow_status_key_rotation {
            self.source
                .revoke_onboard_status_key()
                .await
                .map_err(source_error)?;
            source_key_store::remove(&self.config.source_url, self.identity.user_id)
                .map_err(app_error)?;
            status_key = self
                .source
                .ensure_onboard_status_key()
                .await
                .map_err(source_error)?;
            let key = status_key.key().cloned().ok_or_else(|| {
                ApplicationError::new(
                    ErrorCategory::Source,
                    "STATUS_KEY_ROTATION_FAILED",
                    "源站生成新公共状态密钥后没有返回密钥内容",
                    true,
                )
            })?;
            source_key_store::save(
                &self.config.source_url,
                self.identity.user_id,
                status_key.metadata.id,
                &key,
            )
            .map_err(app_error)?;
            shared_status_key = Some(key);
            self.allow_status_key_rotation = false;
        }

        if shared_status_key.is_none() {
            return Err(ApplicationError::new(
                ErrorCategory::Conflict,
                "STATUS_KEY_CONTENT_UNAVAILABLE",
                "源站公共状态密钥已存在，但当前控制端没有保存密钥内容",
                true,
            ));
        }

        let deployment = DeploymentRuntime::prepare_with_ssh_password(
            &self.config,
            self.identity.user_id,
            &catalog.response_sha256,
            status_key.metadata.id,
            shared_status_key.as_ref(),
            self.ssh_password.clone(),
        )
        .map_err(app_error)?;
        source_key_store::save(
            &self.config.source_url,
            self.identity.user_id,
            status_key.metadata.id,
            &deployment.secrets.public_status_source_key,
        )
        .map_err(app_error)?;
        persist_source_session(&self.source)?;

        let message = format!(
            "源站资源已就绪：{} 个分组，Token 新建 {}、复用 {}、修正 {}",
            catalog.groups.len(),
            token_sync.created,
            token_sync.reused,
            token_sync.updated
        );
        self.catalog = Some(catalog);
        self.pricing = Some(pricing);
        self.token_sync = Some(token_sync);
        self.status_key = Some(status_key);
        self.shared_status_key = shared_status_key;
        self.deployment = Some(deployment);
        Ok(StageOutput {
            message,
            progress: None,
            credential_kinds: Vec::new(),
        })
    }

    async fn initialize_downstream(&mut self) -> ApplicationResult<StageOutput> {
        let config = self.config.clone();
        let deployment = self.deployment()?;
        let mut downstream =
            NewApiClient::connect(&deployment.executor, deployment.state.newapi_port)
                .map_err(app_error)?;
        downstream
            .initialize_and_login(&config, &deployment.secrets.newapi_admin_password)
            .await
            .map_err(app_error)?;
        downstream
            .configure_site(&config.website_name)
            .await
            .map_err(app_error)?;
        let mut credential_kinds = Vec::new();
        if deployment.credentials_should_display {
            self.credentials = vec![
                AdministratorCredential {
                    kind: "newapi_admin".to_owned(),
                    username: config.newapi_admin_username.clone(),
                    password: deployment.secrets.newapi_admin_password.clone(),
                },
                AdministratorCredential {
                    kind: "kuma_admin".to_owned(),
                    username: config.kuma_admin_username.clone(),
                    password: deployment.secrets.kuma_admin_password.clone(),
                },
            ];
            credential_kinds.extend(["newapi_admin".to_owned(), "kuma_admin".to_owned()]);
        }
        self.downstream = Some(downstream);
        Ok(StageOutput {
            message: "下游管理员和站点配置已就绪".to_owned(),
            progress: None,
            credential_kinds,
        })
    }

    async fn import_pricing(&mut self) -> ApplicationResult<StageOutput> {
        let pricing = self
            .pricing
            .as_ref()
            .ok_or_else(|| missing_stage("源站价格配置"))?;
        let pricing_hashes = self
            .downstream()?
            .import_pricing(pricing)
            .await
            .map_err(app_error)?;
        let deployment = self.deployment_mut()?;
        deployment.state.pricing_sha256 = pricing_hashes;
        deployment.state.mark_phase(
            "pricing",
            "DONE",
            "价格表、Seedance 和市场配置已写入并回读一致",
        );
        deployment.persist_state().map_err(app_error)?;
        Ok(StageOutput {
            message: "价格表和市场配置已同步".to_owned(),
            progress: None,
            credential_kinds: Vec::new(),
        })
    }

    async fn synchronize_channels(&mut self) -> ApplicationResult<StageOutput> {
        let config = self.config.clone();
        let catalog = self
            .catalog
            .as_ref()
            .ok_or_else(|| missing_stage("源站分组"))?;
        let token_sync = self
            .token_sync
            .as_ref()
            .ok_or_else(|| missing_stage("源站 Token"))?;
        let deployment = self.deployment()?;
        let (result, channels) = self
            .downstream()?
            .sync_channels(
                &config,
                &deployment.container_source_url,
                catalog,
                &token_sync.bindings,
                &deployment.state.channels,
                true,
            )
            .await
            .map_err(app_error)?;
        let deployment = self.deployment_mut()?;
        deployment.state.channels = channels;
        deployment.state.mark_phase(
            "channels",
            "DONE",
            format!(
                "渠道新建 {}，复用 {}，更新 {}",
                result.created, result.reused, result.updated
            ),
        );
        deployment.persist_state().map_err(app_error)?;
        Ok(StageOutput {
            message: format!(
                "下游渠道已同步：新建 {}，复用 {}，更新 {}",
                result.created, result.reused, result.updated
            ),
            progress: None,
            credential_kinds: Vec::new(),
        })
    }

    async fn synchronize_kuma(
        &mut self,
        progress: &mut (dyn FnMut(&str) + Send),
    ) -> ApplicationResult<StageOutput> {
        let config = self.config.clone();
        self.deployment_mut()?
            .deploy_kuma(&config, |message| {
                progress(message);
                tracing::info!(stage = "kuma_synchronization", %message, "deployment progress");
            })
            .map_err(app_error)?;
        let deployment = self.deployment()?;
        let manifest = self
            .source
            .onboard_status_manifest(&deployment.secrets.public_status_source_key)
            .await
            .map_err(source_error)?;
        let deployment_id = config.deployment_id();
        let result = kuma::sync_status_page(kuma::KumaSyncOptions {
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
        })
        .map_err(app_error)?;
        let public_status_url = kuma::internal_status_page_url(&result.page_slug);
        self.downstream()?
            .configure_public_status_url(&public_status_url)
            .await
            .map_err(app_error)?;
        let deployment = self.deployment_mut()?;
        deployment.state.manifest_sha256 = result.manifest_sha256;
        deployment.state.kuma_monitors = result.monitors;
        deployment.state.mark_phase(
            "kuma",
            "DONE",
            format!("status page {} synchronized", result.page_slug),
        );
        deployment.persist_state().map_err(app_error)?;
        Ok(StageOutput {
            message: format!(
                "公共状态已同步：{} 个监控",
                deployment.state.kuma_monitors.len()
            ),
            progress: None,
            credential_kinds: Vec::new(),
        })
    }

    fn complete_deployment(&mut self) -> ApplicationResult<StageOutput> {
        let deployment = self.deployment_mut()?;
        deployment.state.last_sync_at = crate::state::unix_timestamp();
        deployment.state.last_sync_success = true;
        deployment.state.mark_phase(
            "onboard",
            "DONE",
            "base services, pricing, channels and public status initialized",
        );
        deployment.persist_state().map_err(app_error)?;
        persist_source_session(&self.source)?;
        Ok(StageOutput {
            message: "最终部署状态已保存".to_owned(),
            progress: None,
            credential_kinds: Vec::new(),
        })
    }
}

impl OnboardBackend for ProductionOnboardBackend {
    fn prepare_resume<'a>(
        &'a mut self,
        completed_stages: &'a BTreeSet<OperationStage>,
    ) -> BoxFuture<'a, ApplicationResult<()>> {
        Box::pin(async move {
            if completed_stages.contains(&OperationStage::SourceResources) {
                self.prepare_source_resources(&CancellationToken::default())
                    .await?;
            }
            if completed_stages.contains(&OperationStage::DownstreamInitialization) {
                self.initialize_downstream().await?;
            }
            Ok(())
        })
    }

    fn run_stage<'a>(
        &'a mut self,
        stage: OperationStage,
        input: &'a DeploymentInput,
        cancellation: &'a CancellationToken,
        progress: &'a mut (dyn FnMut(&str) + Send),
    ) -> BoxFuture<'a, ApplicationResult<StageOutput>> {
        Box::pin(async move {
            match stage {
                OperationStage::InputValidation => {
                    input.validate().map_err(|error| {
                        ApplicationError::new(
                            ErrorCategory::Validation,
                            error.code.as_str(),
                            error.message,
                            error.retryable,
                        )
                        .with_field(error.field)
                    })?;
                    Ok(completed("部署输入有效"))
                }
                OperationStage::SourceConnectivity => {
                    self.source
                        .check_connectivity()
                        .await
                        .map_err(source_error)?;
                    Ok(completed("源站连接正常"))
                }
                OperationStage::SourceAuthentication => {
                    self.source.validate_session().await.map_err(source_error)?;
                    Ok(completed("源站账号已验证"))
                }
                OperationStage::SourceApproval => {
                    self.source
                        .check_onboard_access()
                        .await
                        .map_err(source_error)?;
                    Ok(completed("源站账号已获部署批准"))
                }
                OperationStage::TargetValidation => {
                    let probe = probe_deployment_target(
                        DeploymentTargetProbeRequest {
                            target: input.target.clone(),
                            directory: input.directory.clone(),
                            newapi_port: input.newapi_port,
                            kuma_port: input.kuma_port,
                            ssh_password: self.ssh_password.clone(),
                        },
                        cancellation,
                    )?;
                    Ok(completed(format!(
                        "目标权限、目录和端口检查通过：New API {}，Uptime Kuma {}",
                        probe.newapi_port, probe.kuma_port
                    )))
                }
                OperationStage::SourceResources => {
                    self.prepare_source_resources(cancellation).await
                }
                OperationStage::BaseServices => {
                    let config = self.config.clone();
                    self.deployment_mut()?
                        .deploy_base_stack(&config, |message| {
                            progress(message);
                            tracing::info!(stage = "base_services", %message, "deployment progress");
                        })
                        .map_err(app_error)?;
                    Ok(completed("New API、PostgreSQL 和 Redis 已就绪"))
                }
                OperationStage::DownstreamInitialization => self.initialize_downstream().await,
                OperationStage::PricingImport => self.import_pricing().await,
                OperationStage::ChannelSynchronization => self.synchronize_channels().await,
                OperationStage::KumaSynchronization => self.synchronize_kuma(progress).await,
                OperationStage::FinalVerification => self.complete_deployment(),
                OperationStage::Cleanup | OperationStage::Rollback => Err(ApplicationError::new(
                    ErrorCategory::Conflict,
                    "UNEXPECTED_ONBOARD_STAGE",
                    "部署计划包含不支持的阶段",
                    false,
                )),
            }
        })
    }

    fn finish<'a>(&'a mut self) -> BoxFuture<'a, ApplicationResult<Vec<AdministratorCredential>>> {
        Box::pin(async move { Ok(std::mem::take(&mut self.credentials)) })
    }
}

fn completed(message: impl Into<String>) -> StageOutput {
    StageOutput {
        message: message.into(),
        progress: None,
        credential_kinds: Vec::new(),
    }
}

fn missing_stage(name: &str) -> ApplicationError {
    ApplicationError::new(
        ErrorCategory::Internal,
        "ONBOARD_STAGE_DATA_MISSING",
        format!("恢复部署时缺少{name}"),
        false,
    )
}

fn persistence_error(error: AppError) -> ApplicationError {
    ApplicationError::new(
        ErrorCategory::Persistence,
        "CHECKPOINT_WRITE_FAILED",
        "无法保存部署检查点",
        true,
    )
    .with_diagnostic(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::application::operation::CollectedEventSink;

    #[derive(Default)]
    struct MemoryStore {
        checkpoints: Vec<OperationCheckpoint>,
    }

    impl CheckpointStore for MemoryStore {
        fn save(&mut self, checkpoint: &OperationCheckpoint) -> ApplicationResult<()> {
            self.checkpoints.push(checkpoint.clone());
            Ok(())
        }
    }

    struct MockBackend {
        calls: Vec<OperationStage>,
        failures: Arc<Mutex<usize>>,
    }

    struct CancellingBackend {
        control: OperationControl,
    }

    impl OnboardBackend for CancellingBackend {
        fn run_stage<'a>(
            &'a mut self,
            stage: OperationStage,
            _input: &'a DeploymentInput,
            _cancellation: &'a CancellationToken,
            _progress: &'a mut (dyn FnMut(&str) + Send),
        ) -> BoxFuture<'a, ApplicationResult<StageOutput>> {
            Box::pin(async move {
                if stage == OperationStage::InputValidation {
                    cancel_operation(&self.control);
                }
                Ok(completed("阶段已到达安全点"))
            })
        }

        fn finish<'a>(
            &'a mut self,
        ) -> BoxFuture<'a, ApplicationResult<Vec<AdministratorCredential>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl OnboardBackend for MockBackend {
        fn run_stage<'a>(
            &'a mut self,
            stage: OperationStage,
            _input: &'a DeploymentInput,
            _cancellation: &'a CancellationToken,
            progress: &'a mut (dyn FnMut(&str) + Send),
        ) -> BoxFuture<'a, ApplicationResult<StageOutput>> {
            Box::pin(async move {
                self.calls.push(stage);
                if stage == OperationStage::BaseServices {
                    progress("正在等待容器健康检查");
                }
                let mut failures = self.failures.lock().expect("failure counter");
                if stage == OperationStage::TargetValidation && *failures > 0 {
                    *failures -= 1;
                    return Err(ApplicationError::new(
                        ErrorCategory::Target,
                        "TARGET_UNAVAILABLE",
                        "下游目标暂时不可用",
                        true,
                    ));
                }
                Ok(StageOutput {
                    message: format!("{stage:?} 已完成"),
                    progress: None,
                    credential_kinds: if stage == OperationStage::DownstreamInitialization {
                        vec!["newapi_admin".to_owned(), "kuma_admin".to_owned()]
                    } else {
                        Vec::new()
                    },
                })
            })
        }

        fn finish<'a>(
            &'a mut self,
        ) -> BoxFuture<'a, ApplicationResult<Vec<AdministratorCredential>>> {
            Box::pin(async {
                Ok(vec![AdministratorCredential {
                    kind: "newapi_admin".to_owned(),
                    username: "admin".to_owned(),
                    password: SecretString::from("generated-only-in-result"),
                }])
            })
        }
    }

    #[tokio::test]
    async fn mock_backend_completes_without_terminal_or_remote_services() {
        let input = DeploymentInput {
            image_ref: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            ..DeploymentInput::default()
        };
        let sink = CollectedEventSink::default();
        let mut store = MemoryStore::default();
        let mut backend = MockBackend {
            calls: Vec::new(),
            failures: Arc::new(Mutex::new(0)),
        };
        let outcome = start_onboard(
            &mut backend,
            &input,
            "operation-mock",
            sink.clone(),
            &mut store,
        )
        .await
        .expect("mock onboard");
        assert_eq!(
            outcome.checkpoint.status,
            super::super::operation::OperationStatus::Completed
        );
        assert_eq!(backend.calls.len(), 12);
        assert!(store.checkpoints.iter().any(|checkpoint| {
            checkpoint.status == super::super::operation::OperationStatus::Completed
        }));
        let events = sink.events();
        assert!(
            events
                .windows(2)
                .all(|pair| pair[0].sequence < pair[1].sequence)
        );
        assert!(
            !events
                .iter()
                .any(|event| event.message.contains("generated-only"))
        );
        assert!(events.iter().any(|event| {
            event.stage == Some(OperationStage::BaseServices)
                && event.kind == super::super::operation::OperationEventKind::Message
                && event.message == "正在等待容器健康检查"
        }));
        assert!(!format!("{:?}", outcome.credentials[0]).contains("generated-only-in-result"));
    }

    #[tokio::test]
    async fn retry_resumes_from_failed_stage_and_preserves_checkpoint() {
        let input = DeploymentInput {
            image_ref: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            ..DeploymentInput::default()
        };
        let sink = CollectedEventSink::default();
        let mut store = MemoryStore::default();
        let failures = Arc::new(Mutex::new(1));
        let mut backend = MockBackend {
            calls: Vec::new(),
            failures: failures.clone(),
        };
        let first = start_onboard(
            &mut backend,
            &input,
            "operation-retry",
            sink.clone(),
            &mut store,
        )
        .await;
        let checkpoint = store
            .checkpoints
            .iter()
            .find(|checkpoint| {
                checkpoint.status == super::super::operation::OperationStatus::Failed
            })
            .cloned()
            .expect("failed checkpoint");
        assert!(first.is_err());
        let outcome = resume_onboard(&mut backend, &input, checkpoint, sink, &mut store)
            .await
            .expect("resumed onboard");
        assert_eq!(
            outcome.checkpoint.status,
            super::super::operation::OperationStatus::Completed
        );
        assert_eq!(
            backend
                .calls
                .iter()
                .filter(|stage| **stage == OperationStage::InputValidation)
                .count(),
            1
        );
        assert_eq!(
            backend
                .calls
                .iter()
                .filter(|stage| **stage == OperationStage::TargetValidation)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn cancellation_stops_at_the_next_safe_point_and_is_persisted() {
        let input = DeploymentInput {
            image_ref: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            ..DeploymentInput::default()
        };
        let control = OperationControl::default();
        let mut backend = CancellingBackend {
            control: control.clone(),
        };
        let sink = CollectedEventSink::default();
        let mut store = MemoryStore::default();
        let error = start_onboard_with_control(
            &mut backend,
            &input,
            "operation-cancel",
            sink.clone(),
            &mut store,
            &control,
        )
        .await
        .expect_err("cancelled onboard");
        assert_eq!(error.category, ErrorCategory::Cancelled);
        assert!(store.checkpoints.iter().any(|checkpoint| {
            checkpoint.status == super::super::operation::OperationStatus::Cancelled
        }));
        assert!(sink.events().iter().any(|event| {
            matches!(
                event.kind,
                super::super::operation::OperationEventKind::OperationCancelled
            )
        }));
    }
}
