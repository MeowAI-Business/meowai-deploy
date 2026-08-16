use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    fs::{self, File, OpenOptions},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, header},
    middleware::{self, Next},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use fs2::FileExt;
use futures_util::StreamExt;
use include_dir::{Dir, include_dir};
use rand::{Rng, distributions::Alphanumeric};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    net::TcpListener,
    sync::{Notify, broadcast},
};
use tokio_stream::wrappers::BroadcastStream;

use crate::{
    application::{
        error::{ApplicationError, ErrorCategory},
        input::{
            DEFAULT_CONTAINER_NAME, DEFAULT_DIRECTORY, DEFAULT_IMAGE, DEFAULT_KUMA_PORT,
            DEFAULT_NEWAPI_PORT, DEFAULT_SOURCE_URL, DEFAULT_WEBSITE_NAME, DeploymentTargetInput,
        },
        manage::{
            SyncDeploymentRequest, clean_deployment, read_deployment_status, rollback_deployment,
            rollback_deployment_with_ssh_password, sync_deployment_with_progress,
        },
        onboard::{
            CheckpointStore, DeploymentStateCheckpointStore, OperationControl,
            ProductionOnboardBackend, resume_onboard_with_control, start_onboard_with_control,
        },
        operation::{
            CancellationToken, EventSeverity, EventSink, OperationCheckpoint, OperationEvent,
            OperationEventKind, OperationFailure, OperationKind, OperationStage, OperationStatus,
        },
        source::{
            SourceAccountRequest, login_source_account, probe_source_url, register_source_account,
        },
        target::{
            DeploymentTargetProbeRequest, ImageResolutionRequest, RemotePortRequest,
            check_remote_port, probe_deployment_connection, probe_deployment_target,
            resolve_latest_image, validate_remote_directory,
        },
    },
    cli::WebArgs,
    commands::{
        load_deployment_config, persist_deployment_config, persist_source_session,
        source_for_operation,
    },
    config::{DeploymentConfig, Target},
    error::{AppError, Result as AppResult},
    platform,
    source::{SourceAccountMode, SourceClient, SourceError, SourceIdentity},
    state::unix_timestamp,
    storage,
    target::ssh::{ProgramStatus, discover_openssh},
};

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/webui/dist");
const SESSION_COOKIE: &str = "meowai_session";
const BOOTSTRAP_TTL: Duration = Duration::from_secs(2 * 60);
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);
const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(30 * 60);
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const SOURCE_CHECK_LIMIT: usize = 30;
const SOURCE_ACCOUNT_LIMIT: usize = 10;
const TARGET_CHECK_LIMIT: usize = 20;
const DIRECTORY_CHECK_LIMIT: usize = 30;
const PORT_CHECK_LIMIT: usize = 60;
const IMAGE_CHECK_LIMIT: usize = 30;
const OPERATION_CREATE_LIMIT: usize = 10;
const OPERATION_READ_LIMIT: usize = 120;
const OPERATION_MUTATION_LIMIT: usize = 20;

#[derive(Clone)]
pub struct WebState {
    inner: Arc<WebInner>,
    origin: Arc<str>,
    port: u16,
}

struct WebInner {
    bootstrap_token: Mutex<Option<BootstrapToken>>,
    instance_token: String,
    sessions: Mutex<HashMap<String, Session>>,
    rate_limits: Mutex<HashMap<&'static str, VecDeque<Instant>>>,
    events: broadcast::Sender<OperationEvent>,
    operations: Mutex<HashMap<String, Arc<WebOperation>>>,
    operation_lock: Mutex<Option<String>>,
    active_browsers: AtomicU64,
    last_activity: Mutex<Instant>,
    shutdown_requested: AtomicBool,
    shutdown: Notify,
    _lock: Arc<SingleInstanceLock>,
}

#[derive(Clone)]
struct BootstrapToken {
    value: String,
    expires_at: Instant,
}

struct BrowserConnectionGuard {
    inner: Arc<WebInner>,
}

impl BrowserConnectionGuard {
    fn new(inner: Arc<WebInner>) -> Self {
        inner.active_browsers.fetch_add(1, Ordering::SeqCst);
        Self { inner }
    }
}

impl Drop for BrowserConnectionGuard {
    fn drop(&mut self) {
        self.inner.active_browsers.fetch_sub(1, Ordering::SeqCst);
    }
}

struct WebOperation {
    kind: OperationKind,
    replace_existing: bool,
    checkpoint: Mutex<OperationCheckpoint>,
    control: Mutex<OperationControl>,
    config: Mutex<Option<DeploymentConfig>>,
    result: Mutex<Option<Value>>,
    credentials: Mutex<Option<Vec<WebCredential>>>,
    ssh_password: Mutex<Option<SecretString>>,
    events: Mutex<Vec<OperationEvent>>,
    sequence: AtomicU64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WebCredential {
    kind: String,
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct CreateOperationRequest {
    #[serde(default)]
    kind: Option<OperationKind>,
    #[serde(default)]
    include_pricing: bool,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    revoke_source: bool,
    #[serde(default)]
    replace_existing: bool,
    source_url: Option<String>,
    #[serde(default)]
    source_account_mode: SourceAccountMode,
    source_username: Option<String>,
    source_password: Option<String>,
    website_name: Option<String>,
    container_name: Option<String>,
    directory: Option<String>,
    newapi_port: Option<u16>,
    kuma_port: Option<u16>,
    target: Option<WebDeploymentTarget>,
    ssh_destination: Option<String>,
    ssh_password: Option<String>,
    newapi_admin_username: Option<String>,
    newapi_admin_password: Option<String>,
    kuma_admin_username: Option<String>,
    kuma_admin_password: Option<String>,
    image: Option<String>,
    image_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WebDeploymentTarget {
    Local,
    Ssh,
}

#[derive(Debug, Serialize)]
struct CreateOperationResponse {
    operation_id: String,
    status: OperationStatus,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeOperationRequest {
    source_password: Option<String>,
    ssh_password: Option<String>,
    #[serde(default)]
    rotate_status_key: bool,
}

#[derive(Debug, Serialize)]
struct OperationView {
    checkpoint: OperationCheckpoint,
    events: Vec<OperationEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<WebCredential>>,
}

#[derive(Debug)]
struct Session {
    csrf_token: String,
    expires_at: Instant,
}

struct SingleInstanceLock {
    path: PathBuf,
    instance_path: PathBuf,
    file: File,
}

impl Drop for SingleInstanceLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(&self.instance_path);
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct InstanceMetadata {
    schema_version: u8,
    #[serde(default = "default_instance_host")]
    host: IpAddr,
    port: u16,
    token: String,
}

fn default_instance_host() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

#[derive(Debug, Deserialize, Serialize)]
struct InstanceLinkRequest {
    token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct InstanceLinkResponse {
    url: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

#[derive(Debug, Deserialize)]
struct SessionExchangeRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct SessionResponse {
    authenticated: bool,
    csrf_token: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Serialize)]
struct BootstrapResponse {
    version: &'static str,
    platform: String,
    openssh_ready: bool,
    has_saved_deployment: bool,
    saved_deployment: Option<SavedDeploymentSummary>,
    operation_lock: bool,
    supports_local_target: bool,
    defaults: BootstrapDefaults,
    #[serde(skip_serializing_if = "Option::is_none")]
    draft: Option<WebDraft>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_operation: Option<OperationSummary>,
}

#[derive(Debug, Serialize)]
struct SavedDeploymentSummary {
    target: WebDeploymentTarget,
    ssh_destination: Option<String>,
    source_url: String,
    source_username: String,
    website_name: String,
    container_name: String,
    directory: String,
    newapi_port: u16,
    kuma_port: u16,
    newapi_admin_username: String,
    kuma_admin_username: String,
    image: String,
    image_ref: String,
}

impl From<&DeploymentConfig> for SavedDeploymentSummary {
    fn from(config: &DeploymentConfig) -> Self {
        let (target, ssh_destination) = match &config.target {
            Target::Local => (WebDeploymentTarget::Local, None),
            Target::Ssh { destination } => (WebDeploymentTarget::Ssh, Some(destination.clone())),
        };
        Self {
            target,
            ssh_destination,
            source_url: config.source_url.clone(),
            source_username: config.source_username.clone(),
            website_name: config.website_name.clone(),
            container_name: config.container_name.clone(),
            directory: config.directory.to_string_lossy().into_owned(),
            newapi_port: config.newapi_port,
            kuma_port: config.kuma_port,
            newapi_admin_username: config.newapi_admin_username.clone(),
            kuma_admin_username: config.kuma_admin_username.clone(),
            image: config.image.clone(),
            image_ref: config.image_ref.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct BootstrapDefaults {
    source_url: &'static str,
    website_name: &'static str,
    container_name: &'static str,
    directory: &'static str,
    newapi_port: u16,
    kuma_port: u16,
    image: &'static str,
}

#[derive(Debug, Deserialize)]
struct TargetPreflightRequest {
    target: WebDeploymentTarget,
    ssh_destination: Option<String>,
    ssh_password: Option<String>,
    directory: String,
    newapi_port: u16,
    kuma_port: u16,
    #[serde(default)]
    check_site: bool,
}

#[derive(Debug, Serialize)]
struct TargetPreflightResponse {
    fingerprint: String,
    newapi_port: u16,
    kuma_port: u16,
}

#[derive(Debug, Deserialize)]
struct SourcePreflightRequest {
    source_url: String,
    source_username: String,
    source_password: String,
}

#[derive(Debug, Serialize)]
struct SourcePreflightResponse {
    username: String,
    user_id: i64,
}

#[derive(Debug, Deserialize)]
struct ImagePreflightRequest {
    image: String,
}

#[derive(Debug, Serialize)]
struct ImagePreflightResponse {
    image: String,
    immutable_ref: String,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WebDraft {
    source_url: String,
    source_account_mode: SourceAccountMode,
    source_username: String,
    website_name: String,
    container_name: String,
    directory: String,
    newapi_port: u16,
    kuma_port: u16,
    ssh_destination: String,
    newapi_admin_username: String,
    kuma_admin_username: String,
    image: String,
    image_ref: String,
}

#[derive(Debug, Serialize)]
struct OperationSummary {
    operation_id: String,
    kind: OperationKind,
    status: OperationStatus,
    current_stage: Option<OperationStage>,
    retryable: bool,
}

#[derive(Debug, Deserialize)]
struct SourceCheckRequest {
    source_url: String,
}

#[derive(Debug, Deserialize)]
struct SourceAccountCheckRequest {
    source_url: String,
    mode: SourceAccountMode,
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct SourceAccountCheckResponse {
    username: String,
    approved: bool,
}

#[derive(Debug, Deserialize)]
struct TargetCheckRequest {
    destination: String,
    directory: String,
    newapi_port: u16,
    kuma_port: u16,
}

#[derive(Debug, Serialize)]
struct TargetCheckResponse {
    fingerprint: String,
    newapi_port: u16,
    kuma_port: u16,
}

#[derive(Debug, Deserialize)]
struct DirectoryCheckRequest {
    destination: String,
    directory: String,
}

#[derive(Debug, Deserialize)]
struct PortCheckRequest {
    destination: String,
    directory: String,
    port: u16,
}

#[derive(Debug, Serialize)]
struct PortCheckResponse {
    port: u16,
    available: bool,
}

#[derive(Debug, Deserialize)]
struct ImageCheckRequest {
    image: String,
}

#[derive(Debug, Serialize)]
struct ImageResolutionResponse {
    image: String,
    immutable_ref: String,
}

#[derive(Debug, Serialize)]
struct CheckResponse {
    ok: bool,
    message: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
    field: Option<String>,
    diagnostic: Option<String>,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

impl ApiError {
    fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: code.into(),
            message: message.into(),
            field: None,
            diagnostic: None,
        }
    }

    fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: code.into(),
            message: message.into(),
            field: None,
            diagnostic: None,
        }
    }

    fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: code.into(),
            message: message.into(),
            field: None,
            diagnostic: None,
        }
    }

    fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
            field: None,
            diagnostic: None,
        }
    }

    fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "WEB_RATE_LIMITED".to_owned(),
            message: message.into(),
            field: None,
            diagnostic: None,
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "WEB_INTERNAL_ERROR".to_owned(),
            message: "本地 Web 服务暂时不可用".to_owned(),
            field: None,
            diagnostic: None,
        }
    }

    fn from_application(error: ApplicationError) -> Self {
        let status = match error.category {
            ErrorCategory::Validation => StatusCode::BAD_REQUEST,
            ErrorCategory::Authentication => StatusCode::UNAUTHORIZED,
            ErrorCategory::Authorization => StatusCode::FORBIDDEN,
            ErrorCategory::Conflict => StatusCode::CONFLICT,
            ErrorCategory::Cancelled => StatusCode::CONFLICT,
            ErrorCategory::Source | ErrorCategory::Target => StatusCode::BAD_GATEWAY,
            ErrorCategory::Persistence | ErrorCategory::Internal => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        Self {
            status,
            code: error.code,
            message: error.message,
            field: error
                .field
                .map(|field| format!("{field:?}").to_ascii_lowercase()),
            diagnostic: error.diagnostic,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": {
                    "code": self.code,
                    "message": self.message,
                    "field": self.field,
                    "diagnostic": self.diagnostic,
                }
            })),
        )
            .into_response()
    }
}

#[derive(Clone)]
struct WebEventSink {
    operation: Arc<WebOperation>,
    sender: broadcast::Sender<OperationEvent>,
}

impl EventSink for WebEventSink {
    fn emit(&self, mut event: OperationEvent) {
        event.sequence = self.operation.sequence.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut events) = self.operation.events.lock() {
            events.push(event.clone());
            if events.len() > 500 {
                let excess = events.len() - 500;
                events.drain(..excess);
            }
        }
        let stage = event.stage.map(|value| format!("{value:?}"));
        match event.severity {
            EventSeverity::Debug => {
                tracing::debug!(operation_id = %event.operation_id, sequence = event.sequence, stage = ?stage, message = %event.message, diagnostic = ?event.diagnostic, "deployment event")
            }
            EventSeverity::Info => {
                tracing::info!(operation_id = %event.operation_id, sequence = event.sequence, stage = ?stage, message = %event.message, diagnostic = ?event.diagnostic, "deployment event")
            }
            EventSeverity::Warning => {
                tracing::warn!(operation_id = %event.operation_id, sequence = event.sequence, stage = ?stage, message = %event.message, diagnostic = ?event.diagnostic, "deployment event")
            }
            EventSeverity::Error => {
                tracing::error!(operation_id = %event.operation_id, sequence = event.sequence, stage = ?stage, message = %event.message, diagnostic = ?event.diagnostic, "deployment event")
            }
        }
        let _ = self.sender.send(event);
    }
}

struct WebCheckpointStore {
    operation: Arc<WebOperation>,
    deployment: DeploymentStateCheckpointStore,
}

impl CheckpointStore for WebCheckpointStore {
    fn save(
        &mut self,
        checkpoint: &OperationCheckpoint,
    ) -> crate::application::error::ApplicationResult<()> {
        self.operation
            .checkpoint
            .lock()
            .map_err(|_| {
                ApplicationError::new(
                    ErrorCategory::Internal,
                    "WEB_LOCK_POISONED",
                    "本地 Web 服务状态不可用",
                    false,
                )
            })?
            .clone_from(checkpoint);
        self.deployment.save(checkpoint)
    }
}

pub async fn run(args: &WebArgs) -> AppResult<()> {
    let Some(lock) = try_acquire_single_instance()? else {
        return reopen_existing_instance(args).await;
    };
    let lock = Arc::new(lock);
    let bootstrap_token = random_token(48);
    let instance_token = random_token(48);
    let listener = TcpListener::bind(SocketAddr::new(args.host, args.port))
        .await
        .map_err(|error| AppError::Message(format!("启动 Web 服务失败: {error}")))?;
    let port = listener
        .local_addr()
        .map_err(|error| AppError::Message(format!("读取 Web 服务端口失败: {error}")))?
        .port();
    let browser_ip = match args.host {
        IpAddr::V4(address) if address.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(address) if address.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        address => address,
    };
    let origin = format!("http://{}", SocketAddr::new(browser_ip, port));
    let metadata = InstanceMetadata {
        schema_version: 1,
        host: args.host,
        port,
        token: instance_token.clone(),
    };
    storage::write(
        storage::WEB_INSTANCE_FILE,
        &serde_json::to_vec_pretty(&metadata)
            .map_err(|error| AppError::State(format!("serialize WebUI instance: {error}")))?,
    )?;
    let recovered = recover_saved_operation()?;
    let state = new_state(
        origin.clone(),
        port,
        bootstrap_token,
        instance_token,
        lock,
        recovered,
    );
    let token = state.bootstrap_token_for_display();
    let url = format!("{origin}/#token={token}");
    let urls = startup_urls(args.host, port, &token, discover_network_ip());
    if urls.len() == 1 {
        println!("WebUI 已启动：{}", urls[0].1);
    } else {
        println!("WebUI 已启动：");
        for (label, url) in urls {
            println!("  {label}：{url}");
        }
    }
    if !args.no_open {
        let open_url = url.clone();
        let opened = tokio::task::spawn_blocking(move || webbrowser::open(&open_url).is_ok())
            .await
            .unwrap_or(false);
        if !opened {
            println!("浏览器未能自动打开，请手动访问上面的本机链接。");
        }
    }

    // Abort the server task when shutdown is requested so long-lived SSE
    // connections cannot keep the CLI process alive indefinitely.
    let server_state = state.clone();
    let mut server = tokio::spawn(async move { axum::serve(listener, router(server_state)).await });
    tokio::select! {
        result = &mut server => {
            result
                .map_err(|error| AppError::Message(format!("Web 服务任务已停止: {error}")))?
                .map_err(|error| AppError::Message(format!("Web 服务已停止: {error}")))
        }
        _ = shutdown_signal(state) => {
            server.abort();
            let _ = server.await;
            Ok(())
        }
    }
}

fn new_state(
    origin: String,
    port: u16,
    bootstrap_token: String,
    instance_token: String,
    lock: Arc<SingleInstanceLock>,
    recovered: Option<Arc<WebOperation>>,
) -> WebState {
    let (events, _) = broadcast::channel(256);
    let mut operations = HashMap::new();
    if let Some(operation) = recovered {
        let operation_id = operation
            .checkpoint
            .lock()
            .map(|checkpoint| checkpoint.operation_id.clone())
            .unwrap_or_else(|_| "recovered-operation".to_owned());
        operations.insert(operation_id, operation);
    }
    WebState {
        inner: Arc::new(WebInner {
            bootstrap_token: Mutex::new(Some(BootstrapToken {
                value: bootstrap_token,
                expires_at: Instant::now() + BOOTSTRAP_TTL,
            })),
            instance_token,
            sessions: Mutex::new(HashMap::new()),
            rate_limits: Mutex::new(HashMap::new()),
            events,
            operations: Mutex::new(operations),
            operation_lock: Mutex::new(None),
            active_browsers: AtomicU64::new(0),
            last_activity: Mutex::new(Instant::now()),
            shutdown_requested: AtomicBool::new(false),
            shutdown: Notify::new(),
            _lock: lock,
        }),
        origin: Arc::from(origin),
        port,
    }
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/instance/link", post(create_instance_link))
        .route(
            "/api/session",
            post(exchange_session).get(read_session).delete(logout),
        )
        .route("/api/bootstrap", get(read_bootstrap))
        .route("/api/preflight/target", post(preflight_target))
        .route("/api/preflight/source", post(preflight_source))
        .route("/api/preflight/image", post(preflight_image))
        .route(
            "/api/draft",
            get(read_draft).put(save_draft).delete(delete_draft),
        )
        .route("/api/checks/source", post(check_source))
        .route("/api/source/account", post(check_source_account))
        .route("/api/checks/target", post(check_target))
        .route("/api/checks/directory", post(check_directory))
        .route("/api/checks/port", post(check_port))
        .route("/api/images/resolve", post(resolve_image))
        .route("/api/events", get(events))
        .route("/api/operations", post(create_operation))
        .route("/api/operations/{id}", get(read_operation))
        .route(
            "/api/operations/{id}/cancel",
            post(cancel_operation_handler),
        )
        .route(
            "/api/operations/{id}/resume",
            post(resume_operation_handler),
        )
        .route("/api/shutdown", post(request_shutdown))
        .fallback(static_asset)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

async fn security_headers(
    State(state): State<WebState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !valid_host(&state, request.headers()) {
        return ApiError::forbidden("WEB_HOST_REJECTED", "只允许从本机地址访问 Web 服务")
            .into_response();
    }
    touch_activity(&state);
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "meowai-deploy-webui",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn create_instance_link(
    State(state): State<WebState>,
    Json(payload): Json<InstanceLinkRequest>,
) -> ApiResult<Json<InstanceLinkResponse>> {
    enforce_rate_limit(&state, "instance_link", 12)?;
    if !constant_time_equal(
        payload.token.as_bytes(),
        state.inner.instance_token.as_bytes(),
    ) {
        return Err(ApiError::unauthorized(
            "WEB_INSTANCE_TOKEN_INVALID",
            "无法连接已有 WebUI 实例",
        ));
    }
    let bootstrap_token = random_token(48);
    *state
        .inner
        .bootstrap_token
        .lock()
        .map_err(|_| ApiError::internal())? = Some(BootstrapToken {
        value: bootstrap_token.clone(),
        expires_at: Instant::now() + BOOTSTRAP_TTL,
    });
    touch_activity(&state);
    Ok(Json(InstanceLinkResponse {
        url: format!("{}/#token={bootstrap_token}", state.origin),
    }))
}

async fn exchange_session(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<SessionExchangeRequest>,
) -> ApiResult<Response> {
    require_origin(&state, &headers)?;
    enforce_rate_limit(&state, "session_exchange", 10)?;
    if payload.token.len() < 32 {
        return Err(ApiError::unauthorized(
            "WEB_BOOTSTRAP_INVALID",
            "本机启动链接已失效，请重新运行 meowai-deploy web",
        ));
    }
    let valid = {
        let mut token = state
            .inner
            .bootstrap_token
            .lock()
            .map_err(|_| ApiError::internal())?;
        let valid = token.as_ref().is_some_and(|expected| {
            expected.expires_at > Instant::now()
                && constant_time_equal(expected.value.as_bytes(), payload.token.as_bytes())
        });
        if valid {
            *token = None;
        }
        valid
    };
    if !valid {
        return Err(ApiError::unauthorized(
            "WEB_BOOTSTRAP_INVALID",
            "本机启动链接已失效，请重新运行 meowai-deploy web",
        ));
    }

    let session_id = random_token(48);
    let csrf_token = random_token(32);
    state
        .inner
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?
        .insert(
            session_id.clone(),
            Session {
                csrf_token: csrf_token.clone(),
                expires_at: Instant::now() + SESSION_TTL,
            },
        );
    touch_activity(&state);
    let cookie = format!("{SESSION_COOKIE}={session_id}; HttpOnly; SameSite=Strict; Path=/");
    let mut response = Json(SessionResponse {
        authenticated: true,
        csrf_token,
        expires_in_seconds: SESSION_TTL.as_secs(),
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| ApiError::internal())?,
    );
    Ok(response)
}

async fn read_session(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> ApiResult<Json<SessionResponse>> {
    let session = require_session(&state, &headers)?;
    Ok(Json(SessionResponse {
        authenticated: true,
        csrf_token: session.csrf_token,
        expires_in_seconds: session
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs(),
    }))
}

async fn logout(State(state): State<WebState>, headers: HeaderMap) -> ApiResult<Response> {
    let session_id = require_mutation(&state, &headers)?;
    state
        .inner
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?
        .remove(&session_id);
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("meowai_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    Ok(response)
}

async fn read_bootstrap(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> ApiResult<Json<BootstrapResponse>> {
    require_session(&state, &headers)?;
    let has_saved_deployment =
        storage::exists(storage::CONFIG_FILE).map_err(|_| ApiError::internal())?;
    let saved_deployment = has_saved_deployment
        .then(load_deployment_config)
        .transpose()
        .map_err(|_| ApiError::internal())?
        .as_ref()
        .map(SavedDeploymentSummary::from);
    Ok(Json(BootstrapResponse {
        version: env!("CARGO_PKG_VERSION"),
        platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        openssh_ready: {
            let discovery = discover_openssh();
            discovery.ssh.status == ProgramStatus::Pass
                && discovery.scp.status == ProgramStatus::Pass
        },
        has_saved_deployment,
        saved_deployment,
        operation_lock: state
            .inner
            .operation_lock
            .lock()
            .map_err(|_| ApiError::internal())?
            .is_some(),
        supports_local_target: platform::supports_local_target(),
        defaults: BootstrapDefaults {
            source_url: DEFAULT_SOURCE_URL,
            website_name: DEFAULT_WEBSITE_NAME,
            container_name: DEFAULT_CONTAINER_NAME,
            directory: DEFAULT_DIRECTORY,
            newapi_port: DEFAULT_NEWAPI_PORT,
            kuma_port: DEFAULT_KUMA_PORT,
            image: DEFAULT_IMAGE,
        },
        draft: load_draft()?,
        current_operation: current_operation_summary(&state)?,
    }))
}

async fn preflight_target(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<TargetPreflightRequest>,
) -> ApiResult<Json<TargetPreflightResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "target_preflight", TARGET_CHECK_LIMIT)?;
    let target = match payload.target {
        WebDeploymentTarget::Local if platform::supports_local_target() => {
            DeploymentTargetInput::Local
        }
        WebDeploymentTarget::Local => {
            return Err(ApiError::bad_request(
                "LOCAL_TARGET_UNSUPPORTED",
                "当前系统不支持本机部署，请改用 SSH 远程部署",
            ));
        }
        WebDeploymentTarget::Ssh => DeploymentTargetInput::Ssh {
            destination: payload
                .ssh_destination
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| ApiError::bad_request("WEB_FIELD_REQUIRED", "请填写 SSH 地址"))?,
        },
    };
    if payload.check_site {
        let request = DeploymentTargetProbeRequest {
            target,
            directory: payload.directory.into(),
            newapi_port: payload.newapi_port,
            kuma_port: payload.kuma_port,
            ssh_password: optional_secret(payload.ssh_password),
        };
        let probe = tokio::task::spawn_blocking(move || {
            probe_deployment_target(request, &CancellationToken::default())
        })
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::from_application)?;
        return Ok(Json(TargetPreflightResponse {
            fingerprint: probe.fingerprint,
            newapi_port: probe.newapi_port,
            kuma_port: probe.kuma_port,
        }));
    }
    let fingerprint = tokio::task::spawn_blocking(move || {
        probe_deployment_connection(
            target,
            optional_secret(payload.ssh_password),
            &CancellationToken::default(),
        )
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_application)?;
    Ok(Json(TargetPreflightResponse {
        fingerprint,
        newapi_port: payload.newapi_port,
        kuma_port: payload.kuma_port,
    }))
}

async fn preflight_source(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<SourcePreflightRequest>,
) -> ApiResult<Json<SourcePreflightResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "source_preflight", SOURCE_ACCOUNT_LIMIT)?;
    let request = SourceAccountRequest::new(
        payload.source_url,
        SourceAccountMode::Login,
        payload.source_username,
        SecretString::from(payload.source_password),
    )
    .map_err(ApiError::from_application)?;
    let authenticated = login_source_account(request)
        .await
        .map_err(ApiError::from_application)?;
    persist_source_session(&authenticated.client)
        .map_err(crate::application::error::app_error)
        .map_err(ApiError::from_application)?;
    Ok(Json(SourcePreflightResponse {
        username: authenticated.identity.username,
        user_id: authenticated.identity.user_id,
    }))
}

async fn preflight_image(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<ImagePreflightRequest>,
) -> ApiResult<Json<ImagePreflightResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "image_preflight", IMAGE_CHECK_LIMIT)?;
    let resolution = resolve_latest_image(
        ImageResolutionRequest {
            image: payload.image,
        },
        &CancellationToken::default(),
    )
    .await
    .map_err(ApiError::from_application)?;
    Ok(Json(ImagePreflightResponse {
        image: resolution.image,
        immutable_ref: resolution.immutable_ref,
        updated_at: resolution.updated_at,
    }))
}

async fn read_draft(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> ApiResult<Json<Option<WebDraft>>> {
    require_session(&state, &headers)?;
    Ok(Json(load_draft()?))
}

async fn save_draft(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(draft): Json<WebDraft>,
) -> ApiResult<Json<WebDraft>> {
    require_mutation(&state, &headers)?;
    validate_web_draft(&draft)?;
    let content = serde_json::to_vec_pretty(&draft).map_err(|_| ApiError::internal())?;
    storage::write(storage::WEB_DRAFT_FILE, &content).map_err(|_| ApiError::internal())?;
    Ok(Json(draft))
}

async fn delete_draft(State(state): State<WebState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    require_mutation(&state, &headers)?;
    storage::remove(storage::WEB_DRAFT_FILE).map_err(|_| ApiError::internal())?;
    Ok(StatusCode::NO_CONTENT)
}

async fn check_source(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<SourceCheckRequest>,
) -> ApiResult<Json<CheckResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "source_check", SOURCE_CHECK_LIMIT)?;
    probe_source_url(&payload.source_url)
        .await
        .map_err(ApiError::from_application)?;
    Ok(Json(CheckResponse {
        ok: true,
        message: "源站可以连接".to_owned(),
    }))
}

async fn check_source_account(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<SourceAccountCheckRequest>,
) -> ApiResult<Json<SourceAccountCheckResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "source_account", SOURCE_ACCOUNT_LIMIT)?;
    let request = SourceAccountRequest::new(
        payload.source_url,
        payload.mode,
        payload.username,
        SecretString::from(payload.password),
    )
    .map_err(ApiError::from_application)?;
    let authenticated = match payload.mode {
        SourceAccountMode::Login => login_source_account(request).await,
        SourceAccountMode::Register => register_source_account(request).await,
    }
    .map_err(ApiError::from_application)?;
    persist_source_session(&authenticated.client)
        .map_err(crate::application::error::app_error)
        .map_err(ApiError::from_application)?;
    Ok(Json(SourceAccountCheckResponse {
        username: authenticated.identity.username,
        approved: true,
    }))
}

async fn check_target(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<TargetCheckRequest>,
) -> ApiResult<Json<TargetCheckResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "target_check", TARGET_CHECK_LIMIT)?;
    let cancellation = crate::application::operation::CancellationToken::default();
    let probe = tokio::task::spawn_blocking(move || {
        probe_deployment_target(
            DeploymentTargetProbeRequest {
                target: DeploymentTargetInput::Ssh {
                    destination: payload.destination,
                },
                directory: payload.directory.into(),
                newapi_port: payload.newapi_port,
                kuma_port: payload.kuma_port,
                ssh_password: None,
            },
            &cancellation,
        )
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_application)?;
    Ok(Json(TargetCheckResponse {
        fingerprint: probe.fingerprint,
        newapi_port: probe.newapi_port,
        kuma_port: probe.kuma_port,
    }))
}

async fn check_directory(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<DirectoryCheckRequest>,
) -> ApiResult<Json<CheckResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "directory_check", DIRECTORY_CHECK_LIMIT)?;
    let cancellation = crate::application::operation::CancellationToken::default();
    tokio::task::spawn_blocking(move || {
        validate_remote_directory(
            &payload.destination,
            payload.directory.into(),
            &cancellation,
        )
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_application)?;
    Ok(Json(CheckResponse {
        ok: true,
        message: "远程目录可写".to_owned(),
    }))
}

async fn check_port(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<PortCheckRequest>,
) -> ApiResult<Json<PortCheckResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "port_check", PORT_CHECK_LIMIT)?;
    let port = payload.port;
    let cancellation = crate::application::operation::CancellationToken::default();
    let available = tokio::task::spawn_blocking(move || {
        check_remote_port(
            RemotePortRequest {
                destination: payload.destination,
                directory: payload.directory.into(),
                port,
            },
            &cancellation,
        )
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(ApiError::from_application)?;
    if !available {
        return Err(ApiError::conflict(
            "REMOTE_PORT_OCCUPIED",
            format!("远程端口 {port} 已被占用"),
        ));
    }
    Ok(Json(PortCheckResponse { port, available }))
}

async fn resolve_image(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<ImageCheckRequest>,
) -> ApiResult<Json<ImageResolutionResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "image_check", IMAGE_CHECK_LIMIT)?;
    let cancellation = crate::application::operation::CancellationToken::default();
    let resolved = resolve_latest_image(
        ImageResolutionRequest {
            image: payload.image,
        },
        &cancellation,
    )
    .await
    .map_err(ApiError::from_application)?;
    Ok(Json(ImageResolutionResponse {
        image: resolved.image,
        immutable_ref: resolved.immutable_ref,
    }))
}

async fn events(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl tokio_stream::Stream<Item = std::result::Result<Event, Infallible>>>> {
    require_session(&state, &headers)?;
    let receiver = state.inner.events.subscribe();
    let connection = BrowserConnectionGuard::new(state.inner.clone());
    let initial = tokio_stream::iter([Ok(Event::default().event("connected").data("{}"))]);
    let updates = BroadcastStream::new(receiver)
        .filter_map(|event| async move { event.ok() })
        .map(move |event| {
            let _connection = &connection;
            Event::default()
                .event("operation")
                .json_data(event)
                .unwrap_or_else(|_| Event::default().event("operation").data("{}"))
        })
        .map(Ok);
    Ok(Sse::new(initial.chain(updates)).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

async fn create_operation(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<CreateOperationRequest>,
) -> ApiResult<Json<CreateOperationResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "operation_create", OPERATION_CREATE_LIMIT)?;
    let kind = payload.kind.unwrap_or_else(|| {
        if payload.source_url.is_some() {
            OperationKind::Onboard
        } else {
            OperationKind::Sync
        }
    });
    let config = if kind == OperationKind::Onboard {
        Some(config_from_request(&payload)?)
    } else {
        None
    };
    if let Some(config) = &config
        && !payload.replace_existing
    {
        match crate::commands::ensure_compatible_current_deployment(config) {
            Ok(()) => {}
            Err(AppError::State(message))
                if message.contains("already manages another deployment") =>
            {
                return Err(ApiError::conflict(
                    "DEPLOYMENT_REPLACEMENT_REQUIRED",
                    "当前控制端已管理另一个部署。继续前需要先停止并清理现有部署。",
                ));
            }
            Err(error) => {
                return Err(ApiError::from_application(
                    crate::application::error::app_error(error),
                ));
            }
        }
    }
    let operation_id = format!("web-{}", random_token(20));
    {
        let mut lock = state
            .inner
            .operation_lock
            .lock()
            .map_err(|_| ApiError::internal())?;
        if let Some(existing) = lock.as_ref() {
            return Err(ApiError::conflict(
                "OPERATION_LOCKED",
                format!("已有操作正在运行：{existing}"),
            ));
        }
        *lock = Some(operation_id.clone());
    }

    let operation = Arc::new(WebOperation {
        kind,
        replace_existing: payload.replace_existing,
        checkpoint: Mutex::new(OperationCheckpoint::new(&operation_id, kind)),
        control: Mutex::new(OperationControl::default()),
        config: Mutex::new(config.clone()),
        result: Mutex::new(None),
        credentials: Mutex::new(None),
        events: Mutex::new(Vec::new()),
        ssh_password: Mutex::new(
            if matches!(
                config.as_ref().map(|value| &value.target),
                Some(Target::Ssh { .. })
            ) {
                optional_secret(payload.ssh_password.clone())
            } else {
                None
            },
        ),
        sequence: AtomicU64::new(0),
    });
    state
        .inner
        .operations
        .lock()
        .map_err(|_| ApiError::internal())?
        .insert(operation_id.clone(), operation.clone());

    let task_state = state.clone();
    let task_operation_id = operation_id.clone();
    tokio::spawn(async move {
        if kind == OperationKind::Onboard {
            if let Some(config) = config {
                run_onboard_operation(
                    task_state.clone(),
                    operation.clone(),
                    config,
                    None,
                    payload.replace_existing,
                    false,
                )
                .await;
            }
        } else {
            run_manage_operation(task_state.clone(), operation.clone(), kind, payload).await;
        }
        release_operation_lock(&task_state, &task_operation_id);
    });

    Ok(Json(CreateOperationResponse {
        operation_id,
        status: OperationStatus::Draft,
    }))
}

async fn read_operation(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> ApiResult<Json<OperationView>> {
    require_session(&state, &headers)?;
    enforce_rate_limit(&state, "operation_read", OPERATION_READ_LIMIT)?;
    let operation = get_operation(&state, &operation_id)?;
    Ok(Json(operation_view(&operation, true)?))
}

async fn cancel_operation_handler(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> ApiResult<Json<OperationView>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "operation_cancel", OPERATION_MUTATION_LIMIT)?;
    let operation = get_operation(&state, &operation_id)?;
    let status = operation
        .checkpoint
        .lock()
        .map_err(|_| ApiError::internal())?
        .status;
    if !matches!(
        status,
        OperationStatus::Running | OperationStatus::Cancelling
    ) {
        return Err(ApiError::conflict(
            "OPERATION_NOT_RUNNING",
            "当前操作已经结束，无法取消",
        ));
    }
    operation
        .control
        .lock()
        .map_err(|_| ApiError::internal())?
        .cancel();
    Ok(Json(operation_view(&operation, false)?))
}

async fn resume_operation_handler(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
    Json(payload): Json<ResumeOperationRequest>,
) -> ApiResult<Json<CreateOperationResponse>> {
    require_mutation(&state, &headers)?;
    enforce_rate_limit(&state, "operation_resume", OPERATION_MUTATION_LIMIT)?;
    let operation = get_operation(&state, &operation_id)?;
    if operation.kind != OperationKind::Onboard {
        return Err(ApiError::conflict(
            "OPERATION_RESUME_UNSUPPORTED",
            "只有部署操作支持从检查点恢复",
        ));
    }
    let checkpoint = operation
        .checkpoint
        .lock()
        .map_err(|_| ApiError::internal())?
        .clone();
    if checkpoint.status != OperationStatus::Failed {
        return Err(ApiError::conflict(
            "OPERATION_NOT_RETRYABLE",
            "当前操作没有可恢复的失败检查点",
        ));
    }
    validate_status_key_rotation_request(&checkpoint, payload.rotate_status_key)?;
    let rotate_status_key = payload.rotate_status_key;
    let mut config = operation
        .config
        .lock()
        .map_err(|_| ApiError::internal())?
        .clone()
        .ok_or_else(ApiError::internal)?;
    if let Some(password) = optional_secret(payload.source_password) {
        config.source_password = Some(password);
    }
    if matches!(&config.target, Target::Ssh { .. })
        && let Some(password) = optional_secret(payload.ssh_password)
    {
        *operation
            .ssh_password
            .lock()
            .map_err(|_| ApiError::internal())? = Some(password);
    }
    {
        let mut lock = state
            .inner
            .operation_lock
            .lock()
            .map_err(|_| ApiError::internal())?;
        if let Some(existing) = lock.as_ref() {
            return Err(ApiError::conflict(
                "OPERATION_LOCKED",
                format!("已有操作正在运行：{existing}"),
            ));
        }
        *lock = Some(operation_id.clone());
    }
    *operation.control.lock().map_err(|_| ApiError::internal())? = OperationControl::default();
    let task_state = state.clone();
    let task_operation = operation.clone();
    let task_operation_id = operation_id.clone();
    let replace_existing = operation.replace_existing;
    tokio::spawn(async move {
        run_onboard_operation(
            task_state.clone(),
            task_operation,
            config,
            Some(checkpoint),
            replace_existing,
            rotate_status_key,
        )
        .await;
        release_operation_lock(&task_state, &task_operation_id);
    });
    Ok(Json(CreateOperationResponse {
        operation_id,
        status: OperationStatus::Running,
    }))
}

fn validate_status_key_rotation_request(
    checkpoint: &OperationCheckpoint,
    requested: bool,
) -> ApiResult<()> {
    if requested
        && checkpoint
            .failure
            .as_ref()
            .is_none_or(|failure| failure.code != "STATUS_KEY_CONTENT_UNAVAILABLE")
    {
        return Err(ApiError::conflict(
            "STATUS_KEY_ROTATION_NOT_REQUIRED",
            "当前失败不需要重新生成公共状态密钥",
        ));
    }
    Ok(())
}

fn config_from_request(payload: &CreateOperationRequest) -> ApiResult<DeploymentConfig> {
    let required = |value: &Option<String>, field: &'static str| {
        value
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::bad_request("WEB_FIELD_REQUIRED", format!("缺少字段：{field}"))
            })
    };
    let target = match payload.target.unwrap_or(WebDeploymentTarget::Ssh) {
        WebDeploymentTarget::Local if platform::supports_local_target() => Target::Local,
        WebDeploymentTarget::Local => {
            return Err(ApiError::bad_request(
                "LOCAL_TARGET_UNSUPPORTED",
                "当前系统不支持本机部署，请改用 SSH 远程部署",
            ));
        }
        WebDeploymentTarget::Ssh => Target::Ssh {
            destination: required(&payload.ssh_destination, "ssh_destination")?,
        },
    };
    let config = DeploymentConfig {
        source_url: required(&payload.source_url, "source_url")?,
        source_account_mode: payload.source_account_mode,
        source_username: required(&payload.source_username, "source_username")?,
        source_password: Some(SecretString::from(required(
            &payload.source_password,
            "source_password",
        )?)),
        website_name: required(&payload.website_name, "website_name")?,
        container_name: required(&payload.container_name, "container_name")?,
        directory: required(&payload.directory, "directory")?.into(),
        newapi_port: payload
            .newapi_port
            .ok_or_else(|| ApiError::bad_request("WEB_FIELD_REQUIRED", "缺少字段：newapi_port"))?,
        kuma_port: payload
            .kuma_port
            .ok_or_else(|| ApiError::bad_request("WEB_FIELD_REQUIRED", "缺少字段：kuma_port"))?,
        target,
        newapi_admin_username: required(&payload.newapi_admin_username, "newapi_admin_username")?,
        newapi_admin_password: payload.newapi_admin_password.clone(),
        kuma_admin_username: required(&payload.kuma_admin_username, "kuma_admin_username")?,
        kuma_admin_password: payload.kuma_admin_password.clone(),
        image: required(&payload.image, "image")?,
        image_ref: required(&payload.image_ref, "image_ref")?,
        ..DeploymentConfig::default()
    };
    config
        .deployment_input()
        .validate()
        .map_err(|error| ApiError::bad_request(error.code.as_str(), error.message))?;
    Ok(config)
}

fn optional_secret(value: Option<String>) -> Option<SecretString> {
    value
        .filter(|value| !value.is_empty())
        .map(SecretString::from)
}

fn get_operation(state: &WebState, operation_id: &str) -> ApiResult<Arc<WebOperation>> {
    state
        .inner
        .operations
        .lock()
        .map_err(|_| ApiError::internal())?
        .get(operation_id)
        .cloned()
        .ok_or_else(|| ApiError::bad_request("OPERATION_NOT_FOUND", "找不到本机操作"))
}

fn operation_view(operation: &WebOperation, reveal_credentials: bool) -> ApiResult<OperationView> {
    let checkpoint = operation
        .checkpoint
        .lock()
        .map_err(|_| ApiError::internal())?
        .clone();
    let result = operation
        .result
        .lock()
        .map_err(|_| ApiError::internal())?
        .clone();
    let events = operation
        .events
        .lock()
        .map_err(|_| ApiError::internal())?
        .clone();
    let credentials = if reveal_credentials && checkpoint.status == OperationStatus::Completed {
        operation
            .credentials
            .lock()
            .map_err(|_| ApiError::internal())?
            .take()
    } else {
        None
    };
    Ok(OperationView {
        checkpoint,
        events,
        result,
        credentials,
    })
}

async fn run_onboard_operation(
    state: WebState,
    operation: Arc<WebOperation>,
    mut config: DeploymentConfig,
    resume: Option<OperationCheckpoint>,
    replace_existing: bool,
    rotate_status_key: bool,
) {
    let mut preparation_stage = OperationStage::InputValidation;
    let result = async {
        emit_web_event(
            &state,
            &operation,
            Some(OperationStage::InputValidation),
            EventSeverity::Info,
            OperationEventKind::Message,
            "正在整理并校验部署配置",
            None,
        );
        config.normalize();
        config.resolve_passwords();
        emit_web_event(
            &state,
            &operation,
            Some(OperationStage::InputValidation),
            EventSeverity::Info,
            OperationEventKind::Message,
            "正在使用已校验的容器镜像版本",
            None,
        );
        config
            .validate()
            .map_err(crate::application::error::app_error)?;
        if replace_existing {
            preparation_stage = OperationStage::Cleanup;
            emit_web_event(
                &state,
                &operation,
                Some(OperationStage::Cleanup),
                EventSeverity::Warning,
                OperationEventKind::Message,
                "正在停止并清理需要替换的现有部署",
                None,
            );
            let existing =
                load_deployment_config().map_err(crate::application::error::app_error)?;
            let ssh_password = operation
                .ssh_password
                .lock()
                .map_err(|_| {
                    ApplicationError::new(
                        ErrorCategory::Internal,
                        "WEB_LOCK_POISONED",
                        "本地 Web 服务状态不可用",
                        false,
                    )
                })?
                .clone();
            rollback_deployment_with_ssh_password(
                &existing,
                None,
                false,
                &CancellationToken::default(),
                ssh_password,
            )
            .await?;
        }
        preparation_stage = OperationStage::InputValidation;
        emit_web_event(
            &state,
            &operation,
            Some(OperationStage::InputValidation),
            EventSeverity::Info,
            OperationEventKind::Message,
            "正在保存部署配置并恢复源站会话",
            None,
        );
        crate::commands::ensure_compatible_current_deployment(&config)
            .map_err(crate::application::error::app_error)?;
        persist_deployment_config(&config).map_err(crate::application::error::app_error)?;
        let (source, identity) = source_for_web_onboard(&config).await?;
        *operation.config.lock().map_err(|_| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "WEB_LOCK_POISONED",
                "本地 Web 服务状态不可用",
                false,
            )
        })? = Some(config.clone());
        let input = config.deployment_input();
        let ssh_password = operation
            .ssh_password
            .lock()
            .map_err(|_| {
                ApplicationError::new(
                    ErrorCategory::Internal,
                    "WEB_LOCK_POISONED",
                    "本地 Web 服务状态不可用",
                    false,
                )
            })?
            .clone();
        let mut backend =
            ProductionOnboardBackend::new(config, source, identity).with_ssh_password(ssh_password);
        if rotate_status_key {
            backend.allow_status_key_rotation();
            emit_web_event(
                &state,
                &operation,
                Some(OperationStage::SourceResources),
                EventSeverity::Warning,
                OperationEventKind::Message,
                "正在撤销旧公共状态密钥并生成新密钥",
                None,
            );
        }
        let control = operation
            .control
            .lock()
            .map_err(|_| {
                ApplicationError::new(
                    ErrorCategory::Internal,
                    "WEB_LOCK_POISONED",
                    "本地 Web 服务状态不可用",
                    false,
                )
            })?
            .clone();
        let sink = WebEventSink {
            operation: operation.clone(),
            sender: state.inner.events.clone(),
        };
        let mut store = WebCheckpointStore {
            operation: operation.clone(),
            deployment: DeploymentStateCheckpointStore,
        };
        let operation_id = operation
            .checkpoint
            .lock()
            .map_err(|_| {
                ApplicationError::new(
                    ErrorCategory::Internal,
                    "WEB_LOCK_POISONED",
                    "本地 Web 服务状态不可用",
                    false,
                )
            })?
            .operation_id
            .clone();
        let outcome = match resume {
            Some(checkpoint) => {
                resume_onboard_with_control(
                    &mut backend,
                    &input,
                    checkpoint,
                    sink,
                    &mut store,
                    &control,
                )
                .await?
            }
            None => {
                start_onboard_with_control(
                    &mut backend,
                    &input,
                    operation_id,
                    sink,
                    &mut store,
                    &control,
                )
                .await?
            }
        };
        let credentials = outcome
            .credentials
            .into_iter()
            .map(|credential| WebCredential {
                kind: credential.kind,
                username: credential.username,
                password: secrecy::ExposeSecret::expose_secret(&credential.password).to_owned(),
            })
            .collect::<Vec<_>>();
        *operation.credentials.lock().map_err(|_| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "WEB_LOCK_POISONED",
                "本地 Web 服务状态不可用",
                false,
            )
        })? = Some(credentials);
        *operation.result.lock().map_err(|_| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "WEB_LOCK_POISONED",
                "本地 Web 服务状态不可用",
                false,
            )
        })? = Some(serde_json::json!({
            "kind": "onboard",
            "operation_id": outcome.operation_id,
        }));
        Ok::<(), ApplicationError>(())
    }
    .await;
    match result {
        Ok(()) => {
            if let Ok(mut password) = operation.ssh_password.lock() {
                *password = None;
            }
        }
        Err(error) => {
            let failure_already_reported = operation
                .checkpoint
                .lock()
                .map(|checkpoint| checkpoint.failure.is_some())
                .unwrap_or(false);
            if !failure_already_reported && let Ok(mut checkpoint) = operation.checkpoint.lock() {
                checkpoint.current_stage = Some(preparation_stage);
            }
            mark_operation_failed(&operation, &error);
            if !failure_already_reported && error.category != ErrorCategory::Cancelled {
                let stage = operation
                    .checkpoint
                    .lock()
                    .ok()
                    .and_then(|checkpoint| checkpoint.current_stage)
                    .or(Some(preparation_stage));
                emit_web_event(
                    &state,
                    &operation,
                    stage,
                    EventSeverity::Error,
                    if error.retryable {
                        OperationEventKind::RecoverableFailure {
                            code: error.code.clone(),
                        }
                    } else {
                        OperationEventKind::FatalFailure {
                            code: error.code.clone(),
                        }
                    },
                    error.message.clone(),
                    error.diagnostic.clone(),
                );
            }
        }
    }
}

async fn run_manage_operation(
    state: WebState,
    operation: Arc<WebOperation>,
    kind: OperationKind,
    payload: CreateOperationRequest,
) {
    let result = async {
        let stage = manage_operation_stage(kind);
        start_manage_checkpoint(&operation, stage)?;
        emit_web_event(
            &state,
            &operation,
            Some(stage),
            EventSeverity::Info,
            OperationEventKind::OperationStarted,
            manage_operation_start_message(kind),
            None,
        );
        let mut config = load_deployment_config().map_err(crate::application::error::app_error)?;
        config.resolve_passwords();
        let control = operation
            .control
            .lock()
            .map_err(|_| {
                ApplicationError::new(
                    ErrorCategory::Internal,
                    "WEB_LOCK_POISONED",
                    "本地 Web 服务状态不可用",
                    false,
                )
            })?
            .clone();
        let cancellation = control.token();
        let value = match kind {
            OperationKind::Status => {
                serde_json::to_value(read_deployment_status(&config, &cancellation)?).map_err(
                    |error| {
                        ApplicationError::new(
                            ErrorCategory::Internal,
                            "WEB_RESULT_SERIALIZE_FAILED",
                            error.to_string(),
                            false,
                        )
                    },
                )?
            }
            OperationKind::Sync => {
                let mut source = source_for_operation(&config)
                    .await
                    .map_err(crate::application::error::app_error)?;
                let progress_state = state.clone();
                let progress_operation = operation.clone();
                serde_json::to_value(
                    sync_deployment_with_progress(
                        &config,
                        &mut source,
                        web_sync_request(&payload),
                        &cancellation,
                        &mut |progress_stage, message| {
                            emit_web_event(
                                &progress_state,
                                &progress_operation,
                                Some(progress_stage),
                                EventSeverity::Info,
                                OperationEventKind::Message,
                                message,
                                None,
                            );
                        },
                    )
                    .await?,
                )
                .map_err(|error| {
                    ApplicationError::new(
                        ErrorCategory::Internal,
                        "WEB_RESULT_SERIALIZE_FAILED",
                        error.to_string(),
                        false,
                    )
                })?
            }
            OperationKind::Clean => serde_json::to_value(clean_deployment(&config, &cancellation)?)
                .map_err(|error| {
                    ApplicationError::new(
                        ErrorCategory::Internal,
                        "WEB_RESULT_SERIALIZE_FAILED",
                        error.to_string(),
                        false,
                    )
                })?,
            OperationKind::Rollback => {
                let mut source = if payload.revoke_source {
                    Some(
                        source_for_operation(&config)
                            .await
                            .map_err(crate::application::error::app_error)?,
                    )
                } else {
                    None
                };
                serde_json::to_value(
                    rollback_deployment(
                        &config,
                        source.as_mut(),
                        payload.revoke_source,
                        &cancellation,
                    )
                    .await?,
                )
                .map_err(|error| {
                    ApplicationError::new(
                        ErrorCategory::Internal,
                        "WEB_RESULT_SERIALIZE_FAILED",
                        error.to_string(),
                        false,
                    )
                })?
            }
            OperationKind::Onboard => unreachable!(),
        };
        complete_manage_checkpoint(&operation, stage)?;
        *operation.result.lock().map_err(|_| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "WEB_LOCK_POISONED",
                "本地 Web 服务状态不可用",
                false,
            )
        })? = Some(value);
        emit_web_event(
            &state,
            &operation,
            Some(stage),
            EventSeverity::Info,
            OperationEventKind::StageCompleted,
            manage_operation_complete_message(kind),
            None,
        );
        emit_web_event(
            &state,
            &operation,
            None,
            EventSeverity::Info,
            OperationEventKind::OperationCompleted,
            manage_operation_complete_message(kind),
            None,
        );
        Ok::<(), ApplicationError>(())
    }
    .await;
    if let Err(error) = result {
        mark_operation_failed(&operation, &error);
        let stage = manage_operation_stage(kind);
        emit_web_event(
            &state,
            &operation,
            Some(stage),
            EventSeverity::Error,
            if error.retryable {
                OperationEventKind::RecoverableFailure {
                    code: error.code.clone(),
                }
            } else {
                OperationEventKind::FatalFailure {
                    code: error.code.clone(),
                }
            },
            error.message.clone(),
            error.diagnostic.clone(),
        );
    }
}

fn web_sync_request(payload: &CreateOperationRequest) -> SyncDeploymentRequest {
    SyncDeploymentRequest {
        include_pricing: payload.include_pricing,
        force: payload.force,
    }
}

fn start_manage_checkpoint(
    operation: &WebOperation,
    stage: OperationStage,
) -> Result<(), ApplicationError> {
    let mut checkpoint = operation.checkpoint.lock().map_err(|_| {
        ApplicationError::new(
            ErrorCategory::Internal,
            "WEB_LOCK_POISONED",
            "本地 Web 服务状态不可用",
            false,
        )
    })?;
    checkpoint.start().map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Conflict,
            "OPERATION_STATE_INVALID",
            error.to_string(),
            false,
        )
    })?;
    checkpoint.start_stage(stage).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Conflict,
            "OPERATION_STATE_INVALID",
            error.to_string(),
            false,
        )
    })?;
    save_web_checkpoint(&checkpoint)
}

fn complete_manage_checkpoint(
    operation: &WebOperation,
    stage: OperationStage,
) -> Result<(), ApplicationError> {
    let mut checkpoint = operation.checkpoint.lock().map_err(|_| {
        ApplicationError::new(
            ErrorCategory::Internal,
            "WEB_LOCK_POISONED",
            "本地 Web 服务状态不可用",
            false,
        )
    })?;
    checkpoint.complete_stage(stage).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Conflict,
            "OPERATION_STATE_INVALID",
            error.to_string(),
            false,
        )
    })?;
    checkpoint.complete().map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Conflict,
            "OPERATION_STATE_INVALID",
            error.to_string(),
            false,
        )
    })?;
    save_web_checkpoint(&checkpoint)
}

fn manage_operation_stage(kind: OperationKind) -> OperationStage {
    match kind {
        OperationKind::Onboard => OperationStage::InputValidation,
        OperationKind::Status => OperationStage::FinalVerification,
        OperationKind::Sync => OperationStage::ChannelSynchronization,
        OperationKind::Clean => OperationStage::Cleanup,
        OperationKind::Rollback => OperationStage::Rollback,
    }
}

fn manage_operation_start_message(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::Onboard => "开始部署",
        OperationKind::Status => "开始读取部署状态",
        OperationKind::Sync => "开始同步部署",
        OperationKind::Clean => "开始清理下游资源",
        OperationKind::Rollback => "开始回滚部署",
    }
}

fn manage_operation_complete_message(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::Onboard => "部署已完成",
        OperationKind::Status => "部署状态读取完成",
        OperationKind::Sync => "部署同步完成",
        OperationKind::Clean => "下游资源清理完成",
        OperationKind::Rollback => "部署回滚完成",
    }
}

fn emit_web_event(
    state: &WebState,
    operation: &Arc<WebOperation>,
    stage: Option<OperationStage>,
    severity: EventSeverity,
    kind: OperationEventKind,
    message: impl Into<String>,
    diagnostic: Option<String>,
) {
    WebEventSink {
        operation: operation.clone(),
        sender: state.inner.events.clone(),
    }
    .emit(OperationEvent {
        operation_id: operation
            .checkpoint
            .lock()
            .map(|checkpoint| checkpoint.operation_id.clone())
            .unwrap_or_default(),
        sequence: 0,
        timestamp: unix_timestamp(),
        stage,
        severity,
        kind,
        message: message.into(),
        diagnostic,
    });
}

fn save_web_checkpoint(checkpoint: &OperationCheckpoint) -> Result<(), ApplicationError> {
    let content = serde_json::to_vec_pretty(checkpoint).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Persistence,
            "CHECKPOINT_SERIALIZE_FAILED",
            error.to_string(),
            true,
        )
    })?;
    storage::write(storage::OPERATION_FILE, &content).map_err(crate::application::error::app_error)
}

fn mark_operation_failed(operation: &WebOperation, error: &ApplicationError) {
    tracing::error!(
        code = %error.code,
        message = %error.message,
        diagnostic = ?error.diagnostic,
        retryable = error.retryable,
        "deployment operation failed"
    );
    if let Ok(mut checkpoint) = operation.checkpoint.lock() {
        let stage = checkpoint
            .current_stage
            .unwrap_or(OperationStage::InputValidation);
        if error.category == ErrorCategory::Cancelled {
            checkpoint.status = OperationStatus::Cancelled;
            checkpoint.current_stage = None;
            checkpoint.failure = None;
        } else {
            checkpoint.status = OperationStatus::Failed;
            checkpoint.current_stage = Some(stage);
            checkpoint.failure = Some(OperationFailure {
                stage,
                code: error.code.clone(),
                message: error.message.clone(),
                retryable: error.retryable,
                diagnostic: error.diagnostic.clone(),
            });
        }
        checkpoint.updated_at = unix_timestamp();
        let _ = save_web_checkpoint(&checkpoint);
    }
}

fn release_operation_lock(state: &WebState, operation_id: &str) {
    if let Ok(mut lock) = state.inner.operation_lock.lock()
        && lock.as_deref() == Some(operation_id)
    {
        *lock = None;
    }
}

async fn request_shutdown(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    require_mutation(&state, &headers)?;
    state.inner.shutdown_requested.store(true, Ordering::SeqCst);
    state.inner.shutdown.notify_waiters();
    Ok(StatusCode::NO_CONTENT)
}

async fn static_asset(State(_state): State<WebState>, uri: Uri) -> Response {
    let requested = uri.path().trim_start_matches('/');
    let path = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };
    let file = STATIC_DIR
        .get_file(path)
        .or_else(|| STATIC_DIR.get_file("index.html"));
    let Some(file) = file else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let content_type = match file
        .path()
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        _ => "application/octet-stream",
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .body(Body::from(file.contents().to_vec()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn require_session(state: &WebState, headers: &HeaderMap) -> ApiResult<Session> {
    valid_host_or_error(state, headers)?;
    let session_id = cookie_value(headers, SESSION_COOKIE).ok_or_else(|| {
        ApiError::unauthorized("WEB_SESSION_REQUIRED", "Web 会话已失效，请重新打开本机链接")
    })?;
    let mut sessions = state
        .inner
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?;
    let Some(session) = sessions.get_mut(&session_id) else {
        return Err(ApiError::unauthorized(
            "WEB_SESSION_REQUIRED",
            "Web 会话已失效，请重新打开本机链接",
        ));
    };
    if session.expires_at <= Instant::now() {
        sessions.remove(&session_id);
        return Err(ApiError::unauthorized(
            "WEB_SESSION_EXPIRED",
            "Web 会话已过期，请重新打开本机链接",
        ));
    }
    session.expires_at = Instant::now() + SESSION_TTL;
    Ok(Session {
        csrf_token: session.csrf_token.clone(),
        expires_at: session.expires_at,
    })
}

fn require_mutation(state: &WebState, headers: &HeaderMap) -> ApiResult<String> {
    require_origin(state, headers)?;
    let session_id = cookie_value(headers, SESSION_COOKIE).ok_or_else(|| {
        ApiError::unauthorized("WEB_SESSION_REQUIRED", "Web 会话已失效，请重新打开本机链接")
    })?;
    let session = require_session(state, headers)?;
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::forbidden("WEB_CSRF_REQUIRED", "请求缺少本机会话校验"))?;
    if !constant_time_equal(csrf.as_bytes(), session.csrf_token.as_bytes()) {
        return Err(ApiError::forbidden("WEB_CSRF_INVALID", "本机会话校验失败"));
    }
    Ok(session_id)
}

fn require_origin(state: &WebState, headers: &HeaderMap) -> ApiResult<()> {
    valid_host_or_error(state, headers)?;
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::forbidden("WEB_ORIGIN_REQUIRED", "请求来源不是本机 Web 页面"))?;
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::forbidden("WEB_HOST_REJECTED", "请求地址无效"))?;
    let origin_url = url::Url::parse(origin)
        .map_err(|_| ApiError::forbidden("WEB_ORIGIN_REJECTED", "请求来源不是当前 WebUI 页面"))?;
    let authority = host
        .parse::<axum::http::uri::Authority>()
        .map_err(|_| ApiError::forbidden("WEB_HOST_REJECTED", "请求地址无效"))?;
    let same_host = origin_url.host_str().is_some_and(|origin_host| {
        origin_host.eq_ignore_ascii_case(
            authority
                .host()
                .trim_start_matches('[')
                .trim_end_matches(']'),
        )
    });
    if origin_url.scheme() != "http"
        || !same_host
        || origin_url.port_or_known_default() != Some(state.port)
    {
        return Err(ApiError::forbidden(
            "WEB_ORIGIN_REJECTED",
            "请求来源不是当前 WebUI 页面",
        ));
    }
    Ok(())
}

fn valid_host(state: &WebState, headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    host.parse::<axum::http::uri::Authority>()
        .ok()
        .is_some_and(|authority| authority.port_u16().unwrap_or(80) == state.port)
}

fn valid_host_or_error(state: &WebState, headers: &HeaderMap) -> ApiResult<()> {
    if valid_host(state, headers) {
        Ok(())
    } else {
        Err(ApiError::forbidden("WEB_HOST_REJECTED", "请求地址无效"))
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then(|| value.to_owned())
    })
}

fn random_token(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn startup_urls(
    host: IpAddr,
    port: u16,
    token: &str,
    network_ip: Option<IpAddr>,
) -> Vec<(&'static str, String)> {
    let url = |address| format!("http://{}/#token={token}", SocketAddr::new(address, port));
    if !host.is_unspecified() {
        return vec![("访问地址", url(host))];
    }
    let loopback = match host {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    let mut urls = vec![("本机地址", url(loopback)), ("监听地址", url(host))];
    if let Some(address) = network_ip.filter(|address| {
        !address.is_loopback() && !address.is_unspecified() && address.is_ipv4() == host.is_ipv4()
    }) {
        urls.push((network_address_label(address), url(address)));
    }
    urls
}

fn network_address_label(address: IpAddr) -> &'static str {
    if is_public_address(address) {
        "公网地址"
    } else {
        "网络地址"
    }
}

fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, third, _] = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_documentation()
                && !address.is_unspecified()
                && first != 0
                && !(first == 100 && (64..=127).contains(&second))
                && !(first == 192 && second == 0 && third == 0)
                && !(first == 198 && matches!(second, 18 | 19))
        }
        IpAddr::V6(address) => {
            !address.is_unique_local()
                && !address.is_unicast_link_local()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unspecified()
                && address.segments()[..2] != [0x2001, 0x0db8]
        }
    }
}

fn discover_network_ip() -> Option<IpAddr> {
    discover_network_ip_for(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80),
    )
    .or_else(|| {
        discover_network_ip_for(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            "[2606:4700:4700::1111]:80".parse().ok()?,
        )
    })
}

fn discover_network_ip_for(bind: SocketAddr, destination: SocketAddr) -> Option<IpAddr> {
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(destination).ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_loopback() && !address.is_unspecified()).then_some(address)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn touch_activity(state: &WebState) {
    if let Ok(mut last_activity) = state.inner.last_activity.lock() {
        *last_activity = Instant::now();
    }
}

fn enforce_rate_limit(state: &WebState, bucket: &'static str, maximum: usize) -> ApiResult<()> {
    let now = Instant::now();
    let mut rate_limits = state
        .inner
        .rate_limits
        .lock()
        .map_err(|_| ApiError::internal())?;
    let attempts = rate_limits.entry(bucket).or_default();
    while attempts
        .front()
        .is_some_and(|attempt| now.duration_since(*attempt) >= RATE_LIMIT_WINDOW)
    {
        attempts.pop_front();
    }
    if attempts.len() >= maximum {
        return Err(ApiError::too_many_requests(
            "请求过于频繁，请稍后重新打开本机页面",
        ));
    }
    attempts.push_back(now);
    Ok(())
}

fn validate_web_draft(draft: &WebDraft) -> ApiResult<()> {
    for (field, value, maximum) in [
        ("source_url", draft.source_url.as_str(), 2048),
        ("source_username", draft.source_username.as_str(), 20),
        ("website_name", draft.website_name.as_str(), 100),
        ("container_name", draft.container_name.as_str(), 63),
        ("directory", draft.directory.as_str(), 1024),
        ("ssh_destination", draft.ssh_destination.as_str(), 512),
        (
            "newapi_admin_username",
            draft.newapi_admin_username.as_str(),
            12,
        ),
        (
            "kuma_admin_username",
            draft.kuma_admin_username.as_str(),
            64,
        ),
        ("image", draft.image.as_str(), 512),
        ("image_ref", draft.image_ref.as_str(), 512),
    ] {
        if value.chars().count() > maximum {
            return Err(ApiError {
                status: StatusCode::BAD_REQUEST,
                code: "WEB_FIELD_TOO_LONG".to_owned(),
                message: format!("字段 {field} 不能超过 {maximum} 个字符"),
                field: Some(field.to_owned()),
                diagnostic: None,
            });
        }
    }
    Ok(())
}

async fn source_for_web_onboard(
    config: &DeploymentConfig,
) -> crate::application::error::ApplicationResult<(SourceClient, SourceIdentity)> {
    if config.source_password.is_none() {
        return Err(ApplicationError::new(
            ErrorCategory::Authentication,
            "SOURCE_PASSWORD_REQUIRED",
            "恢复部署需要重新输入源站密码",
            true,
        ));
    }
    match source_for_operation(config).await {
        Ok(source) => {
            let identity = source
                .identity()
                .cloned()
                .ok_or_else(|| AppError::State("源站会话没有用户身份".to_owned()))
                .map_err(crate::application::error::app_error)?;
            if identity.username == config.source_username {
                return Ok((source, identity));
            }
        }
        Err(AppError::Source(SourceError::InvalidResponse { endpoint, message }))
            if endpoint == "session.json"
                && message == "session belongs to a different source URL" => {}
        Err(error) => return Err(crate::application::error::app_error(error)),
    }

    let (source, identity) = crate::config::authenticate_source(config)
        .await
        .map_err(crate::application::error::app_error)?;
    persist_source_session(&source).map_err(crate::application::error::app_error)?;
    Ok((source, identity))
}

fn load_draft() -> ApiResult<Option<WebDraft>> {
    storage::read(storage::WEB_DRAFT_FILE)
        .map_err(|_| ApiError::internal())?
        .map(|content| {
            serde_json::from_slice(&content).map_err(|error| ApiError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "WEB_DRAFT_INVALID".to_owned(),
                message: "无法读取已保存的网页草稿".to_owned(),
                field: None,
                diagnostic: Some(error.to_string()),
            })
        })
        .transpose()
}

fn current_operation_summary(state: &WebState) -> ApiResult<Option<OperationSummary>> {
    let operations = state
        .inner
        .operations
        .lock()
        .map_err(|_| ApiError::internal())?;
    let latest = operations
        .iter()
        .filter_map(|(operation_id, operation)| {
            operation
                .checkpoint
                .lock()
                .ok()
                .map(|checkpoint| (operation_id.clone(), operation.clone(), checkpoint.clone()))
        })
        .max_by_key(|(_, _, checkpoint)| checkpoint.updated_at);
    let Some((operation_id, operation, checkpoint)) = latest else {
        return Ok(None);
    };
    let has_config = operation
        .config
        .lock()
        .map_err(|_| ApiError::internal())?
        .is_some();
    Ok(Some(OperationSummary {
        operation_id,
        kind: checkpoint.kind,
        status: checkpoint.status,
        current_stage: checkpoint.current_stage,
        retryable: checkpoint.kind == OperationKind::Onboard
            && checkpoint.status == OperationStatus::Failed
            && has_config
            && checkpoint
                .failure
                .as_ref()
                .is_some_and(|failure| failure.retryable),
    }))
}

fn recover_saved_operation() -> AppResult<Option<Arc<WebOperation>>> {
    let Some(content) = storage::read(storage::OPERATION_FILE)? else {
        return Ok(None);
    };
    let mut checkpoint: OperationCheckpoint = serde_json::from_slice(&content)
        .map_err(|error| AppError::State(format!("parse {}: {error}", storage::OPERATION_FILE)))?;
    let config =
        if checkpoint.kind == OperationKind::Onboard && storage::exists(storage::CONFIG_FILE)? {
            Some(load_deployment_config()?)
        } else {
            None
        };
    if normalize_recovered_checkpoint(&mut checkpoint, config.is_some()) {
        let content = serde_json::to_vec_pretty(&checkpoint)
            .map_err(|error| AppError::State(format!("serialize recovered operation: {error}")))?;
        storage::write(storage::OPERATION_FILE, &content)?;
    }
    Ok(Some(Arc::new(WebOperation {
        kind: checkpoint.kind,
        replace_existing: false,
        checkpoint: Mutex::new(checkpoint),
        control: Mutex::new(OperationControl::default()),
        config: Mutex::new(config),
        result: Mutex::new(None),
        credentials: Mutex::new(None),
        ssh_password: Mutex::new(None),
        events: Mutex::new(Vec::new()),
        sequence: AtomicU64::new(0),
    })))
}

fn normalize_recovered_checkpoint(checkpoint: &mut OperationCheckpoint, has_config: bool) -> bool {
    if !matches!(
        checkpoint.status,
        OperationStatus::Draft | OperationStatus::Running | OperationStatus::Cancelling
    ) {
        return false;
    }
    let stage = checkpoint
        .current_stage
        .unwrap_or(OperationStage::InputValidation);
    checkpoint.status = OperationStatus::Failed;
    checkpoint.current_stage = Some(stage);
    checkpoint.failure = Some(OperationFailure {
        stage,
        code: "OPERATION_INTERRUPTED".to_owned(),
        message: "本地服务在操作完成前退出，可从已保存进度继续".to_owned(),
        retryable: checkpoint.kind == OperationKind::Onboard && has_config,
        diagnostic: None,
    });
    checkpoint.updated_at = unix_timestamp();
    true
}

fn try_acquire_single_instance() -> AppResult<Option<SingleInstanceLock>> {
    let root = storage::directory()?;
    fs::create_dir_all(&root).map_err(|error| AppError::WriteFile {
        path: root.clone(),
        source: error,
    })?;
    let path = root.join("webui.lock");
    let instance_path = root.join(storage::WEB_INSTANCE_FILE);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| AppError::WriteFile {
            path: path.clone(),
            source: error,
        })?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(Some(SingleInstanceLock {
            path,
            instance_path,
            file,
        })),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(source) => Err(AppError::WriteFile { path, source }),
    }
}

async fn reopen_existing_instance(args: &WebArgs) -> AppResult<()> {
    let mut metadata = None;
    for _ in 0..20 {
        if let Some(content) = storage::read(storage::WEB_INSTANCE_FILE)? {
            metadata = Some(
                serde_json::from_slice::<InstanceMetadata>(&content).map_err(|error| {
                    AppError::State(format!("parse {}: {error}", storage::WEB_INSTANCE_FILE))
                })?,
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let metadata = metadata.ok_or_else(|| {
        AppError::State("已有 WebUI 正在启动，但实例信息尚不可用，请稍后重试".to_owned())
    })?;
    if metadata.schema_version != 1 || metadata.port == 0 || metadata.token.len() < 32 {
        return Err(AppError::State("已有 WebUI 的实例信息无效".to_owned()));
    }
    let instance_ip = if metadata.host.is_unspecified() {
        default_instance_host()
    } else {
        metadata.host
    };
    let endpoint = format!(
        "http://{}/api/instance/link",
        SocketAddr::new(instance_ip, metadata.port)
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|error| AppError::Message(format!("创建本机 WebUI 客户端失败: {error}")))?;
    let mut last_error = None;
    let mut response = None;
    for _ in 0..30 {
        match client
            .post(&endpoint)
            .json(&InstanceLinkRequest {
                token: metadata.token.clone(),
            })
            .send()
            .await
        {
            Ok(value) => {
                response = Some(value);
                break;
            }
            Err(error) => last_error = Some(error),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let response = response.ok_or_else(|| {
        AppError::Message(format!(
            "连接已有 WebUI 失败: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "服务尚未开始监听".to_owned())
        ))
    })?;
    if !response.status().is_success() {
        return Err(AppError::Message(format!(
            "已有 WebUI 拒绝创建新页面链接: HTTP {}",
            response.status()
        )));
    }
    let link = response
        .json::<InstanceLinkResponse>()
        .await
        .map_err(|error| AppError::State(format!("parse WebUI instance link: {error}")))?;
    let expected_prefix = format!("http://127.0.0.1:{}/#token=", metadata.port);
    if !link.url.starts_with(&expected_prefix) {
        return Err(AppError::State(
            "已有 WebUI 返回了不安全的页面地址".to_owned(),
        ));
    }
    println!("WebUI 已在运行：{}", link.url);
    if !args.no_open {
        let url = link.url.clone();
        let opened = tokio::task::spawn_blocking(move || webbrowser::open(&url).is_ok())
            .await
            .unwrap_or(false);
        if !opened {
            println!("浏览器未能自动打开，请手动访问上面的本机链接。");
        }
    }
    Ok(())
}

impl WebState {
    fn bootstrap_token_for_display(&self) -> String {
        self.inner
            .bootstrap_token
            .lock()
            .ok()
            .and_then(|token| token.as_ref().map(|token| token.value.clone()))
            .unwrap_or_default()
    }
}

async fn shutdown_signal(state: WebState) {
    tokio::select! {
        _ = system_shutdown_signal() => {},
        _ = requested_shutdown(state.clone()) => {},
        _ = idle_shutdown(state, DEFAULT_IDLE_TTL) => {},
    }
}

async fn requested_shutdown(state: WebState) {
    loop {
        let notified = state.inner.shutdown.notified();
        if state.inner.shutdown_requested.load(Ordering::SeqCst) {
            return;
        }
        notified.await;
    }
}

async fn idle_shutdown(state: WebState, idle_ttl: Duration) {
    loop {
        let active_operation = state
            .inner
            .operation_lock
            .lock()
            .map(|operation| operation.is_some())
            .unwrap_or(true);
        let active_browser = state.inner.active_browsers.load(Ordering::SeqCst) > 0;
        let elapsed = state
            .inner
            .last_activity
            .lock()
            .map(|last_activity| last_activity.elapsed())
            .unwrap_or_default();
        if !active_operation && !active_browser && elapsed >= idle_ttl {
            return;
        }
        let wait = if active_operation || active_browser {
            Duration::from_secs(5)
        } else {
            idle_ttl
                .saturating_sub(elapsed)
                .min(Duration::from_secs(30))
                .max(Duration::from_millis(10))
        };
        tokio::time::sleep(wait).await;
    }
}

async fn system_shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = signal.recv() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Method;
    use tower::ServiceExt;

    const TEST_BOOTSTRAP_TOKEN: &str = "test-bootstrap-token-123456789012345678901234";
    const TEST_INSTANCE_TOKEN: &str = "test-instance-token-1234567890123456789012345";

    fn test_state() -> WebState {
        let directory = tempfile::tempdir().expect("lock directory");
        let path = directory.path().join("webui.lock");
        let instance_path = directory.path().join("webui-instance.json");
        std::mem::forget(directory);
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("lock file");
        file.try_lock_exclusive().expect("lock");
        new_state(
            "http://127.0.0.1:41234".to_owned(),
            41234,
            TEST_BOOTSTRAP_TOKEN.to_owned(),
            TEST_INSTANCE_TOKEN.to_owned(),
            Arc::new(SingleInstanceLock {
                path,
                instance_path,
                file,
            }),
            None,
        )
    }

    #[test]
    fn saved_deployment_summary_excludes_all_passwords() {
        let config = DeploymentConfig {
            target: Target::Ssh {
                destination: "deploy@example.test".to_owned(),
            },
            source_username: "source-user".to_owned(),
            source_password: Some(SecretString::from("source-secret")),
            newapi_admin_password: Some("newapi-secret".to_owned()),
            kuma_admin_password: Some("kuma-secret".to_owned()),
            ..DeploymentConfig::default()
        };
        let value = serde_json::to_value(SavedDeploymentSummary::from(&config))
            .expect("serialize saved deployment summary");
        let serialized = value.to_string();
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("source-secret"));
        assert!(!serialized.contains("newapi-secret"));
        assert!(!serialized.contains("kuma-secret"));
    }

    fn authenticated_headers(origin: &str, csrf: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:41234"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_str(origin).expect("origin"),
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("meowai_session=test-session"),
        );
        headers.insert("x-csrf-token", HeaderValue::from_str(csrf).expect("csrf"));
        headers
    }

    fn install_session(state: &WebState, expires_at: Instant) {
        state.inner.sessions.lock().expect("sessions").insert(
            "test-session".to_owned(),
            Session {
                csrf_token: "test-csrf-token".to_owned(),
                expires_at,
            },
        );
    }

    #[tokio::test]
    async fn health_is_loopback_only_and_has_security_headers() {
        let app = router(test_state());
        let request = axum::http::Request::builder()
            .uri("/api/health")
            .header(header::HOST, "127.0.0.1:41234")
            .body(Body::empty())
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        assert!(String::from_utf8_lossy(&body).contains("meowai-deploy-webui"));
    }

    #[tokio::test]
    async fn bootstrap_token_is_one_time_and_sets_httponly_cookie() {
        let app = router(test_state());
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/session")
            .header(header::HOST, "127.0.0.1:41234")
            .header(header::ORIGIN, "http://127.0.0.1:41234")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"token":"{TEST_BOOTSTRAP_TOKEN}"}}"#
            )))
            .expect("request");
        let response = app.clone().oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .expect("cookie")
                .contains("HttpOnly")
        );

        let second = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/session")
            .header(header::HOST, "127.0.0.1:41234")
            .header(header::ORIGIN, "http://127.0.0.1:41234")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"token":"{TEST_BOOTSTRAP_TOKEN}"}}"#
            )))
            .expect("request");
        let response = app.oneshot(second).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn operation_mutations_require_a_session_and_csrf_token() {
        let app = router(test_state());
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/operations")
            .header(header::HOST, "127.0.0.1:41234")
            .header(header::ORIGIN, "http://127.0.0.1:41234")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"kind":"status"}"#))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_host_is_rejected_before_routing() {
        let request = axum::http::Request::builder()
            .uri("/api/health")
            .header(header::HOST, "example.com")
            .body(Body::empty())
            .expect("request");
        let response = router(test_state())
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn expired_bootstrap_token_is_rejected() {
        let state = test_state();
        state
            .inner
            .bootstrap_token
            .lock()
            .expect("bootstrap token")
            .as_mut()
            .expect("token")
            .expires_at = Instant::now() - Duration::from_secs(1);
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/session")
            .header(header::HOST, "127.0.0.1:41234")
            .header(header::ORIGIN, "http://127.0.0.1:41234")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"token":"{TEST_BOOTSTRAP_TOKEN}"}}"#
            )))
            .expect("request");
        let response = router(state).oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn instance_link_rotates_a_fresh_bootstrap_token() {
        let state = test_state();
        let request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/instance/link")
            .header(header::HOST, "127.0.0.1:41234")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(format!(
                r#"{{"token":"{TEST_INSTANCE_TOKEN}"}}"#
            )))
            .expect("request");
        let response = router(state.clone())
            .oneshot(request)
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let link: InstanceLinkResponse = serde_json::from_slice(&body).expect("instance link");
        assert!(link.url.starts_with("http://127.0.0.1:41234/#token="));
        assert!(!link.url.ends_with(TEST_BOOTSTRAP_TOKEN));
        assert_ne!(state.bootstrap_token_for_display(), TEST_BOOTSTRAP_TOKEN);
    }

    #[test]
    fn session_exchange_rate_limit_is_enforced() {
        let state = test_state();
        for _ in 0..10 {
            enforce_rate_limit(&state, "session_exchange", 10).expect("allowed request");
        }
        let error = enforce_rate_limit(&state, "session_exchange", 10).expect_err("rate limit");
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.code, "WEB_RATE_LIMITED");
    }

    #[tokio::test]
    async fn expensive_routes_are_rate_limited_before_work_starts() {
        let account_state = test_state();
        install_session(&account_state, Instant::now() + SESSION_TTL);
        for _ in 0..SOURCE_ACCOUNT_LIMIT {
            enforce_rate_limit(&account_state, "source_account", SOURCE_ACCOUNT_LIMIT)
                .expect("allowed account request");
        }
        let mut account_request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/source/account")
            .body(Body::from(
                r#"{"source_url":"https://source.test","mode":"login","username":"operator","password":"password"}"#,
            ))
            .expect("account request");
        *account_request.headers_mut() =
            authenticated_headers("http://127.0.0.1:41234", "test-csrf-token");
        account_request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let account_response = router(account_state)
            .oneshot(account_request)
            .await
            .expect("account response");
        assert_eq!(account_response.status(), StatusCode::TOO_MANY_REQUESTS);

        let operation_state = test_state();
        install_session(&operation_state, Instant::now() + SESSION_TTL);
        for _ in 0..OPERATION_CREATE_LIMIT {
            enforce_rate_limit(&operation_state, "operation_create", OPERATION_CREATE_LIMIT)
                .expect("allowed operation request");
        }
        let mut operation_request = axum::http::Request::builder()
            .method(Method::POST)
            .uri("/api/operations")
            .body(Body::from(r#"{"kind":"status"}"#))
            .expect("operation request");
        *operation_request.headers_mut() =
            authenticated_headers("http://127.0.0.1:41234", "test-csrf-token");
        operation_request.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let operation_response = router(operation_state)
            .oneshot(operation_request)
            .await
            .expect("operation response");
        assert_eq!(operation_response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn mutation_rejects_cross_origin_and_invalid_csrf() {
        let state = test_state();
        install_session(&state, Instant::now() + SESSION_TTL);

        let cross_origin = authenticated_headers("http://example.com", "test-csrf-token");
        assert_eq!(
            require_mutation(&state, &cross_origin)
                .expect_err("cross origin")
                .code,
            "WEB_ORIGIN_REJECTED"
        );

        let invalid_csrf = authenticated_headers("http://127.0.0.1:41234", "wrong-token");
        assert_eq!(
            require_mutation(&state, &invalid_csrf)
                .expect_err("invalid csrf")
                .code,
            "WEB_CSRF_INVALID"
        );
    }

    #[test]
    fn expired_session_is_removed() {
        let state = test_state();
        install_session(&state, Instant::now() - Duration::from_secs(1));
        let headers = authenticated_headers("http://127.0.0.1:41234", "test-csrf-token");
        assert_eq!(
            require_session(&state, &headers)
                .expect_err("expired session")
                .code,
            "WEB_SESSION_EXPIRED"
        );
        assert!(state.inner.sessions.lock().expect("sessions").is_empty());
    }

    #[test]
    fn web_draft_round_trip_contains_no_secret_fields() {
        let draft = WebDraft {
            source_url: "https://source.test".to_owned(),
            source_username: "operator".to_owned(),
            website_name: "Site".to_owned(),
            ..WebDraft::default()
        };
        let content = serde_json::to_vec(&draft).expect("serialize draft");
        let value: Value = serde_json::from_slice(&content).expect("draft value");
        assert_eq!(value["source_username"], "operator");
        assert!(value.get("source_password").is_none());
        assert!(value.get("newapi_admin_password").is_none());
        assert!(value.get("kuma_admin_password").is_none());
        let restored: WebDraft = serde_json::from_slice(&content).expect("restore draft");
        assert_eq!(restored.source_url, "https://source.test");
        assert!(
            serde_json::from_str::<WebDraft>(r#"{"source_password":"must-not-persist"}"#).is_err()
        );
    }

    #[test]
    fn web_draft_rejects_fields_over_the_persistence_limit() {
        let draft = WebDraft {
            source_url: "源".repeat(2049),
            ..WebDraft::default()
        };
        let error = validate_web_draft(&draft).expect_err("oversized draft");
        assert_eq!(error.status, StatusCode::BAD_REQUEST);
        assert_eq!(error.code, "WEB_FIELD_TOO_LONG");
        assert_eq!(error.field.as_deref(), Some("source_url"));
    }

    #[test]
    fn web_sync_request_preserves_explicit_flags() {
        let payload: CreateOperationRequest = serde_json::from_value(serde_json::json!({
            "kind": "sync",
            "include_pricing": true,
            "force": true
        }))
        .expect("sync payload");
        let request = web_sync_request(&payload);
        assert!(request.include_pricing);
        assert!(request.force);
    }

    #[test]
    fn interrupted_operation_recovers_as_retryable_failure() {
        let mut checkpoint = OperationCheckpoint::new("web-recover", OperationKind::Onboard);
        checkpoint.start().expect("start");
        checkpoint
            .start_stage(OperationStage::BaseServices)
            .expect("stage");
        assert!(normalize_recovered_checkpoint(&mut checkpoint, true));
        assert_eq!(checkpoint.status, OperationStatus::Failed);
        let failure = checkpoint.failure.expect("failure");
        assert_eq!(failure.stage, OperationStage::BaseServices);
        assert_eq!(failure.code, "OPERATION_INTERRUPTED");
        assert!(failure.retryable);
    }

    #[test]
    fn status_key_rotation_requires_the_matching_failure_code() {
        let mut checkpoint = OperationCheckpoint::new("web-rotation", OperationKind::Onboard);
        checkpoint.start().expect("start");
        checkpoint
            .fail(
                OperationStage::SourceResources,
                "OTHER_FAILURE",
                "other failure",
                true,
            )
            .expect("fail");
        let error = validate_status_key_rotation_request(&checkpoint, true)
            .expect_err("other failures must not rotate the source key");
        assert_eq!(error.code, "STATUS_KEY_ROTATION_NOT_REQUIRED");

        checkpoint.failure.as_mut().expect("failure").code =
            "STATUS_KEY_CONTENT_UNAVAILABLE".to_owned();
        validate_status_key_rotation_request(&checkpoint, true)
            .expect("the missing key content failure permits rotation");
    }

    #[test]
    fn operation_view_returns_event_history_with_failure_details() {
        let operation = Arc::new(WebOperation {
            kind: OperationKind::Onboard,
            replace_existing: false,
            checkpoint: Mutex::new(OperationCheckpoint::new(
                "web-events",
                OperationKind::Onboard,
            )),
            control: Mutex::new(OperationControl::default()),
            config: Mutex::new(None),
            result: Mutex::new(None),
            credentials: Mutex::new(None),
            ssh_password: Mutex::new(None),
            events: Mutex::new(Vec::new()),
            sequence: AtomicU64::new(0),
        });
        let (sender, _) = broadcast::channel(4);
        WebEventSink {
            operation: operation.clone(),
            sender,
        }
        .emit(OperationEvent {
            operation_id: "web-events".to_owned(),
            sequence: 0,
            timestamp: 1,
            stage: Some(OperationStage::TargetValidation),
            severity: EventSeverity::Error,
            kind: OperationEventKind::RecoverableFailure {
                code: "SSH_FAILED".to_owned(),
            },
            message: "SSH 连接失败".to_owned(),
            diagnostic: Some("ssh exited with status 255".to_owned()),
        });

        let view = operation_view(&operation, false).expect("operation view");
        assert_eq!(view.events.len(), 1);
        assert_eq!(view.events[0].sequence, 0);
        assert_eq!(
            view.events[0].diagnostic.as_deref(),
            Some("ssh exited with status 255")
        );
    }

    #[test]
    fn completed_operation_is_not_rewritten_during_recovery() {
        let mut checkpoint = OperationCheckpoint::new("web-complete", OperationKind::Status);
        checkpoint.start().expect("start");
        checkpoint.complete().expect("complete");
        assert!(!normalize_recovered_checkpoint(&mut checkpoint, false));
        assert_eq!(checkpoint.status, OperationStatus::Completed);
    }

    #[tokio::test]
    async fn idle_shutdown_waits_for_an_active_operation() {
        let state = test_state();
        *state.inner.last_activity.lock().expect("activity") =
            Instant::now() - Duration::from_secs(1);
        *state.inner.operation_lock.lock().expect("operation lock") = Some("web-active".to_owned());

        assert!(
            tokio::time::timeout(
                Duration::from_millis(25),
                idle_shutdown(state.clone(), Duration::from_millis(1)),
            )
            .await
            .is_err()
        );

        *state.inner.operation_lock.lock().expect("operation lock") = None;
        tokio::time::timeout(
            Duration::from_millis(100),
            idle_shutdown(state, Duration::from_millis(1)),
        )
        .await
        .expect("idle shutdown");
    }

    #[tokio::test]
    async fn idle_shutdown_waits_for_an_open_browser_stream() {
        let state = test_state();
        *state.inner.last_activity.lock().expect("activity") =
            Instant::now() - Duration::from_secs(1);
        state.inner.active_browsers.store(1, Ordering::SeqCst);

        assert!(
            tokio::time::timeout(
                Duration::from_millis(25),
                idle_shutdown(state.clone(), Duration::from_millis(1)),
            )
            .await
            .is_err()
        );

        state.inner.active_browsers.store(0, Ordering::SeqCst);
        tokio::time::timeout(
            Duration::from_millis(100),
            idle_shutdown(state, Duration::from_millis(1)),
        )
        .await
        .expect("idle shutdown");
    }
}
