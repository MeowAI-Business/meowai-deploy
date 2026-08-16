use std::{
    collections::HashMap,
    convert::Infallible,
    fs::{self, File, OpenOptions},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
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
use include_dir::{Dir, include_dir};
use rand::{Rng, distributions::Alphanumeric};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{net::TcpListener, sync::broadcast};
use tokio_stream::{StreamExt, wrappers::BroadcastStream};

use crate::{
    application::{
        error::{ApplicationError, ErrorCategory},
        manage::{
            SyncDeploymentRequest, clean_deployment, read_deployment_status, rollback_deployment,
            sync_deployment,
        },
        onboard::{
            CheckpointStore, DeploymentStateCheckpointStore, OperationControl,
            ProductionOnboardBackend, resume_onboard_with_control, start_onboard_with_control,
        },
        operation::{
            EventSink, OperationCheckpoint, OperationEvent, OperationFailure, OperationKind,
            OperationStage, OperationStatus,
        },
    },
    cli::WebArgs,
    commands::{
        load_deployment_config, persist_deployment_config, persist_source_session,
        source_for_operation,
    },
    config::{DeploymentConfig, Target},
    error::{AppError, Result as AppResult},
    state::unix_timestamp,
    storage,
};

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/webui/dist");
const SESSION_COOKIE: &str = "meowai_session";
const SESSION_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone)]
pub struct WebState {
    inner: Arc<WebInner>,
    origin: Arc<str>,
    port: u16,
}

struct WebInner {
    bootstrap_token: Mutex<Option<String>>,
    sessions: Mutex<HashMap<String, Session>>,
    events: broadcast::Sender<OperationEvent>,
    operations: Mutex<HashMap<String, Arc<WebOperation>>>,
    operation_lock: Mutex<Option<String>>,
    _lock: Arc<SingleInstanceLock>,
}

struct WebOperation {
    kind: OperationKind,
    checkpoint: Mutex<OperationCheckpoint>,
    control: Mutex<OperationControl>,
    config: Mutex<Option<DeploymentConfig>>,
    result: Mutex<Option<Value>>,
    credentials: Mutex<Option<Vec<WebCredential>>>,
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
    source_url: Option<String>,
    source_username: Option<String>,
    source_password: Option<String>,
    website_name: Option<String>,
    container_name: Option<String>,
    directory: Option<String>,
    newapi_port: Option<u16>,
    kuma_port: Option<u16>,
    ssh_destination: Option<String>,
    newapi_admin_username: Option<String>,
    newapi_admin_password: Option<String>,
    kuma_admin_username: Option<String>,
    kuma_admin_password: Option<String>,
    image: Option<String>,
    image_ref: Option<String>,
}

#[derive(Debug, Serialize)]
struct CreateOperationResponse {
    operation_id: String,
    status: OperationStatus,
}

#[derive(Debug, Serialize)]
struct OperationView {
    checkpoint: OperationCheckpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<Vec<WebCredential>>,
}

struct Session {
    csrf_token: String,
    expires_at: Instant,
}

struct SingleInstanceLock {
    path: PathBuf,
    file: File,
}

impl Drop for SingleInstanceLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
        let _ = fs::remove_file(&self.path);
    }
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
    has_saved_deployment: bool,
    operation_lock: bool,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

impl ApiError {
    fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: code.into(),
            message: message.into(),
        }
    }

    fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: code.into(),
            message: message.into(),
        }
    }

    fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: code.into(),
            message: message.into(),
        }
    }

    fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: code.into(),
            message: message.into(),
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "WEB_INTERNAL_ERROR".to_owned(),
            message: "本地 Web 服务暂时不可用".to_owned(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({
                "error": {"code": self.code, "message": self.message}
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
    let lock = Arc::new(acquire_single_instance()?);
    let bootstrap_token = random_token(48);
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .map_err(|error| AppError::Message(format!("启动 loopback Web 服务失败: {error}")))?;
    let port = listener
        .local_addr()
        .map_err(|error| AppError::Message(format!("读取 Web 服务端口失败: {error}")))?
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    let state = new_state(origin.clone(), port, bootstrap_token, lock);
    let url = format!("{origin}/#token={}", state.bootstrap_token_for_display());

    println!("WebUI 已启动：{url}");
    if !args.no_open {
        let open_url = url.clone();
        let opened = tokio::task::spawn_blocking(move || webbrowser::open(&open_url).is_ok())
            .await
            .unwrap_or(false);
        if !opened {
            println!("浏览器未能自动打开，请手动访问上面的本机链接。");
        }
    }

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| AppError::Message(format!("Web 服务已停止: {error}")))
}

fn new_state(
    origin: String,
    port: u16,
    bootstrap_token: String,
    lock: Arc<SingleInstanceLock>,
) -> WebState {
    let (events, _) = broadcast::channel(256);
    WebState {
        inner: Arc::new(WebInner {
            bootstrap_token: Mutex::new(Some(bootstrap_token)),
            sessions: Mutex::new(HashMap::new()),
            events,
            operations: Mutex::new(HashMap::new()),
            operation_lock: Mutex::new(None),
            _lock: lock,
        }),
        origin: Arc::from(origin),
        port,
    }
}

pub fn router(state: WebState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route(
            "/api/session",
            post(exchange_session).get(read_session).delete(logout),
        )
        .route("/api/bootstrap", get(read_bootstrap))
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

async fn exchange_session(
    State(state): State<WebState>,
    headers: HeaderMap,
    Json(payload): Json<SessionExchangeRequest>,
) -> ApiResult<Response> {
    require_origin(&state, &headers)?;
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
        let valid = token.as_deref().is_some_and(|expected| {
            constant_time_equal(expected.as_bytes(), payload.token.as_bytes())
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
    Ok(Json(BootstrapResponse {
        version: env!("CARGO_PKG_VERSION"),
        has_saved_deployment: storage::exists(storage::CONFIG_FILE)
            .map_err(|_| ApiError::internal())?,
        operation_lock: state
            .inner
            .operation_lock
            .lock()
            .map_err(|_| ApiError::internal())?
            .is_some(),
    }))
}

async fn events(
    State(state): State<WebState>,
    headers: HeaderMap,
) -> ApiResult<Sse<impl tokio_stream::Stream<Item = std::result::Result<Event, Infallible>>>> {
    require_session(&state, &headers)?;
    let receiver = state.inner.events.subscribe();
    let initial = tokio_stream::iter([Ok(Event::default().event("connected").data("{}"))]);
    let updates = BroadcastStream::new(receiver)
        .filter_map(|event| event.ok())
        .map(|event| {
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
        checkpoint: Mutex::new(OperationCheckpoint::new(&operation_id, kind)),
        control: Mutex::new(OperationControl::default()),
        config: Mutex::new(config.clone()),
        result: Mutex::new(None),
        credentials: Mutex::new(None),
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
                run_onboard_operation(task_state.clone(), operation.clone(), config, None).await;
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
    let operation = get_operation(&state, &operation_id)?;
    Ok(Json(operation_view(&operation, true)?))
}

async fn cancel_operation_handler(
    State(state): State<WebState>,
    headers: HeaderMap,
    Path(operation_id): Path<String>,
) -> ApiResult<Json<OperationView>> {
    require_mutation(&state, &headers)?;
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
) -> ApiResult<Json<CreateOperationResponse>> {
    require_mutation(&state, &headers)?;
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
    let config = operation
        .config
        .lock()
        .map_err(|_| ApiError::internal())?
        .clone()
        .ok_or_else(ApiError::internal)?;
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
    tokio::spawn(async move {
        run_onboard_operation(task_state.clone(), task_operation, config, Some(checkpoint)).await;
        release_operation_lock(&task_state, &task_operation_id);
    });
    Ok(Json(CreateOperationResponse {
        operation_id,
        status: OperationStatus::Running,
    }))
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
    Ok(DeploymentConfig {
        source_url: required(&payload.source_url, "source_url")?,
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
        target: Target::Ssh {
            destination: required(&payload.ssh_destination, "ssh_destination")?,
        },
        newapi_admin_username: required(&payload.newapi_admin_username, "newapi_admin_username")?,
        newapi_admin_password: payload.newapi_admin_password.clone(),
        kuma_admin_username: required(&payload.kuma_admin_username, "kuma_admin_username")?,
        kuma_admin_password: payload.kuma_admin_password.clone(),
        image: required(&payload.image, "image")?,
        image_ref: payload.image_ref.clone().unwrap_or_default(),
        ..DeploymentConfig::default()
    })
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
        result,
        credentials,
    })
}

async fn run_onboard_operation(
    state: WebState,
    operation: Arc<WebOperation>,
    mut config: DeploymentConfig,
    resume: Option<OperationCheckpoint>,
) {
    let result = async {
        config.normalize();
        config.resolve_passwords();
        config
            .resolve_image_ref()
            .await
            .map_err(crate::application::error::app_error)?;
        config
            .validate()
            .map_err(crate::application::error::app_error)?;
        crate::commands::ensure_compatible_current_deployment(&config)
            .map_err(crate::application::error::app_error)?;
        persist_deployment_config(&config).map_err(crate::application::error::app_error)?;
        let (source, identity) = if resume.is_some() {
            let source = source_for_operation(&config)
                .await
                .map_err(crate::application::error::app_error)?;
            let identity = source.identity().cloned().ok_or_else(|| {
                ApplicationError::new(
                    ErrorCategory::Authentication,
                    "SOURCE_IDENTITY_MISSING",
                    "源站会话没有用户身份",
                    true,
                )
            })?;
            (source, identity)
        } else {
            let (source, identity) = crate::config::authenticate_source(&config)
                .await
                .map_err(crate::application::error::app_error)?;
            persist_source_session(&source).map_err(crate::application::error::app_error)?;
            (source, identity)
        };
        *operation.config.lock().map_err(|_| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "WEB_LOCK_POISONED",
                "本地 Web 服务状态不可用",
                false,
            )
        })? = Some(config.clone());
        let input = config.deployment_input();
        let mut backend = ProductionOnboardBackend::new(config, source, identity);
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
    if let Err(error) = result {
        mark_operation_failed(&operation, &error);
    }
}

async fn run_manage_operation(
    state: WebState,
    operation: Arc<WebOperation>,
    kind: OperationKind,
    payload: CreateOperationRequest,
) {
    let result = async {
        start_manage_checkpoint(&operation)?;
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
                serde_json::to_value(
                    sync_deployment(
                        &config,
                        &mut source,
                        SyncDeploymentRequest {
                            include_pricing: payload.include_pricing,
                            force: payload.force,
                        },
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
        complete_manage_checkpoint(&operation)?;
        *operation.result.lock().map_err(|_| {
            ApplicationError::new(
                ErrorCategory::Internal,
                "WEB_LOCK_POISONED",
                "本地 Web 服务状态不可用",
                false,
            )
        })? = Some(value);
        Ok::<(), ApplicationError>(())
    }
    .await;
    if let Err(error) = result {
        mark_operation_failed(&operation, &error);
    }
    let _ = state;
}

fn start_manage_checkpoint(operation: &WebOperation) -> Result<(), ApplicationError> {
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
    save_web_checkpoint(&checkpoint)
}

fn complete_manage_checkpoint(operation: &WebOperation) -> Result<(), ApplicationError> {
    let mut checkpoint = operation.checkpoint.lock().map_err(|_| {
        ApplicationError::new(
            ErrorCategory::Internal,
            "WEB_LOCK_POISONED",
            "本地 Web 服务状态不可用",
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
    let Some(session) = sessions.get(&session_id) else {
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
    let localhost_origin = format!("http://localhost:{}", state.port);
    if origin != state.origin.as_ref() && origin != localhost_origin {
        return Err(ApiError::forbidden(
            "WEB_ORIGIN_REJECTED",
            "请求来源不是本机 Web 页面",
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
    host == format!("127.0.0.1:{}", state.port) || host == format!("localhost:{}", state.port)
}

fn valid_host_or_error(state: &WebState, headers: &HeaderMap) -> ApiResult<()> {
    if valid_host(state, headers) {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "WEB_HOST_REJECTED",
            "只允许从本机地址访问 Web 服务",
        ))
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

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn acquire_single_instance() -> AppResult<SingleInstanceLock> {
    let root = storage::directory()?;
    fs::create_dir_all(&root).map_err(|error| AppError::WriteFile {
        path: root.clone(),
        source: error,
    })?;
    let path = root.join("webui.lock");
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
    file.try_lock_exclusive()
        .map_err(|_| AppError::Message("已有 WebUI 在运行；请关闭现有窗口后重试".to_owned()))?;
    Ok(SingleInstanceLock { path, file })
}

impl WebState {
    fn bootstrap_token_for_display(&self) -> String {
        self.inner
            .bootstrap_token
            .lock()
            .ok()
            .and_then(|token| token.clone())
            .unwrap_or_default()
    }
}

async fn shutdown_signal() {
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

    fn test_state() -> WebState {
        let directory = tempfile::tempdir().expect("lock directory");
        let path = directory.path().join("webui.lock");
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
            "test-bootstrap-token-123456789012345678901234".to_owned(),
            Arc::new(SingleInstanceLock { path, file }),
        )
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
            .body(Body::from(
                r#"{"token":"test-bootstrap-token-123456789012345678901234"}"#,
            ))
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
            .body(Body::from(
                r#"{"token":"test-bootstrap-token-123456789012345678901234"}"#,
            ))
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
}
