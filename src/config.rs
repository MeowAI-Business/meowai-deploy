use std::{
    env, fmt, fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};

use cliclack::{input, intro, outro, password, select, spinner};
use console::{Term, style};
use rand::{Rng, distributions::Alphanumeric};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    application::{
        input::{self, DeploymentInput, DeploymentTargetInput, InputField, ValidationError},
        operation::CancellationToken,
        source::{self as application_source, SourceAccountRequest},
        target::{
            DeploymentTargetProbeRequest, probe_deployment_connection, probe_deployment_target,
        },
    },
    cli::OnboardArgs,
    error::{AppError, Result},
    platform,
    registry::latest_image_digest,
    source::{SourceAccountMode, SourceClient, SourceIdentity},
};

pub use input::{
    DEFAULT_IMAGE, DEFAULT_KUMA_PORT, DEFAULT_NEWAPI_PORT, DEFAULT_SOURCE_URL, DEFAULT_WEBSITE_NAME,
};

static PROMPT_SECTION: Mutex<Option<String>> = Mutex::new(None);

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeploymentConfig {
    pub source_url: String,
    pub source_account_mode: SourceAccountMode,
    pub source_username: String,
    #[serde(skip)]
    pub source_password: Option<SecretString>,
    pub website_name: String,
    pub container_name: String,
    pub directory: PathBuf,
    pub newapi_bind: String,
    pub kuma_bind: String,
    pub newapi_port: u16,
    pub kuma_port: u16,
    pub target: Target,
    pub newapi_admin_username: String,
    #[serde(skip_serializing)]
    pub newapi_admin_password: Option<String>,
    pub kuma_admin_username: String,
    #[serde(skip_serializing)]
    pub kuma_admin_password: Option<String>,
    pub image: String,
    pub image_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Local,
    Ssh { destination: String },
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            source_url: DEFAULT_SOURCE_URL.to_owned(),
            source_account_mode: SourceAccountMode::Login,
            source_username: String::new(),
            source_password: None,
            website_name: DEFAULT_WEBSITE_NAME.to_owned(),
            container_name: input::DEFAULT_CONTAINER_NAME.to_owned(),
            directory: PathBuf::from(input::DEFAULT_DIRECTORY),
            newapi_bind: input::DEFAULT_BIND.to_owned(),
            kuma_bind: input::DEFAULT_BIND.to_owned(),
            newapi_port: DEFAULT_NEWAPI_PORT,
            kuma_port: DEFAULT_KUMA_PORT,
            target: Target::Local,
            newapi_admin_username: input::DEFAULT_ADMIN_USERNAME.to_owned(),
            newapi_admin_password: None,
            kuma_admin_username: input::DEFAULT_ADMIN_USERNAME.to_owned(),
            kuma_admin_password: None,
            image: DEFAULT_IMAGE.to_owned(),
            image_ref: String::new(),
        }
    }
}

impl DeploymentConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|source| AppError::ReadFile {
            path: path.to_owned(),
            source,
        })?;
        toml::from_str(&content).map_err(AppError::from)
    }

    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(AppError::from)
    }

    pub fn write_template(path: &Path) -> Result<()> {
        let template = r#"# meowai-deploy onboard configuration
source_url = "https://enterprise.meowai.net"
source_account_mode = "login"
source_username = ""
website_name = "Meow AI Downstream"
container_name = "newapi"
directory = "/opt/meowai-deploy/newapi"
newapi_bind = "0.0.0.0"
kuma_bind = "0.0.0.0"
newapi_port = 3000
kuma_port = 3001
target = "local"
newapi_admin_username = "admin"
kuma_admin_username = "admin"
image = "ghcr.io/moorcorpa/new-api-outgap"
# Leave empty to resolve the immutable digest currently published as latest.
image_ref = ""

# Passwords may be supplied through the environment or an interactive prompt.
# Source account password uses MEOWAI_DEPLOY_SOURCE_PASSWORD.
# Do not put secrets in a shared config file.
"#;
        fs::write(path, template).map_err(|source| AppError::WriteFile {
            path: path.to_owned(),
            source,
        })
    }

    pub fn apply_cli_target(&mut self, args: &OnboardArgs) {
        if let Some(destination) = &args.ssh {
            self.target = Target::Ssh {
                destination: destination.clone(),
            };
        } else if args.local {
            self.target = Target::Local;
        }
    }

    pub fn normalize(&mut self) {
        let mut input = self.deployment_input();
        input.normalize();
        self.website_name = input.website_name;
        self.container_name = input.container_name;
        self.directory = input.directory;
    }

    pub fn resolve_passwords(&mut self) {
        if self.source_password.is_none() {
            self.source_password = env::var("MEOWAI_DEPLOY_SOURCE_PASSWORD")
                .ok()
                .map(SecretString::from);
        }
        if self.newapi_admin_password.is_none() {
            self.newapi_admin_password = Some(
                env::var("MEOWAI_DEPLOY_NEWAPI_ADMIN_PASSWORD").unwrap_or_else(|_| random_secret()),
            );
        }
        if self.kuma_admin_password.is_none() {
            self.kuma_admin_password = Some(
                env::var("MEOWAI_DEPLOY_KUMA_ADMIN_PASSWORD").unwrap_or_else(|_| random_secret()),
            );
        }
    }

    pub async fn resolve_image_ref(&mut self) -> Result<()> {
        if self.image_ref.trim().is_empty() {
            self.image_ref = latest_image_digest(&self.image).await?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if matches!(self.target, Target::Local) && !platform::supports_local_target() {
            return Err(AppError::InvalidConfig(
                "Windows 控制端不支持本机部署；请使用 --ssh user@linux-host".to_owned(),
            ));
        }
        self.deployment_input().validate().map_err(invalid_config)
    }

    pub fn deployment_id(&self) -> String {
        let identity = format!(
            "{}\0{}\0{}\0{}",
            self.source_url,
            self.target_label(),
            self.directory.display(),
            self.container_name
        );
        let digest = Sha256::digest(identity.as_bytes());
        digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn target_label(&self) -> String {
        match &self.target {
            Target::Local => "local".to_owned(),
            Target::Ssh { destination } => format!("ssh:{destination}"),
        }
    }

    pub fn deployment_input(&self) -> DeploymentInput {
        DeploymentInput {
            source_url: self.source_url.clone(),
            website_name: self.website_name.clone(),
            container_name: self.container_name.clone(),
            directory: self.directory.clone(),
            newapi_bind: self.newapi_bind.clone(),
            kuma_bind: self.kuma_bind.clone(),
            newapi_port: self.newapi_port,
            kuma_port: self.kuma_port,
            target: match &self.target {
                Target::Local => DeploymentTargetInput::Local,
                Target::Ssh { destination } => DeploymentTargetInput::Ssh {
                    destination: destination.clone(),
                },
            },
            newapi_admin_username: self.newapi_admin_username.clone(),
            kuma_admin_username: self.kuma_admin_username.clone(),
            image: self.image.clone(),
            image_ref: self.image_ref.clone(),
        }
    }
}

impl fmt::Debug for DeploymentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentConfig")
            .field("source_url", &self.source_url)
            .field("source_account_mode", &self.source_account_mode)
            .field("source_username", &self.source_username)
            .field("source_password", &"<redacted>")
            .field("website_name", &self.website_name)
            .field("container_name", &self.container_name)
            .field("directory", &self.directory)
            .field("newapi_bind", &self.newapi_bind)
            .field("kuma_bind", &self.kuma_bind)
            .field("newapi_port", &self.newapi_port)
            .field("kuma_port", &self.kuma_port)
            .field("target", &self.target)
            .field("newapi_admin_username", &self.newapi_admin_username)
            .field("newapi_admin_password", &"<redacted>")
            .field("kuma_admin_username", &self.kuma_admin_username)
            .field("kuma_admin_password", &"<redacted>")
            .field("image", &self.image)
            .field("image_ref", &self.image_ref)
            .finish()
    }
}

impl fmt::Display for DeploymentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "website_name: {}", self.website_name)?;
        writeln!(formatter, "container_name: {}", self.container_name)?;
        writeln!(formatter, "directory: {}", self.directory.display())?;
        writeln!(formatter, "target: {}", self.target_label())?;
        writeln!(formatter, "source_url: {}", self.source_url)?;
        writeln!(formatter, "source_username: {}", self.source_username)?;
        writeln!(
            formatter,
            "source_account_mode: {:?}",
            self.source_account_mode
        )?;
        writeln!(
            formatter,
            "newapi: {}:{}",
            self.newapi_bind, self.newapi_port
        )?;
        writeln!(
            formatter,
            "uptime_kuma: {}:{}",
            self.kuma_bind, self.kuma_port
        )?;
        writeln!(formatter, "image: {}@{}", self.image, self.image_ref)?;
        write!(formatter, "admin_passwords: resolved at runtime")
    }
}

pub async fn interactive_config(
    args: &OnboardArgs,
) -> Result<(
    DeploymentConfig,
    SourceClient,
    SourceIdentity,
    Option<SecretString>,
)> {
    if args.config.is_some() {
        return Err(AppError::InvalidConfig(
            "interactive_config cannot load a config file".to_owned(),
        ));
    }
    prompt_config(args).await
}

pub async fn authenticate_source(
    config: &DeploymentConfig,
) -> Result<(SourceClient, SourceIdentity)> {
    let password = config.source_password.clone().ok_or_else(|| {
        AppError::InvalidConfig(
            "source password is required; set MEOWAI_DEPLOY_SOURCE_PASSWORD or use the prompt"
                .to_owned(),
        )
    })?;
    let request = SourceAccountRequest::new(
        config.source_url.clone(),
        config.source_account_mode,
        config.source_username.clone(),
        password,
    )?;
    let authenticated = match config.source_account_mode {
        SourceAccountMode::Login => application_source::login_source_account(request).await?,
        SourceAccountMode::Register => application_source::register_source_account(request).await?,
    };
    Ok((authenticated.client, authenticated.identity))
}

pub async fn reauthenticate_source(
    config: &DeploymentConfig,
) -> Result<(SourceClient, SourceIdentity)> {
    let mut account_error = None;
    loop {
        prompt_screen("源站重新登录")?;
        let label = retry_label(
            &format!("{} 的源站密码", config.source_username),
            account_error.as_deref(),
            3,
        )?;
        let source_password = prompt_io(password(label).mask('•').interact())?;
        let request = match SourceAccountRequest::new(
            config.source_url.clone(),
            SourceAccountMode::Login,
            config.source_username.clone(),
            SecretString::from(source_password),
        ) {
            Ok(request) => request,
            Err(_) => {
                account_error = Some("密码长度不符合要求".to_owned());
                continue;
            }
        };
        match application_source::login_source_account(request).await {
            Ok(authenticated) => {
                redraw_success(
                    "源站账号",
                    &config.source_username,
                    "登录成功 · 已获上游批准",
                    3,
                )?;
                finish_prompt_flow()?;
                return Ok((authenticated.client, authenticated.identity));
            }
            Err(_) => {
                account_error = Some("登录失败，请检查密码".to_owned());
            }
        }
    }
}

async fn prompt_config(
    args: &OnboardArgs,
) -> Result<(
    DeploymentConfig,
    SourceClient,
    SourceIdentity,
    Option<SecretString>,
)> {
    prompt_screen("部署位置")?;
    let target = if cfg!(windows) || args.ssh.is_some() {
        "ssh".to_owned()
    } else if args.local {
        "local".to_owned()
    } else {
        prompt_io(
            select("部署方式")
                .item("local".to_owned(), "本机", "直接在当前服务器运行")
                .item("ssh".to_owned(), "SSH 远程", "连接 user@host 目标服务器")
                .initial_value("local".to_owned())
                .interact(),
        )?
    };
    let (target, ssh_password) = if target == "ssh" {
        let destination = if let Some(destination) = &args.ssh {
            destination.clone()
        } else {
            prompt_screen("部署位置")?;
            prompt_io(input("SSH 目标（user@host）").interact())?
        };
        input::validate_ssh_destination(&destination).map_err(invalid_config)?;
        prompt_screen("部署位置")?;
        let password = prompt_io(
            password("SSH 密码（可选）")
                .mask('•')
                .allow_empty()
                .interact(),
        )?;
        let password = (!password.is_empty()).then(|| SecretString::from(password));
        let target = Target::Ssh { destination };
        let progress = spinner();
        progress.start("正在预检 SSH 连接");
        let result = probe_deployment_connection(
            deployment_target_input(&target),
            password.clone(),
            &CancellationToken::default(),
        );
        match result {
            Ok(_) => progress.stop("SSH 连接可用"),
            Err(error) => {
                progress.error("SSH 连接不可用");
                return Err(error.into());
            }
        }
        (target, password)
    } else {
        let target = Target::Local;
        let progress = spinner();
        progress.start("正在预检本机连接");
        probe_deployment_connection(
            deployment_target_input(&target),
            None,
            &CancellationToken::default(),
        )
        .map_err(|error| {
            progress.error("本机连接不可用");
            AppError::from(error)
        })?;
        progress.stop("本机连接可用");
        (target, None)
    };

    let mut source_error = None;
    let source_url = loop {
        prompt_screen("源站账号")?;
        let label = retry_label("源站 URL", source_error.as_deref(), 3)?;
        let source_url: String =
            prompt_io(input(label).default_input(DEFAULT_SOURCE_URL).interact())?;
        if input::validate_source_url(&source_url).is_err() {
            source_error = Some("URL 格式无效".to_owned());
            continue;
        }
        match application_source::probe_source_url(&source_url).await {
            Ok(_) => {
                redraw_success("源站 URL", &source_url, "可连通", 3)?;
                break source_url;
            }
            Err(_) => {
                source_error = Some("无法连通，请检查地址和网络".to_owned());
            }
        }
    };
    prompt_screen("源站账号")?;
    let source_account_mode: SourceAccountMode = prompt_io(
        select("账号操作")
            .item(
                SourceAccountMode::Login,
                "登录已有账号",
                "使用源站现有普通账号",
            )
            .item(
                SourceAccountMode::Register,
                "注册新账号",
                "在源站创建普通账号后继续",
            )
            .initial_value(SourceAccountMode::Login)
            .interact(),
    )?;
    let mut account_error = None;
    let (source_username, source_password, source, identity) = loop {
        prompt_screen("源站账号")?;
        let username_label = retry_label("源站用户名", account_error.as_deref(), 6)?;
        let source_username: String = prompt_io(input(username_label).interact())?;
        prompt_screen("源站账号")?;
        let source_password = prompt_io(password("源站密码").mask('•').interact())?;
        let request = match SourceAccountRequest::new(
            source_url.clone(),
            source_account_mode,
            source_username.clone(),
            SecretString::from(source_password.clone()),
        ) {
            Ok(request) => request,
            Err(_) => {
                account_error = Some("账号长度或密码长度不符合要求".to_owned());
                continue;
            }
        };
        let authenticated = match source_account_mode {
            SourceAccountMode::Login => application_source::login_source_account(request).await,
            SourceAccountMode::Register => {
                application_source::register_source_account(request).await
            }
        };
        match authenticated {
            Ok(authenticated) => {
                let status = if source_account_mode == SourceAccountMode::Register {
                    "注册成功 · 已获上游批准"
                } else {
                    "登录成功 · 已获上游批准"
                };
                redraw_success("源站账号", &source_username, status, 6)?;
                break (
                    source_username,
                    Some(source_password),
                    authenticated.client,
                    authenticated.identity,
                );
            }
            Err(_) => {
                account_error = Some("登录/注册失败，请检查账号密码".to_owned());
            }
        }
    };

    prompt_screen("站点设置")?;
    let website_name: String = prompt_io(
        input("网站名称")
            .default_input(DEFAULT_WEBSITE_NAME)
            .interact(),
    )?;
    let container_name = prompt_container_name()?;
    let default_directory = format!("/opt/meowai-deploy/{container_name}");
    let directory = prompt_directory(&default_directory, matches!(&target, Target::Ssh { .. }))?;
    let newapi_bind = prompt_bind("站点设置", "New API 监听地址")?;
    let kuma_bind = prompt_bind("站点设置", "Uptime Kuma 监听地址")?;
    let newapi_port = prompt_port("站点设置", "New API 端口", DEFAULT_NEWAPI_PORT)?;
    let kuma_port = prompt_port("站点设置", "Uptime Kuma 端口", DEFAULT_KUMA_PORT)?;

    let progress = spinner();
    progress.start("正在预检部署目录、Docker 和端口");
    probe_deployment_target(
        DeploymentTargetProbeRequest {
            target: deployment_target_input(&target),
            directory: directory.clone(),
            newapi_port,
            kuma_port,
            ssh_password: ssh_password.clone(),
        },
        &CancellationToken::default(),
    )
    .map_err(|error| {
        progress.error("目标环境预检失败");
        AppError::from(error)
    })?;
    progress.stop("部署目录、Docker 和端口可用");

    let newapi_admin_username =
        prompt_username("管理员凭证", "New API 管理员用户名", "admin", Some(12))?;
    let newapi_admin_password = Some(prompt_secret("管理员凭证", "New API 管理员密码")?);
    let kuma_admin_username =
        prompt_username("管理员凭证", "Uptime Kuma 管理员用户名", "admin", None)?;
    let kuma_admin_password = Some(prompt_secret("管理员凭证", "Uptime Kuma 管理员密码")?);
    prompt_screen("镜像版本")?;
    let image_input: String = prompt_io(input("容器镜像").default_input(DEFAULT_IMAGE).interact())?;
    let image = image_input.trim().to_owned();
    let image_ref = prompt_image_ref("镜像版本", &image).await?;
    let mut config = DeploymentConfig {
        source_url,
        source_account_mode,
        source_username,
        source_password: source_password.map(SecretString::from),
        website_name,
        container_name,
        directory,
        newapi_bind,
        kuma_bind,
        newapi_port,
        kuma_port,
        target,
        newapi_admin_username,
        newapi_admin_password,
        kuma_admin_username,
        kuma_admin_password,
        image,
        image_ref,
        ..DeploymentConfig::default()
    };
    config.normalize();
    config.validate()?;
    finish_prompt_flow()?;
    Ok((config, source, identity, ssh_password))
}

fn deployment_target_input(target: &Target) -> DeploymentTargetInput {
    match target {
        Target::Local => DeploymentTargetInput::Local,
        Target::Ssh { destination } => DeploymentTargetInput::Ssh {
            destination: destination.clone(),
        },
    }
}

fn prompt_container_name() -> Result<String> {
    let mut error = None;
    loop {
        prompt_screen("站点设置")?;
        let label = retry_label("容器名", error.as_deref(), 3)?;
        let value: String = prompt_io(input(label).default_input("newapi").interact())?;
        match validate_identifier("container_name", &value) {
            Ok(()) => {
                redraw_success("容器名", &value, "格式有效", 3)?;
                return Ok(value);
            }
            Err(_) => {
                error = Some("只能使用字母、数字、-、_、.，最长 63 个字符".to_owned());
            }
        }
    }
}

fn prompt_directory(default: &str, remote: bool) -> Result<PathBuf> {
    let mut error = None;
    loop {
        prompt_screen("站点设置")?;
        let label = retry_label("部署目录", error.as_deref(), 3)?;
        let value: String = prompt_io(input(label).default_input(default).interact())?;
        let directory = PathBuf::from(value);
        let validation = if remote || cfg!(windows) {
            input::validate_remote_directory(&directory).map_err(invalid_config)
        } else {
            validate_directory(&directory)
        };
        match validation {
            Ok(()) => {
                redraw_success("部署目录", &directory.display().to_string(), "路径有效", 3)?;
                return Ok(directory);
            }
            Err(_) => {
                error = Some("必须是安全的绝对路径".to_owned());
            }
        }
    }
}

fn prompt_username(
    section: &str,
    label: &str,
    default: &str,
    max_length: Option<usize>,
) -> Result<String> {
    let mut error = None;
    loop {
        prompt_screen(section)?;
        let prompt = retry_label(label, error.as_deref(), 3)?;
        let value: String = prompt_io(input(prompt).default_input(default).interact())?;
        if max_length.is_none_or(|limit| value.len() <= limit) {
            if max_length.is_some() {
                redraw_success(label, &value, "格式有效", 3)?;
            }
            return Ok(value);
        }
        error = Some(format!("不能超过 {} 个字符", max_length.unwrap_or(0)));
    }
}

fn prompt_secret(section: &str, label: &str) -> Result<String> {
    prompt_screen(section)?;
    let mode: String = prompt_io(
        select(format!("{label} · 密码来源"))
            .item("random".to_owned(), "随机生成", "推荐：安全随机值")
            .item("manual".to_owned(), "手动输入", "密码不会回显")
            .initial_value("random".to_owned())
            .interact(),
    )?;
    if mode == "random" {
        Ok(random_secret())
    } else {
        prompt_screen(section)?;
        prompt_io(password(label).mask('•').interact())
    }
}

fn prompt_bind(section: &str, label: &str) -> Result<String> {
    prompt_screen(section)?;
    prompt_io(
        select(label)
            .item("0.0.0.0".to_owned(), "0.0.0.0", "公网开放（默认）")
            .item("127.0.0.1".to_owned(), "127.0.0.1", "仅本机访问")
            .initial_value("0.0.0.0".to_owned())
            .interact(),
    )
}

fn prompt_port(section: &str, label: &str, default: u16) -> Result<u16> {
    let mut error = None;
    loop {
        prompt_screen(section)?;
        let default_value = default.to_string();
        let prompt = retry_label(label, error.as_deref(), 3)?;
        let value: String = prompt_io(input(prompt).default_input(&default_value).interact())?;
        let requested = match value.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => {
                error = Some("必须是 1-65535 的端口".to_owned());
                continue;
            }
        };
        redraw_success(label, &value, "格式有效，稍后检查目标端口", 3)?;
        return Ok(requested);
    }
}

async fn prompt_image_ref(section: &str, image: &str) -> Result<String> {
    prompt_screen(section)?;
    let mut latest = fetch_latest_image_digest(image).await;
    let mut error = latest
        .as_ref()
        .err()
        .map(|error| format!("最新构建获取失败：{error}；手动输入，或留空重试"));
    loop {
        prompt_screen(section)?;
        let label = retry_label("上游 commit SHA/digest", error.as_deref(), 3)?;
        let image_ref: String = if let Ok(digest) = &latest {
            prompt_io(input(label).default_input(digest).interact())?
        } else {
            prompt_io(input(label).required(false).interact())?
        };
        if image_ref.trim().is_empty() {
            latest = fetch_latest_image_digest(image).await;
            error = latest
                .as_ref()
                .err()
                .map(|error| format!("最新构建获取失败：{error}；手动输入，或留空重试"));
            continue;
        }
        if is_immutable_image_ref(&image_ref) {
            let status = if latest.as_ref().is_ok_and(|digest| digest == &image_ref) {
                "最新成功构建"
            } else {
                "格式有效"
            };
            redraw_success("上游 commit SHA/digest", &image_ref, status, 3)?;
            return Ok(image_ref);
        }
        error = Some("必须是 7-64 位十六进制 SHA 或 sha256 digest".to_owned());
    }
}

async fn fetch_latest_image_digest(image: &str) -> Result<String> {
    let progress = spinner();
    progress.start("正在获取上游最新成功构建镜像");
    match latest_image_digest(image).await {
        Ok(digest) => {
            progress.stop("已获取上游最新成功构建镜像");
            Ok(digest)
        }
        Err(error) => {
            progress.error("获取上游最新成功构建镜像失败");
            Err(error)
        }
    }
}

fn prompt_io<T>(result: io::Result<T>) -> Result<T> {
    result.map_err(AppError::from_prompt)
}

fn retry_label(label: &str, error: Option<&str>, lines_to_replace: usize) -> Result<String> {
    if let Some(error) = error {
        Term::stderr()
            .clear_last_lines(lines_to_replace)
            .map_err(AppError::from_prompt)?;
        Ok(format!("{label} {}", style(format!("· {error}")).red()))
    } else {
        Ok(label.to_owned())
    }
}

fn redraw_success(label: &str, value: &str, status: &str, lines_to_replace: usize) -> Result<()> {
    let term = Term::stderr();
    term.clear_last_lines(lines_to_replace)
        .map_err(AppError::from_prompt)?;
    term.write_line(&format!(
        "{}  {label} {}",
        style("◇").green(),
        style(format!("· {status}")).green()
    ))
    .map_err(AppError::from_prompt)?;
    term.write_line(&format!("{}  {}", style("│").dim(), style(value).dim()))
        .map_err(AppError::from_prompt)?;
    term.write_line(&style("│").dim().to_string())
        .map_err(AppError::from_prompt)
}

fn prompt_screen(section: &str) -> Result<()> {
    let mut current = PROMPT_SECTION
        .lock()
        .map_err(|_| AppError::Message("prompt section state is unavailable".to_owned()))?;
    if current.as_deref() != Some(section) {
        if let Some(previous) = current.as_deref() {
            prompt_io(outro(format!("{previous}配置完成")))?;
            println!();
        }
        prompt_io(intro(format!("meowai-deploy · {section}")))?;
        *current = Some(section.to_owned());
    }
    Ok(())
}

fn finish_prompt_flow() -> Result<()> {
    let mut current = PROMPT_SECTION
        .lock()
        .map_err(|_| AppError::Message("prompt section state is unavailable".to_owned()))?;
    if current.take().is_some() {
        prompt_io(outro("配置输入完成"))?;
        println!();
    }
    Ok(())
}

fn validate_directory(directory: &Path) -> Result<()> {
    input::validate_directory(directory).map_err(invalid_config)
}

fn is_immutable_image_ref(value: &str) -> bool {
    input::is_immutable_image_ref(value)
}

pub fn random_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    let field = match field {
        "container_name" => InputField::ContainerName,
        _ => InputField::ContainerName,
    };
    input::validate_identifier(field, value).map_err(invalid_config)
}

fn invalid_config(error: ValidationError) -> AppError {
    AppError::InvalidConfig(error.message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::SourceCredentials;

    #[test]
    fn defaults_are_deploy_defaults() {
        let mut config = DeploymentConfig::default();
        assert_eq!(config.website_name, DEFAULT_WEBSITE_NAME);
        config.website_name.clear();
        config.normalize();
        config.image_ref =
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_owned();
        assert_eq!(config.container_name, "newapi");
        assert_eq!(config.website_name, DEFAULT_WEBSITE_NAME);
        assert_eq!(config.newapi_port, DEFAULT_NEWAPI_PORT);
        assert_eq!(config.kuma_port, DEFAULT_KUMA_PORT);
        if cfg!(windows) {
            config.target = Target::Ssh {
                destination: "deploy@example.test".to_owned(),
            };
        }
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_ports_and_unsafe_container_names() {
        let mut config = DeploymentConfig::default();
        config.normalize();
        config.kuma_port = config.newapi_port;
        assert!(config.validate().is_err());
        config.kuma_port = DEFAULT_KUMA_PORT;
        config.container_name = "bad/name".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn debug_output_redacts_admin_passwords() {
        let config = DeploymentConfig {
            newapi_admin_password: Some("newapi-secret".to_owned()),
            kuma_admin_password: Some("kuma-secret".to_owned()),
            source_username: "source-user".to_owned(),
            source_password: Some(SecretString::from("source-secret".to_owned())),
            ..DeploymentConfig::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("newapi-secret"));
        assert!(!debug.contains("kuma-secret"));
        assert!(!debug.contains("source-secret"));
        assert!(debug.contains("<redacted>"));
        let serialized = toml::to_string(&config).expect("serialize non-secret config");
        assert!(!serialized.contains("source-secret"));
        assert!(!serialized.contains("source_password"));
    }

    #[test]
    fn source_credentials_follow_source_validation_limits() {
        let short =
            SourceCredentials::new("valid-user", SecretString::from("valid-pass".to_owned()));
        assert!(short.is_ok());
        assert!(
            SourceCredentials::new(
                "this-username-is-too-long",
                SecretString::from("valid-pass".to_owned())
            )
            .is_err()
        );
        assert!(
            SourceCredentials::new("valid-user", SecretString::from("tiny".to_owned())).is_err()
        );
    }

    #[test]
    fn deployment_id_is_stable_for_the_same_target() {
        let mut first = DeploymentConfig::default();
        first.normalize();
        let mut second = first.clone();
        assert_eq!(first.deployment_id(), second.deployment_id());
        second.container_name = "other".to_owned();
        assert_ne!(first.deployment_id(), second.deployment_id());
    }
}
