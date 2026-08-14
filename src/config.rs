use std::{
    env, fmt, fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
};

use cliclack::{input, intro, log, outro, password, select};
use rand::{Rng, distributions::Alphanumeric};
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{
    cli::OnboardArgs,
    error::{AppError, Result},
};

pub const DEFAULT_SOURCE_URL: &str = "https://enterprise.meowai.net";
pub const DEFAULT_NEWAPI_PORT: u16 = 3000;
pub const DEFAULT_KUMA_PORT: u16 = 3001;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeploymentConfig {
    pub source_url: String,
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
            website_name: String::new(),
            container_name: "newapi".to_owned(),
            directory: PathBuf::from("/opt/meowai-deploy/newapi"),
            newapi_bind: "0.0.0.0".to_owned(),
            kuma_bind: "0.0.0.0".to_owned(),
            newapi_port: DEFAULT_NEWAPI_PORT,
            kuma_port: DEFAULT_KUMA_PORT,
            target: Target::Local,
            newapi_admin_username: "admin".to_owned(),
            newapi_admin_password: None,
            kuma_admin_username: "admin".to_owned(),
            kuma_admin_password: None,
            image: "ghcr.io/moorcorpa/new-api-outgap".to_owned(),
            image_ref: "current-commit-or-digest".to_owned(),
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

    pub fn write_template(path: &Path) -> Result<()> {
        let template = r#"# meowai-deploy onboard configuration
source_url = "https://enterprise.meowai.net"
website_name = ""
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
image_ref = "current-commit-or-digest"

# Passwords may be supplied through the environment or an interactive prompt.
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
        if self.website_name.trim().is_empty() {
            self.website_name = self.container_name.clone();
        }
        if self.directory.as_os_str().is_empty() {
            self.directory = PathBuf::from(format!("/opt/meowai-deploy/{}", self.container_name));
        }
    }

    pub fn resolve_passwords(&mut self) {
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

    pub fn validate(&self) -> Result<()> {
        Url::parse(&self.source_url)
            .map_err(|_| AppError::InvalidConfig("source_url must be a valid URL".to_owned()))?;
        if self.website_name.trim().is_empty() {
            return Err(AppError::InvalidConfig(
                "website_name cannot be empty".to_owned(),
            ));
        }
        validate_identifier("container_name", &self.container_name)?;
        validate_bind("newapi_bind", &self.newapi_bind)?;
        validate_bind("kuma_bind", &self.kuma_bind)?;
        if self.newapi_port == 0 || self.kuma_port == 0 {
            return Err(AppError::InvalidConfig(
                "ports must be between 1 and 65535".to_owned(),
            ));
        }
        if self.newapi_port == self.kuma_port {
            return Err(AppError::InvalidConfig(
                "New API and Kuma ports must be different".to_owned(),
            ));
        }
        if self.newapi_admin_username.trim().is_empty()
            || self.kuma_admin_username.trim().is_empty()
        {
            return Err(AppError::InvalidConfig(
                "administrator usernames cannot be empty".to_owned(),
            ));
        }
        if self.image.trim().is_empty() || self.image_ref.trim().is_empty() {
            return Err(AppError::InvalidConfig(
                "image and image_ref cannot be empty".to_owned(),
            ));
        }
        if matches!(self.image_ref.as_str(), "latest" | "main" | "master") {
            return Err(AppError::InvalidConfig(
                "image_ref must be a commit SHA or digest, not a mutable tag".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn target_label(&self) -> String {
        match &self.target {
            Target::Local => "local".to_owned(),
            Target::Ssh { destination } => format!("ssh:{destination}"),
        }
    }
}

impl fmt::Debug for DeploymentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeploymentConfig")
            .field("source_url", &self.source_url)
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

pub async fn interactive_config(args: &OnboardArgs) -> Result<DeploymentConfig> {
    let mut config = if let Some(path) = &args.config {
        DeploymentConfig::from_file(path)?
    } else {
        prompt_config()?
    };
    config.apply_cli_target(args);
    config.normalize();
    config.validate()?;
    Ok(config)
}

fn prompt_config() -> Result<DeploymentConfig> {
    prompt_io(intro("meowai-deploy  ·  onboard"))?;
    prompt_io(log::step("项目身份"))?;
    let website_name: String = prompt_io(
        input("网站名称")
            .placeholder("例如：Acme AI（回车使用容器名）")
            .required(false)
            .interact(),
    )?;
    let container_name: String = prompt_io(input("容器名").default_input("newapi").interact())?;
    let default_directory = format!("/opt/meowai-deploy/{container_name}");
    let directory_value: String = prompt_io(
        input("部署目录")
            .default_input(&default_directory)
            .interact(),
    )?;
    let directory = PathBuf::from(directory_value);
    prompt_io(log::step("网络与目标"))?;
    let newapi_bind = prompt_bind("New API 监听地址")?;
    let kuma_bind = prompt_bind("Uptime Kuma 监听地址")?;
    let newapi_port = prompt_port("New API 端口", DEFAULT_NEWAPI_PORT)?;
    let kuma_port = prompt_port("Uptime Kuma 端口", DEFAULT_KUMA_PORT)?;
    let source_url: String = prompt_io(
        input("源站 URL")
            .default_input(DEFAULT_SOURCE_URL)
            .interact(),
    )?;
    let target: String = prompt_io(
        select("部署方式")
            .item("local".to_owned(), "本机", "直接在当前服务器运行")
            .item("ssh".to_owned(), "SSH 远程", "连接 user@host 目标服务器")
            .initial_value("local".to_owned())
            .interact(),
    )?;
    let target = if target == "ssh" {
        let destination: String = prompt_io(input("SSH 目标（user@host）").interact())?;
        Target::Ssh { destination }
    } else {
        Target::Local
    };
    prompt_io(log::step("管理员凭证"))?;
    let newapi_admin_username = prompt_username("New API 管理员用户名", "admin")?;
    let newapi_admin_password = Some(prompt_secret("New API 管理员密码")?);
    let kuma_admin_username = prompt_username("Uptime Kuma 管理员用户名", "admin")?;
    let kuma_admin_password = Some(prompt_secret("Uptime Kuma 管理员密码")?);
    let config = DeploymentConfig {
        source_url,
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
        ..DeploymentConfig::default()
    };
    prompt_io(outro("配置输入完成"))?;
    Ok(config)
}

fn prompt_username(label: &str, default: &str) -> Result<String> {
    prompt_io(input(label).default_input(default).interact())
}

fn prompt_secret(label: &str) -> Result<String> {
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
        prompt_io(password(label).mask('•').interact())
    }
}

fn prompt_bind(label: &str) -> Result<String> {
    prompt_io(
        select(label)
            .item("0.0.0.0".to_owned(), "0.0.0.0", "公网开放（默认）")
            .item("127.0.0.1".to_owned(), "127.0.0.1", "仅本机访问")
            .initial_value("0.0.0.0".to_owned())
            .interact(),
    )
}

fn prompt_port(label: &str, default: u16) -> Result<u16> {
    let default_value = default.to_string();
    let value: String = prompt_io(input(label).default_input(&default_value).interact())?;
    value.parse::<u16>().map_err(|_| {
        AppError::InvalidConfig(format!("{label} must be a number between 1 and 65535"))
    })
}

fn prompt_io<T>(result: io::Result<T>) -> Result<T> {
    result.map_err(AppError::from_prompt)
}

pub fn random_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn validate_identifier(field: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(AppError::InvalidConfig(format!(
            "{field} must contain only ASCII letters, digits, '-', '_' or '.' and be at most 63 characters"
        )));
    }
    Ok(())
}

fn validate_bind(field: &str, value: &str) -> Result<()> {
    value
        .parse::<IpAddr>()
        .map_err(|_| AppError::InvalidConfig(format!("{field} must be an IP address")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_deploy_defaults() {
        let mut config = DeploymentConfig::default();
        config.normalize();
        assert_eq!(config.container_name, "newapi");
        assert_eq!(config.website_name, "newapi");
        assert_eq!(config.newapi_port, DEFAULT_NEWAPI_PORT);
        assert_eq!(config.kuma_port, DEFAULT_KUMA_PORT);
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
            ..DeploymentConfig::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("newapi-secret"));
        assert!(!debug.contains("kuma-secret"));
        assert!(debug.contains("<redacted>"));
    }
}
