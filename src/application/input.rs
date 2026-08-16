use std::{
    fmt,
    net::IpAddr,
    path::{Component, PathBuf},
};

use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::target::remote_path::RemotePath;

pub const DEFAULT_SOURCE_URL: &str = "https://enterprise.meowai.net";
pub const DEFAULT_WEBSITE_NAME: &str = "Meow AI Downstream";
pub const DEFAULT_CONTAINER_NAME: &str = "newapi";
pub const DEFAULT_DIRECTORY: &str = "/opt/meowai-deploy/newapi";
pub const DEFAULT_BIND: &str = "0.0.0.0";
pub const DEFAULT_NEWAPI_PORT: u16 = 3000;
pub const DEFAULT_KUMA_PORT: u16 = 3001;
pub const DEFAULT_ADMIN_USERNAME: &str = "admin";
pub const DEFAULT_IMAGE: &str = "ghcr.io/moorcorpa/new-api-outgap";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentTargetInput {
    Local,
    Ssh { destination: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeploymentInput {
    pub source_url: String,
    pub website_name: String,
    pub container_name: String,
    pub directory: PathBuf,
    pub newapi_bind: String,
    pub kuma_bind: String,
    pub newapi_port: u16,
    pub kuma_port: u16,
    pub target: DeploymentTargetInput,
    pub newapi_admin_username: String,
    pub kuma_admin_username: String,
    pub image: String,
    pub image_ref: String,
}

impl Default for DeploymentInput {
    fn default() -> Self {
        Self {
            source_url: DEFAULT_SOURCE_URL.to_owned(),
            website_name: DEFAULT_WEBSITE_NAME.to_owned(),
            container_name: DEFAULT_CONTAINER_NAME.to_owned(),
            directory: PathBuf::from(DEFAULT_DIRECTORY),
            newapi_bind: DEFAULT_BIND.to_owned(),
            kuma_bind: DEFAULT_BIND.to_owned(),
            newapi_port: DEFAULT_NEWAPI_PORT,
            kuma_port: DEFAULT_KUMA_PORT,
            target: DeploymentTargetInput::Local,
            newapi_admin_username: DEFAULT_ADMIN_USERNAME.to_owned(),
            kuma_admin_username: DEFAULT_ADMIN_USERNAME.to_owned(),
            image: DEFAULT_IMAGE.to_owned(),
            image_ref: String::new(),
        }
    }
}

impl DeploymentInput {
    pub fn normalize(&mut self) {
        if self.website_name.trim().is_empty() {
            self.website_name = DEFAULT_WEBSITE_NAME.to_owned();
        }
        if self.directory.as_os_str().is_empty() {
            self.directory = PathBuf::from(format!("/opt/meowai-deploy/{}", self.container_name));
        }
    }

    pub fn validate(&self) -> ValidationResult<()> {
        validate_source_url(&self.source_url)?;
        if self.website_name.trim().is_empty() {
            return Err(ValidationError::new(
                ValidationCode::EmptyWebsiteName,
                InputField::WebsiteName,
                "website_name cannot be empty",
            ));
        }
        validate_identifier(InputField::ContainerName, &self.container_name)?;
        match &self.target {
            DeploymentTargetInput::Local => validate_directory(&self.directory)?,
            DeploymentTargetInput::Ssh { .. } => validate_remote_directory(&self.directory)?,
        }
        validate_bind(InputField::NewApiBind, &self.newapi_bind)?;
        validate_bind(InputField::KumaBind, &self.kuma_bind)?;
        validate_ports(self.newapi_port, self.kuma_port)?;
        if self.newapi_admin_username.trim().is_empty()
            || self.kuma_admin_username.trim().is_empty()
        {
            return Err(ValidationError::new(
                ValidationCode::InvalidAdminUsername,
                if self.newapi_admin_username.trim().is_empty() {
                    InputField::NewApiAdminUsername
                } else {
                    InputField::KumaAdminUsername
                },
                "administrator usernames cannot be empty",
            ));
        }
        if self.newapi_admin_username.len() > 12 {
            return Err(ValidationError::new(
                ValidationCode::InvalidAdminUsername,
                InputField::NewApiAdminUsername,
                "New API administrator username must not exceed 12 characters",
            ));
        }
        if self.image.trim().is_empty() || self.image_ref.trim().is_empty() {
            return Err(ValidationError::new(
                if self.image.trim().is_empty() {
                    ValidationCode::EmptyImage
                } else {
                    ValidationCode::InvalidImageRef
                },
                if self.image.trim().is_empty() {
                    InputField::Image
                } else {
                    InputField::ImageRef
                },
                "image and image_ref cannot be empty",
            ));
        }
        validate_image_ref(&self.image_ref)?;
        if let DeploymentTargetInput::Ssh { destination } = &self.target {
            validate_ssh_destination(destination)?;
        }
        Ok(())
    }
}

pub type ValidationResult<T> = std::result::Result<T, ValidationError>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationCode {
    InvalidSourceUrl,
    EmptyWebsiteName,
    InvalidIdentifier,
    InvalidDirectory,
    InvalidBindAddress,
    InvalidPort,
    DuplicatePort,
    InvalidAdminUsername,
    EmptyImage,
    InvalidImageRef,
    InvalidSshDestination,
}

impl ValidationCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSourceUrl => "INVALID_SOURCE_URL",
            Self::EmptyWebsiteName => "EMPTY_WEBSITE_NAME",
            Self::InvalidIdentifier => "INVALID_IDENTIFIER",
            Self::InvalidDirectory => "INVALID_DIRECTORY",
            Self::InvalidBindAddress => "INVALID_BIND_ADDRESS",
            Self::InvalidPort => "INVALID_PORT",
            Self::DuplicatePort => "DUPLICATE_PORT",
            Self::InvalidAdminUsername => "INVALID_ADMIN_USERNAME",
            Self::EmptyImage => "EMPTY_IMAGE",
            Self::InvalidImageRef => "INVALID_IMAGE_REF",
            Self::InvalidSshDestination => "INVALID_SSH_DESTINATION",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InputField {
    SourceUrl,
    WebsiteName,
    ContainerName,
    Directory,
    NewApiBind,
    KumaBind,
    NewApiPort,
    KumaPort,
    Target,
    NewApiAdminUsername,
    KumaAdminUsername,
    Image,
    ImageRef,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ValidationError {
    pub code: ValidationCode,
    pub field: InputField,
    pub message: String,
    pub retryable: bool,
}

impl ValidationError {
    fn new(code: ValidationCode, field: InputField, message: impl Into<String>) -> Self {
        Self {
            code,
            field,
            message: message.into(),
            retryable: true,
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_source_url(value: &str) -> ValidationResult<()> {
    let parsed = Url::parse(value).map_err(|_| {
        ValidationError::new(
            ValidationCode::InvalidSourceUrl,
            InputField::SourceUrl,
            "source_url must be a valid URL",
        )
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ValidationError::new(
            ValidationCode::InvalidSourceUrl,
            InputField::SourceUrl,
            "source_url must use http or https",
        ));
    }
    if parsed.scheme() != "https" && !is_loopback(&parsed) {
        return Err(ValidationError::new(
            ValidationCode::InvalidSourceUrl,
            InputField::SourceUrl,
            "source_url must use HTTPS unless it points to loopback",
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ValidationError::new(
            ValidationCode::InvalidSourceUrl,
            InputField::SourceUrl,
            "source_url must not contain credentials",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ValidationError::new(
            ValidationCode::InvalidSourceUrl,
            InputField::SourceUrl,
            "source_url must not contain a query string or fragment",
        ));
    }
    if !matches!(parsed.path(), "" | "/") {
        return Err(ValidationError::new(
            ValidationCode::InvalidSourceUrl,
            InputField::SourceUrl,
            "source_url must not contain a path",
        ));
    }
    Ok(())
}

pub fn validate_identifier(field: InputField, value: &str) -> ValidationResult<()> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        return Err(ValidationError::new(
            ValidationCode::InvalidIdentifier,
            field,
            "container_name must contain only ASCII letters, digits, '-', '_' or '.' and be at most 63 characters",
        ));
    }
    Ok(())
}

pub fn validate_directory(directory: &std::path::Path) -> ValidationResult<()> {
    if !directory.is_absolute() {
        return Err(ValidationError::new(
            ValidationCode::InvalidDirectory,
            InputField::Directory,
            "directory must be an absolute path",
        ));
    }
    if directory == std::path::Path::new("/")
        || directory
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(ValidationError::new(
            ValidationCode::InvalidDirectory,
            InputField::Directory,
            "directory must be an absolute deployment subdirectory and cannot contain '.' or '..'",
        ));
    }
    let value = directory.to_string_lossy();
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
    {
        return Err(ValidationError::new(
            ValidationCode::InvalidDirectory,
            InputField::Directory,
            "directory may contain only letters, numbers, '/', '_', '-' and '.'",
        ));
    }
    Ok(())
}

pub fn validate_remote_directory(directory: &std::path::Path) -> ValidationResult<()> {
    RemotePath::parse(&directory.to_string_lossy()).map_err(|error| {
        ValidationError::new(
            ValidationCode::InvalidDirectory,
            InputField::Directory,
            error.to_string(),
        )
    })?;
    Ok(())
}

pub fn validate_bind(field: InputField, value: &str) -> ValidationResult<()> {
    let field_name = match field {
        InputField::KumaBind => "kuma_bind",
        _ => "newapi_bind",
    };
    value.parse::<IpAddr>().map_err(|_| {
        ValidationError::new(
            ValidationCode::InvalidBindAddress,
            field,
            format!("{field_name} must be an IP address"),
        )
    })?;
    Ok(())
}

pub fn validate_ports(newapi_port: u16, kuma_port: u16) -> ValidationResult<()> {
    if newapi_port == 0 || kuma_port == 0 {
        return Err(ValidationError::new(
            ValidationCode::InvalidPort,
            if newapi_port == 0 {
                InputField::NewApiPort
            } else {
                InputField::KumaPort
            },
            "ports must be between 1 and 65535",
        ));
    }
    if newapi_port == kuma_port {
        return Err(ValidationError::new(
            ValidationCode::DuplicatePort,
            InputField::KumaPort,
            "New API and Kuma ports must be different",
        ));
    }
    Ok(())
}

pub fn validate_image_ref(value: &str) -> ValidationResult<()> {
    if value.trim().is_empty() {
        return Err(ValidationError::new(
            ValidationCode::InvalidImageRef,
            InputField::ImageRef,
            "image_ref cannot be empty",
        ));
    }
    if !is_immutable_image_ref(value) {
        return Err(ValidationError::new(
            ValidationCode::InvalidImageRef,
            InputField::ImageRef,
            "image_ref must be a 7-64 character hexadecimal commit SHA or sha256 digest",
        ));
    }
    Ok(())
}

pub fn is_immutable_image_ref(value: &str) -> bool {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    (7..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn validate_ssh_destination(value: &str) -> ValidationResult<()> {
    let invalid = || {
        ValidationError::new(
            ValidationCode::InvalidSshDestination,
            InputField::Target,
            "SSH destination must use the format user@host",
        )
    };
    if value.trim() != value
        || value.len() > 255
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(invalid());
    }
    let (user, host) = value.split_once('@').ok_or_else(invalid)?;
    if user.is_empty()
        || host.is_empty()
        || host.contains('@')
        || !user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid());
    }
    let host_is_valid = if let Some(ipv6) = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        ipv6.parse::<IpAddr>()
            .is_ok_and(|address| address.is_ipv6())
    } else {
        !host.starts_with('-')
            && !host.ends_with('-')
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    };
    if !host_is_valid {
        return Err(invalid());
    }
    Ok(())
}

fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> DeploymentInput {
        let mut input = DeploymentInput {
            image_ref: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            ..DeploymentInput::default()
        };
        if cfg!(windows) {
            input.target = DeploymentTargetInput::Ssh {
                destination: "deploy@example.test".to_owned(),
            };
        }
        input
    }

    #[test]
    fn defaults_and_validation_are_ui_independent() {
        let input = valid_input();
        assert_eq!(input.container_name, DEFAULT_CONTAINER_NAME);
        assert_eq!(input.directory, PathBuf::from(DEFAULT_DIRECTORY));
        assert!(input.validate().is_ok());
    }

    #[test]
    fn validation_identifies_the_field_and_stable_code() {
        let mut input = valid_input();
        input.kuma_port = input.newapi_port;
        let error = input.validate().expect_err("duplicate ports must fail");
        assert_eq!(error.code, ValidationCode::DuplicatePort);
        assert_eq!(error.field, InputField::KumaPort);
        assert!(error.retryable);
    }

    #[test]
    fn remote_plain_http_source_is_rejected_but_loopback_is_allowed() {
        assert!(validate_source_url("http://127.0.0.1:8080").is_ok());
        let error = validate_source_url("http://example.com").expect_err("HTTPS is required");
        assert_eq!(error.code, ValidationCode::InvalidSourceUrl);
    }

    #[test]
    fn ssh_destination_requires_user_and_valid_host() {
        for value in [
            "random",
            "@example.com",
            "user@",
            "user name@example.com",
            "user@example.com;id",
        ] {
            assert!(
                validate_ssh_destination(value).is_err(),
                "accepted {value:?}"
            );
        }
        assert!(validate_ssh_destination("deploy@example.test").is_ok());
        assert!(validate_ssh_destination("deploy@[2001:db8::1]").is_ok());
    }
}
