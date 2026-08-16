use super::input::InputField;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Validation,
    Source,
    Authentication,
    Authorization,
    Target,
    Persistence,
    Conflict,
    Cancelled,
    Internal,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApplicationError {
    pub category: ErrorCategory,
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub field: Option<InputField>,
    pub diagnostic: Option<String>,
}

impl ApplicationError {
    pub fn new(
        category: ErrorCategory,
        code: impl Into<String>,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            category,
            code: code.into(),
            message: message.into(),
            retryable,
            field: None,
            diagnostic: None,
        }
    }

    pub fn with_field(mut self, field: InputField) -> Self {
        self.field = Some(field);
        self
    }

    pub fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        let diagnostic = diagnostic.into();
        if !diagnostic.trim().is_empty() {
            self.diagnostic = Some(sanitize_diagnostic(&diagnostic));
        }
        self
    }
}

impl std::fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ApplicationError {}

pub type ApplicationResult<T> = std::result::Result<T, ApplicationError>;

pub fn app_error(error: crate::error::AppError) -> ApplicationError {
    if let crate::error::AppError::Source(source) = error {
        return source_error(source);
    }
    let (category, code, message, retryable) = match &error {
        crate::error::AppError::InvalidConfig(_) | crate::error::AppError::InvalidToml(_) => (
            ErrorCategory::Validation,
            "DEPLOYMENT_INPUT_INVALID",
            "部署配置无效",
            true,
        ),
        crate::error::AppError::Target(_) => (
            ErrorCategory::Target,
            "TARGET_OPERATION_FAILED",
            "下游目标操作失败",
            true,
        ),
        crate::error::AppError::State(_) => (
            ErrorCategory::Conflict,
            "DEPLOYMENT_STATE_INVALID",
            "部署状态不允许继续当前操作",
            false,
        ),
        crate::error::AppError::Cancelled => (
            ErrorCategory::Cancelled,
            "OPERATION_CANCELLED",
            "操作已取消",
            false,
        ),
        crate::error::AppError::ReadFile { .. } | crate::error::AppError::WriteFile { .. } => (
            ErrorCategory::Persistence,
            "DEPLOYMENT_FILE_FAILED",
            "无法读写部署状态",
            true,
        ),
        _ => (
            ErrorCategory::Internal,
            "DEPLOYMENT_INTERNAL_ERROR",
            "部署过程中发生内部错误",
            false,
        ),
    };
    ApplicationError::new(category, code, message, retryable).with_diagnostic(error.to_string())
}

pub fn source_error(error: crate::source::SourceError) -> ApplicationError {
    let (category, code, message, retryable) = match &error {
        crate::source::SourceError::ApprovalRequired => (
            ErrorCategory::Authorization,
            "SOURCE_APPROVAL_REQUIRED",
            "需要上游批准后才能部署",
            true,
        ),
        crate::source::SourceError::AuthenticationRequired
        | crate::source::SourceError::TwoFactorRequired
        | crate::source::SourceError::InvalidCredentials(_) => (
            ErrorCategory::Authentication,
            "SOURCE_AUTHENTICATION_FAILED",
            "源站账号验证失败",
            true,
        ),
        crate::source::SourceError::InvalidUrl(_) => (
            ErrorCategory::Validation,
            "SOURCE_URL_INVALID",
            "源站地址无效",
            true,
        ),
        crate::source::SourceError::RateLimited { .. }
        | crate::source::SourceError::Transport { .. }
        | crate::source::SourceError::HttpStatus { .. } => (
            ErrorCategory::Source,
            "SOURCE_UNAVAILABLE",
            "源站暂时不可用",
            true,
        ),
        _ => (
            ErrorCategory::Source,
            "SOURCE_RESPONSE_INVALID",
            "源站返回的数据无法用于部署",
            false,
        ),
    };
    ApplicationError::new(category, code, message, retryable).with_diagnostic(error.to_string())
}

pub fn sanitize_diagnostic(value: &str) -> String {
    let mut sanitized = value.replace(['\n', '\r', '\t'], " ");
    for marker in ["password", "token", "secret", "api_key", "access_token"] {
        let lower = sanitized.to_ascii_lowercase();
        if lower.contains(marker) {
            sanitized = format!("诊断信息包含敏感字段 {marker}，已隐藏");
            break;
        }
    }
    if sanitized.len() > 512 {
        sanitized.truncate(512);
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_bounded_and_redact_secret_markers() {
        let error =
            ApplicationError::new(ErrorCategory::Target, "TARGET_FAILED", "目标检查失败", true)
                .with_diagnostic("token=private-value\nmore details");
        assert_eq!(
            error.diagnostic.as_deref(),
            Some("诊断信息包含敏感字段 token，已隐藏")
        );
    }
}
