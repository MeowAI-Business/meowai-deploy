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
    if let crate::error::AppError::Target(message) = &error {
        if message.starts_with("SSH 认证失败") {
            return ApplicationError::new(
                ErrorCategory::Authentication,
                "SSH_AUTHENTICATION_FAILED",
                "SSH 认证失败，请检查密码、密钥或 ssh-agent。",
                true,
            )
            .with_diagnostic(error.to_string());
        }
        let summary = message.lines().next().unwrap_or("下游目标操作失败");
        return ApplicationError::new(
            ErrorCategory::Target,
            "TARGET_OPERATION_FAILED",
            format!("下游目标操作失败：{}", sanitize_diagnostic(summary)),
            true,
        )
        .with_diagnostic(error.to_string());
    }
    let (category, code, message, retryable) = match &error {
        crate::error::AppError::InvalidConfig(_) | crate::error::AppError::InvalidToml(_) => (
            ErrorCategory::Validation,
            "DEPLOYMENT_INPUT_INVALID",
            "部署配置无效",
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
        sanitized = redact_assignment(&sanitized, marker);
    }
    sanitized = redact_bearer_token(&sanitized);
    if sanitized.len() > 512 {
        sanitized.truncate(512);
    }
    sanitized
}

fn redact_assignment(value: &str, marker: &str) -> String {
    let mut result = value.to_owned();
    let mut search_from = 0;
    loop {
        let lower = result.to_ascii_lowercase();
        let Some(relative) = lower[search_from..].find(marker) else {
            break;
        };
        let marker_start = search_from + relative;
        let marker_end = marker_start + marker.len();
        let bytes = result.as_bytes();
        if marker_start > 0
            && matches!(bytes[marker_start - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
        {
            search_from = marker_end;
            continue;
        }
        let mut separator = marker_end;
        if bytes
            .get(separator)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"'))
        {
            separator += 1;
        }
        while bytes.get(separator).is_some_and(u8::is_ascii_whitespace) {
            separator += 1;
        }
        if !bytes
            .get(separator)
            .is_some_and(|byte| matches!(byte, b'=' | b':'))
        {
            search_from = marker_end;
            continue;
        }
        let mut value_start = separator + 1;
        while bytes.get(value_start).is_some_and(u8::is_ascii_whitespace) {
            value_start += 1;
        }
        let quote = bytes
            .get(value_start)
            .copied()
            .filter(|byte| matches!(byte, b'\'' | b'"'));
        if quote.is_some() {
            value_start += 1;
        }
        let mut value_end = value_start;
        while let Some(byte) = bytes.get(value_end) {
            if quote.is_some_and(|quote| *byte == quote)
                || (quote.is_none()
                    && (byte.is_ascii_whitespace()
                        || matches!(byte, b',' | b';' | b'&' | b'}' | b']')))
            {
                break;
            }
            value_end += 1;
        }
        result.replace_range(value_start..value_end, "[REDACTED]");
        search_from = value_start + "[REDACTED]".len();
    }
    result
}

fn redact_bearer_token(value: &str) -> String {
    let mut result = value.to_owned();
    let mut search_from = 0;
    loop {
        let lower = result.to_ascii_lowercase();
        let Some(relative) = lower[search_from..].find("bearer ") else {
            break;
        };
        let value_start = search_from + relative + "bearer ".len();
        let value_end = result[value_start..]
            .find(|character: char| character.is_whitespace() || matches!(character, ',' | ';'))
            .map(|offset| value_start + offset)
            .unwrap_or(result.len());
        result.replace_range(value_start..value_end, "[REDACTED]");
        search_from = value_start + "[REDACTED]".len();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_redact_values_without_hiding_actionable_context() {
        let error = ApplicationError::new(
            ErrorCategory::Target,
            "TARGET_FAILED",
            "目标检查失败",
            true,
        )
        .with_diagnostic(
            "docker compose --env-file secrets.env failed: token=private-value\nmore details",
        );
        assert_eq!(
            error.diagnostic.as_deref(),
            Some("docker compose --env-file secrets.env failed: token=[REDACTED] more details")
        );
    }

    #[test]
    fn diagnostics_redact_json_and_bearer_credentials() {
        assert_eq!(
            sanitize_diagnostic("{\"password\":\"private\"} Authorization: Bearer abc.def"),
            "{\"password\":\"[REDACTED]\"} Authorization: Bearer [REDACTED]"
        );
    }

    #[test]
    fn target_errors_keep_the_actionable_command_failure() {
        let error = app_error(crate::error::AppError::Target(
            "docker compose --env-file secrets.env exited with status 1\nservice failed".to_owned(),
        ));
        assert_eq!(
            error.message,
            "下游目标操作失败：docker compose --env-file secrets.env exited with status 1"
        );
        assert_eq!(
            error.diagnostic.as_deref(),
            Some(
                "target operation failed: docker compose --env-file secrets.env exited with status 1 service failed"
            )
        );
    }
}
