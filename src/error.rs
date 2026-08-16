use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Message(String),

    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("configuration file is invalid: {0}")]
    InvalidToml(#[from] toml::de::Error),

    #[error("doctor found one or more blocking checks")]
    DoctorFailed,

    #[error("操作已取消")]
    Cancelled,

    #[error("target operation failed: {0}")]
    Target(String),

    #[error("deployment state is invalid: {0}")]
    State(String),

    #[error(transparent)]
    Source(#[from] crate::source::SourceError),
}

impl AppError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::DoctorFailed => 2,
            Self::Cancelled => 130,
            Self::InvalidConfig(_)
            | Self::InvalidToml(_)
            | Self::ReadFile { .. }
            | Self::WriteFile { .. }
            | Self::Message(_)
            | Self::Target(_)
            | Self::State(_)
            | Self::Source(_) => 1,
        }
    }
}

impl AppError {
    pub fn from_prompt(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::Interrupted {
            Self::Cancelled
        } else {
            Self::Message(error.to_string())
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(source: std::io::Error) -> Self {
        Self::Message(source.to_string())
    }
}

impl From<crate::application::error::ApplicationError> for AppError {
    fn from(error: crate::application::error::ApplicationError) -> Self {
        use crate::application::error::ErrorCategory;

        match error.category {
            ErrorCategory::Cancelled => Self::Cancelled,
            ErrorCategory::Validation => {
                Self::InvalidConfig(format!("{} ({})", error.message, error.code))
            }
            ErrorCategory::Target => Self::Target(format!("{} ({})", error.message, error.code)),
            ErrorCategory::Source
            | ErrorCategory::Authentication
            | ErrorCategory::Authorization => {
                Self::Message(format!("{} ({})", error.message, error.code))
            }
            _ => Self::State(format!("{} ({})", error.message, error.code)),
        }
    }
}
