use std::fmt;

use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{SourceClient, SourceError, SourceResult, require_data};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SourceAccountMode {
    #[default]
    Login,
    Register,
}

#[derive(Clone)]
pub struct SourceCredentials {
    username: String,
    password: SecretString,
}

impl SourceCredentials {
    pub fn new(username: impl Into<String>, password: SecretString) -> SourceResult<Self> {
        let username = username.into();
        let username = username.trim();
        if username.is_empty() || username.len() > 20 {
            return Err(SourceError::InvalidCredentials(
                "username must be between 1 and 20 characters".to_owned(),
            ));
        }
        if password.expose_secret().len() < 8 || password.expose_secret().len() > 20 {
            return Err(SourceError::InvalidCredentials(
                "password must be between 8 and 20 characters".to_owned(),
            ));
        }
        Ok(Self {
            username: username.to_owned(),
            password,
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}

impl fmt::Debug for SourceCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SourceIdentity {
    pub user_id: i64,
    pub username: String,
}

#[derive(Serialize)]
struct AccountRequest<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginData {
    #[serde(default)]
    pub(super) access_token: Option<String>,
    #[serde(default)]
    pub(super) token_type: String,
    #[serde(default)]
    pub(super) access_expires_at: i64,
    #[serde(default)]
    pub(super) session: LoginSession,
    #[serde(default)]
    pub(super) user: LoginUser,
    #[serde(default)]
    require_2fa: bool,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct LoginSession {
    #[serde(default)]
    pub(super) sid: String,
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct LoginUser {
    pub(super) id: i64,
    #[serde(default)]
    pub(super) username: String,
}

impl SourceClient {
    pub async fn authenticate(
        &mut self,
        mode: SourceAccountMode,
        credentials: &SourceCredentials,
    ) -> SourceResult<SourceIdentity> {
        if mode == SourceAccountMode::Register {
            self.register(credentials).await?;
        }
        self.login(credentials).await
    }

    pub async fn register(&self, credentials: &SourceCredentials) -> SourceResult<()> {
        let request = AccountRequest {
            username: credentials.username(),
            password: credentials.password.expose_secret(),
        };
        self.public_request::<serde_json::Value, _>(
            Method::POST,
            "/api/user/register",
            Some(&request),
        )
        .await?;
        Ok(())
    }

    pub async fn login(&mut self, credentials: &SourceCredentials) -> SourceResult<SourceIdentity> {
        let request = AccountRequest {
            username: credentials.username(),
            password: credentials.password.expose_secret(),
        };
        let envelope = self
            .public_request::<LoginData, _>(Method::POST, "/api/user/login", Some(&request))
            .await?;
        let data = require_data(envelope, "/api/user/login")?;
        if data.require_2fa {
            return Err(SourceError::TwoFactorRequired);
        }
        self.set_session(data)
    }
}
