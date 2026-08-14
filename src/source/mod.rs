mod auth;
mod groups;

pub use auth::{SourceAccountMode, SourceCredentials, SourceIdentity};
pub use groups::{GroupCatalog, SourceGroup, TokenBinding, TokenSync};

use std::{net::IpAddr, time::Duration};

use reqwest::{Client, Method, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

pub type SourceResult<T> = std::result::Result<T, SourceError>;

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("invalid source URL: {0}")]
    InvalidUrl(String),

    #[error("source request to {endpoint} failed: {source}")]
    Transport {
        endpoint: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("source returned HTTP {status} for {endpoint}")]
    HttpStatus {
        endpoint: String,
        status: StatusCode,
    },

    #[error("source rate limited {endpoint}; retry after {retry_after:?} seconds")]
    RateLimited {
        endpoint: String,
        retry_after: Option<u64>,
    },

    #[error("source rejected {endpoint}: {message}")]
    Api { endpoint: String, message: String },

    #[error("source returned an invalid response for {endpoint}: {message}")]
    InvalidResponse { endpoint: String, message: String },

    #[error("source account requires 2FA; log in on the website before continuing")]
    TwoFactorRequired,

    #[error("source authentication is required")]
    AuthenticationRequired,

    #[error("invalid source account input: {0}")]
    InvalidCredentials(String),

    #[error("invalid deployment identity: {0}")]
    InvalidDeployment(String),

    #[error("source token state is ambiguous: {0}")]
    AmbiguousToken(String),

    #[error("source group catalog is empty")]
    EmptyGroups,
}

pub struct SourceClient {
    http: Client,
    base_url: Url,
    session: Option<AuthSession>,
}

struct AuthSession {
    access_token: SecretString,
    access_expires_at: i64,
    session_id: String,
    identity: SourceIdentity,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    #[serde(default)]
    message: String,
    data: Option<T>,
}

impl SourceClient {
    pub fn new(source_url: &str) -> SourceResult<Self> {
        let mut base_url =
            Url::parse(source_url).map_err(|error| SourceError::InvalidUrl(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(SourceError::InvalidUrl(
                "only http and https URLs are supported".to_owned(),
            ));
        }
        if base_url.scheme() != "https" && !is_loopback(&base_url) {
            return Err(SourceError::InvalidUrl(
                "HTTPS is required for non-loopback sources".to_owned(),
            ));
        }
        if !base_url.username().is_empty() || base_url.password().is_some() {
            return Err(SourceError::InvalidUrl(
                "credentials must not be embedded in the URL".to_owned(),
            ));
        }
        if base_url.query().is_some() || base_url.fragment().is_some() {
            return Err(SourceError::InvalidUrl(
                "query strings and fragments are not allowed".to_owned(),
            ));
        }
        if !matches!(base_url.path(), "" | "/") {
            return Err(SourceError::InvalidUrl(
                "the source URL must not contain a path".to_owned(),
            ));
        }
        base_url.set_path("/");

        let http = Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("meowai-deploy/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|source| SourceError::Transport {
                endpoint: "client initialization".to_owned(),
                source,
            })?;

        Ok(Self {
            http,
            base_url,
            session: None,
        })
    }

    pub fn identity(&self) -> Option<&SourceIdentity> {
        self.session.as_ref().map(|session| &session.identity)
    }

    fn endpoint(&self, path: &str) -> SourceResult<Url> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|error| SourceError::InvalidUrl(error.to_string()))
    }

    async fn public_request<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> SourceResult<ApiEnvelope<T>> {
        let endpoint = self.endpoint(path)?;
        let mut request = self.http.request(method, endpoint);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|source| SourceError::Transport {
                endpoint: path.to_owned(),
                source,
            })?;
        parse_response(response, path).await
    }

    async fn authenticated_request<T: DeserializeOwned>(
        &mut self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> SourceResult<ApiEnvelope<T>> {
        self.refresh_if_needed().await?;
        let mut refreshed = false;
        loop {
            let token = self
                .session
                .as_ref()
                .ok_or(SourceError::AuthenticationRequired)?
                .access_token
                .expose_secret()
                .to_owned();
            let endpoint = self.endpoint(path)?;
            let mut request = self
                .http
                .request(method.clone(), endpoint)
                .bearer_auth(token);
            if let Some(body) = &body {
                request = request.json(body);
            }
            let response = request
                .send()
                .await
                .map_err(|source| SourceError::Transport {
                    endpoint: path.to_owned(),
                    source,
                })?;
            if response.status() == StatusCode::UNAUTHORIZED && !refreshed {
                self.refresh_session().await?;
                refreshed = true;
                continue;
            }
            return parse_response(response, path).await;
        }
    }

    async fn refresh_if_needed(&mut self) -> SourceResult<()> {
        let now = unix_timestamp();
        let should_refresh = self
            .session
            .as_ref()
            .is_some_and(|session| session.access_expires_at <= now + 30);
        if should_refresh {
            self.refresh_session().await?;
        }
        Ok(())
    }

    async fn refresh_session(&mut self) -> SourceResult<()> {
        let session_id = self
            .session
            .as_ref()
            .ok_or(SourceError::AuthenticationRequired)?
            .session_id
            .clone();
        let endpoint = self.endpoint("api/user/auth/refresh")?;
        let response = self
            .http
            .post(endpoint)
            .header("X-Auth-Session", session_id)
            .send()
            .await
            .map_err(|source| SourceError::Transport {
                endpoint: "/api/user/auth/refresh".to_owned(),
                source,
            })?;
        let envelope: ApiEnvelope<auth::LoginData> =
            parse_response(response, "/api/user/auth/refresh").await?;
        let data = require_data(envelope, "/api/user/auth/refresh")?;
        self.set_session(data)?;
        Ok(())
    }

    fn set_session(&mut self, data: auth::LoginData) -> SourceResult<SourceIdentity> {
        let access_token = data
            .access_token
            .ok_or_else(|| SourceError::InvalidResponse {
                endpoint: "/api/user/login".to_owned(),
                message: "missing access_token".to_owned(),
            })?;
        if !data.token_type.eq_ignore_ascii_case("bearer") {
            return Err(SourceError::InvalidResponse {
                endpoint: "/api/user/login".to_owned(),
                message: "unsupported token_type".to_owned(),
            });
        }
        let session_id = data.session.sid;
        if session_id.trim().is_empty() {
            return Err(SourceError::InvalidResponse {
                endpoint: "/api/user/login".to_owned(),
                message: "missing session id".to_owned(),
            });
        }
        let identity = SourceIdentity {
            user_id: data.user.id,
            username: data.user.username,
        };
        self.session = Some(AuthSession {
            access_token: SecretString::from(access_token),
            access_expires_at: data.access_expires_at,
            session_id,
            identity: identity.clone(),
        });
        Ok(identity)
    }
}

async fn parse_response<T: DeserializeOwned>(
    response: reqwest::Response,
    endpoint: &str,
) -> SourceResult<ApiEnvelope<T>> {
    let status = response.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        return Err(SourceError::RateLimited {
            endpoint: endpoint.to_owned(),
            retry_after,
        });
    }
    if !status.is_success() {
        return Err(SourceError::HttpStatus {
            endpoint: endpoint.to_owned(),
            status,
        });
    }
    let envelope =
        response
            .json::<ApiEnvelope<T>>()
            .await
            .map_err(|source| SourceError::Transport {
                endpoint: endpoint.to_owned(),
                source,
            })?;
    if !envelope.success {
        return Err(SourceError::Api {
            endpoint: endpoint.to_owned(),
            message: if envelope.message.trim().is_empty() {
                "request was rejected".to_owned()
            } else {
                envelope.message
            },
        });
    }
    Ok(envelope)
}

fn require_data<T>(envelope: ApiEnvelope<T>, endpoint: &str) -> SourceResult<T> {
    envelope.data.ok_or_else(|| SourceError::InvalidResponse {
        endpoint: endpoint.to_owned(),
        message: "missing data".to_owned(),
    })
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(host) => host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback()),
        None => false,
    }
}

#[cfg(test)]
mod tests;
