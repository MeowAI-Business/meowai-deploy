use std::fmt;

use secrecy::SecretString;

use crate::{
    application::{
        error::{
            ApplicationError, ApplicationResult, ErrorCategory, source_error as map_source_error,
        },
        input,
        operation::CancellationToken,
    },
    pricing::PricingConfig,
    source::{
        GroupCatalog, SourceAccountMode, SourceClient, SourceCredentials, SourceIdentity, TokenSync,
    },
    storage::{self, SESSION_FILE},
};

pub struct SourceAccountRequest {
    pub source_url: String,
    pub mode: SourceAccountMode,
    pub username: String,
    pub password: SecretString,
}

impl SourceAccountRequest {
    pub fn new(
        source_url: impl Into<String>,
        mode: SourceAccountMode,
        username: impl Into<String>,
        password: SecretString,
    ) -> ApplicationResult<Self> {
        let source_url = source_url.into();
        input::validate_source_url(&source_url).map_err(|error| {
            ApplicationError::new(
                ErrorCategory::Validation,
                error.code.as_str(),
                error.message,
                error.retryable,
            )
            .with_field(error.field)
        })?;
        let username = username.into();
        SourceCredentials::new(username.clone(), password.clone()).map_err(map_source_error)?;
        Ok(Self {
            source_url,
            mode,
            username,
            password,
        })
    }
}

impl fmt::Debug for SourceAccountRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceAccountRequest")
            .field("source_url", &self.source_url)
            .field("mode", &self.mode)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

pub struct AuthenticatedSource {
    pub client: SourceClient,
    pub identity: SourceIdentity,
}

#[derive(Debug)]
pub struct SourceResources {
    pub catalog: GroupCatalog,
    pub pricing: PricingConfig,
    pub token_sync: TokenSync,
}

pub async fn probe_source_url(source_url: &str) -> ApplicationResult<SourceClient> {
    let source = SourceClient::new(source_url).map_err(map_source_error)?;
    source
        .check_connectivity()
        .await
        .map_err(map_source_error)?;
    Ok(source)
}

pub async fn login_source_account(
    request: SourceAccountRequest,
) -> ApplicationResult<AuthenticatedSource> {
    authenticate_source_account(SourceAccountRequest {
        mode: SourceAccountMode::Login,
        ..request
    })
    .await
}

pub async fn register_source_account(
    request: SourceAccountRequest,
) -> ApplicationResult<AuthenticatedSource> {
    authenticate_source_account(SourceAccountRequest {
        mode: SourceAccountMode::Register,
        ..request
    })
    .await
}

pub async fn authenticate_source_account(
    request: SourceAccountRequest,
) -> ApplicationResult<AuthenticatedSource> {
    let mut source = probe_source_url(&request.source_url).await?;
    let credentials =
        SourceCredentials::new(request.username, request.password).map_err(map_source_error)?;
    let identity = source
        .authenticate(request.mode, &credentials)
        .await
        .map_err(map_source_error)?;
    check_source_approval(&mut source).await?;
    Ok(AuthenticatedSource {
        client: source,
        identity,
    })
}

pub async fn check_source_approval(source: &mut SourceClient) -> ApplicationResult<()> {
    source
        .check_onboard_access()
        .await
        .map_err(map_source_error)?;
    Ok(())
}

pub async fn read_source_resources(
    source: &mut SourceClient,
    cancellation: &CancellationToken,
) -> ApplicationResult<SourceResources> {
    check_cancellation(cancellation)?;
    let catalog = source.groups().await.map_err(map_source_error)?;
    check_cancellation(cancellation)?;
    let pricing = source.pricing().await.map_err(map_source_error)?;
    check_cancellation(cancellation)?;
    let token_sync = source
        .ensure_group_tokens(&catalog)
        .await
        .map_err(map_source_error)?;
    check_cancellation(cancellation)?;
    Ok(SourceResources {
        catalog,
        pricing,
        token_sync,
    })
}

pub fn persist_source_session(source: &SourceClient) -> ApplicationResult<()> {
    let session = source.export_session().map_err(map_source_error)?;
    let content = serde_json::to_vec_pretty(&session).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Persistence,
            "SOURCE_SESSION_SERIALIZE_FAILED",
            "无法保存源站会话",
            true,
        )
        .with_diagnostic(error.to_string())
    })?;
    storage::write(SESSION_FILE, &content).map_err(super::error::app_error)
}

fn check_cancellation(cancellation: &CancellationToken) -> ApplicationResult<()> {
    if cancellation.is_cancelled() {
        Err(ApplicationError::new(
            ErrorCategory::Cancelled,
            "OPERATION_CANCELLED",
            "操作已取消",
            false,
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[test]
    fn source_request_debug_output_redacts_password() {
        let request = SourceAccountRequest::new(
            "http://127.0.0.1:8080",
            SourceAccountMode::Login,
            "source-user",
            SecretString::from("source-secret".to_owned()),
        )
        .expect("valid source account request");
        let debug = format!("{request:?}");
        assert!(!debug.contains("source-secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[tokio::test]
    async fn login_use_case_checks_connectivity_authentication_and_approval() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/status"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/user/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .append_header(
                        "Set-Cookie",
                        "new_api_refresh=session-1.secret; Path=/api/user/auth; HttpOnly",
                    )
                    .set_body_json(json!({
                        "success": true,
                        "message": "",
                        "data": {
                            "access_token": "access-one",
                            "token_type": "Bearer",
                            "access_expires_at": i64::MAX,
                            "session": {"sid": "session-1"},
                            "user": {"id": 42, "username": "downstream-owner"}
                        }
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/onboard/access"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": {"allowed": true}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let request = SourceAccountRequest::new(
            server.uri(),
            SourceAccountMode::Login,
            "downstream-owner",
            SecretString::from("secret-probe-1".to_owned()),
        )
        .expect("valid request");
        let authenticated = login_source_account(request)
            .await
            .expect("complete login use case");
        assert_eq!(authenticated.identity.user_id, 42);
        assert_eq!(authenticated.identity.username, "downstream-owner");
    }
}
