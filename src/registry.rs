use std::env;

use reqwest::{Client, Response, StatusCode, header};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::{AppError, Result};

const MANIFEST_ACCEPT: &str = concat!(
    "application/vnd.oci.image.index.v1+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json, ",
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.docker.distribution.manifest.v2+json"
);

pub async fn latest_image_digest(image: &str) -> Result<String> {
    RegistryClient::new(image)?.latest_digest().await
}

pub async fn latest_image_metadata(image: &str) -> Result<ImageMetadata> {
    RegistryClient::new(image)?.latest_metadata().await
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImageMetadata {
    pub digest: String,
    pub updated_at: Option<String>,
}

#[derive(Clone)]
pub struct RegistryCredentials {
    username: String,
    password: SecretString,
}

impl RegistryCredentials {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        self.password.expose_secret()
    }
}

pub fn credentials_from_env() -> Result<Option<RegistryCredentials>> {
    let username = env::var("MEOWAI_DEPLOY_REGISTRY_USERNAME")
        .ok()
        .filter(|value| !value.is_empty());
    let password = env::var("MEOWAI_DEPLOY_REGISTRY_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    match (username, password) {
        (Some(username), Some(password)) => Ok(Some(RegistryCredentials {
            username,
            password: SecretString::from(password),
        })),
        (None, None) => Ok(None),
        _ => Err(AppError::InvalidConfig(
            "MEOWAI_DEPLOY_REGISTRY_USERNAME and MEOWAI_DEPLOY_REGISTRY_PASSWORD must be set together"
                .to_owned(),
        )),
    }
}

struct RegistryClient {
    client: Client,
    registry: String,
    repository: String,
    base_url: Url,
    credentials: Option<RegistryCredentials>,
}

#[derive(Deserialize)]
struct RegistryToken {
    token: Option<String>,
    access_token: Option<String>,
}

struct BearerChallenge {
    realm: Url,
    service: Option<String>,
    scope: Option<String>,
}

impl RegistryClient {
    fn new(image: &str) -> Result<Self> {
        let (registry, _) = image.split_once('/').ok_or_else(|| {
            AppError::InvalidConfig("image must include a registry and repository".to_owned())
        })?;
        let scheme = if registry.starts_with("localhost") || registry.starts_with("127.0.0.1") {
            "http"
        } else {
            "https"
        };
        let base_url = Url::parse(&format!("{scheme}://{registry}"))
            .map_err(|error| AppError::Message(format!("invalid image registry URL: {error}")))?;
        let credentials = credentials_from_env()?;
        Self::with_base_and_credentials(image, base_url, credentials)
    }

    #[cfg(test)]
    fn with_base(image: &str, base_url: Url) -> Result<Self> {
        Self::with_base_and_credentials(image, base_url, None)
    }

    fn with_base_and_credentials(
        image: &str,
        base_url: Url,
        credentials: Option<RegistryCredentials>,
    ) -> Result<Self> {
        let (registry, repository) = image.split_once('/').ok_or_else(|| {
            AppError::InvalidConfig("image must include a registry and repository".to_owned())
        })?;
        let client = Client::builder()
            .user_agent(concat!("meowai-deploy/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|error| AppError::Message(format!("build registry client: {error}")))?;
        Ok(Self {
            client,
            registry: registry.to_owned(),
            repository: repository.to_owned(),
            base_url,
            credentials,
        })
    }

    async fn latest_digest(&self) -> Result<String> {
        let (response, _) = self.latest_manifest().await?;
        Ok(manifest_document(response).await?.0)
    }

    async fn latest_metadata(&self) -> Result<ImageMetadata> {
        let (response, token) = self.latest_manifest().await?;
        let (digest, document) = manifest_document(response).await?;
        let updated_at = match document {
            Some(document) => self
                .resolve_created_time(&document, token.as_deref())
                .await
                .unwrap_or_else(|error| {
                    tracing::debug!(%error, "image creation time is unavailable");
                    None
                }),
            None => None,
        };
        Ok(ImageMetadata { digest, updated_at })
    }

    async fn latest_manifest(&self) -> Result<(Response, Option<String>)> {
        let manifest_url = self
            .base_url
            .join(&format!("/v2/{}/manifests/latest", self.repository))
            .map_err(|error| AppError::Message(format!("build manifest URL: {error}")))?;
        tracing::debug!(registry = %self.registry, repository = %self.repository, "requesting latest image manifest");
        let response = self.manifest_request(manifest_url.clone(), None).await?;
        tracing::debug!(status = %response.status(), "latest image manifest response received");
        let (response, token) = if response.status() == StatusCode::UNAUTHORIZED {
            let challenge = response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    AppError::Message(
                        "registry requires authentication without a Bearer challenge".to_owned(),
                    )
                })
                .and_then(parse_bearer_challenge)?;
            let token = self.fetch_token(challenge).await?;
            let response = self.manifest_request(manifest_url, Some(&token)).await?;
            tracing::debug!(status = %response.status(), "authenticated image manifest response received");
            (response, Some(token))
        } else {
            (response, None)
        };
        Ok((response, token))
    }

    async fn manifest_request(&self, url: Url, token: Option<&str>) -> Result<Response> {
        let mut request = self.client.get(url).header(header::ACCEPT, MANIFEST_ACCEPT);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        request
            .send()
            .await
            .map_err(|error| AppError::Message(format!("request image manifest: {error}")))
    }

    async fn resolve_created_time(
        &self,
        document: &Value,
        token: Option<&str>,
    ) -> Result<Option<String>> {
        if let Some(created) = image_created_annotation(document) {
            return Ok(Some(created));
        }
        let manifest = if let Some(digest) = linux_amd64_manifest_digest(document) {
            let url = self
                .base_url
                .join(&format!("/v2/{}/manifests/{digest}", self.repository))
                .map_err(|error| {
                    AppError::Message(format!("build platform manifest URL: {error}"))
                })?;
            let response = self.manifest_request(url, token).await?;
            let (_, document) = manifest_document(response).await?;
            document
        } else {
            Some(document.clone())
        };
        let Some(config_digest) = manifest
            .as_ref()
            .and_then(|manifest| manifest.pointer("/config/digest"))
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        validate_digest(config_digest)?;
        let url = self
            .base_url
            .join(&format!("/v2/{}/blobs/{config_digest}", self.repository))
            .map_err(|error| AppError::Message(format!("build image config URL: {error}")))?;
        let mut request = self.client.get(url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| AppError::Message(format!("request image config: {error}")))?;
        if !response.status().is_success() {
            return Ok(None);
        }
        let config: Value = response
            .json()
            .await
            .map_err(|error| AppError::Message(format!("decode image config: {error}")))?;
        Ok(config
            .get("created")
            .and_then(Value::as_str)
            .map(str::to_owned))
    }

    async fn fetch_token(&self, challenge: BearerChallenge) -> Result<String> {
        let mut request = self.client.get(challenge.realm);
        if let Some(credentials) = &self.credentials {
            request = request.basic_auth(credentials.username(), Some(credentials.password()));
        }
        if let Some(service) = challenge.service.as_deref() {
            request = request.query(&[("service", service)]);
        }
        let default_scope = format!("repository:{}:pull", self.repository);
        request = request.query(&[(
            "scope",
            challenge.scope.as_deref().unwrap_or(&default_scope),
        )]);
        let response = request
            .send()
            .await
            .map_err(|error| AppError::Message(format!("request registry token: {error}")))?;
        tracing::debug!(status = %response.status(), registry = %self.registry, "registry token response received");
        if !response.status().is_success() {
            return Err(AppError::Message(format!(
                "registry token request failed with HTTP {} for {}",
                response.status(),
                self.registry
            )));
        }
        let token: RegistryToken = response
            .json()
            .await
            .map_err(|error| AppError::Message(format!("decode registry token: {error}")))?;
        token.token.or(token.access_token).ok_or_else(|| {
            AppError::Message("registry token response did not contain a token".to_owned())
        })
    }
}

fn parse_bearer_challenge(value: &str) -> Result<BearerChallenge> {
    let fields = value.strip_prefix("Bearer ").ok_or_else(|| {
        AppError::Message("registry did not return a Bearer challenge".to_owned())
    })?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for field in fields.split(',') {
        let Some((name, value)) = field.trim().split_once('=') else {
            continue;
        };
        let value = value.trim_matches('"').to_owned();
        match name {
            "realm" => {
                realm = Some(Url::parse(&value).map_err(|error| {
                    AppError::Message(format!("invalid registry token URL: {error}"))
                })?)
            }
            "service" => service = Some(value),
            "scope" => scope = Some(value),
            _ => {}
        }
    }
    Ok(BearerChallenge {
        realm: realm.ok_or_else(|| {
            AppError::Message("registry Bearer challenge is missing realm".to_owned())
        })?,
        service,
        scope,
    })
}

async fn manifest_document(response: Response) -> Result<(String, Option<Value>)> {
    if !response.status().is_success() {
        return Err(AppError::Message(format!(
            "latest image manifest request failed with HTTP {}",
            response.status()
        )));
    }
    let header_digest = response
        .headers()
        .get("docker-content-digest")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response
        .bytes()
        .await
        .map_err(|error| AppError::Message(format!("read image manifest: {error}")))?;
    let digest = header_digest.unwrap_or_else(|| format!("sha256:{:x}", Sha256::digest(&body)));
    validate_digest(&digest)?;
    let document = serde_json::from_slice(&body).ok();
    Ok((digest, document))
}

fn image_created_annotation(document: &Value) -> Option<String> {
    document
        .pointer("/annotations/org.opencontainers.image.created")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn linux_amd64_manifest_digest(document: &Value) -> Option<&str> {
    document
        .get("manifests")?
        .as_array()?
        .iter()
        .find_map(|manifest| {
            let platform = manifest.get("platform")?;
            (platform.get("os")?.as_str()? == "linux"
                && platform.get("architecture")?.as_str()? == "amd64")
                .then(|| manifest.get("digest")?.as_str())
                .flatten()
        })
}

fn validate_digest(value: &str) -> Result<()> {
    let hash = value.strip_prefix("sha256:").ok_or_else(|| {
        AppError::Message("registry returned an unsupported image digest".to_owned())
    })?;
    if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::Message(
            "registry returned an invalid sha256 image digest".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const CONFIG_DIGEST: &str =
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const MANIFEST_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[tokio::test]
    async fn resolves_digest_after_registry_bearer_authentication() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/moorcorpa/new-api-outgap/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(401).insert_header(
                    "www-authenticate",
                    format!(
                        "Bearer realm=\"{}/token\",service=\"ghcr.io\",scope=\"repository:moorcorpa/new-api-outgap:pull\"",
                        server.uri()
                    ),
                ),
            )
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .and(query_param("service", "ghcr.io"))
            .and(query_param(
                "scope",
                "repository:moorcorpa/new-api-outgap:pull",
            ))
            .and(header(
                "authorization",
                "Basic bW9vcmNvcnBhOnRlc3QtdG9rZW4=",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token": "registry-token"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/moorcorpa/new-api-outgap/manifests/latest"))
            .and(header("authorization", "Bearer registry-token"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", DIGEST)
                    .set_body_json(serde_json::json!({"schemaVersion": 2})),
            )
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;

        let client = RegistryClient::with_base_and_credentials(
            "ghcr.io/moorcorpa/new-api-outgap",
            Url::parse(&server.uri()).expect("mock URL"),
            Some(RegistryCredentials {
                username: "moorcorpa".to_owned(),
                password: SecretString::from("test-token".to_owned()),
            }),
        )
        .expect("registry client");
        let metadata = client.latest_metadata().await.expect("latest metadata");
        assert_eq!(metadata.digest, DIGEST);
        assert_eq!(metadata.updated_at, None);
    }

    #[tokio::test]
    async fn reads_image_creation_time_from_the_config_blob() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/moorcorpa/new-api-outgap/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", DIGEST)
                    .set_body_json(serde_json::json!({
                        "schemaVersion": 2,
                        "config": {"digest": CONFIG_DIGEST}
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/moorcorpa/new-api-outgap/blobs/{CONFIG_DIGEST}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "created": "2026-08-16T10:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = RegistryClient::with_base(
            "ghcr.io/moorcorpa/new-api-outgap",
            Url::parse(&server.uri()).expect("mock URL"),
        )
        .expect("registry client");

        let metadata = client.latest_metadata().await.expect("latest metadata");

        assert_eq!(metadata.digest, DIGEST);
        assert_eq!(metadata.updated_at.as_deref(), Some("2026-08-16T10:00:00Z"));
    }

    #[tokio::test]
    async fn reads_linux_amd64_creation_time_from_an_image_index() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/moorcorpa/new-api-outgap/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", DIGEST)
                    .set_body_json(serde_json::json!({
                        "schemaVersion": 2,
                        "manifests": [{
                            "digest": MANIFEST_DIGEST,
                            "platform": {"os": "linux", "architecture": "amd64"}
                        }]
                    })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/moorcorpa/new-api-outgap/manifests/{MANIFEST_DIGEST}"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", MANIFEST_DIGEST)
                    .set_body_json(serde_json::json!({
                        "schemaVersion": 2,
                        "config": {"digest": CONFIG_DIGEST}
                    })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v2/moorcorpa/new-api-outgap/blobs/{CONFIG_DIGEST}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "created": "2026-08-16T11:00:00Z"
            })))
            .mount(&server)
            .await;
        let client = RegistryClient::with_base(
            "ghcr.io/moorcorpa/new-api-outgap",
            Url::parse(&server.uri()).expect("mock URL"),
        )
        .expect("registry client");

        let metadata = client.latest_metadata().await.expect("latest metadata");

        assert_eq!(metadata.digest, DIGEST);
        assert_eq!(metadata.updated_at.as_deref(), Some("2026-08-16T11:00:00Z"));
    }

    #[tokio::test]
    async fn rejects_unsuccessful_manifest_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/moorcorpa/new-api-outgap/manifests/latest"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let client = RegistryClient::with_base(
            "ghcr.io/moorcorpa/new-api-outgap",
            Url::parse(&server.uri()).expect("mock URL"),
        )
        .expect("registry client");
        assert!(client.latest_metadata().await.is_err());
    }
}
