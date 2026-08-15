use reqwest::{Client, Response, StatusCode, header};
use serde::Deserialize;
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

struct RegistryClient {
    client: Client,
    registry: String,
    repository: String,
    base_url: Url,
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
        Self::with_base(image, base_url)
    }

    fn with_base(image: &str, base_url: Url) -> Result<Self> {
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
        })
    }

    async fn latest_digest(&self) -> Result<String> {
        let manifest_url = self
            .base_url
            .join(&format!("/v2/{}/manifests/latest", self.repository))
            .map_err(|error| AppError::Message(format!("build manifest URL: {error}")))?;
        let response = self.manifest_request(manifest_url.clone(), None).await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return manifest_digest(response).await;
        }

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
        manifest_digest(response).await
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

    async fn fetch_token(&self, challenge: BearerChallenge) -> Result<String> {
        let mut request = self.client.get(challenge.realm);
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

async fn manifest_digest(response: Response) -> Result<String> {
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
    Ok(digest)
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

        let client = RegistryClient::with_base(
            "ghcr.io/moorcorpa/new-api-outgap",
            Url::parse(&server.uri()).expect("mock URL"),
        )
        .expect("registry client");
        assert_eq!(client.latest_digest().await.expect("latest digest"), DIGEST);
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
        assert!(client.latest_digest().await.is_err());
    }
}
