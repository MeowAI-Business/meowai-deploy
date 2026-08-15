use std::collections::{BTreeMap, HashMap, HashSet};

use reqwest::{Client, Method};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    config::DeploymentConfig,
    error::{AppError, Result},
    pricing::{PricingConfig, VideoCapabilityPolicy, VideoCostPolicy, VideoSalesPolicy},
    security::sha256_hex,
    source::{GroupCatalog, TokenBinding},
    state::ChannelState,
    target::{TargetEndpoint, TargetExecutor},
};

const CHANNEL_TYPE_NEWAPI: i64 = 60;
const CHANNEL_STATUS_ENABLED: i64 = 1;
const CHANNEL_STATUS_MANUALLY_DISABLED: i64 = 2;
const CHANNEL_SOURCE_NAME: &str = "MeowAI";

pub struct NewApiClient {
    endpoint: TargetEndpoint,
    http: Client,
    access_token: Option<SecretString>,
}

#[derive(Debug, Default)]
pub struct ChannelSyncResult {
    pub created: usize,
    pub updated: usize,
    pub reused: usize,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    success: bool,
    #[serde(default)]
    message: String,
    data: Option<T>,
}

#[derive(Debug, Deserialize)]
struct SetupData {
    status: bool,
}

#[derive(Debug, Deserialize)]
struct LoginData {
    access_token: String,
}

#[derive(Debug, Deserialize)]
struct Page<T> {
    items: Vec<T>,
    total: usize,
    page: usize,
    page_size: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct RemoteChannel {
    id: i64,
    #[serde(rename = "type")]
    channel_type: i64,
    name: String,
    status: i64,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    models: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    tag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OptionEntry {
    key: String,
    value: Value,
}

#[derive(Debug, Deserialize)]
struct VideoPricingResponse {
    sales: Vec<VideoSalesPolicy>,
    costs: Vec<RemoteVideoCostPolicy>,
}

#[derive(Debug, Deserialize)]
struct RemoteVideoCostPolicy {
    provider: String,
    public_model: String,
    upstream_group_rate_bps: i64,
    promotion_rate_bps: i64,
    #[serde(default)]
    promotion_scope: String,
    #[serde(default)]
    promotion_effective_from: i64,
    #[serde(default)]
    promotion_effective_until: i64,
    effective_from: i64,
    #[serde(default)]
    effective_until: i64,
    evidence_status: String,
}

#[derive(Debug, Deserialize)]
struct RemoteVideoCapabilityPolicy {
    public_model: String,
    capabilities_json: String,
    effective_from: i64,
    #[serde(default)]
    effective_until: i64,
}

impl NewApiClient {
    pub fn connect(executor: &TargetExecutor, port: u16) -> Result<Self> {
        let endpoint = executor.endpoint(port)?;
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|error| AppError::Target(format!("create downstream API client: {error}")))?;
        Ok(Self {
            endpoint,
            http,
            access_token: None,
        })
    }

    pub async fn initialize_and_login(
        &mut self,
        config: &DeploymentConfig,
        password: &SecretString,
    ) -> Result<()> {
        let setup: SetupData = self.request(Method::GET, "/api/setup", None, false).await?;
        if !setup.status {
            let body = json!({
                "username": config.newapi_admin_username,
                "password": password.expose_secret(),
                "confirmPassword": password.expose_secret(),
                "SelfUseModeEnabled": false,
                "DemoSiteEnabled": false
            });
            self.request_no_data(Method::POST, "/api/setup", Some(body), false)
                .await?;
        }
        let login: LoginData = self
            .request(
                Method::POST,
                "/api/user/login",
                Some(json!({
                    "username": config.newapi_admin_username,
                    "password": password.expose_secret()
                })),
                false,
            )
            .await?;
        if login.access_token.trim().is_empty() {
            return Err(AppError::Target(
                "downstream login returned an empty access token".to_owned(),
            ));
        }
        self.access_token = Some(SecretString::from(login.access_token));
        Ok(())
    }

    pub async fn configure_site(&self, website_name: &str) -> Result<()> {
        self.update_option("SystemName", website_name).await?;
        self.update_option("console_setting.uptime_kuma_enabled", "false")
            .await
    }

    pub async fn import_pricing(
        &self,
        source_pricing: &PricingConfig,
    ) -> Result<BTreeMap<String, String>> {
        let options_to_import = source_pricing.options()?;
        for option in &options_to_import {
            self.update_option(option.key, &option.canonical_json)
                .await?;
        }
        let options = self.options().await?;
        let mut hashes = BTreeMap::new();
        for option in &options_to_import {
            let returned = options.get(option.key).ok_or_else(|| {
                AppError::Target(format!("downstream option {} was not returned", option.key))
            })?;
            if !option.matches(returned).map_err(|error| {
                AppError::Target(format!(
                    "downstream option {} is invalid after import: {error}",
                    option.key
                ))
            })? {
                return Err(AppError::Target(format!(
                    "downstream option {} differs after import",
                    option.key
                )));
            }
            hashes.insert(option.source_field.to_owned(), option.sha256.clone());
        }
        self.import_video_policies(source_pricing).await?;
        for (name, value) in [
            (
                "video_sales_policies",
                serde_json::to_value(&source_pricing.video_sales_policies),
            ),
            (
                "video_cost_policies",
                serde_json::to_value(&source_pricing.video_cost_policies),
            ),
            (
                "video_capabilities",
                serde_json::to_value(&source_pricing.video_capabilities),
            ),
        ] {
            let value = value.map_err(|error| AppError::State(error.to_string()))?;
            hashes.insert(
                name.to_owned(),
                sha256_hex(
                    serde_json::to_string(&value)
                        .map_err(|error| AppError::State(error.to_string()))?
                        .as_bytes(),
                ),
            );
        }
        Ok(hashes)
    }

    async fn import_video_policies(&self, source: &PricingConfig) -> Result<()> {
        let current: VideoPricingResponse = self
            .request(Method::GET, "/api/option/video-pricing", None, true)
            .await?;
        let mut imported_sales = HashSet::new();
        for (index, desired) in source.video_sales_policies.iter().enumerate() {
            if current.sales.iter().any(|policy| policy == desired)
                || !sales_can_precede_current_costs(&current, desired)
            {
                continue;
            }
            self.create_video_sales_policy(desired).await?;
            imported_sales.insert(index);
        }
        for desired in &source.video_cost_policies {
            let matched = current
                .costs
                .iter()
                .any(|policy| remote_cost_matches(policy, desired));
            if !matched {
                let mut body = serde_json::to_value(desired).map_err(|error| {
                    AppError::Target(format!("serialize video cost policy: {error}"))
                })?;
                body["status"] = Value::String("active".to_owned());
                body["reason"] = Value::String("meowai-deploy source sync".to_owned());
                self.request_no_data(
                    Method::POST,
                    "/api/option/video-pricing/costs",
                    Some(body),
                    true,
                )
                .await?;
            }
        }
        for (index, desired) in source.video_sales_policies.iter().enumerate() {
            if current.sales.iter().any(|policy| policy == desired)
                || imported_sales.contains(&index)
            {
                continue;
            }
            self.create_video_sales_policy(desired).await?;
        }

        let current_capabilities: Vec<RemoteVideoCapabilityPolicy> = self
            .request(Method::GET, "/api/option/video-capabilities", None, true)
            .await?;
        for desired in &source.video_capabilities {
            let matched = current_capabilities
                .iter()
                .any(|policy| remote_capability_matches(policy, desired));
            if !matched {
                let mut body = serde_json::to_value(desired).map_err(|error| {
                    AppError::Target(format!("serialize video capability policy: {error}"))
                })?;
                body["status"] = Value::String("active".to_owned());
                body["reason"] = Value::String("meowai-deploy source sync".to_owned());
                self.request_no_data(
                    Method::POST,
                    "/api/option/video-capabilities",
                    Some(body),
                    true,
                )
                .await?;
            }
        }

        let refreshed: VideoPricingResponse = self
            .request(Method::GET, "/api/option/video-pricing", None, true)
            .await?;
        if source
            .video_sales_policies
            .iter()
            .any(|desired| !refreshed.sales.iter().any(|policy| policy == desired))
            || source.video_cost_policies.iter().any(|desired| {
                !refreshed
                    .costs
                    .iter()
                    .any(|policy| remote_cost_matches(policy, desired))
            })
        {
            return Err(AppError::Target(
                "downstream Seedance pricing differs after import".to_owned(),
            ));
        }
        let refreshed_capabilities: Vec<RemoteVideoCapabilityPolicy> = self
            .request(Method::GET, "/api/option/video-capabilities", None, true)
            .await?;
        if source.video_capabilities.iter().any(|desired| {
            !refreshed_capabilities
                .iter()
                .any(|policy| remote_capability_matches(policy, desired))
        }) {
            return Err(AppError::Target(
                "downstream Seedance capabilities differ after import".to_owned(),
            ));
        }
        Ok(())
    }

    async fn create_video_sales_policy(&self, desired: &VideoSalesPolicy) -> Result<()> {
        let mut body = serde_json::to_value(desired)
            .map_err(|error| AppError::Target(format!("serialize video sales policy: {error}")))?;
        body["status"] = Value::String("active".to_owned());
        body["reason"] = Value::String("meowai-deploy source sync".to_owned());
        self.request_no_data(
            Method::POST,
            "/api/option/video-pricing/sales",
            Some(body),
            true,
        )
        .await
    }

    pub async fn sync_channels(
        &self,
        config: &DeploymentConfig,
        container_source_url: &str,
        catalog: &GroupCatalog,
        bindings: &[TokenBinding],
        previous: &BTreeMap<String, ChannelState>,
        force: bool,
    ) -> Result<(ChannelSyncResult, BTreeMap<String, ChannelState>)> {
        let binding_by_group = bindings
            .iter()
            .map(|binding| (binding.group_id.as_str(), binding))
            .collect::<HashMap<_, _>>();
        if binding_by_group.len() != catalog.groups.len() {
            return Err(AppError::Target(
                "source token bindings do not cover every source group".to_owned(),
            ));
        }

        let mut ratios = BTreeMap::new();
        for group in &catalog.groups {
            ratios.insert(group.group_name.clone(), 1.0_f64);
        }
        self.update_option(
            "GroupRatio",
            &serde_json::to_string(&ratios)
                .map_err(|error| AppError::Target(format!("serialize GroupRatio: {error}")))?,
        )
        .await?;

        let existing = self.channels().await?;
        let mut result = ChannelSyncResult::default();
        let mut next = BTreeMap::new();
        for group in &catalog.groups {
            let binding = binding_by_group
                .get(group.group_id.as_str())
                .ok_or_else(|| {
                    AppError::Target(format!(
                        "missing token for source group {}",
                        group.group_name
                    ))
                })?;
            let tag = channel_tag(&config.deployment_id(), &group.group_id);
            let matching = existing
                .iter()
                .filter(|channel| channel.tag.as_deref() == Some(tag.as_str()))
                .collect::<Vec<_>>();
            if matching.len() > 1 {
                return Err(AppError::Target(format!(
                    "multiple downstream channels use managed tag {tag}"
                )));
            }
            let desired = DesiredChannel::new(container_source_url, group, binding, tag.clone())?;
            let old = previous.get(&group.group_id);
            let channel_id = if let Some(channel) = matching.first() {
                let key_changed = old
                    .map(|state| state.key_sha256 != desired.key_sha256)
                    .unwrap_or(false);
                let legacy_name = format!("{} / {}", config.website_name, group.group_name);
                let is_legacy_name_only =
                    is_legacy_name_only_change(channel, &desired, &legacy_name, key_changed);
                if channel_needs_update(channel, &desired) || key_changed {
                    if !force && old.is_some() && !is_legacy_name_only {
                        return Err(AppError::Target(format!(
                            "managed downstream channel {} drifted; rerun sync with --force",
                            channel.id
                        )));
                    }
                    self.update_channel(channel.id, &desired).await?;
                    result.updated += 1;
                } else {
                    result.reused += 1;
                }
                if channel.status != CHANNEL_STATUS_ENABLED {
                    self.update_channel_status(channel.id, CHANNEL_STATUS_ENABLED)
                        .await?;
                }
                channel.id
            } else {
                self.create_channel(&desired).await?;
                let refreshed = self.channels().await?;
                let created = refreshed
                    .iter()
                    .filter(|channel| channel.tag.as_deref() == Some(tag.as_str()))
                    .collect::<Vec<_>>();
                if created.len() != 1 {
                    return Err(AppError::Target(format!(
                        "could not uniquely read back channel {tag} after creation"
                    )));
                }
                result.created += 1;
                created[0].id
            };
            next.insert(
                group.group_id.clone(),
                ChannelState {
                    group_id: group.group_id.clone(),
                    group_name: group.group_name.clone(),
                    token_id: binding.token_id,
                    token_name: binding.token_name.clone(),
                    channel_id,
                    key_sha256: desired.key_sha256,
                    config_sha256: desired.config_sha256,
                    enabled: true,
                },
            );
        }
        Ok((result, next))
    }

    pub async fn disable_channel(&self, channel_id: i64) -> Result<()> {
        self.update_channel_status(channel_id, CHANNEL_STATUS_MANUALLY_DISABLED)
            .await
    }

    pub async fn disable_removed_channels(
        &self,
        previous: &BTreeMap<String, ChannelState>,
        current: &mut BTreeMap<String, ChannelState>,
    ) -> Result<usize> {
        let mut disabled = 0;
        for (group_id, state) in previous {
            if current.contains_key(group_id) {
                continue;
            }
            let mut retained = state.clone();
            if state.enabled {
                self.disable_channel(state.channel_id).await?;
                retained.enabled = false;
                disabled += 1;
            }
            current.insert(group_id.clone(), retained);
        }
        Ok(disabled)
    }

    async fn channels(&self) -> Result<Vec<RemoteChannel>> {
        let mut all = Vec::new();
        let mut page = 1;
        loop {
            let path = format!("/api/channel/?p={page}&size=100");
            let current: Page<RemoteChannel> = self.request(Method::GET, &path, None, true).await?;
            let count = current.items.len();
            all.extend(current.items);
            if all.len() >= current.total || count == 0 {
                break;
            }
            if current.page != page || current.page_size == 0 {
                return Err(AppError::Target(
                    "downstream channel pagination returned invalid metadata".to_owned(),
                ));
            }
            page += 1;
        }
        Ok(all)
    }

    async fn create_channel(&self, desired: &DesiredChannel) -> Result<()> {
        self.request_no_data(
            Method::POST,
            "/api/channel/",
            Some(json!({"mode": "single", "channel": desired.body()})),
            true,
        )
        .await
    }

    async fn update_channel(&self, id: i64, desired: &DesiredChannel) -> Result<()> {
        let mut body = desired.body();
        body["id"] = json!(id);
        self.request_no_data(Method::PUT, "/api/channel/", Some(body), true)
            .await
    }

    async fn update_channel_status(&self, id: i64, status: i64) -> Result<()> {
        let path = format!("/api/channel/{id}/status");
        let _: Value = self
            .request(Method::POST, &path, Some(json!({"status": status})), true)
            .await?;
        Ok(())
    }

    async fn options(&self) -> Result<BTreeMap<String, String>> {
        let entries: Vec<OptionEntry> = self
            .request(Method::GET, "/api/option/", None, true)
            .await?;
        let mut options = BTreeMap::new();
        for entry in entries {
            let value = match entry.value {
                Value::String(value) => value,
                value => value.to_string(),
            };
            options.insert(entry.key, value);
        }
        Ok(options)
    }

    async fn update_option(&self, key: &str, value: &str) -> Result<()> {
        self.request_no_data(
            Method::PUT,
            "/api/option/",
            Some(json!({"key": key, "value": value})),
            true,
        )
        .await
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        authenticated: bool,
    ) -> Result<T> {
        let url = format!("{}{}", self.endpoint.base_url(), path);
        let mut request = self.http.request(method, &url);
        if authenticated {
            let token = self.access_token.as_ref().ok_or_else(|| {
                AppError::Target(
                    "downstream request requires an authenticated admin session".to_owned(),
                )
            })?;
            request = request.bearer_auth(token.expose_secret());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| AppError::Target(format!("downstream request {path}: {error}")))?;
        let status = response.status();
        let envelope = response.json::<ApiEnvelope<T>>().await.map_err(|error| {
            AppError::Target(format!(
                "decode downstream response {path} (HTTP {status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.success {
            return Err(AppError::Target(format!(
                "downstream request {path} failed (HTTP {status}): {}",
                envelope.message
            )));
        }
        envelope
            .data
            .ok_or_else(|| AppError::Target(format!("downstream response {path} has no data")))
    }

    async fn request_no_data(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        authenticated: bool,
    ) -> Result<()> {
        let url = format!("{}{}", self.endpoint.base_url(), path);
        let mut request = self.http.request(method, &url);
        if authenticated {
            let token = self.access_token.as_ref().ok_or_else(|| {
                AppError::Target(
                    "downstream request requires an authenticated admin session".to_owned(),
                )
            })?;
            request = request.bearer_auth(token.expose_secret());
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| AppError::Target(format!("downstream request {path}: {error}")))?;
        let status = response.status();
        let envelope = response
            .json::<ApiEnvelope<Value>>()
            .await
            .map_err(|error| {
                AppError::Target(format!(
                    "decode downstream response {path} (HTTP {status}): {error}"
                ))
            })?;
        if !status.is_success() || !envelope.success {
            return Err(AppError::Target(format!(
                "downstream request {path} failed (HTTP {status}): {}",
                envelope.message
            )));
        }
        Ok(())
    }
}

fn sales_can_precede_current_costs(
    current: &VideoPricingResponse,
    desired: &VideoSalesPolicy,
) -> bool {
    current
        .costs
        .iter()
        .filter(|cost| cost.public_model == desired.public_model)
        .all(|cost| desired.customer_rate_bps > cost.upstream_group_rate_bps)
}

fn remote_cost_matches(remote: &RemoteVideoCostPolicy, desired: &VideoCostPolicy) -> bool {
    let scope = if remote.promotion_scope.trim().is_empty() {
        None
    } else {
        serde_json::from_str::<Value>(&remote.promotion_scope).ok()
    };
    remote.provider == desired.provider
        && remote.public_model == desired.public_model
        && remote.upstream_group_rate_bps == desired.upstream_group_rate_bps
        && remote.promotion_rate_bps == desired.promotion_rate_bps
        && scope == desired.promotion_scope
        && remote.promotion_effective_from == desired.promotion_effective_from
        && remote.promotion_effective_until == desired.promotion_effective_until
        && remote.effective_from == desired.effective_from
        && remote.effective_until == desired.effective_until
        && remote.evidence_status == desired.evidence_status
}

fn remote_capability_matches(
    remote: &RemoteVideoCapabilityPolicy,
    desired: &VideoCapabilityPolicy,
) -> bool {
    remote.public_model == desired.public_model
        && remote.effective_from == desired.effective_from
        && remote.effective_until == desired.effective_until
        && serde_json::from_str::<Value>(&remote.capabilities_json)
            .is_ok_and(|value| value == desired.capabilities)
}

struct DesiredChannel {
    name: String,
    base_url: String,
    key: String,
    key_sha256: String,
    models: String,
    group: String,
    tag: String,
    config_sha256: String,
}

impl DesiredChannel {
    fn new(
        container_source_url: &str,
        group: &crate::source::SourceGroup,
        binding: &TokenBinding,
        tag: String,
    ) -> Result<Self> {
        let models = group.models.join(",");
        let key = binding.api_key().expose_secret().to_owned();
        let name = managed_channel_name(&group.group_name);
        let base_url = container_source_url.trim_end_matches('/').to_owned();
        let key_sha256 = sha256_hex(key.as_bytes());
        let fingerprint = json!({
            "type": CHANNEL_TYPE_NEWAPI,
            "name": name,
            "base_url": base_url,
            "models": models,
            "group": group.group_name,
            "tag": tag,
            "key_sha256": key_sha256
        });
        let config_sha256 = sha256_hex(
            serde_json::to_vec(&fingerprint)
                .map_err(|error| {
                    AppError::Target(format!("serialize channel fingerprint: {error}"))
                })?
                .as_slice(),
        );
        Ok(Self {
            name,
            base_url,
            key,
            key_sha256,
            models,
            group: group.group_name.clone(),
            tag,
            config_sha256,
        })
    }

    fn body(&self) -> Value {
        json!({
            "type": CHANNEL_TYPE_NEWAPI,
            "name": self.name,
            "key": self.key,
            "base_url": self.base_url,
            "models": self.models,
            "group": self.group,
            "tag": self.tag,
            "status": CHANNEL_STATUS_ENABLED,
            "other": "",
            "other_info": ""
        })
    }
}

fn managed_channel_name(group_name: &str) -> String {
    format!("{CHANNEL_SOURCE_NAME} / {group_name}")
}

fn channel_tag(deployment_id: &str, group_id: &str) -> String {
    format!(
        "meowai-deploy:{deployment_id}:{}",
        &sha256_hex(group_id.as_bytes())[..16]
    )
}

fn channel_needs_update(current: &RemoteChannel, desired: &DesiredChannel) -> bool {
    current.channel_type != CHANNEL_TYPE_NEWAPI
        || current.name != desired.name
        || channel_needs_update_except_name(current, desired)
}

fn channel_needs_update_except_name(current: &RemoteChannel, desired: &DesiredChannel) -> bool {
    current.channel_type != CHANNEL_TYPE_NEWAPI
        || current
            .base_url
            .as_deref()
            .unwrap_or_default()
            .trim_end_matches('/')
            != desired.base_url
        || current.models != desired.models
        || current.group != desired.group
        || current.tag.as_deref() != Some(desired.tag.as_str())
}

fn is_legacy_name_only_change(
    current: &RemoteChannel,
    desired: &DesiredChannel,
    legacy_name: &str,
    key_changed: bool,
) -> bool {
    !key_changed
        && current.name == legacy_name
        && !channel_needs_update_except_name(current, desired)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::{config::Target, pricing::PricingConfig};

    use super::*;

    #[test]
    fn channel_tag_is_stable_and_does_not_include_the_raw_group_name() {
        let first = channel_tag("deployment", "official/secret group");
        assert_eq!(first, channel_tag("deployment", "official/secret group"));
        assert!(!first.contains("secret group"));
    }

    #[test]
    fn channel_name_identifies_the_upstream_provider() {
        assert_eq!(managed_channel_name("default"), "MeowAI / default");
    }

    #[test]
    fn readback_comparison_normalizes_a_trailing_base_url_slash() {
        let desired = DesiredChannel {
            name: "site / default".to_owned(),
            base_url: "https://source.example".to_owned(),
            key: "sk-secret".to_owned(),
            key_sha256: "hash".to_owned(),
            models: "gpt-test".to_owned(),
            group: "default".to_owned(),
            tag: "tag".to_owned(),
            config_sha256: "hash".to_owned(),
        };
        let current = RemoteChannel {
            id: 1,
            channel_type: CHANNEL_TYPE_NEWAPI,
            name: desired.name.clone(),
            status: CHANNEL_STATUS_ENABLED,
            base_url: Some("https://source.example/".to_owned()),
            models: desired.models.clone(),
            group: desired.group.clone(),
            tag: Some(desired.tag.clone()),
        };
        assert!(!channel_needs_update(&current, &desired));
    }

    #[test]
    fn legacy_downstream_site_prefix_is_a_name_only_change() {
        let desired = DesiredChannel {
            name: "MeowAI / default".to_owned(),
            base_url: "https://source.example".to_owned(),
            key: "sk-secret".to_owned(),
            key_sha256: "hash".to_owned(),
            models: "gpt-test".to_owned(),
            group: "default".to_owned(),
            tag: "tag".to_owned(),
            config_sha256: "hash".to_owned(),
        };
        let current = RemoteChannel {
            id: 1,
            channel_type: CHANNEL_TYPE_NEWAPI,
            name: "Downstream Site / default".to_owned(),
            status: CHANNEL_STATUS_ENABLED,
            base_url: Some(desired.base_url.clone()),
            models: desired.models.clone(),
            group: desired.group.clone(),
            tag: Some(desired.tag.clone()),
        };

        assert!(channel_needs_update(&current, &desired));
        assert!(!channel_needs_update_except_name(&current, &desired));
        assert!(is_legacy_name_only_change(
            &current,
            &desired,
            "Downstream Site / default",
            false
        ));
    }

    #[test]
    fn video_policy_readback_accepts_omitted_zero_time_fields() {
        let pricing: VideoPricingResponse = serde_json::from_value(json!({
            "sales": [{
                "public_model": "seedance-2.0",
                "official_no_video_micros": 46000000,
                "official_with_video_micros": 46000000,
                "customer_rate_bps": 8300,
                "effective_from": 100
            }],
            "costs": [{
                "provider": "4api-seedance-cn",
                "public_model": "seedance-2.0",
                "upstream_group_rate_bps": 7000,
                "promotion_rate_bps": 10000,
                "promotion_scope": "",
                "effective_from": 100,
                "evidence_status": "unverified"
            }]
        }))
        .expect("decode downstream video pricing response");
        assert_eq!(pricing.sales[0].effective_until, 0);
        assert_eq!(pricing.costs[0].promotion_effective_from, 0);
        assert_eq!(pricing.costs[0].promotion_effective_until, 0);
        assert_eq!(pricing.costs[0].effective_until, 0);

        let capabilities: Vec<RemoteVideoCapabilityPolicy> = serde_json::from_value(json!([{
            "public_model": "seedance-2.0",
            "capabilities_json": "{}",
            "effective_from": 100
        }]))
        .expect("decode downstream video capabilities response");
        assert_eq!(capabilities[0].effective_until, 0);
    }

    #[test]
    fn video_policy_import_orders_increases_sales_before_costs() {
        let current: VideoPricingResponse = serde_json::from_value(json!({
            "sales": [],
            "costs": [{
                "provider": "4api-seedance-cn",
                "public_model": "seedance-2.0",
                "upstream_group_rate_bps": 7500,
                "promotion_rate_bps": 10000,
                "promotion_scope": "",
                "effective_from": 0,
                "evidence_status": "unverified"
            }]
        }))
        .expect("decode current video pricing");
        let desired = VideoSalesPolicy {
            public_model: "seedance-2.0".to_owned(),
            official_no_video_micros: 46_000_000,
            official_with_video_micros: 46_000_000,
            customer_rate_bps: 9000,
            effective_from: 0,
            effective_until: 0,
        };
        assert!(sales_can_precede_current_costs(&current, &desired));
    }

    #[test]
    fn video_policy_import_orders_decreases_costs_before_sales() {
        let current: VideoPricingResponse = serde_json::from_value(json!({
            "sales": [],
            "costs": [{
                "provider": "4api-seedance-cn",
                "public_model": "seedance-2.0",
                "upstream_group_rate_bps": 7000,
                "promotion_rate_bps": 10000,
                "promotion_scope": "",
                "effective_from": 0,
                "evidence_status": "unverified"
            }]
        }))
        .expect("decode current video pricing");
        let desired = VideoSalesPolicy {
            public_model: "seedance-2.0".to_owned(),
            official_no_video_micros: 46_000_000,
            official_with_video_micros: 46_000_000,
            customer_rate_bps: 6500,
            effective_from: 0,
            effective_until: 0,
        };
        assert!(!sales_can_precede_current_costs(&current, &desired));
    }

    #[tokio::test]
    async fn import_pricing_writes_and_reads_all_source_options() {
        let source_pricing = PricingConfig::from_value(json!({
            "model_price": {"fixed": 2},
            "model_ratio": {"input": 1},
            "cache_ratio": {"cache": 0.5},
            "create_cache_ratio": {"create": 1.25},
            "completion_ratio": {"output": 3},
            "image_ratio": {"image": 4},
            "audio_ratio": {"audio": 5},
            "audio_completion_ratio": {"audio-output": 6}
        }))
        .expect("parse source pricing");
        let options = source_pricing.options().expect("build source options");
        let returned_options = options
            .iter()
            .map(|option| json!({"key": option.key, "value": option.canonical_json}))
            .collect::<Vec<_>>();

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api/option/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": ""
            })))
            .expect(20)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/option/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": returned_options
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/option/video-pricing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": {"sales": [], "costs": []}
            })))
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/option/video-capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": []
            })))
            .expect(2)
            .mount(&server)
            .await;

        let port = server.address().port();
        let executor = TargetExecutor::new(Target::Local, PathBuf::from("/tmp/meowai-deploy-test"));
        let mut client = NewApiClient::connect(&executor, port).expect("create client");
        client.access_token = Some(SecretString::from("downstream-admin"));

        let hashes = client
            .import_pricing(&source_pricing)
            .await
            .expect("import source pricing");
        assert_eq!(hashes.len(), 23);
        assert_eq!(hashes.get("model_price").map(String::len), Some(64));
    }
}
