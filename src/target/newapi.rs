use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use reqwest::{Client, Method};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    config::DeploymentConfig,
    error::{AppError, Result},
    pricing::{
        AccountPurchase, AccountSeedancePurchase, PricingConfig, VideoCapabilityPolicy,
        VideoSalesPolicy,
    },
    security::sha256_hex,
    source::{GroupCatalog, TokenBinding},
    state::ChannelState,
    sync_plan::{SyncModule, module_for_pricing_key},
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

#[derive(Debug, Deserialize)]
struct ManagedChannelPricingPatchResult {
    matched: usize,
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
    #[serde(default)]
    other_info: Value,
    #[serde(flatten)]
    extra_fields: BTreeMap<String, Value>,
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

#[allow(dead_code)]
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

    pub async fn login_existing(
        &mut self,
        config: &DeploymentConfig,
        password: &SecretString,
    ) -> Result<()> {
        let setup: SetupData = self.request(Method::GET, "/api/setup", None, false).await?;
        if !setup.status {
            return Err(AppError::Target(
                "downstream is not initialized; run onboard before sync".to_owned(),
            ));
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

    pub async fn configure_public_status_url(&self, public_status_url: &str) -> Result<()> {
        self.update_option("console_setting.public_status_url", public_status_url)
            .await?;
        let options = self.options().await?;
        if options
            .get("console_setting.public_status_url")
            .is_none_or(|value| value != public_status_url)
        {
            return Err(AppError::Target(
                "downstream public status URL differs after configuration".to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn apply_group_structure(&self, catalog: &GroupCatalog) -> Result<()> {
        let user_usable_groups = catalog
            .groups
            .iter()
            .filter(|group| group.user_selectable)
            .map(|group| (group.group_name.clone(), group.description.clone()))
            .collect::<BTreeMap<_, _>>();
        self.update_json_option("UserUsableGroups", &user_usable_groups)
            .await
    }

    pub async fn apply_group_pricing(&self, catalog: &GroupCatalog) -> Result<()> {
        let mut ratios = BTreeMap::new();
        for group in &catalog.groups {
            if group.group_name == "seedance-cn"
                && group
                    .ratio
                    .as_f64()
                    .is_none_or(|ratio| (ratio - 1.0).abs() > f64::EPSILON)
            {
                return Err(AppError::State(
                    "seedance-cn group ratio must remain 1.0".to_owned(),
                ));
            }
            ratios.insert(group.group_name.clone(), group.ratio.clone());
        }
        self.update_json_option("GroupRatio", &ratios).await
    }

    pub async fn apply_topup_pricing(&self, catalog: &GroupCatalog) -> Result<()> {
        let topup_ratios = catalog
            .groups
            .iter()
            .filter_map(|group| {
                group
                    .topup_ratio
                    .clone()
                    .map(|ratio| (group.group_name.clone(), ratio))
            })
            .collect::<BTreeMap<_, _>>();
        self.update_json_option("TopupGroupRatio", &topup_ratios)
            .await
    }

    async fn update_json_option<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let expected = serde_json::to_value(value)
            .map_err(|error| AppError::Target(format!("serialize {key}: {error}")))?;
        self.update_option(key, &expected.to_string()).await?;
        let returned = self.options().await?;
        let actual = returned
            .get(key)
            .ok_or_else(|| AppError::Target(format!("downstream option {key} is missing")))
            .and_then(|value| {
                serde_json::from_str::<Value>(value)
                    .map_err(|error| AppError::Target(format!("decode {key}: {error}")))
            })?;
        if actual != expected {
            return Err(AppError::Target(format!(
                "downstream option {key} differs after update"
            )));
        }
        Ok(())
    }

    pub async fn import_pricing(
        &self,
        source_pricing: &PricingConfig,
    ) -> Result<BTreeMap<String, String>> {
        self.import_pricing_modules(
            source_pricing,
            &SyncModule::ALL.into_iter().collect::<BTreeSet<_>>(),
        )
        .await
    }

    pub async fn import_pricing_modules(
        &self,
        source_pricing: &PricingConfig,
        modules: &BTreeSet<SyncModule>,
    ) -> Result<BTreeMap<String, String>> {
        let options_to_import = source_pricing
            .options()?
            .into_iter()
            .filter(|option| modules.contains(&module_for_pricing_key(option.key)))
            .collect::<Vec<_>>();
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
        if modules.contains(&SyncModule::Seedance) {
            self.import_video_policies(source_pricing).await?;
            for (name, value) in [
                (
                    "video_sales_policies",
                    serde_json::to_value(&source_pricing.video_sales_policies),
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
        }
        Ok(hashes)
    }

    pub async fn read_managed_snapshot(
        &self,
        source_pricing: &PricingConfig,
        deployment_id: &str,
        managed_channel_tags: &BTreeSet<String>,
    ) -> Result<BTreeMap<SyncModule, Value>> {
        let options = self.options().await?;
        let mut modules = SyncModule::ALL
            .into_iter()
            .map(|module| (module, serde_json::Map::new()))
            .collect::<BTreeMap<_, _>>();
        for option in source_pricing.options()? {
            let value = options
                .get(option.key)
                .map(|value| snapshot_option_value(value))
                .unwrap_or(Value::Null);
            modules
                .get_mut(&module_for_pricing_key(option.key))
                .expect("all sync modules initialized")
                .insert(option.key.to_owned(), value);
        }
        for (key, module) in [
            ("UserUsableGroups", SyncModule::Groups),
            ("GroupRatio", SyncModule::GroupPricing),
            ("TopupGroupRatio", SyncModule::Units),
            ("console_setting.public_status_url", SyncModule::Kuma),
        ] {
            modules
                .get_mut(&module)
                .expect("all sync modules initialized")
                .insert(
                    key.to_owned(),
                    options
                        .get(key)
                        .map(|value| snapshot_option_value(value))
                        .unwrap_or(Value::Null),
                );
        }

        let tag_prefix = format!("meowai-deploy:{deployment_id}:");
        let remote_channels = self.channels().await?;
        let purchase_channels = remote_channels
            .iter()
            .filter(|channel| {
                channel.channel_type == CHANNEL_TYPE_NEWAPI
                    && channel
                        .tag
                        .as_ref()
                        .is_some_and(|tag| managed_channel_tags.contains(tag))
            })
            .collect::<Vec<_>>();
        let managed_channel_purchase =
            managed_channel_purchase_snapshot(&purchase_channels, !managed_channel_tags.is_empty());
        let mut channels = remote_channels
            .into_iter()
            .filter(|channel| {
                channel.status == CHANNEL_STATUS_ENABLED
                    && channel
                        .tag
                        .as_deref()
                        .is_some_and(|tag| tag.starts_with(&tag_prefix))
            })
            .map(|channel| {
                json!({
                    "type": channel.channel_type,
                    "name": channel.name,
                    "status": channel.status,
                    "base_url": channel.base_url.unwrap_or_default().trim_end_matches('/'),
                    "models": channel.models,
                    "group": channel.group,
                    "tag": channel.tag.unwrap_or_default(),
                    "metadata": channel_snapshot_metadata(&channel.other_info),
                })
            })
            .collect::<Vec<_>>();
        channels.sort_by(|left, right| left["tag"].as_str().cmp(&right["tag"].as_str()));
        modules
            .get_mut(&SyncModule::Channels)
            .expect("channels module initialized")
            .insert("channels".to_owned(), Value::Array(channels));
        modules
            .get_mut(&SyncModule::Channels)
            .expect("channels module initialized")
            .insert("token_actions".to_owned(), Value::Array(Vec::new()));

        let video_pricing: VideoPricingResponse = self
            .request(Method::GET, "/api/option/video-pricing", None, true)
            .await?;
        let capabilities: Vec<RemoteVideoCapabilityPolicy> = self
            .request(Method::GET, "/api/option/video-capabilities", None, true)
            .await?;
        let seedance = modules
            .get_mut(&SyncModule::Seedance)
            .expect("Seedance module initialized");
        seedance.insert(
            "sales".to_owned(),
            serde_json::to_value(video_pricing.sales)
                .map_err(|error| AppError::State(error.to_string()))?,
        );
        seedance.insert(
            "capabilities".to_owned(),
            Value::Array(
                capabilities
                    .into_iter()
                    .map(|policy| {
                        json!({
                            "public_model": policy.public_model,
                            "capabilities": snapshot_option_value(&policy.capabilities_json),
                            "effective_from": policy.effective_from,
                            "effective_until": policy.effective_until,
                        })
                    })
                    .collect(),
            ),
        );
        seedance.insert(
            "managed_channel_purchase".to_owned(),
            managed_channel_purchase,
        );
        Ok(modules
            .into_iter()
            .map(|(module, values)| (module, Value::Object(values)))
            .collect())
    }

    pub async fn apply_snapshot_module(
        &self,
        module: SyncModule,
        deployment_id: &str,
        desired: &Value,
        downstream_current: &Value,
    ) -> Result<()> {
        if matches!(module, SyncModule::Channels | SyncModule::Kuma) {
            return Err(AppError::State(format!(
                "{} is not an option snapshot module",
                module.name()
            )));
        }
        let desired = desired.as_object().ok_or_else(|| {
            AppError::State(format!("{} snapshot must be an object", module.name()))
        })?;
        let current = downstream_current.as_object();
        for (key, value) in desired {
            if matches!(
                key.as_str(),
                "groups"
                    | "purchase"
                    | "account_purchase"
                    | "managed_channel_purchase"
                    | "sales"
                    | "capabilities"
                    | "channels"
                    | "tokens"
                    | "removed_tokens"
                    | "manifest"
            ) || current.and_then(|current| current.get(key)) == Some(value)
            {
                continue;
            }
            self.update_option(key, &snapshot_option_string(value)?)
                .await?;
        }
        if module == SyncModule::Seedance {
            let sales = desired
                .get("sales")
                .cloned()
                .map(serde_json::from_value::<Vec<VideoSalesPolicy>>)
                .transpose()
                .map_err(|error| AppError::State(format!("invalid Seedance sales: {error}")))?
                .unwrap_or_default();
            let capabilities = desired
                .get("capabilities")
                .cloned()
                .map(serde_json::from_value::<Vec<VideoCapabilityPolicy>>)
                .transpose()
                .map_err(|error| {
                    AppError::State(format!("invalid Seedance capabilities: {error}"))
                })?
                .unwrap_or_default();
            self.import_video_snapshot(&sales, &capabilities).await?;
            let account_purchase = desired
                .get("account_purchase")
                .cloned()
                .map(serde_json::from_value::<AccountPurchase>)
                .transpose()
                .map_err(|error| {
                    AppError::State(format!("invalid Seedance account purchase: {error}"))
                })?
                .ok_or_else(|| {
                    AppError::State("Seedance snapshot is missing account_purchase".to_owned())
                })?;
            self.patch_managed_channel_pricing(deployment_id, &account_purchase.seedance)
                .await?;
        }
        Ok(())
    }

    async fn patch_managed_channel_pricing(
        &self,
        deployment_id: &str,
        seedance_purchase: &[AccountSeedancePurchase],
    ) -> Result<()> {
        let purchases = seedance_purchase_metadata(seedance_purchase);
        let result: ManagedChannelPricingPatchResult = self
            .request(
                Method::PATCH,
                "/api/channel/managed-pricing",
                Some(json!({
                    "deployment_id": deployment_id,
                    "seedance_purchase": purchases,
                })),
                true,
            )
            .await?;
        let expected = managed_channel_metadata_from_seedance(seedance_purchase);
        let tag_prefix = format!("meowai-deploy:{deployment_id}:");
        let channels = self
            .channels()
            .await?
            .into_iter()
            .filter(|channel| {
                channel.channel_type == CHANNEL_TYPE_NEWAPI
                    && channel
                        .tag
                        .as_deref()
                        .is_some_and(|tag| tag.starts_with(&tag_prefix))
            })
            .collect::<Vec<_>>();
        if result.matched != channels.len() {
            return Err(AppError::Target(format!(
                "downstream patched {} managed channels but {} deployment channels were returned",
                result.matched,
                channels.len()
            )));
        }
        if channels
            .iter()
            .any(|channel| !managed_channel_metadata_matches(&channel.other_info, &expected))
        {
            return Err(AppError::Target(
                "downstream managed channel pricing metadata differs after update".to_owned(),
            ));
        }
        Ok(())
    }

    async fn import_video_snapshot(
        &self,
        sales: &[VideoSalesPolicy],
        capabilities: &[VideoCapabilityPolicy],
    ) -> Result<()> {
        let current: VideoPricingResponse = self
            .request(Method::GET, "/api/option/video-pricing", None, true)
            .await?;
        for desired in sales {
            if !current.sales.iter().any(|policy| policy == desired) {
                self.create_video_sales_policy(desired).await?;
            }
        }
        let current_capabilities: Vec<RemoteVideoCapabilityPolicy> = self
            .request(Method::GET, "/api/option/video-capabilities", None, true)
            .await?;
        for desired in capabilities {
            if current_capabilities
                .iter()
                .any(|policy| remote_capability_matches(policy, desired))
            {
                continue;
            }
            let mut body = serde_json::to_value(desired).map_err(|error| {
                AppError::Target(format!("serialize video capability policy: {error}"))
            })?;
            body["status"] = Value::String("active".to_owned());
            body["reason"] = Value::String("meowai-deploy confirmed sync".to_owned());
            self.request_no_data(
                Method::POST,
                "/api/option/video-capabilities",
                Some(body),
                true,
            )
            .await?;
        }
        Ok(())
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

    #[allow(clippy::too_many_arguments)]
    pub async fn sync_channels_with_pricing(
        &self,
        config: &DeploymentConfig,
        container_source_url: &str,
        catalog: &GroupCatalog,
        bindings: &[TokenBinding],
        previous: &BTreeMap<String, ChannelState>,
        force: bool,
        pricing: Option<&PricingConfig>,
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
            let desired =
                DesiredChannel::new(container_source_url, group, binding, tag.clone(), pricing)?;
            let old = previous.get(&group.group_id);
            let channel_id = if let Some(channel) = matching.first() {
                let key_changed = old
                    .map(|state| state.key_sha256 != desired.key_sha256)
                    .unwrap_or(false);
                let legacy_name = format!("{} / {}", config.website_name, group.group_name);
                let is_legacy_name_only =
                    is_legacy_name_only_change(channel, &desired, &legacy_name, key_changed);
                let local_drift = old.is_some_and(|state| {
                    remote_channel_config_sha256(channel, &state.key_sha256) != state.config_sha256
                });
                let manually_disabled = old.is_some_and(|state| state.enabled)
                    && channel.status != CHANNEL_STATUS_ENABLED;
                if channel_needs_update(channel, &desired) || key_changed {
                    if !force && local_drift && !is_legacy_name_only {
                        result.reused += 1;
                    } else {
                        self.update_channel(channel.id, &desired, Some(channel))
                            .await?;
                        result.updated += 1;
                    }
                } else {
                    result.reused += 1;
                }
                if channel.status != CHANNEL_STATUS_ENABLED && (force || !manually_disabled) {
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
                    enabled: matching.first().is_none_or(|channel| {
                        channel.status == CHANNEL_STATUS_ENABLED
                            || force
                            || !old.is_some_and(|state| state.enabled)
                    }),
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

    async fn update_channel(
        &self,
        id: i64,
        desired: &DesiredChannel,
        existing: Option<&RemoteChannel>,
    ) -> Result<()> {
        let mut body = desired.body_with_existing(existing);
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
        .all(|cost| desired.customer_rate_bps >= cost.upstream_group_rate_bps)
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

fn snapshot_option_value(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_owned()))
}

fn snapshot_option_string(value: &Value) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        value => serde_json::to_string(value)
            .map_err(|error| AppError::State(format!("serialize option snapshot: {error}"))),
    }
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
    metadata: Value,
}

impl DesiredChannel {
    fn new(
        container_source_url: &str,
        group: &crate::source::SourceGroup,
        binding: &TokenBinding,
        tag: String,
        pricing: Option<&PricingConfig>,
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
            metadata: managed_channel_metadata(pricing),
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
            "other_info": self.metadata.to_string()
        })
    }

    fn body_with_existing(&self, existing: Option<&RemoteChannel>) -> Value {
        let mut body = self.body();
        if let Some(existing) = existing {
            for field in [
                "openai_organization",
                "test_model",
                "weight",
                "other",
                "model_mapping",
                "status_code_mapping",
                "priority",
                "auto_ban",
                "setting",
                "settings",
                "param_override",
                "header_override",
                "remark",
            ] {
                if let Some(value) = existing.extra_fields.get(field) {
                    body[field] = value.clone();
                }
            }
            let mut metadata = channel_metadata_value(&existing.other_info);
            if let (Some(current), Some(desired)) =
                (metadata.as_object_mut(), self.metadata.as_object())
            {
                for (key, value) in desired {
                    current.insert(key.clone(), value.clone());
                }
                body["other_info"] = Value::String(Value::Object(current.clone()).to_string());
            }
        }
        body.as_object_mut()
            .expect("channel body is an object")
            .remove("status");
        body
    }
}

pub(crate) fn managed_channel_name(group_name: &str) -> String {
    format!("{CHANNEL_SOURCE_NAME} / {group_name}")
}

pub(crate) fn channel_tag(deployment_id: &str, group_id: &str) -> String {
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
        || !managed_channel_metadata_matches(&current.other_info, &desired.metadata)
}

fn remote_channel_config_sha256(current: &RemoteChannel, key_sha256: &str) -> String {
    let fingerprint = json!({
        "type": current.channel_type,
        "name": current.name,
        "base_url": current.base_url.as_deref().unwrap_or_default().trim_end_matches('/'),
        "models": current.models,
        "group": current.group,
        "tag": current.tag.clone().unwrap_or_default(),
        "key_sha256": key_sha256,
    });
    sha256_hex(
        serde_json::to_vec(&fingerprint)
            .expect("serialize channel fingerprint")
            .as_slice(),
    )
}

fn managed_channel_metadata(pricing: Option<&PricingConfig>) -> Value {
    let mut metadata = json!({
        "managed_by": "meowai-deploy",
        "pricing_source": "meowai-onboard",
        "capability_source": "4api-compatible",
    });
    if let Some(pricing) = pricing {
        metadata["seedance_purchase"] =
            seedance_purchase_metadata(&pricing.account_purchase.seedance);
    }
    metadata
}

fn managed_channel_metadata_from_seedance(policies: &[AccountSeedancePurchase]) -> Value {
    json!({
        "managed_by": "meowai-deploy",
        "pricing_source": "meowai-onboard",
        "capability_source": "4api-compatible",
        "seedance_purchase": seedance_purchase_metadata(policies),
    })
}

fn seedance_purchase_metadata(policies: &[AccountSeedancePurchase]) -> Value {
    Value::Object(
        policies
            .iter()
            .map(|policy| {
                (
                    policy.public_model.clone(),
                    json!({
                        "purchase_rate_bps": policy.purchase_rate_bps,
                        "purchase_source": policy.purchase_source,
                        "policy_version": policy.policy_version,
                        "effective_from": policy.effective_from,
                    }),
                )
            })
            .collect(),
    )
}

fn channel_metadata_value(value: &Value) -> Value {
    match value {
        Value::String(value) => serde_json::from_str(value).unwrap_or(Value::Null),
        Value::Object(_) => value.clone(),
        _ => Value::Null,
    }
}

fn channel_snapshot_metadata(value: &Value) -> Value {
    let mut metadata = channel_metadata_value(value);
    if let Some(metadata) = metadata.as_object_mut() {
        metadata.remove("seedance_purchase");
    }
    metadata
}

fn managed_channel_purchase_snapshot(
    channels: &[&RemoteChannel],
    channels_expected: bool,
) -> Value {
    if channels.is_empty() {
        return if channels_expected {
            Value::Null
        } else {
            Value::Object(serde_json::Map::new())
        };
    }
    let purchases = channels
        .iter()
        .map(|channel| {
            channel_metadata_value(&channel.other_info)
                .get("seedance_purchase")
                .cloned()
                .unwrap_or(Value::Null)
        })
        .map(|purchase| (purchase.to_string(), purchase))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect::<Vec<_>>();
    if purchases.len() == 1 {
        purchases.into_iter().next().unwrap_or(Value::Null)
    } else {
        Value::Array(purchases)
    }
}

fn managed_channel_metadata_matches(value: &Value, expected: &Value) -> bool {
    let value = channel_metadata_value(value);
    expected.as_object().is_some_and(|expected| {
        value.as_object().is_some_and(|actual| {
            expected
                .iter()
                .all(|(key, expected)| actual.get(key) == Some(expected))
        })
    })
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
            metadata: managed_channel_metadata(None),
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
            other_info: Value::String(desired.metadata.to_string()),
            extra_fields: BTreeMap::new(),
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
            metadata: managed_channel_metadata(None),
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
            other_info: Value::String(desired.metadata.to_string()),
            extra_fields: BTreeMap::new(),
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
    fn channel_update_preserves_downstream_owned_operational_fields() {
        let desired = DesiredChannel {
            name: "MeowAI / default".to_owned(),
            base_url: "https://source.example".to_owned(),
            key: "sk-new".to_owned(),
            key_sha256: "new-hash".to_owned(),
            models: "gpt-new".to_owned(),
            group: "default".to_owned(),
            tag: "managed-tag".to_owned(),
            config_sha256: "config-hash".to_owned(),
            metadata: managed_channel_metadata(None),
        };
        let current = RemoteChannel {
            id: 7,
            channel_type: CHANNEL_TYPE_NEWAPI,
            name: "MeowAI / default".to_owned(),
            status: CHANNEL_STATUS_ENABLED,
            base_url: Some("https://source.example".to_owned()),
            models: "gpt-old".to_owned(),
            group: "default".to_owned(),
            tag: Some("managed-tag".to_owned()),
            other_info: json!({
                "managed_by": "meowai-deploy",
                "local_note": "keep-me"
            }),
            extra_fields: BTreeMap::from([
                ("priority".to_owned(), json!(20)),
                ("weight".to_owned(), json!(30)),
                (
                    "setting".to_owned(),
                    json!("{\"proxy\":\"socks5://127.0.0.1:1080\"}"),
                ),
                ("model_mapping".to_owned(), json!("{\"alias\":\"gpt-new\"}")),
                ("param_override".to_owned(), json!("{\"temperature\":0.2}")),
                ("header_override".to_owned(), json!("{\"X-Local\":\"1\"}")),
                ("status_code_mapping".to_owned(), json!("{\"429\":503}")),
                ("auto_ban".to_owned(), json!(0)),
                ("remark".to_owned(), json!("local operations")),
            ]),
        };

        let body = desired.body_with_existing(Some(&current));
        assert_eq!(body["priority"], json!(20));
        assert_eq!(body["weight"], json!(30));
        assert_eq!(body["setting"], current.extra_fields["setting"]);
        assert_eq!(body["model_mapping"], current.extra_fields["model_mapping"]);
        assert_eq!(
            body["param_override"],
            current.extra_fields["param_override"]
        );
        assert_eq!(
            body["header_override"],
            current.extra_fields["header_override"]
        );
        assert_eq!(
            body["status_code_mapping"],
            current.extra_fields["status_code_mapping"]
        );
        assert_eq!(body["auto_ban"], json!(0));
        assert_eq!(body["remark"], json!("local operations"));
        assert!(body.get("status").is_none());
        let metadata = channel_metadata_value(&body["other_info"]);
        assert_eq!(metadata["local_note"], json!("keep-me"));
        assert_eq!(metadata["managed_by"], json!("meowai-deploy"));
        assert_eq!(body["key"], json!("sk-new"));
        assert_eq!(body["models"], json!("gpt-new"));
    }

    #[test]
    fn channel_snapshot_assigns_seedance_purchase_to_the_seedance_module() {
        let first = RemoteChannel {
            id: 1,
            channel_type: CHANNEL_TYPE_NEWAPI,
            name: "MeowAI / first".to_owned(),
            status: CHANNEL_STATUS_ENABLED,
            base_url: None,
            models: "seedance-2.0".to_owned(),
            group: "seedance-cn".to_owned(),
            tag: Some("meowai-deploy:0123456789abcdef:first".to_owned()),
            other_info: json!({
                "managed_by": "meowai-deploy",
                "local_note": "keep",
                "seedance_purchase": {"seedance-2.0": {"purchase_rate_bps": 7000}},
            }),
            extra_fields: BTreeMap::new(),
        };
        let mut second = first.clone();
        second.id = 2;
        second.other_info = json!({
            "managed_by": "meowai-deploy",
            "seedance_purchase": {"seedance-2.0": {"purchase_rate_bps": 7100}},
        });

        let channel_metadata = channel_snapshot_metadata(&first.other_info);
        assert_eq!(channel_metadata["local_note"], json!("keep"));
        assert!(channel_metadata.get("seedance_purchase").is_none());
        let purchase_snapshot = managed_channel_purchase_snapshot(&[&first, &second], true);
        assert_eq!(purchase_snapshot.as_array().map(Vec::len), Some(2));
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
    fn video_policy_import_allows_zero_margin_sales_at_current_cost() {
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
            customer_rate_bps: 7500,
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
    async fn public_status_url_is_written_to_the_downstream_kuma_page() {
        let server = MockServer::start().await;
        let expected = "http://uptime-kuma:3001/status/meowai-abcdef12";
        Mock::given(method("PUT"))
            .and(path("/api/option/"))
            .and(wiremock::matchers::body_json(json!({
                "key": "console_setting.public_status_url",
                "value": expected
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": ""
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/option/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": [{
                    "key": "console_setting.public_status_url",
                    "value": expected
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let port = server.address().port();
        let executor = TargetExecutor::new(Target::Local, PathBuf::from("/tmp/meowai-deploy-test"));
        let mut client = NewApiClient::connect(&executor, port).expect("create client");
        client.access_token = Some(SecretString::from("downstream-admin"));
        client
            .configure_public_status_url(expected)
            .await
            .expect("configure downstream Kuma URL");
    }

    #[tokio::test]
    async fn standalone_seedance_apply_refreshes_managed_channel_purchase_metadata() {
        let server = MockServer::start().await;
        let deployment_id = "0123456789abcdef";
        let expected_purchase = json!({
            "seedance-2.0": {
                "purchase_rate_bps": 8000,
                "purchase_source": "group_override",
                "policy_version": 1,
                "effective_from": 123,
            },
            "seedance-2.0-intl": {
                "purchase_rate_bps": 8300,
                "purchase_source": "group_override",
                "policy_version": 1,
                "effective_from": 124,
            }
        });
        Mock::given(method("GET"))
            .and(path("/api/option/video-pricing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": {"sales": [], "costs": []}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/option/video-capabilities"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .and(path("/api/channel/managed-pricing"))
            .and(wiremock::matchers::body_json(json!({
                "deployment_id": deployment_id,
                "seedance_purchase": expected_purchase,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": {"matched": 1, "updated": 1}
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/channel/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": {
                    "items": [{
                        "id": 1,
                        "type": 60,
                        "name": "MeowAI / seedance-cn",
                        "status": 2,
                        "base_url": "https://source.example",
                        "models": "seedance-2.0",
                        "group": "seedance-cn",
                        "tag": "meowai-deploy:0123456789abcdef:group-one",
                        "other_info": {
                            "managed_by": "meowai-deploy",
                            "pricing_source": "meowai-onboard",
                            "capability_source": "4api-compatible",
                            "local_note": "preserved",
                            "seedance_purchase": expected_purchase,
                        }
                    }],
                    "total": 1,
                    "page": 1,
                    "page_size": 100
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let port = server.address().port();
        let executor = TargetExecutor::new(Target::Local, PathBuf::from("/tmp/meowai-deploy-test"));
        let mut client = NewApiClient::connect(&executor, port).expect("create client");
        client.access_token = Some(SecretString::from("downstream-admin"));
        let desired = json!({
            "sales": [],
            "capabilities": [],
            "account_purchase": {
                "seedance": [
                    {
                        "public_model": "seedance-2.0",
                        "terminal_rate_bps": 8300,
                        "purchase_rate_bps": 8000,
                        "purchase_source": "group_override",
                        "policy_version": 1,
                        "effective_from": 123,
                    },
                    {
                        "public_model": "seedance-2.0-intl",
                        "terminal_rate_bps": 8700,
                        "purchase_rate_bps": 8300,
                        "purchase_source": "group_override",
                        "policy_version": 1,
                        "effective_from": 124,
                    }
                ]
            }
        });
        client
            .apply_snapshot_module(SyncModule::Seedance, deployment_id, &desired, &desired)
            .await
            .expect("apply standalone Seedance module");

        let requests = server
            .received_requests()
            .await
            .expect("read recorded requests");
        assert!(requests.iter().all(|request| {
            request.method.as_str() == "GET"
                || (request.method.as_str() == "PATCH"
                    && request.url.path() == "/api/channel/managed-pricing")
        }));
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
            "audio_completion_ratio": {"audio-output": 6},
            "general_setting": {
                "quota_display_type": "CNY",
                "custom_currency_symbol": "CNY",
                "custom_currency_exchange_rate": 7.3
            },
            "quota_per_unit": 500000,
            "usd_exchange_rate": 7.3,
            "price": 7.3,
            "display_token_stat_enabled": true,
            "display_in_currency_enabled": true,
            "pre_consumed_quota": 500,
            "quota_setting": {"enable_free_model_pre_consume": false},
            "billing_setting": {
                "billing_task_estimate": {"video-model": "{\"1080p\":300000}"},
                "billing_task_deposit": {"video-model": "20"}
            },
            "tool_prices": {"web_search": 12},
            "group_behavior": {
                "group_group_ratio": {"vip": {"default": 0.9}},
                "group_special_usable_group": {"vip": {"+:seedance-cn": "video"}},
                "auto_groups": ["default", "vip"],
                "max_token_auto_groups": 5,
                "default_use_auto_group": true
            },
            "video_cost_policies": [{
                "provider": "private-source-supplier",
                "public_model": "seedance-2.0",
                "upstream_group_rate_bps": 4100,
                "promotion_rate_bps": 10000,
                "promotion_effective_from": 0,
                "effective_from": 0,
                "evidence_status": "private"
            }],
            "marketplace": {
                "marketplace_enabled": true,
                "provider_self_apply_enabled": false,
                "official_groups_selectable_enabled": true,
                "marketplace_commission_bps": 2000,
                "marketplace_probe_interval_minutes": 10,
                "official_credential_recheck_enabled": true,
                "official_credential_rate_limit_cooldown_seconds": 60,
                "official_credential_recheck_scan_interval_seconds": 300,
                "official_credential_health_recheck_interval_seconds": 21600,
                "official_credential_grade_recheck_interval_seconds": 604800,
                "official_credential_failed_recheck_interval_seconds": 900,
                "official_credential_recheck_batch_size": 50,
                "official_credential_recheck_lock_seconds": 600,
                "official_credential_supplier_recheck_min_interval_seconds": 900,
                "official_credential_supplier_recheck_daily_limit": 10,
                "official_credential_recheck_jitter_seconds": 300,
                "official_credential_availability_window_days": 30
            }
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
            .expect(54)
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
        assert_eq!(hashes.len(), 56);
        assert!(!hashes.contains_key("video_cost_policies"));
        assert_eq!(hashes.get("model_price").map(String::len), Some(64));
    }
}
