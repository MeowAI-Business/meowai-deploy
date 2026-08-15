use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Deserializer, Serialize, de::MapAccess};
use serde_json::Value;

use crate::{
    error::{AppError, Result},
    security::sha256_hex,
};

#[derive(Clone, Debug)]
pub struct PricingOption {
    pub key: &'static str,
    pub source_field: &'static str,
    pub canonical_json: String,
    pub sha256: String,
    comparison: PricingComparison,
}

#[derive(Clone, Copy, Debug)]
enum PricingComparison {
    PriceMap,
    Json,
    Exact,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HomePricingConfig {
    pub table: String,
    pub title: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VideoSettingConfig {
    pub video_canonical_api_enabled: bool,
    pub seedance_domestic_canonical_enabled: bool,
    pub video_asset_affinity_enforced: bool,
    pub seedance_completion_token_billing_enabled: bool,
    pub video_playground_real_token_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MarketplaceConfig {
    marketplace_enabled: bool,
    provider_self_apply_enabled: bool,
    official_groups_selectable_enabled: bool,
    marketplace_commission_bps: i64,
    marketplace_probe_interval_minutes: i64,
    official_credential_recheck_enabled: bool,
    official_credential_rate_limit_cooldown_seconds: i64,
    official_credential_recheck_scan_interval_seconds: i64,
    official_credential_health_recheck_interval_seconds: i64,
    official_credential_grade_recheck_interval_seconds: i64,
    official_credential_failed_recheck_interval_seconds: i64,
    official_credential_recheck_batch_size: i64,
    official_credential_recheck_lock_seconds: i64,
    official_credential_supplier_recheck_min_interval_seconds: i64,
    official_credential_supplier_recheck_daily_limit: i64,
    official_credential_recheck_jitter_seconds: i64,
    official_credential_availability_window_days: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VideoSalesPolicy {
    pub public_model: String,
    pub official_no_video_micros: i64,
    pub official_with_video_micros: i64,
    pub customer_rate_bps: i64,
    pub effective_from: i64,
    #[serde(default)]
    pub effective_until: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct VideoCostPolicy {
    pub provider: String,
    pub public_model: String,
    pub upstream_group_rate_bps: i64,
    pub promotion_rate_bps: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promotion_scope: Option<Value>,
    pub promotion_effective_from: i64,
    #[serde(default)]
    pub promotion_effective_until: i64,
    pub effective_from: i64,
    #[serde(default)]
    pub effective_until: i64,
    pub evidence_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct VideoCapabilityPolicy {
    pub public_model: String,
    pub capabilities: Value,
    pub effective_from: i64,
    #[serde(default)]
    pub effective_until: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct GeneralSettingConfig {
    pub quota_display_type: String,
    pub custom_currency_symbol: String,
    pub custom_currency_exchange_rate: f64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuotaSettingConfig {
    pub enable_free_model_pre_consume: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct BillingSettingConfig {
    pub billing_task_estimate: BTreeMap<String, String>,
    pub billing_task_deposit: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct GroupBehaviorConfig {
    pub group_group_ratio: BTreeMap<String, BTreeMap<String, f64>>,
    pub group_special_usable_group: BTreeMap<String, BTreeMap<String, String>>,
    pub auto_groups: Vec<String>,
    pub max_token_auto_groups: i64,
    pub default_use_auto_group: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PricingConfig {
    model_price: StrictPriceMap,
    model_ratio: StrictPriceMap,
    cache_ratio: StrictPriceMap,
    create_cache_ratio: StrictPriceMap,
    completion_ratio: StrictPriceMap,
    image_ratio: StrictPriceMap,
    audio_ratio: StrictPriceMap,
    audio_completion_ratio: StrictPriceMap,
    #[serde(default)]
    billing_mode: BTreeMap<String, String>,
    #[serde(default)]
    billing_expr: BTreeMap<String, String>,
    #[serde(default)]
    general_setting: GeneralSettingConfig,
    #[serde(default)]
    quota_per_unit: f64,
    #[serde(default)]
    usd_exchange_rate: f64,
    #[serde(default)]
    display_token_stat_enabled: bool,
    #[serde(default)]
    display_in_currency_enabled: bool,
    #[serde(default)]
    pre_consumed_quota: i64,
    #[serde(default)]
    quota_setting: QuotaSettingConfig,
    #[serde(default)]
    billing_setting: BillingSettingConfig,
    #[serde(default)]
    tool_prices: BTreeMap<String, f64>,
    #[serde(default)]
    group_behavior: GroupBehaviorConfig,
    #[serde(default)]
    home_pricing: HomePricingConfig,
    #[serde(default)]
    video_setting: VideoSettingConfig,
    marketplace: MarketplaceConfig,
    #[serde(default)]
    pub video_sales_policies: Vec<VideoSalesPolicy>,
    #[serde(default)]
    pub video_cost_policies: Vec<VideoCostPolicy>,
    #[serde(default)]
    pub video_capabilities: Vec<VideoCapabilityPolicy>,
    #[serde(default)]
    #[serde(rename = "public_status_url")]
    _public_status_url: String,
}

impl PricingConfig {
    pub fn from_value(value: Value) -> std::result::Result<Self, String> {
        serde_json::from_value(value).map_err(|error| error.to_string())
    }

    pub fn options(&self) -> Result<Vec<PricingOption>> {
        let mut options = [
            ("ModelPrice", "model_price", &self.model_price),
            ("ModelRatio", "model_ratio", &self.model_ratio),
            ("CacheRatio", "cache_ratio", &self.cache_ratio),
            (
                "CreateCacheRatio",
                "create_cache_ratio",
                &self.create_cache_ratio,
            ),
            (
                "CompletionRatio",
                "completion_ratio",
                &self.completion_ratio,
            ),
            ("ImageRatio", "image_ratio", &self.image_ratio),
            ("AudioRatio", "audio_ratio", &self.audio_ratio),
            (
                "AudioCompletionRatio",
                "audio_completion_ratio",
                &self.audio_completion_ratio,
            ),
        ]
        .into_iter()
        .map(|(key, source_field, values)| {
            let canonical_json = serde_json::to_string(&values.0).map_err(|error| {
                AppError::State(format!(
                    "serialize source pricing field {source_field}: {error}"
                ))
            })?;
            Ok(PricingOption {
                key,
                source_field,
                sha256: sha256_hex(canonical_json.as_bytes()),
                canonical_json,
                comparison: PricingComparison::PriceMap,
            })
        })
        .collect::<Result<Vec<_>>>()?;

        let add_json = |options: &mut Vec<PricingOption>,
                        key: &'static str,
                        source_field: &'static str,
                        value: &Value|
         -> Result<()> {
            let canonical_json = canonical_json_value(value)?;
            options.push(PricingOption {
                key,
                source_field,
                sha256: sha256_hex(canonical_json.as_bytes()),
                canonical_json,
                comparison: PricingComparison::Json,
            });
            Ok(())
        };
        add_json(
            &mut options,
            "billing_setting.billing_mode",
            "billing_mode",
            &serde_json::to_value(&self.billing_mode)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        add_json(
            &mut options,
            "billing_setting.billing_expr",
            "billing_expr",
            &serde_json::to_value(&self.billing_expr)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        add_json(
            &mut options,
            "billing_setting.billing_task_estimate",
            "billing_setting.billing_task_estimate",
            &serde_json::to_value(&self.billing_setting.billing_task_estimate)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        add_json(
            &mut options,
            "billing_setting.billing_task_deposit",
            "billing_setting.billing_task_deposit",
            &serde_json::to_value(&self.billing_setting.billing_task_deposit)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        add_json(
            &mut options,
            "tool_price_setting.prices",
            "tool_prices",
            &serde_json::to_value(&self.tool_prices)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        add_json(
            &mut options,
            "GroupGroupRatio",
            "group_behavior.group_group_ratio",
            &serde_json::to_value(&self.group_behavior.group_group_ratio)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        add_json(
            &mut options,
            "group_ratio_setting.group_special_usable_group",
            "group_behavior.group_special_usable_group",
            &serde_json::to_value(&self.group_behavior.group_special_usable_group)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        add_json(
            &mut options,
            "AutoGroups",
            "group_behavior.auto_groups",
            &serde_json::to_value(&self.group_behavior.auto_groups)
                .map_err(|error| AppError::State(error.to_string()))?,
        )?;
        options.push(exact_option(
            "MaxTokenAutoGroups",
            "group_behavior.max_token_auto_groups",
            &self.group_behavior.max_token_auto_groups.to_string(),
        ));
        options.push(exact_option(
            "DefaultUseAutoGroup",
            "group_behavior.default_use_auto_group",
            bool_string(self.group_behavior.default_use_auto_group),
        ));
        options.push(exact_option(
            "QuotaPerUnit",
            "quota_per_unit",
            &format_float(self.quota_per_unit),
        ));
        options.push(exact_option(
            "USDExchangeRate",
            "usd_exchange_rate",
            &format_float(self.usd_exchange_rate),
        ));
        options.push(exact_option(
            "DisplayTokenStatEnabled",
            "display_token_stat_enabled",
            bool_string(self.display_token_stat_enabled),
        ));
        options.push(exact_option(
            "DisplayInCurrencyEnabled",
            "display_in_currency_enabled",
            bool_string(self.display_in_currency_enabled),
        ));
        options.push(exact_option(
            "PreConsumedQuota",
            "pre_consumed_quota",
            &self.pre_consumed_quota.to_string(),
        ));
        options.push(exact_option(
            "general_setting.quota_display_type",
            "general_setting.quota_display_type",
            &self.general_setting.quota_display_type,
        ));
        options.push(exact_option(
            "general_setting.custom_currency_symbol",
            "general_setting.custom_currency_symbol",
            &self.general_setting.custom_currency_symbol,
        ));
        options.push(exact_option(
            "general_setting.custom_currency_exchange_rate",
            "general_setting.custom_currency_exchange_rate",
            &format_float(self.general_setting.custom_currency_exchange_rate),
        ));
        options.push(exact_option(
            "quota_setting.enable_free_model_pre_consume",
            "quota_setting.enable_free_model_pre_consume",
            bool_string(self.quota_setting.enable_free_model_pre_consume),
        ));
        if !self.home_pricing.table.is_empty() {
            let table: Value = serde_json::from_str(&self.home_pricing.table).map_err(|error| {
                AppError::State(format!("invalid source home pricing table: {error}"))
            })?;
            ensure_home_pricing_has_no_notes(&table)?;
            add_json(
                &mut options,
                "home_setting.pricing_table",
                "home_pricing.table",
                &table,
            )?;
        } else {
            options.push(exact_option(
                "home_setting.pricing_table",
                "home_pricing.table",
                "",
            ));
        }
        options.push(exact_option(
            "home_setting.pricing_title",
            "home_pricing.title",
            &self.home_pricing.title,
        ));
        options.push(exact_option(
            "home_setting.pricing_description",
            "home_pricing.description",
            &self.home_pricing.description,
        ));
        options.push(exact_option(
            "home_setting.pricing_enabled",
            "home_pricing.enabled",
            if self.home_pricing.enabled {
                "true"
            } else {
                "false"
            },
        ));
        options.push(exact_option(
            "video_setting.video_canonical_api_enabled",
            "video_setting.video_canonical_api_enabled",
            bool_string(self.video_setting.video_canonical_api_enabled),
        ));
        options.push(exact_option(
            "video_setting.seedance_domestic_canonical_enabled",
            "video_setting.seedance_domestic_canonical_enabled",
            bool_string(self.video_setting.seedance_domestic_canonical_enabled),
        ));
        options.push(exact_option(
            "video_setting.video_asset_affinity_enforced",
            "video_setting.video_asset_affinity_enforced",
            bool_string(self.video_setting.video_asset_affinity_enforced),
        ));
        options.push(exact_option(
            "video_setting.seedance_completion_token_billing_enabled",
            "video_setting.seedance_completion_token_billing_enabled",
            bool_string(self.video_setting.seedance_completion_token_billing_enabled),
        ));
        options.push(exact_option(
            "video_setting.video_playground_real_token_enabled",
            "video_setting.video_playground_real_token_enabled",
            bool_string(self.video_setting.video_playground_real_token_enabled),
        ));
        let marketplace_options = [
            (
                "MarketplaceEnabled",
                "marketplace.marketplace_enabled",
                bool_string(self.marketplace.marketplace_enabled).to_owned(),
            ),
            (
                "ProviderSelfApplyEnabled",
                "marketplace.provider_self_apply_enabled",
                bool_string(self.marketplace.provider_self_apply_enabled).to_owned(),
            ),
            (
                "OfficialGroupsSelectableEnabled",
                "marketplace.official_groups_selectable_enabled",
                bool_string(self.marketplace.official_groups_selectable_enabled).to_owned(),
            ),
            (
                "MarketplaceCommissionBps",
                "marketplace.marketplace_commission_bps",
                self.marketplace.marketplace_commission_bps.to_string(),
            ),
            (
                "MarketplaceProbeIntervalMinutes",
                "marketplace.marketplace_probe_interval_minutes",
                self.marketplace
                    .marketplace_probe_interval_minutes
                    .to_string(),
            ),
            (
                "OfficialCredentialRecheckEnabled",
                "marketplace.official_credential_recheck_enabled",
                bool_string(self.marketplace.official_credential_recheck_enabled).to_owned(),
            ),
            (
                "OfficialCredentialRateLimitCooldownSeconds",
                "marketplace.official_credential_rate_limit_cooldown_seconds",
                self.marketplace
                    .official_credential_rate_limit_cooldown_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialRecheckScanIntervalSeconds",
                "marketplace.official_credential_recheck_scan_interval_seconds",
                self.marketplace
                    .official_credential_recheck_scan_interval_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialHealthRecheckIntervalSeconds",
                "marketplace.official_credential_health_recheck_interval_seconds",
                self.marketplace
                    .official_credential_health_recheck_interval_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialGradeRecheckIntervalSeconds",
                "marketplace.official_credential_grade_recheck_interval_seconds",
                self.marketplace
                    .official_credential_grade_recheck_interval_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialFailedRecheckIntervalSeconds",
                "marketplace.official_credential_failed_recheck_interval_seconds",
                self.marketplace
                    .official_credential_failed_recheck_interval_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialRecheckBatchSize",
                "marketplace.official_credential_recheck_batch_size",
                self.marketplace
                    .official_credential_recheck_batch_size
                    .to_string(),
            ),
            (
                "OfficialCredentialRecheckLockSeconds",
                "marketplace.official_credential_recheck_lock_seconds",
                self.marketplace
                    .official_credential_recheck_lock_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialSupplierRecheckMinIntervalSeconds",
                "marketplace.official_credential_supplier_recheck_min_interval_seconds",
                self.marketplace
                    .official_credential_supplier_recheck_min_interval_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialSupplierRecheckDailyLimit",
                "marketplace.official_credential_supplier_recheck_daily_limit",
                self.marketplace
                    .official_credential_supplier_recheck_daily_limit
                    .to_string(),
            ),
            (
                "OfficialCredentialRecheckJitterSeconds",
                "marketplace.official_credential_recheck_jitter_seconds",
                self.marketplace
                    .official_credential_recheck_jitter_seconds
                    .to_string(),
            ),
            (
                "OfficialCredentialAvailabilityWindowDays",
                "marketplace.official_credential_availability_window_days",
                self.marketplace
                    .official_credential_availability_window_days
                    .to_string(),
            ),
        ];
        options.extend(
            marketplace_options
                .into_iter()
                .map(|(key, source_field, value)| exact_option(key, source_field, &value)),
        );
        Ok(options)
    }
}

impl PricingOption {
    pub fn matches(&self, returned: &str) -> std::result::Result<bool, String> {
        let normalized = match self.comparison {
            PricingComparison::PriceMap => canonical_price_json(returned)?,
            PricingComparison::Json => {
                let value: Value =
                    serde_json::from_str(returned).map_err(|error| error.to_string())?;
                canonical_json_value_raw(&value)?
            }
            PricingComparison::Exact => returned.to_owned(),
        };
        Ok(normalized == self.canonical_json)
    }
}

fn bool_string(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn format_float(value: f64) -> String {
    value.to_string()
}

fn exact_option(key: &'static str, source_field: &'static str, value: &str) -> PricingOption {
    PricingOption {
        key,
        source_field,
        canonical_json: value.to_owned(),
        sha256: sha256_hex(value.as_bytes()),
        comparison: PricingComparison::Exact,
    }
}

fn canonical_json_value(value: &Value) -> Result<String> {
    canonical_json_value_raw(value).map_err(AppError::State)
}

fn canonical_json_value_raw(value: &Value) -> std::result::Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

fn ensure_home_pricing_has_no_notes(value: &Value) -> Result<()> {
    let rows = value
        .as_array()
        .ok_or_else(|| AppError::State("source home pricing table must be an array".to_owned()))?;
    if rows.iter().any(|row| row.get("note").is_some()) {
        return Err(AppError::State(
            "source home pricing table still contains note fields".to_owned(),
        ));
    }
    Ok(())
}

pub fn canonical_price_json(source: &str) -> std::result::Result<String, String> {
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let parsed =
        StrictPriceMap::deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    serde_json::to_string(&parsed.0).map_err(|error| error.to_string())
}

#[derive(Clone, Debug)]
struct StrictPriceMap(BTreeMap<String, f64>);

impl<'de> Deserialize<'de> for StrictPriceMap {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(StrictPriceVisitor)
    }
}

struct StrictPriceVisitor;

impl<'de> serde::de::Visitor<'de> for StrictPriceVisitor {
    type Value = StrictPriceMap;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object mapping non-empty model names to finite numbers")
    }

    fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some(raw_key) = access.next_key::<String>()? {
            let key = raw_key.trim();
            if key.is_empty() {
                return Err(serde::de::Error::custom("model name cannot be empty"));
            }
            if values.contains_key(key) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate model name {key}"
                )));
            }
            let value = access.next_value::<f64>()?;
            if !value.is_finite() {
                return Err(serde::de::Error::custom(format!(
                    "price for {key} must be finite"
                )));
            }
            values.insert(key.to_owned(), value);
        }
        Ok(StrictPriceMap(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_configuration_maps_complete_option_snapshot() {
        let config = PricingConfig::from_value(serde_json::json!({
            "model_price": {"fixed": 2},
            "model_ratio": {"input": 1},
            "cache_ratio": {"cache": 0.5},
            "create_cache_ratio": {"create": 1.25},
            "completion_ratio": {"output": 3},
            "image_ratio": {"image": 4},
            "audio_ratio": {"audio": 5},
            "audio_completion_ratio": {"audio-output": 6},
            "marketplace": marketplace_config()
        }))
        .expect("parse source pricing");

        let options = config.options().expect("build pricing options");
        assert_eq!(options.len(), 53);
        assert!(
            options
                .iter()
                .all(|option| option.key != "console_setting.public_status_url")
        );
        assert_eq!(options[0].key, "ModelPrice");
        assert_eq!(options[0].source_field, "model_price");
        assert_eq!(options[0].canonical_json, r#"{"fixed":2.0}"#);
        let marketplace_enabled = options
            .iter()
            .find(|option| option.key == "MarketplaceEnabled")
            .expect("marketplace enabled option");
        assert_eq!(
            marketplace_enabled.source_field,
            "marketplace.marketplace_enabled"
        );
        assert_eq!(marketplace_enabled.canonical_json, "true");
        let availability_window = options
            .iter()
            .find(|option| option.key == "OfficialCredentialAvailabilityWindowDays")
            .expect("credential availability option");
        assert_eq!(availability_window.canonical_json, "30");
        assert!(options.iter().all(|option| option.sha256.len() == 64));
    }

    #[test]
    fn home_pricing_notes_are_rejected_if_the_source_did_not_remove_them() {
        let config = PricingConfig::from_value(serde_json::json!({
            "model_price": {}, "model_ratio": {}, "cache_ratio": {},
            "create_cache_ratio": {}, "completion_ratio": {}, "image_ratio": {},
            "audio_ratio": {}, "audio_completion_ratio": {},
            "marketplace": marketplace_config(),
            "home_pricing": {
                "table": "[{\"model\":\"seedance-2.0\",\"note\":\"private\"}]",
                "title": "", "description": "", "enabled": true
            }
        }))
        .expect("parse source pricing");
        assert!(config.options().is_err());
    }

    #[test]
    fn source_configuration_requires_all_fields_and_valid_maps() {
        let missing = serde_json::json!({
            "model_price": {},
            "model_ratio": {},
            "cache_ratio": {},
            "create_cache_ratio": {},
            "completion_ratio": {},
            "image_ratio": {},
            "audio_ratio": {},
            "marketplace": marketplace_config()
        });
        assert!(PricingConfig::from_value(missing).is_err());

        let invalid = serde_json::json!({
            "model_price": {"": 1},
            "model_ratio": {},
            "cache_ratio": {},
            "create_cache_ratio": {},
            "completion_ratio": {},
            "image_ratio": {},
            "audio_ratio": {},
            "audio_completion_ratio": {},
            "marketplace": marketplace_config()
        });
        assert!(PricingConfig::from_value(invalid).is_err());
    }

    #[test]
    fn parser_rejects_duplicates_non_numbers_and_trailing_content() {
        assert!(canonical_price_json(r#"{"gpt":1,"gpt":2}"#).is_err());
        assert!(canonical_price_json(r#"{"gpt":"one"}"#).is_err());
        assert!(canonical_price_json(r#"{"gpt":1} trailing"#).is_err());
        assert!(canonical_price_json(r#"{"":1}"#).is_err());
    }

    #[test]
    fn canonical_output_is_sorted() {
        assert_eq!(
            canonical_price_json(r#"{"z":2,"a":1}"#).expect("canonicalize"),
            r#"{"a":1.0,"z":2.0}"#
        );
    }

    fn marketplace_config() -> Value {
        serde_json::json!({
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
        })
    }
}
