use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result as AppResult},
    pricing::PricingConfig,
    security::sha256_hex,
    source::{GroupCatalog, GroupTokenPlan, RemovedGroupTokenPlan, StatusManifest},
    state::{SNAPSHOT_SCHEMA_VERSION, SyncSnapshot},
    target::{
        kuma::{internal_status_page_url, status_page_slug},
        newapi::{channel_tag, managed_channel_name},
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SyncModule {
    Groups,
    Channels,
    GroupPricing,
    ModelPricing,
    Units,
    Seedance,
    Site,
    Kuma,
}

impl SyncModule {
    pub const ALL: [Self; 8] = [
        Self::Groups,
        Self::Channels,
        Self::GroupPricing,
        Self::ModelPricing,
        Self::Units,
        Self::Seedance,
        Self::Site,
        Self::Kuma,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Groups => "groups",
            Self::Channels => "channels",
            Self::GroupPricing => "group_pricing",
            Self::ModelPricing => "model_pricing",
            Self::Units => "units",
            Self::Seedance => "seedance",
            Self::Site => "site",
            Self::Kuma => "kuma",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Groups => "分组结构",
            Self::Channels => "渠道与源站 Key",
            Self::GroupPricing => "分组定价与利润",
            Self::ModelPricing => "普通模型计费",
            Self::Units => "计价单位与充值",
            Self::Seedance => "Seedance",
            Self::Site => "首页与市场",
            Self::Kuma => "Kuma 与公开状态",
        }
    }
}

impl fmt::Display for SyncModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl FromStr for SyncModule {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "groups" | "group" => Ok(Self::Groups),
            "channels" | "channel" => Ok(Self::Channels),
            "group_pricing" | "group-pricing" | "pricing" => Ok(Self::GroupPricing),
            "model_pricing" | "model-pricing" | "models" => Ok(Self::ModelPricing),
            "units" | "quota" => Ok(Self::Units),
            "seedance" | "video" => Ok(Self::Seedance),
            "site" | "marketplace" => Ok(Self::Site),
            "kuma" | "status" => Ok(Self::Kuma),
            _ => Err(format!("unknown sync module: {value}")),
        }
    }
}

pub fn parse_modules(values: &[String]) -> std::result::Result<BTreeSet<SyncModule>, String> {
    values.iter().map(|value| value.parse()).collect()
}

#[derive(Clone, Debug)]
pub struct SyncPlan {
    pub source: SyncSnapshot,
    pub downstream: SyncSnapshot,
    pub last_applied: Option<SyncSnapshot>,
    pub diffs: BTreeMap<SyncModule, Vec<FieldDiff>>,
}

impl SyncPlan {
    pub fn new(
        source: SyncSnapshot,
        downstream: SyncSnapshot,
        last_applied: Option<SyncSnapshot>,
    ) -> Self {
        let diffs = SyncModule::ALL
            .into_iter()
            .map(|module| {
                let baseline = last_applied
                    .as_ref()
                    .and_then(|snapshot| snapshot.modules.get(module.name()))
                    .map(|snapshot| &snapshot.data);
                let source_current = snapshot_module_data(&source, module);
                let downstream_current = snapshot_module_data(&downstream, module);
                (
                    module,
                    diff_snapshots(baseline, source_current, downstream_current),
                )
            })
            .collect();
        Self {
            source,
            downstream,
            last_applied,
            diffs,
        }
    }

    pub fn changed_modules(&self) -> BTreeSet<SyncModule> {
        self.diffs
            .iter()
            .filter(|(_, diffs)| !diffs.is_empty())
            .map(|(module, _)| *module)
            .collect()
    }

    pub fn actionable_modules(&self) -> BTreeSet<SyncModule> {
        self.diffs
            .iter()
            .filter(|(_, diffs)| {
                diffs.iter().any(|diff| {
                    !matches!(
                        diff.classification,
                        SnapshotClassification::Unchanged
                            | SnapshotClassification::BothChangedToSame
                    )
                })
            })
            .map(|(module, _)| *module)
            .collect()
    }

    pub fn converged_modules(&self) -> BTreeSet<SyncModule> {
        self.diffs
            .iter()
            .filter(|(_, diffs)| {
                !diffs.is_empty()
                    && diffs.iter().all(|diff| {
                        diff.classification == SnapshotClassification::BothChangedToSame
                    })
            })
            .map(|(module, _)| *module)
            .collect()
    }

    pub fn source_value(&self, module: SyncModule) -> &Value {
        snapshot_module_data(&self.source, module)
    }

    pub fn downstream_value(&self, module: SyncModule) -> &Value {
        snapshot_module_data(&self.downstream, module)
    }

    pub fn baseline_value(&self, module: SyncModule) -> Option<&Value> {
        self.last_applied
            .as_ref()
            .and_then(|snapshot| snapshot.modules.get(module.name()))
            .map(|module| &module.data)
    }

    pub fn has_downstream_drift(&self, module: SyncModule) -> bool {
        self.diffs.get(&module).is_some_and(|diffs| {
            diffs.iter().any(|diff| {
                matches!(
                    diff.classification,
                    SnapshotClassification::DownstreamChanged | SnapshotClassification::Conflict
                )
            })
        })
    }

    pub fn fingerprint(&self) -> String {
        let value = serde_json::json!({
            "source": self.source,
            "downstream": self.downstream,
            "last_applied": self.last_applied,
        });
        fingerprint(&value)
    }
}

pub fn snapshot_from_modules(modules: BTreeMap<SyncModule, Value>) -> SyncSnapshot {
    let mut snapshot = SyncSnapshot::new();
    for module in SyncModule::ALL {
        let data = modules.get(&module).cloned().unwrap_or(Value::Null);
        let digest = fingerprint(&data);
        snapshot.set_module(module.name(), data, digest);
    }
    snapshot
}

pub fn snapshots_match(left: &SyncSnapshot, right: &SyncSnapshot) -> bool {
    left.schema_version == right.schema_version
        && SyncModule::ALL.into_iter().all(|module| {
            let left = left.modules.get(module.name());
            let right = right.modules.get(module.name());
            left.map(|module| (&module.fingerprint, &module.data))
                == right.map(|module| (&module.fingerprint, &module.data))
        })
}

pub fn update_snapshot_module(snapshot: &mut SyncSnapshot, module: SyncModule, data: Value) {
    snapshot.schema_version = SNAPSHOT_SCHEMA_VERSION;
    snapshot.set_module(module.name(), data.clone(), fingerprint(&data));
}

pub struct SourceSnapshotInput<'a> {
    pub catalog: &'a GroupCatalog,
    pub pricing: &'a PricingConfig,
    pub token_plan: &'a GroupTokenPlan,
    pub removed_tokens: &'a [RemovedGroupTokenPlan],
    pub manifest: &'a StatusManifest,
    pub deployment_id: &'a str,
    pub website_name: &'a str,
    pub container_source_url: &'a str,
    pub status_key_sha256: &'a str,
}

pub fn build_source_modules(
    input: SourceSnapshotInput<'_>,
) -> AppResult<BTreeMap<SyncModule, Value>> {
    let mut modules = SyncModule::ALL
        .into_iter()
        .map(|module| (module, serde_json::Map::new()))
        .collect::<BTreeMap<_, _>>();

    for option in input.pricing.options()? {
        let value = serde_json::from_str(&option.canonical_json)
            .unwrap_or(Value::String(option.canonical_json));
        modules
            .get_mut(&module_for_pricing_key(option.key))
            .expect("all sync modules initialized")
            .insert(option.key.to_owned(), value);
    }

    let user_usable_groups = input
        .catalog
        .groups
        .iter()
        .filter(|group| group.user_selectable)
        .map(|group| (group.group_name.clone(), group.description.clone()))
        .collect::<BTreeMap<_, _>>();
    modules
        .get_mut(&SyncModule::Groups)
        .expect("groups module initialized")
        .insert(
            "UserUsableGroups".to_owned(),
            serde_json::to_value(user_usable_groups)
                .map_err(|error| AppError::State(format!("serialize source groups: {error}")))?,
        );

    let group_ratios = input
        .catalog
        .groups
        .iter()
        .map(|group| (group.group_name.clone(), group.ratio.clone()))
        .collect::<BTreeMap<_, _>>();
    let purchase = input
        .catalog
        .groups
        .iter()
        .map(|group| {
            (
                group.group_name.clone(),
                json!({
                    "ratio": group.purchase_ratio,
                    "source": group.purchase_source,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let group_pricing = modules
        .get_mut(&SyncModule::GroupPricing)
        .expect("group pricing module initialized");
    group_pricing.insert(
        "GroupRatio".to_owned(),
        serde_json::to_value(group_ratios)
            .map_err(|error| AppError::State(format!("serialize group ratios: {error}")))?,
    );
    let group_discounts = input
        .catalog
        .groups
        .iter()
        .filter_map(|group| {
            group
                .discount
                .clone()
                .map(|discount| (group.group_name.clone(), discount))
        })
        .collect::<BTreeMap<_, _>>();
    group_pricing.insert(
        "GroupDiscount".to_owned(),
        serde_json::to_value(group_discounts)
            .map_err(|error| AppError::State(format!("serialize group discounts: {error}")))?,
    );
    group_pricing.insert(
        "purchase".to_owned(),
        serde_json::to_value(purchase)
            .map_err(|error| AppError::State(format!("serialize purchase ratios: {error}")))?,
    );

    let topup_ratios = input
        .catalog
        .groups
        .iter()
        .filter_map(|group| {
            group
                .topup_ratio
                .clone()
                .map(|ratio| (group.group_name.clone(), ratio))
        })
        .collect::<BTreeMap<_, _>>();
    modules
        .get_mut(&SyncModule::Units)
        .expect("units module initialized")
        .insert(
            "TopupGroupRatio".to_owned(),
            serde_json::to_value(topup_ratios)
                .map_err(|error| AppError::State(format!("serialize topup ratios: {error}")))?,
        );

    let token_actions = input
        .token_plan
        .entries
        .iter()
        .filter_map(|entry| {
            let action = if entry.needs_create {
                "create"
            } else if entry.needs_update {
                "update"
            } else {
                return None;
            };
            Some(json!({
                "action": action,
                "group_id": entry.group_id,
                "group_name": entry.group_name,
                "token_id": entry.token_id,
                "token_name": entry.token_name,
            }))
        })
        .chain(
            input
                .removed_tokens
                .iter()
                .filter(|entry| entry.enabled)
                .map(|entry| {
                    json!({
                        "action": "disable",
                        "group_name": entry.group_name,
                        "token_id": entry.token_id,
                        "token_name": entry.token_name,
                    })
                }),
        )
        .collect::<Vec<_>>();
    let seedance_purchase = input
        .pricing
        .account_purchase
        .seedance
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
        .collect::<serde_json::Map<_, _>>();
    let mut channels = input
        .catalog
        .groups
        .iter()
        .map(|group| {
            json!({
                "type": 60,
                "name": managed_channel_name(&group.group_name),
                "status": 1,
                "base_url": input.container_source_url.trim_end_matches('/'),
                "models": group.models.join(","),
                "group": group.group_name,
                "tag": channel_tag(input.deployment_id, &group.group_id),
                "metadata": {
                    "managed_by": "meowai-deploy",
                    "pricing_source": "meowai-onboard",
                    "capability_source": "4api-compatible",
                }
            })
        })
        .collect::<Vec<_>>();
    channels.sort_by(|left, right| left["tag"].as_str().cmp(&right["tag"].as_str()));
    let channels_module = modules
        .get_mut(&SyncModule::Channels)
        .expect("channels module initialized");
    channels_module.insert("channels".to_owned(), Value::Array(channels));
    channels_module.insert("token_actions".to_owned(), Value::Array(token_actions));

    let seedance = modules
        .get_mut(&SyncModule::Seedance)
        .expect("Seedance module initialized");
    seedance.insert(
        "sales".to_owned(),
        serde_json::to_value(&input.pricing.video_sales_policies)
            .map_err(|error| AppError::State(format!("serialize Seedance sales: {error}")))?,
    );
    seedance.insert(
        "capabilities".to_owned(),
        serde_json::to_value(&input.pricing.video_capabilities).map_err(|error| {
            AppError::State(format!("serialize Seedance capabilities: {error}"))
        })?,
    );
    seedance.insert(
        "account_purchase".to_owned(),
        serde_json::to_value(&input.pricing.account_purchase).map_err(|error| {
            AppError::State(format!("serialize account purchase policy: {error}"))
        })?,
    );
    seedance.insert(
        "managed_channel_purchase".to_owned(),
        if input.catalog.groups.is_empty() {
            Value::Object(serde_json::Map::new())
        } else {
            Value::Object(seedance_purchase)
        },
    );

    let slug = status_page_slug(input.deployment_id);
    let mut groups = input
        .manifest
        .monitors
        .iter()
        .map(|monitor| (monitor.group_id.clone(), monitor.group.clone()))
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .map(|(source_group_id, name)| {
            json!({
                "source_group_id": source_group_id,
                "name": name,
                "active": true,
            })
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        left["source_group_id"]
            .as_str()
            .cmp(&right["source_group_id"].as_str())
    });
    let mut monitors = input
        .manifest
        .monitors
        .iter()
        .map(|monitor| {
            json!({
                "source_monitor_id": monitor.id,
                "name": monitor.name,
                "group_id": monitor.group_id,
                "url": format!(
                    "{}/api/onboard/status/monitors/{}",
                    input.container_source_url.trim_end_matches('/'),
                    monitor.id
                ),
                "key_sha256": input.status_key_sha256,
                "interval": monitor.interval,
                "timeout": monitor.timeout,
                "retries": monitor.retries,
                "enabled": monitor.display_enabled,
            })
        })
        .collect::<Vec<_>>();
    monitors.sort_by(|left, right| {
        left["source_monitor_id"]
            .as_str()
            .cmp(&right["source_monitor_id"].as_str())
    });
    let kuma = modules
        .get_mut(&SyncModule::Kuma)
        .expect("Kuma module initialized");
    kuma.insert(
        "page".to_owned(),
        json!({
            "exists": true,
            "slug": slug,
            "title": input.website_name,
            "description": input.manifest.page_description,
            "theme": input.manifest.theme,
        }),
    );
    kuma.insert("groups".to_owned(), Value::Array(groups));
    kuma.insert("monitors".to_owned(), Value::Array(monitors));
    kuma.insert(
        "console_setting.public_status_url".to_owned(),
        Value::String(internal_status_page_url(&slug)),
    );

    Ok(modules
        .into_iter()
        .map(|(module, values)| (module, Value::Object(values)))
        .collect())
}

fn snapshot_module_data(snapshot: &SyncSnapshot, module: SyncModule) -> &Value {
    snapshot
        .modules
        .get(module.name())
        .map(|module| &module.data)
        .unwrap_or(&Value::Null)
}

pub fn module_for_pricing_key(key: &str) -> SyncModule {
    if key.starts_with("home_setting.") || key.starts_with("Marketplace") {
        SyncModule::Site
    } else if key.starts_with("video_setting.") {
        SyncModule::Seedance
    } else if matches!(
        key,
        "QuotaPerUnit"
            | "USDExchangeRate"
            | "Price"
            | "DisplayTokenStatEnabled"
            | "DisplayInCurrencyEnabled"
            | "PreConsumedQuota"
            | "general_setting.quota_display_type"
            | "general_setting.custom_currency_symbol"
            | "general_setting.custom_currency_exchange_rate"
            | "quota_setting.enable_free_model_pre_consume"
    ) {
        SyncModule::Units
    } else if matches!(
        key,
        "GroupGroupRatio"
            | "GroupDiscount"
            | "group_ratio_setting.group_special_usable_group"
            | "AutoGroups"
            | "MaxTokenAutoGroups"
            | "DefaultUseAutoGroup"
    ) {
        SyncModule::Groups
    } else {
        SyncModule::ModelPricing
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotClassification {
    Unchanged,
    SourceChanged,
    DownstreamChanged,
    BothChangedToSame,
    Conflict,
    UnknownBaseline,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct FieldDiff {
    pub path: String,
    pub last_applied: Option<Value>,
    pub source_current: Option<Value>,
    pub downstream_current: Option<Value>,
    pub classification: SnapshotClassification,
    pub risk: RiskLevel,
    pub sensitive: bool,
}

pub fn classify_field(
    last_applied: Option<&Value>,
    source_current: Option<&Value>,
    downstream_current: Option<&Value>,
) -> SnapshotClassification {
    if source_current == downstream_current {
        return match last_applied {
            Some(last) if Some(last) == source_current => SnapshotClassification::Unchanged,
            Some(_) => SnapshotClassification::BothChangedToSame,
            None if source_current.is_some() => SnapshotClassification::UnknownBaseline,
            None => SnapshotClassification::Unchanged,
        };
    }
    let Some(last) = last_applied else {
        return SnapshotClassification::UnknownBaseline;
    };
    let source_changed = Some(last) != source_current;
    let downstream_changed = Some(last) != downstream_current;
    match (source_changed, downstream_changed) {
        (false, false) => SnapshotClassification::Unchanged,
        (true, false) => SnapshotClassification::SourceChanged,
        (false, true) => SnapshotClassification::DownstreamChanged,
        (true, true) => SnapshotClassification::Conflict,
    }
}

pub fn diff_snapshots(
    last_applied: Option<&Value>,
    source_current: &Value,
    downstream_current: &Value,
) -> Vec<FieldDiff> {
    let mut paths = BTreeSet::new();
    let mut baseline = BTreeMap::new();
    let mut source = BTreeMap::new();
    let mut downstream = BTreeMap::new();
    flatten_value(last_applied, "", &mut baseline);
    flatten_value(Some(source_current), "", &mut source);
    flatten_value(Some(downstream_current), "", &mut downstream);
    paths.extend(baseline.keys().cloned());
    paths.extend(source.keys().cloned());
    paths.extend(downstream.keys().cloned());
    paths
        .into_iter()
        .filter_map(|path| {
            let last = baseline.get(&path).and_then(Clone::clone);
            let source_value = source.get(&path).and_then(Clone::clone);
            let downstream_value = downstream.get(&path).and_then(Clone::clone);
            let classification = classify_field(
                last.as_ref(),
                source_value.as_ref(),
                downstream_value.as_ref(),
            );
            if classification == SnapshotClassification::Unchanged {
                return None;
            }
            let sensitive = is_sensitive_path(&path);
            Some(FieldDiff {
                risk: risk_for_path(&path, classification),
                path,
                last_applied: last.map(|value| display_value(&value, sensitive)),
                source_current: source_value.map(|value| display_value(&value, sensitive)),
                downstream_current: downstream_value.map(|value| display_value(&value, sensitive)),
                classification,
                sensitive,
            })
        })
        .collect()
}

pub fn fingerprint(value: &Value) -> String {
    let canonical = serde_json::to_vec(value).unwrap_or_default();
    sha256_hex(&canonical)
}

pub fn advance_last_applied(
    baseline: Option<&Value>,
    source_current: &Value,
    downstream_current: &Value,
    force: bool,
) -> Value {
    merge_desired_value(
        baseline,
        Some(source_current),
        Some(downstream_current),
        force,
    )
    .unwrap_or(Value::Null)
}

fn merge_desired_value(
    baseline: Option<&Value>,
    source: Option<&Value>,
    downstream: Option<&Value>,
    force: bool,
) -> Option<Value> {
    match (baseline, source, downstream) {
        (
            base @ (Some(Value::Object(_)) | None),
            Some(Value::Object(source)),
            Some(Value::Object(downstream)),
        ) => {
            let base = base.and_then(Value::as_object);
            let keys = base
                .into_iter()
                .flat_map(|base| base.keys())
                .chain(source.keys())
                .chain(downstream.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut merged = serde_json::Map::new();
            for key in keys {
                if let Some(value) = merge_desired_value(
                    base.and_then(|base| base.get(&key)),
                    source.get(&key),
                    downstream.get(&key),
                    force,
                ) {
                    merged.insert(key, value);
                }
            }
            Some(Value::Object(merged))
        }
        _ => match classify_field(baseline, source, downstream) {
            SnapshotClassification::DownstreamChanged | SnapshotClassification::Conflict
                if !force =>
            {
                downstream.cloned()
            }
            SnapshotClassification::UnknownBaseline
                if !force && source.is_none() && downstream.is_some() =>
            {
                downstream.cloned()
            }
            _ => source.cloned(),
        },
    }
}

pub fn checkpoint_last_applied(
    baseline: Option<&Value>,
    source_current: &Value,
    downstream_before: &Value,
    downstream_after: &Value,
    force: bool,
) -> Value {
    checkpoint_applied_value(
        baseline,
        Some(source_current),
        Some(downstream_before),
        Some(downstream_after),
        force,
    )
    .unwrap_or(Value::Null)
}

fn checkpoint_applied_value(
    baseline: Option<&Value>,
    source: Option<&Value>,
    downstream_before: Option<&Value>,
    downstream_after: Option<&Value>,
    force: bool,
) -> Option<Value> {
    match (baseline, source, downstream_before, downstream_after) {
        (
            base @ (Some(Value::Object(_)) | None),
            Some(Value::Object(source)),
            Some(Value::Object(before)),
            Some(Value::Object(after)),
        ) => {
            let base = base.and_then(Value::as_object);
            let keys = base
                .into_iter()
                .flat_map(|base| base.keys())
                .chain(source.keys())
                .chain(before.keys())
                .chain(after.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            let mut checkpoint = serde_json::Map::new();
            for key in keys {
                if let Some(value) = checkpoint_applied_value(
                    base.and_then(|base| base.get(&key)),
                    source.get(&key),
                    before.get(&key),
                    after.get(&key),
                    force,
                ) {
                    checkpoint.insert(key, value);
                }
            }
            Some(Value::Object(checkpoint))
        }
        _ => match classify_field(baseline, source, downstream_before) {
            SnapshotClassification::DownstreamChanged | SnapshotClassification::Conflict
                if !force =>
            {
                baseline.cloned()
            }
            SnapshotClassification::UnknownBaseline
                if !force && source.is_none() && downstream_before.is_some() =>
            {
                baseline.cloned()
            }
            _ => downstream_after.cloned(),
        },
    }
}

fn flatten_value(value: Option<&Value>, path: &str, output: &mut BTreeMap<String, Option<Value>>) {
    let Some(value) = value else {
        output.insert(path.to_owned(), None);
        return;
    };
    if let Value::Object(object) = value {
        if object.is_empty() {
            output.insert(path.to_owned(), Some(Value::Object(object.clone())));
            return;
        }
        for (key, child) in object {
            let child_path = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            flatten_value(Some(child), &child_path, output);
        }
        return;
    }
    output.insert(path.to_owned(), Some(value.clone()));
}

fn is_sensitive_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    ["key", "password", "secret", "authorization", "credential"]
        .iter()
        .any(|marker| path.contains(marker))
}

fn display_value(value: &Value, sensitive: bool) -> Value {
    if !sensitive {
        return value.clone();
    }
    Value::String(format!(
        "sha256:{}",
        sha256_hex(value.to_string().as_bytes())
    ))
}

fn risk_for_path(path: &str, classification: SnapshotClassification) -> RiskLevel {
    if classification == SnapshotClassification::Conflict {
        return RiskLevel::High;
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("price") || lower.contains("ratio") || lower.contains("cost") {
        RiskLevel::High
    } else if lower.contains("token") || lower.contains("channel") || lower.contains("monitor") {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn three_way_classification_distinguishes_source_and_downstream_changes() {
        let baseline = json!(1);
        assert_eq!(
            classify_field(Some(&baseline), Some(&json!(2)), Some(&json!(1))),
            SnapshotClassification::SourceChanged
        );
        assert_eq!(
            classify_field(Some(&baseline), Some(&json!(1)), Some(&json!(2))),
            SnapshotClassification::DownstreamChanged
        );
        assert_eq!(
            classify_field(Some(&baseline), Some(&json!(2)), Some(&json!(3))),
            SnapshotClassification::Conflict
        );
        assert_eq!(
            classify_field(Some(&baseline), Some(&json!(2)), Some(&json!(2))),
            SnapshotClassification::BothChangedToSame
        );
        assert_eq!(
            classify_field(None, Some(&json!(2)), Some(&json!(1))),
            SnapshotClassification::UnknownBaseline
        );
    }

    #[test]
    fn field_diff_is_nested_and_redacts_sensitive_values() {
        let diffs = diff_snapshots(
            Some(&json!({"channel": {"key": "old", "models": ["a"]}})),
            &json!({"channel": {"key": "new", "models": ["a", "b"]}}),
            &json!({"channel": {"key": "manual", "models": ["a"]}}),
        );
        assert!(diffs.iter().any(|diff| diff.path == "channel.models"));
        let key = diffs
            .iter()
            .find(|diff| diff.path == "channel.key")
            .expect("key diff");
        assert!(key.sensitive);
        assert!(
            !key.source_current
                .as_ref()
                .unwrap()
                .to_string()
                .contains("new")
        );
    }

    #[test]
    fn non_forced_merge_preserves_manual_downstream_values() {
        let merged = advance_last_applied(
            Some(&json!({"price": 1, "description": "old"})),
            &json!({"price": 2, "description": "source"}),
            &json!({"price": 1.5, "description": "manual"}),
            false,
        );
        assert_eq!(merged["price"], json!(1.5));
        assert_eq!(merged["description"], json!("manual"));
    }

    #[test]
    fn non_forced_merge_handles_source_and_downstream_deletions() {
        let merged = advance_last_applied(
            Some(&json!({
                "price": 1,
                "source_deleted": true,
                "downstream_deleted": true
            })),
            &json!({"price": 2, "downstream_deleted": true, "source_added": true}),
            &json!({"price": 1, "source_deleted": true}),
            false,
        );

        assert_eq!(merged, json!({"price": 2, "source_added": true}));
    }

    #[test]
    fn non_forced_merge_preserves_downstream_only_fields() {
        let merged = advance_last_applied(
            Some(&json!({"managed": 1})),
            &json!({"managed": 2}),
            &json!({"managed": 1, "local_price": 1.25}),
            false,
        );

        assert_eq!(merged, json!({"managed": 2, "local_price": 1.25}));
    }

    #[test]
    fn non_forced_initial_merge_preserves_downstream_only_fields() {
        let source = json!({"managed": 2});
        let before = json!({"managed": 1, "local_price": 1.25});
        let after = advance_last_applied(None, &source, &before, false);
        let checkpoint = checkpoint_last_applied(None, &source, &before, &after, false);

        assert_eq!(after, json!({"managed": 2, "local_price": 1.25}));
        assert_eq!(checkpoint, json!({"managed": 2}));
    }

    #[test]
    fn checkpoint_does_not_claim_preserved_downstream_only_fields() {
        let baseline = json!({"managed": 1});
        let source = json!({"managed": 2});
        let before = json!({"managed": 1, "local_price": 1.25});
        let after = advance_last_applied(Some(&baseline), &source, &before, false);
        let checkpoint = checkpoint_last_applied(Some(&baseline), &source, &before, &after, false);

        assert_eq!(after, json!({"managed": 2, "local_price": 1.25}));
        assert_eq!(checkpoint, json!({"managed": 2}));
    }

    #[test]
    fn force_removes_downstream_only_fields() {
        let baseline = json!({"managed": 1});
        let source = json!({"managed": 2});
        let before = json!({"managed": 1, "local_price": 1.25});
        let after = advance_last_applied(Some(&baseline), &source, &before, true);
        let checkpoint = checkpoint_last_applied(Some(&baseline), &source, &before, &after, true);

        assert_eq!(after, json!({"managed": 2}));
        assert_eq!(checkpoint, json!({"managed": 2}));
    }

    #[test]
    fn checkpoint_keeps_original_baseline_for_preserved_manual_fields() {
        let baseline = json!({"price": 1, "description": "old"});
        let source = json!({"price": 2, "description": "source"});
        let before = json!({"price": 1, "description": "manual"});
        let after = advance_last_applied(Some(&baseline), &source, &before, false);
        let checkpoint = checkpoint_last_applied(Some(&baseline), &source, &before, &after, false);

        assert_eq!(after, json!({"price": 2, "description": "manual"}));
        assert_eq!(checkpoint, json!({"price": 2, "description": "old"}));
        assert_eq!(
            classify_field(
                checkpoint.get("description"),
                source.get("description"),
                after.get("description")
            ),
            SnapshotClassification::Conflict
        );
    }

    #[test]
    fn same_value_changes_update_facts_without_becoming_apply_actions() {
        let source = snapshot_from_modules(BTreeMap::from([(
            SyncModule::GroupPricing,
            json!({"purchase": {"gpt-pro": 0.3}}),
        )]));
        let downstream = source.clone();
        let baseline = snapshot_from_modules(BTreeMap::from([(
            SyncModule::GroupPricing,
            json!({"purchase": {"gpt-pro": 0.2}}),
        )]));
        let plan = SyncPlan::new(source, downstream, Some(baseline));
        assert!(plan.changed_modules().contains(&SyncModule::GroupPricing));
        assert!(
            !plan
                .actionable_modules()
                .contains(&SyncModule::GroupPricing)
        );
        assert!(plan.converged_modules().contains(&SyncModule::GroupPricing));
    }

    #[test]
    fn managed_channel_purchase_changes_are_owned_by_seedance() {
        let channels = json!({"channels": [{
            "tag": "meowai-deploy:0123456789abcdef:group-one",
            "metadata": {"managed_by": "meowai-deploy"}
        }]});
        let source = snapshot_from_modules(BTreeMap::from([
            (SyncModule::Channels, channels.clone()),
            (
                SyncModule::Seedance,
                json!({"managed_channel_purchase": {"seedance-2.0": {"purchase_rate_bps": 7000}}}),
            ),
        ]));
        let downstream = snapshot_from_modules(BTreeMap::from([
            (SyncModule::Channels, channels.clone()),
            (
                SyncModule::Seedance,
                json!({"managed_channel_purchase": {"seedance-2.0": {"purchase_rate_bps": 8300}}}),
            ),
        ]));
        let baseline = downstream.clone();

        let plan = SyncPlan::new(source, downstream, Some(baseline));

        assert!(plan.actionable_modules().contains(&SyncModule::Seedance));
        assert!(!plan.actionable_modules().contains(&SyncModule::Channels));
    }

    #[test]
    fn mixed_same_value_and_actionable_changes_do_not_advance_a_module_baseline() {
        let plan = SyncPlan::new(
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::GroupPricing,
                json!({"purchase": 0.3, "sales": 0.4}),
            )])),
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::GroupPricing,
                json!({"purchase": 0.3, "sales": 0.35}),
            )])),
            Some(snapshot_from_modules(BTreeMap::from([(
                SyncModule::GroupPricing,
                json!({"purchase": 0.2, "sales": 0.35}),
            )]))),
        );

        assert!(
            plan.actionable_modules()
                .contains(&SyncModule::GroupPricing)
        );
        assert!(!plan.converged_modules().contains(&SyncModule::GroupPricing));
    }

    #[test]
    fn downstream_drift_excludes_source_only_and_unknown_baseline_changes() {
        let source_only = SyncPlan::new(
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "new"}),
            )])),
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "old"}),
            )])),
            Some(snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "old"}),
            )]))),
        );
        assert!(!source_only.has_downstream_drift(SyncModule::Kuma));

        let unknown = SyncPlan::new(
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "new"}),
            )])),
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "old"}),
            )])),
            None,
        );
        assert!(!unknown.has_downstream_drift(SyncModule::Kuma));

        let conflict = SyncPlan::new(
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "new"}),
            )])),
            snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "manual"}),
            )])),
            Some(snapshot_from_modules(BTreeMap::from([(
                SyncModule::Kuma,
                json!({"title": "old"}),
            )]))),
        );
        assert!(conflict.has_downstream_drift(SyncModule::Kuma));
    }
}
