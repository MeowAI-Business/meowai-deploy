use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
};

use reqwest::Method;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{SourceClient, SourceError, SourceResult, require_data, unix_timestamp};

const TOKEN_NAME_LIMIT: usize = 50;
const PAGE_SIZE: usize = 100;
const TOKEN_PREFIX: &str = "meowai-deploy/";

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SourceGroup {
    pub group_id: String,
    pub group_name: String,
    pub description: String,
    pub base_ratio: serde_json::Value,
    pub ratio: serde_json::Value,
    pub purchase_ratio: Option<serde_json::Value>,
    pub purchase_source: String,
    pub discount: Option<String>,
    pub topup_ratio: Option<serde_json::Value>,
    pub user_selectable: bool,
    pub models: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct GroupCatalog {
    pub groups: Vec<SourceGroup>,
    pub fetched_at: i64,
    pub response_sha256: String,
}

pub struct TokenBinding {
    pub group_id: String,
    pub group_name: String,
    pub token_id: i64,
    pub token_name: String,
    pub reused: bool,
    api_key: SecretString,
}

impl TokenBinding {
    pub fn api_key(&self) -> &SecretString {
        &self.api_key
    }
}

impl fmt::Debug for TokenBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenBinding")
            .field("group_id", &self.group_id)
            .field("group_name", &self.group_name)
            .field("token_id", &self.token_id)
            .field("token_name", &self.token_name)
            .field("reused", &self.reused)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub struct TokenSync {
    pub bindings: Vec<TokenBinding>,
    pub created: usize,
    pub reused: usize,
    pub updated: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupTokenPlanEntry {
    pub group_id: String,
    pub group_name: String,
    pub token_name: String,
    pub token_id: Option<i64>,
    pub needs_create: bool,
    pub needs_update: bool,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GroupTokenPlan {
    pub entries: Vec<GroupTokenPlanEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemovedGroupTokenPlan {
    pub token_id: i64,
    pub token_name: String,
    pub group_name: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawGroup {
    #[serde(default)]
    description: String,
    #[serde(default)]
    base_ratio: Option<serde_json::Value>,
    #[serde(default)]
    terminal_ratio: Option<serde_json::Value>,
    #[serde(default)]
    purchase_ratio: Option<serde_json::Value>,
    #[serde(default)]
    purchase_source: Option<String>,
    #[serde(default)]
    discount: Option<String>,
    #[serde(default)]
    ratio: Option<serde_json::Value>,
    #[serde(default)]
    topup_ratio: Option<serde_json::Value>,
    #[serde(default)]
    user_selectable: bool,
    #[serde(default)]
    models: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SourceToken {
    id: i64,
    name: String,
    status: i32,
    remain_quota: i64,
    unlimited_quota: bool,
    expired_time: i64,
    group: Option<String>,
    model_limits_enabled: bool,
    #[serde(default)]
    model_limits: Option<String>,
    #[serde(default)]
    allow_ips: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Page<T> {
    items: Vec<T>,
    total: usize,
    page: usize,
    page_size: usize,
}

#[derive(Serialize)]
struct DesiredToken<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<i64>,
    name: &'a str,
    status: i32,
    remain_quota: i64,
    expired_time: i64,
    unlimited_quota: bool,
    model_limits_enabled: bool,
    model_limits: &'a str,
    allow_ips: &'a str,
    group: &'a str,
    auto_groups: &'a [String],
    cross_group_retry: bool,
}

#[derive(Serialize)]
struct TokenStatus {
    id: i64,
    status: i32,
}

#[derive(Debug, Deserialize)]
struct TokenKeys {
    keys: HashMap<String, String>,
}

impl SourceClient {
    pub async fn groups(&mut self) -> SourceResult<GroupCatalog> {
        const ENDPOINT: &str = "/api/onboard/groups";
        let envelope = self
            .authenticated_request::<serde_json::Value>(Method::GET, ENDPOINT, None)
            .await?;
        let data = require_data(envelope, ENDPOINT)?;
        let (raw_groups, schema_version) = parse_groups_response(data, ENDPOINT)?;
        if raw_groups.is_empty() {
            return Err(SourceError::EmptyGroups);
        }
        let mut groups = Vec::with_capacity(raw_groups.len());
        for (name, group) in raw_groups
            .into_iter()
            .filter(|(name, _)| is_exportable_group(name))
        {
            let mut models = group.models;
            models.retain(|model| !model.trim().is_empty());
            models
                .iter_mut()
                .for_each(|model| *model = model.trim().to_owned());
            models.sort();
            models.dedup();
            groups.push(SourceGroup {
                group_id: name.clone(),
                group_name: name.clone(),
                description: group.description,
                base_ratio: group
                    .base_ratio
                    .clone()
                    .or_else(|| group.ratio.clone())
                    .ok_or_else(|| SourceError::InvalidResponse {
                        endpoint: ENDPOINT.to_owned(),
                        message: format!("group {name} is missing base ratio"),
                    })?,
                ratio: group
                    .terminal_ratio
                    .clone()
                    .or_else(|| group.base_ratio.clone())
                    .or_else(|| group.ratio.clone())
                    .ok_or_else(|| SourceError::InvalidResponse {
                        endpoint: ENDPOINT.to_owned(),
                        message: format!("group {name} is missing terminal ratio"),
                    })?,
                purchase_ratio: if schema_version >= 2 {
                    Some(
                        group
                            .purchase_ratio
                            .clone()
                            .or_else(|| group.terminal_ratio.clone())
                            .or_else(|| group.base_ratio.clone())
                            .or_else(|| group.ratio.clone())
                            .ok_or_else(|| SourceError::InvalidResponse {
                                endpoint: ENDPOINT.to_owned(),
                                message: format!("group {name} is missing purchase ratio"),
                            })?,
                    )
                } else {
                    None
                },
                purchase_source: group.purchase_source.unwrap_or_else(|| {
                    if schema_version >= 2 {
                        "base_ratio"
                    } else {
                        "unknown"
                    }
                    .to_owned()
                }),
                discount: group
                    .discount
                    .map(|discount| discount.trim().to_owned())
                    .filter(|discount| !discount.is_empty()),
                topup_ratio: group.topup_ratio,
                user_selectable: group.user_selectable,
                models,
            });
        }
        if groups.is_empty() {
            return Err(SourceError::EmptyGroups);
        }
        let canonical =
            serde_json::to_vec(&groups).map_err(|error| SourceError::InvalidResponse {
                endpoint: ENDPOINT.to_owned(),
                message: error.to_string(),
            })?;
        let response_sha256 = hex_digest(&canonical);
        Ok(GroupCatalog {
            groups,
            fetched_at: unix_timestamp(),
            response_sha256,
        })
    }

    pub async fn plan_group_tokens(
        &mut self,
        catalog: &GroupCatalog,
    ) -> SourceResult<GroupTokenPlan> {
        if catalog.groups.is_empty() {
            return Err(SourceError::EmptyGroups);
        }

        let desired = desired_token_names(&catalog.groups)?;
        let tokens = self.list_tokens().await?;
        let mut entries = Vec::with_capacity(catalog.groups.len());
        for (group, token_name) in catalog.groups.iter().zip(&desired) {
            let matches = matching_tokens(&tokens, token_name);
            if matches.len() > 1 {
                return Err(SourceError::AmbiguousToken(format!(
                    "multiple tokens named {token_name} exist for group {}",
                    group.group_name
                )));
            }
            let token = matches.first().copied();
            entries.push(GroupTokenPlanEntry {
                group_id: group.group_id.clone(),
                group_name: group.group_name.clone(),
                token_name: token_name.clone(),
                token_id: token.map(|token| token.id),
                needs_create: token.is_none(),
                needs_update: token
                    .is_some_and(|token| token_needs_update(token, &group.group_name)),
                enabled: token.is_some_and(|token| token.status == 1),
            });
        }
        Ok(GroupTokenPlan { entries })
    }

    pub async fn apply_group_tokens(
        &mut self,
        catalog: &GroupCatalog,
        plan: &GroupTokenPlan,
    ) -> SourceResult<TokenSync> {
        if catalog.groups.len() != plan.entries.len()
            || catalog
                .groups
                .iter()
                .zip(&plan.entries)
                .any(|(group, entry)| group.group_id != entry.group_id)
        {
            return Err(SourceError::InvalidDeployment(
                "group token plan no longer matches the source catalog".to_owned(),
            ));
        }
        let mut created = 0;
        let mut initially_present = BTreeMap::new();
        for entry in &plan.entries {
            if entry.needs_create {
                self.create_token(&entry.token_name, &entry.group_name)
                    .await?;
                created += 1;
            } else if let Some(token_id) = entry.token_id {
                initially_present.insert(entry.group_id.clone(), token_id);
            }
        }

        let refresh_tokens = created > 0 || plan.entries.iter().any(|entry| entry.needs_update);
        let tokens = if refresh_tokens {
            self.list_tokens().await?
        } else {
            Vec::new()
        };
        let mut updated = 0;
        let mut selected = Vec::with_capacity(catalog.groups.len());

        for (group, entry) in catalog.groups.iter().zip(&plan.entries) {
            if tokens.is_empty() {
                let token_id = entry.token_id.ok_or_else(|| SourceError::InvalidResponse {
                    endpoint: "/api/token/".to_owned(),
                    message: format!("token {} disappeared after planning", entry.token_name),
                })?;
                selected.push((
                    group.clone(),
                    entry.token_name.clone(),
                    token_id,
                    initially_present.contains_key(&group.group_id),
                ));
                continue;
            }
            let matches = matching_tokens(&tokens, &entry.token_name);
            if matches.len() != 1 {
                return Err(SourceError::AmbiguousToken(format!(
                    "expected one token named {} for group {}, found {}",
                    entry.token_name,
                    group.group_name,
                    matches.len()
                )));
            }
            let token = matches[0];
            if token_needs_update(token, &group.group_name) {
                let was_disabled = token.status != 1;
                self.update_token(token.id, &entry.token_name, &group.group_name)
                    .await?;
                if was_disabled {
                    self.enable_token(token.id).await?;
                }
                updated += 1;
            }
            selected.push((
                group.clone(),
                entry.token_name.clone(),
                token.id,
                initially_present.contains_key(&group.group_id),
            ));
        }

        let ids = selected.iter().map(|(_, _, id, _)| *id).collect::<Vec<_>>();
        let keys = self.token_keys(&ids).await?;
        let mut bindings = Vec::with_capacity(selected.len());
        for (group, token_name, token_id, reused) in selected {
            let raw_key = keys.get(&token_id.to_string()).cloned().ok_or_else(|| {
                SourceError::InvalidResponse {
                    endpoint: "/api/token/batch/keys".to_owned(),
                    message: format!("missing key for token {token_id}"),
                }
            })?;
            let api_key = if raw_key.starts_with("sk-") {
                raw_key
            } else {
                format!("sk-{raw_key}")
            };
            bindings.push(TokenBinding {
                group_id: group.group_id.clone(),
                group_name: group.group_name.clone(),
                token_id,
                token_name: token_name.clone(),
                reused,
                api_key: SecretString::from(api_key),
            });
        }

        Ok(TokenSync {
            reused: bindings.len() - created,
            bindings,
            created,
            updated,
        })
    }

    pub async fn plan_removed_group_tokens(
        &mut self,
        active_group_ids: &BTreeSet<String>,
    ) -> SourceResult<Vec<RemovedGroupTokenPlan>> {
        let tokens = self.list_tokens().await?;
        Ok(tokens
            .into_iter()
            .filter(|token| {
                is_account_group_token(token)
                    && token
                        .group
                        .as_deref()
                        .is_some_and(|group| !active_group_ids.contains(group))
            })
            .map(|token| RemovedGroupTokenPlan {
                token_id: token.id,
                token_name: token.name,
                group_name: token.group.unwrap_or_default(),
                enabled: token.status == 1,
            })
            .collect())
    }

    pub async fn apply_removed_group_tokens(
        &mut self,
        plan: &[RemovedGroupTokenPlan],
    ) -> SourceResult<usize> {
        let mut disabled = 0;
        for entry in plan {
            if entry.enabled {
                self.update_token_status(entry.token_id, 2).await?;
                disabled += 1;
            }
        }
        Ok(disabled)
    }

    pub async fn ensure_group_tokens(&mut self, catalog: &GroupCatalog) -> SourceResult<TokenSync> {
        let plan = self.plan_group_tokens(catalog).await?;
        self.apply_group_tokens(catalog, &plan).await
    }

    pub async fn disable_removed_group_tokens(
        &mut self,
        active_group_ids: &BTreeSet<String>,
    ) -> SourceResult<usize> {
        let plan = self.plan_removed_group_tokens(active_group_ids).await?;
        self.apply_removed_group_tokens(&plan).await
    }

    pub async fn revoke_account_group_tokens(&mut self) -> SourceResult<usize> {
        let tokens = self.list_tokens().await?;
        let mut revoked = 0;
        for token in tokens {
            if is_account_group_token(&token) {
                self.delete_token(token.id).await?;
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn list_tokens(&mut self) -> SourceResult<Vec<SourceToken>> {
        let mut tokens = Vec::new();
        let mut page_number = 1;
        loop {
            let path = format!("/api/token/?p={page_number}&size={PAGE_SIZE}");
            let envelope = self
                .authenticated_request::<Page<SourceToken>>(Method::GET, &path, None)
                .await?;
            let page = require_data(envelope, &path)?;
            let item_count = page.items.len();
            tokens.extend(page.items);
            if tokens.len() >= page.total || item_count == 0 {
                break;
            }
            if page.page_size == 0 || page.page != page_number {
                return Err(SourceError::InvalidResponse {
                    endpoint: path,
                    message: "invalid pagination metadata".to_owned(),
                });
            }
            page_number += 1;
        }
        Ok(tokens)
    }

    async fn create_token(&mut self, name: &str, group: &str) -> SourceResult<()> {
        let request = desired_token(None, name, group);
        self.authenticated_request::<serde_json::Value>(
            Method::POST,
            "/api/token/",
            Some(
                serde_json::to_value(request).map_err(|error| SourceError::InvalidResponse {
                    endpoint: "/api/token/".to_owned(),
                    message: error.to_string(),
                })?,
            ),
        )
        .await?;
        Ok(())
    }

    async fn update_token(&mut self, id: i64, name: &str, group: &str) -> SourceResult<()> {
        let request = desired_token(Some(id), name, group);
        self.authenticated_request::<serde_json::Value>(
            Method::PUT,
            "/api/token/",
            Some(
                serde_json::to_value(request).map_err(|error| SourceError::InvalidResponse {
                    endpoint: "/api/token/".to_owned(),
                    message: error.to_string(),
                })?,
            ),
        )
        .await?;
        Ok(())
    }

    async fn enable_token(&mut self, id: i64) -> SourceResult<()> {
        let body = serde_json::to_value(TokenStatus { id, status: 1 }).map_err(|error| {
            SourceError::InvalidResponse {
                endpoint: "/api/token/".to_owned(),
                message: error.to_string(),
            }
        })?;
        self.authenticated_request::<serde_json::Value>(
            Method::PUT,
            "/api/token/?status_only=true",
            Some(body),
        )
        .await?;
        Ok(())
    }

    async fn update_token_status(&mut self, id: i64, status: i32) -> SourceResult<()> {
        let body = serde_json::to_value(TokenStatus { id, status }).map_err(|error| {
            SourceError::InvalidResponse {
                endpoint: "/api/token/?status_only=true".to_owned(),
                message: error.to_string(),
            }
        })?;
        self.authenticated_request::<serde_json::Value>(
            Method::PUT,
            "/api/token/?status_only=true",
            Some(body),
        )
        .await?;
        Ok(())
    }

    async fn delete_token(&mut self, id: i64) -> SourceResult<()> {
        let path = format!("/api/token/{id}");
        self.authenticated_request::<serde_json::Value>(Method::DELETE, &path, None)
            .await?;
        Ok(())
    }

    async fn token_keys(&mut self, ids: &[i64]) -> SourceResult<HashMap<String, String>> {
        let mut keys = HashMap::new();
        for chunk in ids.chunks(100) {
            let body = serde_json::json!({"ids": chunk});
            let envelope = self
                .authenticated_request::<TokenKeys>(
                    Method::POST,
                    "/api/token/batch/keys",
                    Some(body),
                )
                .await?;
            for (id, key) in require_data(envelope, "/api/token/batch/keys")?.keys {
                if key.trim().is_empty() {
                    return Err(SourceError::InvalidResponse {
                        endpoint: "/api/token/batch/keys".to_owned(),
                        message: format!("empty key for token {id}"),
                    });
                }
                keys.insert(id, key);
            }
        }
        Ok(keys)
    }
}

fn parse_groups_response(
    value: serde_json::Value,
    endpoint: &str,
) -> SourceResult<(BTreeMap<String, RawGroup>, u32)> {
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1) as u32;
    let groups = if schema_version >= 2 {
        value
            .get("groups")
            .cloned()
            .ok_or_else(|| SourceError::InvalidResponse {
                endpoint: endpoint.to_owned(),
                message: "schema_version=2 response is missing groups".to_owned(),
            })?
    } else {
        value
    };
    serde_json::from_value(groups)
        .map(|groups| (groups, schema_version))
        .map_err(|error| SourceError::InvalidResponse {
            endpoint: endpoint.to_owned(),
            message: error.to_string(),
        })
}

fn is_exportable_group(name: &str) -> bool {
    let normalized = name.trim();
    !normalized.is_empty() && normalized != "下游" && !normalized.starts_with("official-")
}

fn desired_token<'a>(id: Option<i64>, name: &'a str, group: &'a str) -> DesiredToken<'a> {
    DesiredToken {
        id,
        name,
        status: 1,
        remain_quota: 0,
        expired_time: -1,
        unlimited_quota: true,
        model_limits_enabled: false,
        model_limits: "",
        allow_ips: "",
        group,
        auto_groups: &[],
        cross_group_retry: false,
    }
}

fn matching_tokens<'a>(tokens: &'a [SourceToken], name: &str) -> Vec<&'a SourceToken> {
    tokens.iter().filter(|token| token.name == name).collect()
}

fn token_needs_update(token: &SourceToken, group: &str) -> bool {
    token.status != 1
        || token.remain_quota != 0
        || !token.unlimited_quota
        || token.expired_time != -1
        || token.group.as_deref().unwrap_or_default() != group
        || token.model_limits_enabled
        || token
            .model_limits
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        || token
            .allow_ips
            .as_deref()
            .is_some_and(|value| !value.is_empty())
}

fn desired_token_names(groups: &[SourceGroup]) -> SourceResult<Vec<String>> {
    let mut names = Vec::with_capacity(groups.len());
    for group in groups {
        let name = desired_token_name(&group.group_name)?;
        if names.contains(&name) {
            return Err(SourceError::InvalidDeployment(format!(
                "token name collision for group {}",
                group.group_name
            )));
        }
        names.push(name);
    }
    Ok(names)
}

fn desired_token_name(group_name: &str) -> SourceResult<String> {
    if group_name.is_empty() {
        return Err(SourceError::InvalidDeployment(
            "group name cannot be empty".to_owned(),
        ));
    }
    let full = format!("{TOKEN_PREFIX}{group_name}");
    if full.len() <= TOKEN_NAME_LIMIT {
        return Ok(full);
    }
    let digest = hex_digest(group_name.as_bytes());
    let suffix = format!("-{}", &digest[..10]);
    let available = TOKEN_NAME_LIMIT
        .checked_sub(TOKEN_PREFIX.len() + suffix.len())
        .ok_or_else(|| {
            SourceError::InvalidDeployment(
                "token prefix leaves no room for a group name".to_owned(),
            )
        })?;
    let truncated = truncate_utf8(group_name, available);
    if truncated.is_empty() {
        return Err(SourceError::InvalidDeployment(
            "group name cannot fit in the source token name".to_owned(),
        ));
    }
    Ok(format!("{TOKEN_PREFIX}{truncated}{suffix}"))
}

fn is_account_group_token(token: &SourceToken) -> bool {
    token
        .group
        .as_deref()
        .and_then(|group| desired_token_name(group).ok())
        .is_some_and(|name| token.name == name)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn token_names_are_stable_and_fit_the_source_limit() {
        let groups = vec![SourceGroup {
            group_id: "超长分组".repeat(12),
            group_name: "超长分组".repeat(12),
            description: String::new(),
            base_ratio: serde_json::json!(1),
            ratio: serde_json::json!(1),
            purchase_ratio: None,
            purchase_source: "unknown".to_owned(),
            discount: None,
            topup_ratio: None,
            user_selectable: false,
            models: vec!["gpt-test".to_owned()],
        }];
        let first = desired_token_names(&groups).expect("build token name");
        let second = desired_token_names(&groups).expect("repeat token name");
        assert_eq!(first, second);
        assert!(first[0].len() <= TOKEN_NAME_LIMIT);
        assert!(first[0].starts_with(TOKEN_PREFIX));
    }

    #[test]
    fn token_name_is_scoped_to_the_account_group_not_a_deployment() {
        let groups = vec![SourceGroup {
            group_id: "default".to_owned(),
            group_name: "default".to_owned(),
            description: String::new(),
            base_ratio: serde_json::json!(1),
            ratio: serde_json::json!(1),
            purchase_ratio: None,
            purchase_source: "unknown".to_owned(),
            discount: None,
            topup_ratio: None,
            user_selectable: false,
            models: vec![],
        }];

        assert_eq!(
            desired_token_names(&groups).expect("build token name"),
            ["meowai-deploy/default"]
        );
    }

    #[test]
    fn token_debug_output_redacts_the_key() {
        let binding = TokenBinding {
            group_id: "default".to_owned(),
            group_name: "default".to_owned(),
            token_id: 7,
            token_name: "meowai-deploy/site/default".to_owned(),
            reused: false,
            api_key: SecretString::from("sk-super-secret".to_owned()),
        };
        let debug = format!("{binding:?}");
        assert!(!debug.contains(binding.api_key().expose_secret()));
        assert!(debug.contains("<redacted>"));
    }
}
