use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

use super::{
    SourceAccountMode, SourceClient, SourceCredentials, SourceError, SourceGroup,
    control_plane_endpoint, groups::GroupCatalog,
};

#[test]
fn remote_plain_http_source_and_control_plane_are_allowed() {
    SourceClient::new("http://source.example.test:3001")
        .expect("plain HTTP source should be accepted");

    let endpoint = control_plane_endpoint(
        "http://control.example.test:3001/api",
        "/api/onboard/deployments/example/heartbeat",
    )
    .expect("plain HTTP control plane should be accepted");
    assert_eq!(
        endpoint.as_str(),
        "http://control.example.test:3001/api/onboard/deployments/example/heartbeat"
    );
}

#[test]
fn non_http_source_and_control_plane_are_rejected() {
    assert!(SourceClient::new("ftp://source.example.test").is_err());
    assert!(control_plane_endpoint("ftp://control.example.test", "/heartbeat").is_err());
}

fn credentials() -> SourceCredentials {
    SourceCredentials::new(
        "downstream-owner",
        SecretString::from("secret-probe-1".to_owned()),
    )
    .expect("valid credentials")
}

fn login_data(token: &str, expires_at: i64) -> Value {
    json!({
        "access_token": token,
        "token_type": "Bearer",
        "access_expires_at": expires_at,
        "session": {"sid": "session-1"},
        "user": {"id": 42, "username": "downstream-owner"}
    })
}

fn token(id: i64, name: &str, group: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "key": "abcd**********wxyz",
        "status": 1,
        "remain_quota": 0,
        "used_quota": 0,
        "unlimited_quota": true,
        "expired_time": -1,
        "created_time": 1,
        "accessed_time": 1,
        "group": group,
        "auto_groups": null,
        "cross_group_retry": false,
        "model_limits_enabled": false,
        "model_limits": "",
        "allow_ips": ""
    })
}

fn pricing_data() -> Value {
    json!({
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
        "home_pricing": {
            "table": "[{\"model\":\"seedance-2.0\",\"note\":\"public pricing note\"}]",
            "title": "Pricing",
            "description": "Public prices",
            "enabled": true
        },
        "marketplace": marketplace_data()
    })
}

fn marketplace_data() -> Value {
    json!({
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

async fn mount_login(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/user/login"))
        .and(body_json(json!({
            "username": "downstream-owner",
            "password": "secret-probe-1"
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header(
                    "Set-Cookie",
                    "new_api_refresh=session-1.secret; Path=/api/user/auth; HttpOnly",
                )
                .set_body_json(json!({
                    "success": true,
                    "message": "",
                    "data": login_data("access-one", i64::MAX)
                })),
        )
        .mount(server)
        .await;
}

async fn authenticated_client(server: &MockServer) -> SourceClient {
    mount_login(server).await;
    let mut client = SourceClient::new(&server.uri()).expect("create source client");
    let identity = client
        .authenticate(SourceAccountMode::Login, &credentials())
        .await
        .expect("authenticate");
    assert_eq!(identity.user_id, 42);
    assert_eq!(identity.username, "downstream-owner");
    client
}

#[tokio::test]
async fn onboard_access_accepts_approved_account() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/onboard/access"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"allowed": true}
        })))
        .expect(1)
        .mount(&server)
        .await;

    client
        .check_onboard_access()
        .await
        .expect("approved account");
}

#[tokio::test]
async fn onboard_access_reports_upstream_approval_requirement() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/onboard/access"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "success": false,
            "code": "ONBOARD_APPROVAL_REQUIRED",
            "message": "需要上游批准后才能部署"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = client
        .check_onboard_access()
        .await
        .expect_err("unapproved account must be rejected");
    assert!(matches!(error, SourceError::ApprovalRequired));
    assert_eq!(error.to_string(), "需要上游批准后才能部署");
}

#[tokio::test]
async fn register_then_login_uses_standard_account_endpoints() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/user/register"))
        .and(body_json(json!({
            "username": "downstream-owner",
            "password": "secret-probe-1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": ""
        })))
        .expect(1)
        .mount(&server)
        .await;
    mount_login(&server).await;

    let mut client = SourceClient::new(&server.uri()).expect("create source client");
    let identity = client
        .authenticate(SourceAccountMode::Register, &credentials())
        .await
        .expect("register and login");

    assert_eq!(identity.user_id, 42);
    assert_eq!(client.identity(), Some(&identity));
}

#[tokio::test]
async fn connectivity_check_uses_configured_source_url() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/status"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;

    let client = SourceClient::new(&server.uri()).expect("create source client");
    client
        .check_connectivity()
        .await
        .expect("configured source should be checked");
}

#[tokio::test]
async fn authenticated_session_can_be_persisted_and_restored() {
    let server = MockServer::start().await;
    let client = authenticated_client(&server).await;
    let persisted = client.export_session().expect("export session");
    let debug = format!("{persisted:?}");
    assert!(!debug.contains("access-one"));
    assert!(!debug.contains("session-1.secret"));

    let restored = SourceClient::from_session(&server.uri(), persisted).expect("restore session");
    assert_eq!(restored.identity(), client.identity());
}

#[tokio::test]
async fn two_factor_login_stops_without_exposing_the_password() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/user/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "Two-factor authentication required",
            "data": {
                "require_2fa": true,
                "flow_token": "opaque-flow",
                "expires_at": 123
            }
        })))
        .mount(&server)
        .await;

    let mut client = SourceClient::new(&server.uri()).expect("create source client");
    let error = client
        .login(&credentials())
        .await
        .expect_err("2FA must stop CLI login");
    assert!(matches!(error, SourceError::TwoFactorRequired));
    assert!(!format!("{error:?}").contains("secret-probe-1"));
    assert!(!format!("{:?}", credentials()).contains("secret-probe-1"));
}

#[tokio::test]
async fn rate_limit_error_preserves_retry_after_without_response_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/user/login"))
        .respond_with(
            ResponseTemplate::new(429)
                .append_header("Retry-After", "37")
                .set_body_string("credentials must not be echoed"),
        )
        .mount(&server)
        .await;

    let mut client = SourceClient::new(&server.uri()).expect("create source client");
    let error = client
        .login(&credentials())
        .await
        .expect_err("rate limit must be returned");
    assert!(matches!(
        error,
        SourceError::RateLimited {
            retry_after: Some(37),
            ..
        }
    ));
    assert!(!format!("{error:?}").contains("credentials must not be echoed"));
}

#[tokio::test]
async fn groups_are_complete_sorted_and_hashed_deterministically() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/onboard/groups"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {
                "vip": {
                    "description": "VIP", "ratio": 1.5, "topup_ratio": 1.2,
                    "user_selectable": true, "models": ["gpt-vip", "shared"]
                },
                "default": {
                    "description": "Default", "ratio": 1, "topup_ratio": null,
                    "user_selectable": false, "models": ["gpt-default", "shared"]
                },
                "official-openai": {
                    "description": "Official", "ratio": 1, "topup_ratio": null,
                    "user_selectable": true, "models": ["gpt-official"]
                },
                "下游": {
                    "description": "Deployment", "ratio": 1, "topup_ratio": null,
                    "user_selectable": false, "models": ["gpt-deployment"]
                }
            }
        })))
        .expect(2)
        .mount(&server)
        .await;

    let first = client.groups().await.expect("read groups");
    let second = client.groups().await.expect("read groups again");

    let names = first
        .groups
        .iter()
        .map(|group| group.group_name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["default", "vip"]);
    assert_eq!(first.response_sha256, second.response_sha256);
    assert_eq!(first.groups, second.groups);
    assert_eq!(first.groups[1].models, ["gpt-vip", "shared"]);
    assert_eq!(first.groups[1].topup_ratio, Some(json!(1.2)));
    assert!(first.groups[1].user_selectable);
    assert_eq!(first.groups[1].base_ratio, json!(1.5));
    assert_eq!(first.groups[1].ratio, json!(1.5));
    assert_eq!(first.groups[1].purchase_ratio, None);
    assert_eq!(first.groups[1].purchase_source, "unknown");
}

#[tokio::test]
async fn v2_groups_keep_terminal_and_account_purchase_ratios_separate() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/onboard/groups"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {
                "schema_version": 2,
                "terminal_user_group": "default",
                "account_user_group": "downstream",
                "groups": {
                    "gpt-pro": {
                        "description": "GPT Pro",
                        "base_ratio": 0.4,
                        "terminal_ratio": 0.4,
                        "purchase_ratio": 0.3,
                        "purchase_source": "special_ratio",
                        "user_selectable": true,
                        "models": ["gpt-5.2"]
                    },
                    "zero-margin": {
                        "base_ratio": 1,
                        "terminal_ratio": 1,
                        "models": []
                    }
                }
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let catalog = client.groups().await.expect("read v2 groups");
    let group = catalog
        .groups
        .iter()
        .find(|group| group.group_id == "gpt-pro")
        .expect("gpt-pro group");
    assert_eq!(group.base_ratio, json!(0.4));
    assert_eq!(group.ratio, json!(0.4));
    assert_eq!(group.purchase_ratio, Some(json!(0.3)));
    assert_eq!(group.purchase_source, "special_ratio");
    let fallback = catalog
        .groups
        .iter()
        .find(|group| group.group_id == "zero-margin")
        .expect("fallback group");
    assert_eq!(fallback.purchase_ratio, Some(json!(1)));
    assert_eq!(fallback.purchase_source, "base_ratio");
}

#[derive(Clone)]
struct StatefulTokenList {
    calls: Arc<AtomicUsize>,
    initial: Value,
    current: Value,
}

impl Respond for StatefulTokenList {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let items = if call == 0 {
            self.initial.clone()
        } else {
            self.current.clone()
        };
        let total = items.as_array().map_or(0, Vec::len);
        ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"items": items, "total": total, "page": 1, "page_size": 100}
        }))
    }
}

#[tokio::test]
async fn missing_group_token_is_created_once_and_reused_on_rerun() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    let default_name = "meowai-deploy/default";
    let vip_name = "meowai-deploy/vip";
    let list_calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("GET"))
        .and(path("/api/token/"))
        .and(query_param("p", "1"))
        .and(query_param("size", "100"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(StatefulTokenList {
            calls: Arc::clone(&list_calls),
            initial: json!([token(10, default_name, "default")]),
            current: json!([
                token(10, default_name, "default"),
                token(11, vip_name, "vip")
            ]),
        })
        .expect(3)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/token/"))
        .and(header("authorization", "Bearer access-one"))
        .and(body_json(json!({
            "name": vip_name,
            "status": 1,
            "remain_quota": 0,
            "expired_time": -1,
            "unlimited_quota": true,
            "model_limits_enabled": false,
            "model_limits": "",
            "allow_ips": "",
            "group": "vip",
            "auto_groups": [],
            "cross_group_retry": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": ""
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/token/batch/keys"))
        .and(body_json(json!({"ids": [10, 11]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"keys": {"10": "default-key", "11": "vip-key"}}
        })))
        .expect(2)
        .mount(&server)
        .await;
    let catalog = GroupCatalog {
        groups: vec![group("default", 1), group("vip", 1.5)],
        fetched_at: 1,
        response_sha256: "hash".to_owned(),
    };

    let first = client
        .ensure_group_tokens(&catalog)
        .await
        .expect("create missing token");
    let second = client
        .ensure_group_tokens(&catalog)
        .await
        .expect("reuse all tokens");

    assert_eq!((first.created, first.reused, first.updated), (1, 1, 0));
    assert_eq!((second.created, second.reused, second.updated), (0, 2, 0));
    assert_eq!(first.bindings[1].api_key().expose_secret(), "sk-vip-key");
    assert_eq!(list_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn legacy_deployment_token_is_left_untouched_when_account_token_is_created() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    let legacy_name = "meowai-deploy/site_123/default";
    let account_name = "meowai-deploy/default";
    let list_calls = Arc::new(AtomicUsize::new(0));

    Mock::given(method("GET"))
        .and(path("/api/token/"))
        .and(query_param("p", "1"))
        .and(query_param("size", "100"))
        .respond_with(StatefulTokenList {
            calls: Arc::clone(&list_calls),
            initial: json!([token(9, legacy_name, "default")]),
            current: json!([
                token(9, legacy_name, "default"),
                token(10, account_name, "default")
            ]),
        })
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/token/"))
        .and(body_json(json!({
            "name": account_name,
            "status": 1,
            "remain_quota": 0,
            "expired_time": -1,
            "unlimited_quota": true,
            "model_limits_enabled": false,
            "model_limits": "",
            "allow_ips": "",
            "group": "default",
            "auto_groups": [],
            "cross_group_retry": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": ""
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/token/batch/keys"))
        .and(body_json(json!({"ids": [10]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"keys": {"10": "account-key"}}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let catalog = GroupCatalog {
        groups: vec![group("default", 1)],
        fetched_at: 1,
        response_sha256: "hash".to_owned(),
    };

    let sync = client
        .ensure_group_tokens(&catalog)
        .await
        .expect("create account token without touching legacy token");

    assert_eq!((sync.created, sync.reused, sync.updated), (1, 0, 0));
    assert_eq!(sync.bindings[0].token_name, account_name);
    assert_eq!(sync.bindings[0].api_key().expose_secret(), "sk-account-key");
    assert_eq!(list_calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn account_group_tokens_are_disabled_and_revoked_without_touching_legacy_tokens() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    let managed_default = token(10, "meowai-deploy/default", "default");
    let managed_removed = token(11, "meowai-deploy/removed", "removed");
    let unrelated = token(12, "manual-token", "removed");
    let legacy = token(13, "meowai-deploy/site_123/removed", "removed");
    Mock::given(method("GET"))
        .and(path("/api/token/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {
                "items": [managed_default, managed_removed, unrelated, legacy],
                "total": 4,
                "page": 1,
                "page_size": 100
            }
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/token/"))
        .and(query_param("status_only", "true"))
        .and(body_json(json!({"id": 11, "status": 2})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": ""
        })))
        .expect(1)
        .mount(&server)
        .await;
    for id in [10, 11] {
        Mock::given(method("DELETE"))
            .and(path(format!("/api/token/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": ""
            })))
            .expect(1)
            .mount(&server)
            .await;
    }

    let disabled = client
        .disable_removed_group_tokens(&BTreeSet::from(["default".to_owned()]))
        .await
        .expect("disable removed account token");
    let revoked = client
        .revoke_account_group_tokens()
        .await
        .expect("revoke account tokens");

    assert_eq!(disabled, 1);
    assert_eq!(revoked, 2);
}

#[tokio::test]
async fn group_token_planning_uses_only_read_requests() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/token/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {
                "items": [token(10, "meowai-deploy/default", "default")],
                "total": 1,
                "page": 1,
                "page_size": 100
            }
        })))
        .expect(2)
        .mount(&server)
        .await;
    let catalog = GroupCatalog {
        groups: vec![group("default", 1)],
        fetched_at: 1,
        response_sha256: "hash".to_owned(),
    };

    client
        .plan_group_tokens(&catalog)
        .await
        .expect("plan active group tokens");
    client
        .plan_removed_group_tokens(&BTreeSet::from(["default".to_owned()]))
        .await
        .expect("plan removed group tokens");

    let requests = server
        .received_requests()
        .await
        .expect("read recorded requests");
    let token_requests = requests
        .iter()
        .filter(|request| request.url.path().starts_with("/api/token"))
        .collect::<Vec<_>>();
    assert_eq!(token_requests.len(), 2);
    assert!(
        token_requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
}

#[tokio::test]
async fn owned_token_drift_is_reconciled_before_key_reuse() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    let token_name = "meowai-deploy/default";
    let mut drifted = token(20, token_name, "wrong-group");
    let object = drifted.as_object_mut().expect("token object");
    object.insert("status".to_owned(), json!(2));
    object.insert("remain_quota".to_owned(), json!(100));
    object.insert("unlimited_quota".to_owned(), json!(false));
    object.insert("expired_time".to_owned(), json!(100));
    object.insert("model_limits_enabled".to_owned(), json!(true));
    object.insert("model_limits".to_owned(), json!("gpt"));
    object.insert("allow_ips".to_owned(), json!("127.0.0.1"));

    Mock::given(method("GET"))
        .and(path("/api/token/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"items": [drifted], "total": 1, "page": 1, "page_size": 100}
        })))
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/token/"))
        .and(body_json(json!({
            "id": 20,
            "name": token_name,
            "status": 1,
            "remain_quota": 0,
            "expired_time": -1,
            "unlimited_quota": true,
            "model_limits_enabled": false,
            "model_limits": "",
            "allow_ips": "",
            "group": "default",
            "auto_groups": [],
            "cross_group_retry": false
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/api/token/"))
        .and(query_param("status_only", "true"))
        .and(body_json(json!({"id": 20, "status": 1})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {}
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/token/batch/keys"))
        .and(body_json(json!({"ids": [20]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"keys": {"20": "reconciled-key"}}
        })))
        .mount(&server)
        .await;
    let catalog = GroupCatalog {
        groups: vec![group("default", 1)],
        fetched_at: 1,
        response_sha256: "hash".to_owned(),
    };

    let sync = client
        .ensure_group_tokens(&catalog)
        .await
        .expect("reconcile token");

    assert_eq!((sync.created, sync.reused, sync.updated), (0, 1, 1));
    assert_eq!(
        sync.bindings[0].api_key().expose_secret(),
        "sk-reconciled-key"
    );
}

#[tokio::test]
async fn expired_access_token_refreshes_before_group_read() {
    let server = MockServer::start().await;
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
                    "data": login_data("expired-access", 1)
                })),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/user/auth/refresh"))
        .and(header("x-auth-session", "session-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": login_data("fresh-access", i64::MAX)
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/onboard/groups"))
        .and(header("authorization", "Bearer fresh-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"default": {
                "description": "Default", "ratio": 1, "topup_ratio": null,
                "user_selectable": true, "models": ["gpt-test"]
            }}
        })))
        .mount(&server)
        .await;
    let mut client = SourceClient::new(&server.uri()).expect("create source client");
    client.login(&credentials()).await.expect("login");

    let catalog = client.groups().await.expect("refresh and read groups");
    assert_eq!(catalog.groups.len(), 1);
}

#[tokio::test]
async fn status_key_is_created_once_and_plaintext_is_not_expected_on_reuse() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    let calls = Arc::new(AtomicUsize::new(0));
    #[derive(Clone)]
    struct StatusKeyLifecycleResponder {
        calls: Arc<AtomicUsize>,
    }
    impl Respond for StatusKeyLifecycleResponder {
        fn respond(&self, _: &Request) -> ResponseTemplate {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(200).set_body_json(json!({
                    "success": true,
                    "message": "",
                    "data": {
                        "key": "osk-created-once",
                        "created": true,
                        "id": 9,
                        "created_at": 100,
                        "last_used_at": 0,
                        "revoked_at": 0
                    }
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(json!({
                    "success": true,
                    "message": "",
                    "data": {
                        "created": false,
                        "id": 9,
                        "created_at": 100,
                        "last_used_at": 200,
                        "revoked_at": 0
                    }
                }))
            }
        }
    }
    Mock::given(method("POST"))
        .and(path("/api/onboard/status-key"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(StatusKeyLifecycleResponder { calls })
        .expect(2)
        .mount(&server)
        .await;
    let first = client
        .ensure_onboard_status_key()
        .await
        .expect("create status key");
    assert!(first.created);
    assert_eq!(
        first.key().expect("plaintext").expose_secret(),
        "osk-created-once"
    );

    let second = client
        .ensure_onboard_status_key()
        .await
        .expect("reuse status key");
    assert!(!second.created);
    assert!(second.key().is_none());
    assert_eq!(second.metadata.id, 9);

    Mock::given(method("DELETE"))
        .and(path("/api/onboard/status-key"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {
                "revoked": true,
                "id": 9,
                "created_at": 100,
                "last_used_at": 200,
                "revoked_at": 300
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let revoked = client
        .revoke_onboard_status_key()
        .await
        .expect("revoke status key");
    assert_eq!(revoked.revoked_at, 300);
}

#[tokio::test]
async fn status_client_reads_direct_manifest_snapshot_and_monitor_payloads() {
    let server = MockServer::start().await;
    let client = SourceClient::new(&server.uri()).expect("create source client");
    let status_key = SecretString::from("osk-status-secret");
    let manifest = json!({
        "success": true,
        "schema_version": "1",
        "page_name": "MeowAI",
        "page_slug": "default",
        "page_description": "status",
        "theme": "dark",
        "public": true,
        "generated_at": "2026-08-14T00:00:00Z",
        "monitors": [{
            "id": "7", "name": "GPT", "type": "http", "sort_order": 0,
            "group_id": "1", "group": "渠道状态", "interval": 900,
            "timeout": 10, "retries": 2, "notifications_enabled": false,
            "display_enabled": true
        }]
    });
    Mock::given(method("GET"))
        .and(path("/api/onboard/status/manifest"))
        .and(header("authorization", "Bearer osk-status-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(manifest))
        .mount(&server)
        .await;
    let result = client
        .onboard_status_manifest(&status_key)
        .await
        .expect("read manifest");
    assert_eq!(result.page_name, "MeowAI");
    assert_eq!(result.monitors[0].id, "7");
    assert_eq!(result.monitors[0].group, "渠道状态");
    assert_eq!(result.monitors[0].interval, 900);

    Mock::given(method("GET"))
        .and(path("/api/onboard/status/snapshot"))
        .and(header("authorization", "Bearer osk-status-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "schema_version": "1",
            "page": {"name":"MeowAI","slug":"default","description":"status","theme":"dark","public":true},
            "generated_at": "2026-08-14T00:00:00Z",
            "monitors": []
        })))
        .mount(&server)
        .await;
    let snapshot = client
        .onboard_status_snapshot(&status_key)
        .await
        .expect("read snapshot");
    assert_eq!(snapshot.page.slug, "default");

    Mock::given(method("GET"))
        .and(path("/api/onboard/status/monitors/7"))
        .and(header("authorization", "Bearer osk-status-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": false,
            "monitor_id": "7",
            "status": "down",
            "message": "failed",
            "checked_at": "2026-08-14T00:00:00Z"
        })))
        .mount(&server)
        .await;
    let monitor = client
        .onboard_status_monitor(&status_key, "7")
        .await
        .expect("read monitor");
    assert!(!monitor.success);
    assert_eq!(monitor.status, "down");
    assert!(
        client
            .onboard_status_monitor(&status_key, "7/secret")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn pricing_reads_all_authenticated_source_fields() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/onboard/pricing"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": pricing_data()
        })))
        .expect(1)
        .mount(&server)
        .await;

    let pricing = client.pricing().await.expect("read source pricing");
    let options = pricing.options().expect("build downstream options");
    assert_eq!(options.len(), 54);
    let home_pricing_table = options
        .iter()
        .find(|option| option.key == "home_setting.pricing_table")
        .expect("home pricing table option");
    let home_pricing_table: Value = serde_json::from_str(&home_pricing_table.canonical_json)
        .expect("decode home pricing table option");
    assert_eq!(home_pricing_table[0]["note"], json!("public pricing note"));
    assert_eq!(
        options
            .iter()
            .map(|option| option.source_field)
            .collect::<Vec<_>>(),
        [
            "model_price",
            "model_ratio",
            "cache_ratio",
            "create_cache_ratio",
            "completion_ratio",
            "image_ratio",
            "audio_ratio",
            "audio_completion_ratio",
            "billing_mode",
            "billing_expr",
            "billing_setting.billing_task_estimate",
            "billing_setting.billing_task_deposit",
            "tool_prices",
            "group_behavior.group_group_ratio",
            "group_behavior.group_special_usable_group",
            "group_behavior.auto_groups",
            "group_behavior.max_token_auto_groups",
            "group_behavior.default_use_auto_group",
            "quota_per_unit",
            "usd_exchange_rate",
            "price",
            "display_token_stat_enabled",
            "display_in_currency_enabled",
            "pre_consumed_quota",
            "general_setting.quota_display_type",
            "general_setting.custom_currency_symbol",
            "general_setting.custom_currency_exchange_rate",
            "quota_setting.enable_free_model_pre_consume",
            "home_pricing.table",
            "home_pricing.title",
            "home_pricing.description",
            "home_pricing.enabled",
            "video_setting.video_canonical_api_enabled",
            "video_setting.seedance_domestic_canonical_enabled",
            "video_setting.video_asset_affinity_enforced",
            "video_setting.seedance_completion_token_billing_enabled",
            "video_setting.video_playground_real_token_enabled",
            "marketplace.marketplace_enabled",
            "marketplace.provider_self_apply_enabled",
            "marketplace.official_groups_selectable_enabled",
            "marketplace.marketplace_commission_bps",
            "marketplace.marketplace_probe_interval_minutes",
            "marketplace.official_credential_recheck_enabled",
            "marketplace.official_credential_rate_limit_cooldown_seconds",
            "marketplace.official_credential_recheck_scan_interval_seconds",
            "marketplace.official_credential_health_recheck_interval_seconds",
            "marketplace.official_credential_grade_recheck_interval_seconds",
            "marketplace.official_credential_failed_recheck_interval_seconds",
            "marketplace.official_credential_recheck_batch_size",
            "marketplace.official_credential_recheck_lock_seconds",
            "marketplace.official_credential_supplier_recheck_min_interval_seconds",
            "marketplace.official_credential_supplier_recheck_daily_limit",
            "marketplace.official_credential_recheck_jitter_seconds",
            "marketplace.official_credential_availability_window_days"
        ]
    );
}

#[tokio::test]
async fn pricing_rejects_missing_or_invalid_source_fields() {
    let mut missing = pricing_data();
    missing
        .as_object_mut()
        .expect("pricing object")
        .remove("audio_completion_ratio");
    let mut invalid = pricing_data();
    invalid
        .as_object_mut()
        .expect("pricing object")
        .insert("model_price".to_owned(), json!({"": 1}));
    let mut missing_marketplace = pricing_data();
    missing_marketplace
        .as_object_mut()
        .expect("pricing object")
        .remove("marketplace");

    for data in [missing, invalid, missing_marketplace] {
        let server = MockServer::start().await;
        let mut client = authenticated_client(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/onboard/pricing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "message": "",
                "data": data
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = client
            .pricing()
            .await
            .expect_err("invalid pricing must be rejected");
        assert!(matches!(
            error,
            SourceError::InvalidResponse { ref endpoint, .. }
                if endpoint == "/api/onboard/pricing"
        ));
    }
}

fn group(name: &str, ratio: impl Into<Value>) -> SourceGroup {
    let ratio = ratio.into();
    SourceGroup {
        group_id: name.to_owned(),
        group_name: name.to_owned(),
        description: name.to_owned(),
        base_ratio: ratio.clone(),
        ratio,
        purchase_ratio: None,
        purchase_source: "unknown".to_owned(),
        topup_ratio: None,
        user_selectable: false,
        models: vec![format!("{name}-model")],
    }
}
