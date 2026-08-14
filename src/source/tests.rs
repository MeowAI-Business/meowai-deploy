use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

use super::{
    SourceAccountMode, SourceClient, SourceCredentials, SourceError, SourceGroup,
    groups::GroupCatalog,
};

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
        .and(path("/api/user/self/groups"))
        .and(header("authorization", "Bearer access-one"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {
                "vip": {"desc": "VIP", "ratio": 1.5},
                "auto": {"desc": "Auto", "ratio": "自动"},
                "default": {"desc": "Default", "ratio": 1}
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
    assert_eq!(names, ["auto", "default", "vip"]);
    assert_eq!(first.response_sha256, second.response_sha256);
    assert_eq!(first.groups, second.groups);
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
    let default_name = "meowai-deploy/site_123/default";
    let vip_name = "meowai-deploy/site_123/vip";
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
        .ensure_group_tokens("site_123", &catalog)
        .await
        .expect("create missing token");
    let second = client
        .ensure_group_tokens("site_123", &catalog)
        .await
        .expect("reuse all tokens");

    assert_eq!((first.created, first.reused, first.updated), (1, 1, 0));
    assert_eq!((second.created, second.reused, second.updated), (0, 2, 0));
    assert_eq!(first.bindings[1].api_key().expose_secret(), "sk-vip-key");
    assert_eq!(list_calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn owned_token_drift_is_reconciled_before_key_reuse() {
    let server = MockServer::start().await;
    let mut client = authenticated_client(&server).await;
    let token_name = "meowai-deploy/site_123/default";
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
        .ensure_group_tokens("site_123", &catalog)
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
        .and(path("/api/user/self/groups"))
        .and(header("authorization", "Bearer fresh-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "message": "",
            "data": {"default": {"desc": "Default", "ratio": 1}}
        })))
        .mount(&server)
        .await;
    let mut client = SourceClient::new(&server.uri()).expect("create source client");
    client.login(&credentials()).await.expect("login");

    let catalog = client.groups().await.expect("refresh and read groups");
    assert_eq!(catalog.groups.len(), 1);
}

fn group(name: &str, ratio: impl Into<Value>) -> SourceGroup {
    SourceGroup {
        group_id: name.to_owned(),
        group_name: name.to_owned(),
        description: name.to_owned(),
        ratio: ratio.into(),
    }
}
