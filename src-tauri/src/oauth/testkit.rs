//! 测试公用：本机假授权服务器（authorize / token / device）+ 以真实凭据库实现（内存凭据库）搭好的 OAuthHub。
//! 仅在测试编译；真实 HTTP，走 127.0.0.1 随机端口。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use tokio::net::{TcpListener, TcpStream};

use super::hub::{HubLimits, OAuthHub, PollResult};
use super::pkce::challenge_for;
use super::service::{OAuthService, OAuthTuning};
use super::OAuthCatalog;
use crate::security::vault::MemoryVault;
use crate::security::{CredentialVault, VaultClientCredentials, VaultTokenStore};
use crate::store;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum RefreshMode {
    #[default]
    Rotate,
    InvalidGrant,
    ServerError,
}

#[derive(Default)]
pub struct Fake {
    pub refresh_mode: Mutex<RefreshMode>,
    pub refresh_count: AtomicUsize,
    pub exchange_count: AtomicUsize,
    pub copilot_count: AtomicUsize,
    pub muse_key_count: AtomicUsize,
    code_counter: AtomicUsize,
    device_counter: AtomicUsize,
    challenges: Mutex<HashMap<String, Option<String>>>,
    pub device_approved: AtomicBool,
    /// state-poll：已发放的 state 集合；state_approved 置位后返回令牌。
    pub states: Mutex<std::collections::HashSet<String>>,
    pub state_approved: AtomicBool,
    state_counter: AtomicUsize,
    state_token_counter: AtomicUsize,
    /// 最近一次 state 请求带的 platform 查询参数（测试断言用）。
    pub last_platform: Mutex<Option<String>>,
    /// 授权码 / 设备码换令牌时附带的 id_token（用于账户标识）。
    pub id_token: Mutex<Option<String>>,
    /// 令牌端点要求的 client_secret（None = 不校验）。
    pub expect_secret: Mutex<Option<String>>,
}

fn json_reply(status: u16, body: Value) -> Response {
    (StatusCode::from_u16(status).unwrap(), Json(body)).into_response()
}

/// state 端点：POST ?platform=… 返回 { code: 0, data: { state, authUrl } }。
async fn state_endpoint(State(f): State<Arc<Fake>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let n = f.state_counter.fetch_add(1, Ordering::SeqCst);
    let state = format!("STATE-{n}");
    f.states.lock().unwrap().insert(state.clone());
    // 记录 platform，供测试断言查询参数确实带上了。
    *f.last_platform.lock().unwrap() = q.get("platform").cloned();
    json_reply(200, json!({"code": 0, "data": {"state": state, "authUrl": "https://example.com/mock-auth"}}))
}

/// state 轮询：GET ?state=… → 0 表示成功，11217 表示仍在登录。
async fn state_token(State(f): State<Arc<Fake>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some(state) = q.get("state") else {
        return json_reply(200, json!({"code": -1, "msg": "missing state"}));
    };
    if !f.states.lock().unwrap().contains(state) {
        return json_reply(200, json!({"code": -1, "msg": "unknown state"}));
    }
    if !f.state_approved.load(Ordering::SeqCst) {
        return json_reply(200, json!({"code": 11217, "msg": "waiting for login"}));
    }
    let n = f.state_token_counter.fetch_add(1, Ordering::SeqCst);
    json_reply(
        200,
        json!({"code": 0, "data": {"accessToken": format!("ACCESS-STATE-{n}"), "refreshToken": format!("REFRESH-STATE-{n}"), "expiresIn": 3600}}),
    )
}

async fn authorize(State(f): State<Arc<Fake>>, Query(q): Query<HashMap<String, String>>) -> Response {
    let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
    let state = q.get("state").cloned().unwrap_or_default();
    let mut target = url::Url::parse(&redirect_uri).expect("redirect_uri is a URL");
    let code = format!("AUTHCODE-{}", f.code_counter.fetch_add(1, Ordering::SeqCst));
    f.challenges.lock().unwrap().insert(code.clone(), q.get("code_challenge").cloned());
    target.query_pairs_mut().append_pair("code", &code).append_pair("state", &state);
    Redirect::to(target.as_str()).into_response()
}

fn tokens_body(f: &Fake, access: String, refresh: String) -> Value {
    let mut body = json!({"access_token": access, "refresh_token": refresh, "expires_in": 3600, "scope": "a b", "token_type": "Bearer"});
    if let Some(id_token) = f.id_token.lock().unwrap().clone() {
        body["id_token"] = json!(id_token);
    }
    body
}

async fn token(State(f): State<Arc<Fake>>, body: Bytes) -> Response {
    let fields: HashMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    if let Some(expected) = f.expect_secret.lock().unwrap().clone() {
        if fields.get("client_secret") != Some(&expected) {
            return json_reply(401, json!({"error": "invalid_client"}));
        }
    }
    match fields.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let n = f.exchange_count.fetch_add(1, Ordering::SeqCst);
            let code = fields.get("code").cloned().unwrap_or_default();
            let Some(challenge) = f.challenges.lock().unwrap().remove(&code) else {
                return json_reply(400, json!({"error": "invalid_grant"}));
            };
            if let Some(challenge) = challenge {
                let verifier = fields.get("code_verifier").cloned().unwrap_or_default();
                if challenge_for(&verifier) != challenge {
                    return json_reply(400, json!({"error": "invalid_grant"}));
                }
            }
            json_reply(200, tokens_body(&f, format!("ACCESS-AUTH-{n}"), format!("REFRESH-AUTH-{n}")))
        }
        Some("refresh_token") => {
            let n = f.refresh_count.fetch_add(1, Ordering::SeqCst) + 1;
            match *f.refresh_mode.lock().unwrap() {
                RefreshMode::InvalidGrant => json_reply(400, json!({"error": "invalid_grant"})),
                RefreshMode::ServerError => json_reply(503, json!({"error": "temporarily_unavailable"})),
                RefreshMode::Rotate => json_reply(
                    200,
                    json!({"access_token": format!("ACCESS-REFRESH-{n}"), "refresh_token": format!("REFRESH-ROT-{n}"), "expires_in": 3600}),
                ),
            }
        }
        _ => json_reply(400, json!({"error": "unsupported_grant_type"})),
    }
}

async fn device_code() -> Response {
    json_reply(
        200,
        json!({"device_code": "DEVICE-SECRET-1", "user_code": "WDJB-MJHT",
               "verification_uri": "https://verify.example/device", "expires_in": 600, "interval": 1}),
    )
}

async fn device_token(State(f): State<Arc<Fake>>) -> Response {
    if !f.device_approved.load(Ordering::SeqCst) {
        return json_reply(400, json!({"error": "authorization_pending"}));
    }    let n = f.device_counter.fetch_add(1, Ordering::SeqCst);
    json_reply(200, tokens_body(&f, format!("ACCESS-DEV-{n}"), format!("REFRESH-DEV-{n}")))
}

async fn copilot_token(State(f): State<Arc<Fake>>, headers: HeaderMap) -> Response {
    for &(name, value) in crate::upstream::github_compat::CLIENT_HEADERS {
        if headers.get(name).and_then(|v| v.to_str().ok()) != Some(value) {
            return json_reply(400, json!({"error":"missing IDE client header"}));
        }
    }
    if !headers.get("authorization").and_then(|v| v.to_str().ok())
        .is_some_and(|value| value.starts_with("token ACCESS-")) {
        return json_reply(401, json!({"error":"unauthorized"}));
    }
    let n = f.copilot_count.fetch_add(1, Ordering::SeqCst) + 1;
    json_reply(200, json!({"token":format!("COPILOT-KEY-{n}"), "expires_at":chrono::Utc::now().timestamp()+3600}))
}

async fn muse_key(State(f): State<Arc<Fake>>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    if !headers.get("authorization").and_then(|v| v.to_str().ok())
        .is_some_and(|value| value.starts_with("Bearer ACCESS-"))
        || body.get("onboard").and_then(Value::as_bool) != Some(true) {
        return json_reply(401, json!({"error":"unauthorized"}));
    }
    let n = f.muse_key_count.fetch_add(1, Ordering::SeqCst) + 1;
    json_reply(200, json!({"api_key":format!("LLM|MUSE-KEY-{n}"), "is_subs_active":true}))
}

/// 测试用目录：每个端点都指向假服务器（http 回环是允许的）。
pub fn catalog_json(base: &str) -> String {
    let code = |id: &str| {
        json!({
            "id": id, "flow": "authorization-code",
            "authorizeUrl": format!("{base}/authorize"), "tokenUrl": format!("{base}/token"),
            "refreshUrl": format!("{base}/token"), "clientId": "cid", "scopes": ["a", "b"], "pkce": true,
            "redirect": {"host": "127.0.0.1", "path": "/cb"}, "refreshLeadSeconds": 300,
            "riskNotice": "risk text"
        })
    };
    let device = |id: &str| {
        json!({
            "id": id, "flow": "device",
            "deviceCodeUrl": format!("{base}/device/code"), "tokenUrl": format!("{base}/device/token"),
            "refreshUrl": format!("{base}/token"), "clientId": "dcid", "scopes": ["x"], "pkce": false
        })
    };
    let state_poll = |id: &str| {
        json!({
            "id": id, "flow": "state-poll",
            "stateUrl": format!("{base}/state"), "tokenUrl": format!("{base}/state/token"),
            "refreshUrl": format!("{base}/token"), "noClientId": true,
            "statePollPlatform": "CLI", "statePollIntervalMs": 20, "scopes": []
        })
    };
    let mut secret = code("t-secret");
    secret["clientId"] = Value::Null;
    secret["requiresClientSecret"] = json!(true);
    let mut hosted = code("t-hosted");
    hosted["clientId"] = Value::Null;
    hosted["baseUrlDefault"] = json!("https://git.example.com");
    let mut github = device("github");
    github["exchangeUrl"] = json!(format!("{base}/copilot/token"));
    let mut muse = device("muse");
    muse["exchangeUrl"] = json!(format!("{base}/muse/key"));
    let custom = json!({"id": "t-custom", "flow": "custom", "custom": {"reason": "proprietary protocol", "requires": ["official API"]}});
    json!({"schemaVersion": 1, "providers": [
        code("t-code"), code("t-code2"), device("t-device"), device("t-device2"), secret, hosted, custom,
        github, muse, state_poll("t-state")
    ]})
    .to_string()
}

pub fn fast_tuning() -> OAuthTuning {
    OAuthTuning {
        callback_timeout: Duration::from_secs(20),
        http_timeout: Duration::from_secs(10),
        device_interval_override: Some(Duration::from_millis(20)),
        slow_down_step: Duration::from_millis(50),
    }
}

pub const PROVIDER_IDS: [&str; 10] =
    ["t-code", "t-code2", "t-device", "t-device2", "t-secret", "t-hosted", "t-custom", "github", "muse", "t-state"];

pub struct Env {
    pub base: String,
    pub fake: Arc<Fake>,
    pub db: SqlitePool,
    /// 令牌与客户端凭据都存在这里（与生产一样经 VaultTokenStore / VaultClientCredentials）。
    pub vault: Arc<MemoryVault>,
    pub service: Arc<OAuthService>,
    pub hub: OAuthHub,
}

pub async fn env() -> Env {
    env_with(fast_tuning(), HubLimits::default()).await
}

pub async fn env_with(tuning: OAuthTuning, limits: HubLimits) -> Env {
    let fake = Arc::new(Fake::default());
    let app = Router::new()
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/device/code", post(device_code))
        .route("/device/token", post(device_token))
        .route("/copilot/token", get(copilot_token))
        .route("/muse/key", post(muse_key))
        .route("/state", post(state_endpoint))
        .route("/state/token", get(state_token))
        .with_state(fake.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let db = store::open_memory().await.unwrap();
    for id in PROVIDER_IDS {
        sqlx::query(
            "INSERT INTO providers (id, kind, display_name, grp, created_at, updated_at) VALUES (?1, 'builtin', ?2, 'oauth', 't', 't')",
        )
        .bind(id)
        .bind(format!("Provider {id}"))
        .execute(&db)
        .await
        .unwrap();
    }

    let vault = Arc::new(MemoryVault::default());
    let dyn_vault: Arc<dyn CredentialVault> = vault.clone();
    let clients = Arc::new(VaultClientCredentials::new(dyn_vault.clone()));
    let tokens = Arc::new(VaultTokenStore::new(dyn_vault));
    let catalog = OAuthCatalog::from_json(&catalog_json(&base)).expect("test catalog is valid");
    let service = Arc::new(OAuthService::new(catalog, clients.clone(), tokens, tuning).unwrap());
    let hub = OAuthHub::with_limits(service.clone(), clients.clone(), db.clone(), limits);
    Env { base, fake, db, vault, service, hub }
}

/// 模拟浏览器：访问授权地址，跟随重定向到回环回调。返回最终状态码。
pub async fn browse(authorize_url: &str) -> u16 {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    client.get(authorize_url).send().await.unwrap().status().as_u16()
}

/// 授权地址里 redirect_uri 的回调端口。
pub fn callback_port(authorize_url: &str) -> u16 {
    let url = url::Url::parse(authorize_url).unwrap();
    let redirect = url.query_pairs().find(|(k, _)| k == "redirect_uri").map(|(_, v)| v.into_owned()).unwrap();
    url::Url::parse(&redirect).unwrap().port().unwrap()
}

pub async fn port_is_closed(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).await.is_err()
}

pub async fn port_is_open(port: u16) -> bool {
    TcpStream::connect(("127.0.0.1", port)).await.is_ok()
}

/// 轮询到离开 Pending（最多 10 秒）。
pub async fn wait_done(hub: &OAuthHub, session_id: &str) -> PollResult {
    for _ in 0..500 {
        let r = hub.poll(session_id);
        if r != PollResult::Pending {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("session did not finish in time");
}

/// 一个未编码的 JWT（只有 payload 有意义），用于 id_token 邮箱。
pub fn fake_jwt_with_email(email: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    format!(
        "{}.{}.sig",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(json!({"email": email}).to_string())
    )
}
