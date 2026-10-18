//! Exchange account OAuth tokens for credentials accepted by inference APIs.
//! The account token is never returned to the gateway as a model key.

use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde_json::{json, Value};

use super::config::{ClientCredentials, OAuthProviderConfig};
use super::error::OAuthError;
use super::http::{self, ExtraHeaders, Reply};
use super::secret::Secret;
use super::token::TokenSet;

fn exchange_error(provider: &str, reply: &Reply, account_token: &str) -> OAuthError {
    match reply.status {
        401 | 403 => OAuthError::ReauthRequired {
            provider: provider.into(), reason: "the account token was rejected by the inference credential endpoint".into(),
        },
        408 | 425 | 429 | 500..=599 => OAuthError::Transient(format!(
            "{provider} inference credential exchange returned HTTP {}", reply.status,
        )),
        status => {
            let (code, description) = http::error_fields(reply.body.as_ref(), &[account_token]);
            OAuthError::TokenEndpoint { status, code, description }
        }
    }
}

fn copilot_expiry(value: &Value) -> Option<DateTime<Utc>> {
    if let Some(seconds) = value.as_i64().or_else(|| value.as_str().and_then(|s| s.parse().ok())) {
        return DateTime::<Utc>::from_timestamp(seconds, 0);
    }
    value.as_str().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|dt| dt.with_timezone(&Utc))
}

pub fn copilot_token_needs_exchange(tokens: &TokenSet, now: DateTime<Utc>, lead_seconds: i64) -> bool {
    tokens.extra_value("copilot_token").is_none()
        || tokens.extra_value("copilot_expires_at")
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
            .is_none_or(|expiry| expiry <= now + Duration::seconds(lead_seconds))
}

pub async fn github_copilot_token(
    client: &Client,
    cfg: &OAuthProviderConfig,
    creds: &ClientCredentials,
    mut tokens: TokenSet,
) -> Result<TokenSet, OAuthError> {
    let url = cfg.exchange_endpoint(creds)?;
    let account_token = tokens.access_token.expose();
    let mut headers = ExtraHeaders(vec![
        ("Authorization".into(), format!("token {account_token}")),
    ]);
    headers.0.extend(crate::upstream::github_compat::CLIENT_HEADERS.iter()
        .map(|&(name, value)| (name.to_string(), value.to_string())));
    let reply = http::get_with(client, &cfg.id, &url, &headers).await?;
    if !(200..300).contains(&reply.status) {
        return Err(exchange_error(&cfg.id, &reply, account_token));
    }
    let body = reply.body.ok_or_else(|| OAuthError::InvalidResponse("Copilot token response is not JSON".into()))?;
    let copilot = body.get("token").and_then(Value::as_str).filter(|s| !s.is_empty())
        .ok_or_else(|| OAuthError::InvalidResponse("Copilot token response has no token".into()))?;
    let expires_at = body.get("expires_at").and_then(copilot_expiry)
        .unwrap_or_else(|| Utc::now() + Duration::minutes(30));
    if expires_at <= Utc::now() {
        return Err(OAuthError::InvalidResponse("Copilot token has already expired".into()));
    }
    tokens.extra.insert("copilot_token".into(), Secret::new(copilot));
    tokens.extra.insert("copilot_expires_at".into(), Secret::new(expires_at.timestamp().to_string()));
    Ok(tokens)
}

pub async fn muse_model_key(
    client: &Client,
    cfg: &OAuthProviderConfig,
    creds: &ClientCredentials,
    mut tokens: TokenSet,
) -> Result<TokenSet, OAuthError> {
    let url = cfg.exchange_endpoint(creds)?;
    let account_token = tokens.extra_value("muse_oauth_token").unwrap_or_else(|| tokens.access_token.expose()).to_owned();
    let headers = ExtraHeaders(vec![
        ("Authorization".into(), format!("Bearer {account_token}")),
        ("x-api-version".into(), "1.0.0".into()),
    ]);
    let mut reply = http::post_json_with(client, &cfg.id, &url, &json!({"onboard": true}), &headers).await?;
    for attempt in 0..2 {
        if !matches!(reply.status, 429 | 500..=599) { break; }
        tokio::time::sleep(std::time::Duration::from_secs(5 * (attempt + 1))).await;
        reply = http::post_json_with(client, &cfg.id, &url, &json!({"onboard": true}), &headers).await?;
    }
    if !(200..300).contains(&reply.status) {
        return Err(exchange_error(&cfg.id, &reply, &account_token));
    }
    let body = reply.body.ok_or_else(|| OAuthError::InvalidResponse("Muse Model API key response is not JSON".into()))?;
    if body.get("is_subs_active").and_then(Value::as_bool) == Some(false) {
        return Err(OAuthError::TokenEndpoint { status: 403, code: "subscription_inactive".into(), description: None });
    }
    let model_key = body.get("api_key").and_then(Value::as_str).filter(|s| !s.is_empty());
    if model_key.is_none() && body.get("require_payment").and_then(Value::as_bool) == Some(true) {
        return Err(OAuthError::TokenEndpoint { status: 402, code: "payment_required".into(), description: None });
    }
    let model_key = model_key.ok_or_else(|| OAuthError::InvalidResponse("Muse Model API key response has no api_key".into()))?;
    tokens.extra.insert("muse_oauth_token".into(), Secret::new(account_token));
    tokens.access_token = Secret::new(model_key);
    tokens.refresh_token = None;
    tokens.expires_at = None;
    Ok(tokens)
}
