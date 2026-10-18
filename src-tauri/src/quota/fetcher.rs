//! 上游配额与余额抓取器。
//!
//! 参考 9Router (`open-sse/services/usage/`) 的真实请求协议，针对不同提供商抓取其活跃额度周期与余额。

use chrono::DateTime;
use reqwest::Client;
use crate::proxy::http::RoutedRequest;
use std::time::Duration;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::store::quota::SnapshotRow;

/// 将各种格式的时间（秒级时间戳、毫秒级时间戳、ISO-8601 字符串）解析为标准的 ISO-8601 字符串
pub fn parse_reset_time_val(val: Option<&Value>) -> Option<String> {
    let v = val?;
    if let Some(s) = v.as_str() {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        if let Ok(ts) = s.parse::<i64>() {
            return timestamp_to_iso(ts);
        }
        if s.contains('T') || s.contains('-') {
            return Some(s.to_string());
        }
    }
    if let Some(n) = v.as_i64() {
        return timestamp_to_iso(n);
    }
    if let Some(n) = v.as_f64() {
        return timestamp_to_iso(n as i64);
    }
    None
}

fn timestamp_to_iso(ts: i64) -> Option<String> {
    if ts <= 0 {
        return None;
    }
    let dt = if ts < 100_000_000_000 {
        DateTime::from_timestamp(ts, 0)
    } else {
        DateTime::from_timestamp_millis(ts)
    };
    dt.map(|d| d.to_rfc3339())
}

pub fn to_finite_f64(val: Option<&Value>) -> Option<f64> {
    let v = val?;
    if let Some(n) = v.as_f64() {
        if n.is_finite() {
            return Some(n);
        }
    }
    if let Some(s) = v.as_str() {
        if let Ok(n) = s.trim().parse::<f64>() {
            if n.is_finite() {
                return Some(n);
            }
        }
    }
    None
}

/// 为指定的连接从上游抓取配额与余额快照列表
pub async fn fetch_quota_from_upstream(
    client: &Client,
    provider_id: &str,
    credential: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    match provider_id {
        "deepseek" => fetch_deepseek(client, credential, connection_id, checked_at).await,
        "claude" => fetch_claude(client, credential, connection_id, checked_at).await,
        "codex" => fetch_codex(client, credential, connection_id, checked_at).await,
        "github" => fetch_github(client, credential, connection_id, checked_at).await,
        "codebuddy-cn" | "codebuddy-intl" => {
            fetch_codebuddy(client, provider_id, credential, connection_id, checked_at).await
        }
        "antigravity" => fetch_antigravity(client, credential, connection_id, checked_at).await,
        "gemini-cli" => fetch_gemini_cli(client, credential, connection_id, checked_at).await,
        "kimi" => fetch_kimi(client, credential, connection_id, checked_at).await,
        "glm" | "glm-cn" => fetch_glm(client, provider_id, credential, connection_id, checked_at).await,
        "grok-cli" => fetch_grok_cli(client, credential, connection_id, checked_at).await,
        "minimax" | "minimax-cn" => {
            fetch_minimax(client, provider_id, credential, connection_id, checked_at).await
        }
        "groq" => fetch_groq(client, credential, connection_id, checked_at).await,
        "openrouter" => fetch_openrouter(client, credential, connection_id, checked_at).await,
        "vercel-ai-gateway" => fetch_vercel(client, credential, connection_id, checked_at).await,
        "ollama" => fetch_ollama(client, credential, connection_id, checked_at).await,
        "kiro" => fetch_kiro(client, credential, connection_id, checked_at).await,
        "qoder" | "qoder-cn" => fetch_qoder(client, provider_id, credential, connection_id, checked_at).await,
        "commandcode" => fetch_commandcode(client, credential, connection_id, checked_at).await,
        "opencode-go" | "opencode-zen" => {
            fetch_opencode(client, provider_id, credential, connection_id, checked_at).await
        }
        "zed" => fetch_zed(client, credential, connection_id, checked_at).await,
        _ => fetch_generic_openai_compatible(client, provider_id, credential, connection_id, checked_at).await,
    }
}

// ──────────────────────── 各提供商专用抓取逻辑 ────────────────────────

async fn fetch_deepseek(
    client: &Client,
    key: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://api.deepseek.com/user/balance")
        .bearer_auth(key)
        .header("User-Agent", crate::upstream::client::user_agent())
        .send_routed("deepseek", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("DeepSeek 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("DeepSeek 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    if let Some(list) = body.get("balance_infos").and_then(|v| v.as_array()) {
        for item in list {
            let currency = item.get("currency").and_then(|v| v.as_str()).unwrap_or("").to_uppercase();
            if currency.is_empty() {
                continue;
            }
            let total = to_finite_f64(item.get("total_balance")).or_else(|| to_finite_f64(item.get("totalBalance"))).unwrap_or(0.0);
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "balance".into(),
                quota_name: currency.clone(),
                unit: currency,
                used: None,
                total: None,
                remaining: Some(total),
                resets_at: None,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_claude(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://api.anthropic.com/api/oauth/usage?cedar_ember=1")
        .bearer_auth(token)
        .header("anthropic-beta", "oauth-2025-04-20")
        .header("anthropic-version", "2023-06-01")
        .header("User-Agent", "claude-cli/2.1.280 (external, cli)")
        .send_routed("claude", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Claude 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Claude 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();

    let parse_win = |win: &Value, name: &str| -> Option<SnapshotRow> {
        let used = win.get("utilization").and_then(|v| v.as_f64())?;
        let remaining = (100.0 - used).max(0.0);
        let resets_at = parse_reset_time_val(win.get("resets_at"));
        Some(SnapshotRow {
            connection_id: connection_id.into(),
            kind: "period".into(),
            quota_name: name.into(),
            unit: "%".into(),
            used: Some(used),
            total: Some(100.0),
            remaining: Some(remaining),
            resets_at,
            checked_at: checked_at.into(),
            source: "live".into(),
            error: None,
        })
    };

    if let Some(w) = body.get("five_hour") {
        if let Some(r) = parse_win(w, "5h") {
            rows.push(r);
        }
    }
    if let Some(w) = body.get("seven_day") {
        if let Some(r) = parse_win(w, "Weekly") {
            rows.push(r);
        }
    }
    if let Some(obj) = body.as_object() {
        for (k, v) in obj {
            if k.starts_with("seven_day_") && k != "seven_day" {
                let model = k.strip_prefix("seven_day_").unwrap_or(k);
                if let Some(r) = parse_win(v, &format!("Weekly ({model})")) {
                    rows.push(r);
                }
            }
        }
    }
    Ok(rows)
}

async fn fetch_codex(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://chatgpt.com/backend-api/wham/usage")
        .bearer_auth(token)
        .header("User-Agent", crate::upstream::client::user_agent())
        .send_routed("codex", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Codex 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Codex 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    let rl = body.get("rate_limit").unwrap_or(&body);

    let parse_win = |win: &Value, name: &str| -> Option<SnapshotRow> {
        let used = to_finite_f64(win.get("used_percent")).or_else(|| to_finite_f64(win.get("percent_used")))?;
        let remaining = (100.0 - used).max(0.0);
        let resets_at = parse_reset_time_val(win.get("reset_at").or_else(|| win.get("resets_at")));
        Some(SnapshotRow {
            connection_id: connection_id.into(),
            kind: "period".into(),
            quota_name: name.into(),
            unit: "%".into(),
            used: Some(used),
            total: Some(100.0),
            remaining: Some(remaining),
            resets_at,
            checked_at: checked_at.into(),
            source: "live".into(),
            error: None,
        })
    };

    if let Some(p) = rl.get("primary_window").or_else(|| rl.get("primary")) {
        if let Some(r) = parse_win(p, "5h") {
            rows.push(r);
        }
    }
    if let Some(s) = rl.get("secondary_window").or_else(|| rl.get("secondary")) {
        if let Some(r) = parse_win(s, "Weekly") {
            rows.push(r);
        }
    }
    Ok(rows)
}

async fn fetch_github(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://api.github.com/copilot_internal/user")
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/json")
        .headers(crate::upstream::github_compat::headers())
        .send_routed("github", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("GitHub Copilot 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("GitHub Copilot 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    let reset_at = parse_reset_time_val(body.get("quota_reset_date").or_else(|| body.get("limited_user_reset_date")));

    if let Some(snaps) = body.get("quota_snapshots").and_then(|v| v.as_object()) {
        for (k, v) in snaps {
            let ent = to_finite_f64(v.get("entitlement")).unwrap_or(0.0);
            let rem = to_finite_f64(v.get("remaining")).unwrap_or(0.0);
            let used = (ent - rem).max(0.0);
            let label = match k.as_str() {
                "chat" => "Monthly",
                "completions" => "Completions",
                "premium_interactions" => "Premium Requests",
                other => other,
            };
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: label.into(),
                unit: "requests".into(),
                used: Some(used),
                total: Some(ent),
                remaining: Some(rem),
                resets_at: reset_at.clone(),
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    } else if let Some(monthly) = body.get("monthly_quotas").and_then(|v| v.as_object()) {
        let used_map = body.get("limited_user_quotas").and_then(|v| v.as_object());
        for (k, v) in monthly {
            let total = to_finite_f64(Some(v)).unwrap_or(0.0);
            let used = used_map.and_then(|m| m.get(k)).and_then(|x| to_finite_f64(Some(x))).unwrap_or(0.0);
            let rem = (total - used).max(0.0);
            let label = match k.as_str() {
                "chat" => "Monthly",
                other => other,
            };
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: label.into(),
                unit: "requests".into(),
                used: Some(used),
                total: Some(total),
                remaining: Some(rem),
                resets_at: reset_at.clone(),
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_codebuddy(
    client: &Client,
    provider_id: &str,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let (url, domain, ua) = if provider_id == "codebuddy-intl" {
        ("https://www.codebuddy.ai/v2/billing/meter/get-user-resource", "www.codebuddy.ai", "IDE/2.63.2 CodeBuddy/2.63.2")
    } else {
        ("https://copilot.tencent.com/v2/billing/meter/get-user-resource", "copilot.tencent.com", "CLI/2.63.2 CodeBuddy/2.63.2")
    };

    let resp = client
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header("X-Domain", domain)
        .header("X-Product", "SaaS")
        .header("X-Requested-With", "XMLHttpRequest")
        .header("User-Agent", ua)
        .body("{}")
        .send_routed(provider_id, Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("CodeBuddy 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("CodeBuddy 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    let accounts = body.pointer("/data/Response/Data/Accounts").and_then(|v| v.as_array());

    if let Some(list) = accounts {
        let mut bonus_idx = 1;
        for acc in list {
            let cycle_end = parse_reset_time_val(acc.get("CycleEndTime"));
            let used_precise = to_finite_f64(acc.get("CycleCapacityUsedPrecise"))
                .or_else(|| to_finite_f64(acc.get("CycleCapacityUsed")))
                .unwrap_or(0.0);
            let total_precise = to_finite_f64(acc.get("CycleCapacitySizePrecise"))
                .or_else(|| to_finite_f64(acc.get("CycleCapacitySize")))
                .unwrap_or(0.0);

            let ded_end = to_finite_f64(acc.get("DeductionEndTime")).unwrap_or(0.0);
            let cyc_end = to_finite_f64(acc.get("CycleEndTime")).unwrap_or(0.0);
            let is_refill = (ded_end - cyc_end) > 172800.0;

            if is_refill {
                rows.push(SnapshotRow {
                    connection_id: connection_id.into(),
                    kind: "period".into(),
                    quota_name: "Monthly".into(),
                    unit: "credits".into(),
                    used: Some(used_precise),
                    total: Some(total_precise),
                    remaining: Some((total_precise - used_precise).max(0.0)),
                    resets_at: cycle_end,
                    checked_at: checked_at.into(),
                    source: "live".into(),
                    error: None,
                });
            } else {
                let bonus_used = to_finite_f64(acc.get("CapacityUsedPrecise"))
                    .or_else(|| to_finite_f64(acc.get("CapacityUsed")))
                    .unwrap_or(0.0);
                let bonus_total = to_finite_f64(acc.get("CapacitySizePrecise"))
                    .or_else(|| to_finite_f64(acc.get("CapacitySize")))
                    .unwrap_or(0.0);
                rows.push(SnapshotRow {
                    connection_id: connection_id.into(),
                    kind: "period".into(),
                    quota_name: format!("Bonus Pack {bonus_idx}"),
                    unit: "credits".into(),
                    used: Some(bonus_used),
                    total: Some(bonus_total),
                    remaining: Some((bonus_total - bonus_used).max(0.0)),
                    resets_at: cycle_end,
                    checked_at: checked_at.into(),
                    source: "live".into(),
                    error: None,
                });
                bonus_idx += 1;
            }
        }
    }
    Ok(rows)
}

async fn fetch_antigravity(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    // 1. 先通过 loadCodeAssist 获取项目名与用户层级信息（完全对齐 9Router）
    let mut project = None;
    let load_body = serde_json::json!({
        "metadata": {
            "ideType": 9,
            "platform": 2,
            "pluginType": 2
        },
        "mode": 1
    });
    let load_resp = client
        .post("https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist")
        .bearer_auth(token)
        .header("User-Agent", "antigravity/1.107.0 darwin/arm64")
        .header("Content-Type", "application/json")
        .header("x-request-source", "local")
        .json(&load_body)
        .send_routed("antigravity", Duration::from_secs(12))
        .await;

    if let Ok(resp) = load_resp {
        if resp.status().is_success() {
            if let Ok(v) = resp.json::<Value>().await {
                if let Some(p) = v.get("cloudaicompanionProject").and_then(|s| s.as_str()) {
                    project = Some(p.to_string());
                }
            }
        }
    }

    // 2. 调用 fetchAvailableModels 获取各模型的配额比例与重置时间（完全对齐 9Router）
    let mut req_body = serde_json::Map::new();
    if let Some(p) = project {
        req_body.insert("project".to_string(), Value::String(p));
    }
    let models_resp = client
        .post("https://cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels")
        .bearer_auth(token)
        .header("User-Agent", "antigravity/1.107.0 darwin/arm64")
        .header("Content-Type", "application/json")
        .header("X-Client-Name", "antigravity")
        .header("X-Client-Version", "1.107.0")
        .header("x-request-source", "local")
        .json(&Value::Object(req_body))
        .send_routed("antigravity", Duration::from_secs(12))
        .await;

    let mut rows = Vec::new();
    if let Ok(resp) = models_resp {
        if resp.status().is_success() {
            if let Ok(body) = resp.json::<Value>().await {
                if let Some(models) = body.get("models").and_then(|m| m.as_object()) {
                    for (model_key, model_val) in models {
                        if model_val.get("isInternal").and_then(|v| v.as_bool()).unwrap_or(false) {
                            continue;
                        }
                        if let Some(qi) = model_val.get("quotaInfo").and_then(|v| v.as_object()) {
                            let fraction = to_finite_f64(qi.get("remainingFraction")).unwrap_or(1.0);
                            let remaining = (1000.0 * fraction).round();
                            let used = (1000.0 - remaining).max(0.0);
                            let resets_at = parse_reset_time_val(qi.get("resetTime").or_else(|| qi.get("resets_at")));
                            let display_name = model_val
                                .get("displayName")
                                .and_then(|s| s.as_str())
                                .unwrap_or(model_key);

                            rows.push(SnapshotRow {
                                connection_id: connection_id.into(),
                                kind: "period".into(),
                                quota_name: display_name.into(),
                                unit: "".into(),
                                used: Some(used),
                                total: Some(1000.0),
                                remaining: Some(remaining),
                                resets_at,
                                checked_at: checked_at.into(),
                                source: "live".into(),
                                error: None,
                            });
                        }
                    }
                }
            }
        }
    }

    if !rows.is_empty() {
        return Ok(rows);
    }

    // 备用兜底：retrieveUserQuotaSummary
    let resp = client
        .post("https://daily-cloudcode-pa.googleapis.com/v1internal:retrieveUserQuotaSummary")
        .bearer_auth(token)
        .header("User-Agent", "antigravity/ide/2.11.0 darwin/arm64")
        .header("Content-Type", "application/json")
        .header("X-Client-Name", "antigravity")
        .header("X-Client-Version", "2.11.0")
        .body("{}")
        .send_routed("antigravity", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Antigravity 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Antigravity 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;

    if let Some(buckets) = body.get("buckets").or_else(|| body.get("models")).and_then(|v| v.as_array()) {
        for b in buckets {
            let model_id = b.get("modelId").or_else(|| b.get("name")).and_then(|v| v.as_str()).unwrap_or("");
            if model_id.is_empty() {
                continue;
            }
            let fraction = to_finite_f64(b.get("remainingFraction")).unwrap_or(1.0);
            let total = 1000.0;
            let remaining = (total * fraction).round();
            let used = (total - remaining).max(0.0);
            let resets_at = parse_reset_time_val(b.get("resetTime").or_else(|| b.get("resets_at")));
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: model_id.into(),
                unit: "".into(),
                used: Some(used),
                total: Some(total),
                remaining: Some(remaining),
                resets_at,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_gemini_cli(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .post("https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota")
        .header("Authorization", format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .body("{}")
        .send_routed("gemini-cli", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Gemini CLI 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Gemini CLI 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();

    if let Some(buckets) = body.get("buckets").and_then(|v| v.as_array()) {
        for b in buckets {
            let model_id = b.get("modelId").and_then(|v| v.as_str()).unwrap_or("");
            if model_id.is_empty() {
                continue;
            }
            let fraction = to_finite_f64(b.get("remainingFraction")).unwrap_or(1.0);
            let total = 1000.0;
            let remaining = (total * fraction).round();
            let used = (total - remaining).max(0.0);
            let resets_at = parse_reset_time_val(b.get("resetTime"));
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: model_id.into(),
                unit: "".into(),
                used: Some(used),
                total: Some(total),
                remaining: Some(remaining),
                resets_at,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_kimi(
    client: &Client,
    key_or_token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let mut req = client.get("https://api.kimi.com/coding/v1/usages");
    if key_or_token.starts_with("sk-") {
        req = req.header("x-api-key", key_or_token);
    } else {
        req = req.header("Authorization", format!("Bearer {key_or_token}"));
    }
    let resp = req.send_routed("kimi", Duration::from_secs(12)).await.map_err(|e| AppError::msg(format!("Kimi 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Kimi 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();

    if let Some(usages) = body.get("usages").and_then(|v| v.as_array()) {
        for u in usages {
            let name = u.get("name").or_else(|| u.get("resource_type")).and_then(|v| v.as_str()).unwrap_or("Usage");
            let used = to_finite_f64(u.get("used")).unwrap_or(0.0);
            let total = to_finite_f64(u.get("total")).or_else(|| to_finite_f64(u.get("limit"))).unwrap_or(100.0);
            let resets_at = parse_reset_time_val(u.get("resets_at").or_else(|| u.get("reset_time")));
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: name.into(),
                unit: "".into(),
                used: Some(used),
                total: Some(total),
                remaining: Some((total - used).max(0.0)),
                resets_at,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_glm(
    client: &Client,
    provider_id: &str,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let url = if provider_id == "glm-cn" {
        "https://open.bigmodel.cn/api/monitor/usage/quota/limit"
    } else {
        "https://api.z.ai/api/monitor/usage/quota/limit"
    };
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send_routed(provider_id, Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("GLM 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("GLM 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();

    if let Some(limits) = body.pointer("/data/limits").and_then(|v| v.as_array()) {
        for lim in limits {
            let pct = to_finite_f64(lim.get("percentage")).unwrap_or(0.0);
            let reset_at = parse_reset_time_val(lim.get("nextResetTime"));
            let unit = lim.get("unit").and_then(|v| v.as_i64()).unwrap_or(0);
            let name = match unit {
                3 => "Session (5h)",
                6 => "Weekly (7d)",
                _ => "Tokens",
            };
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: name.into(),
                unit: "%".into(),
                used: Some(pct),
                total: Some(100.0),
                remaining: Some((100.0 - pct).max(0.0)),
                resets_at: reset_at,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_openrouter(
    client: &Client,
    key: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://openrouter.ai/api/v1/auth/key")
        .bearer_auth(key)
        .send_routed("openrouter", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("OpenRouter 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("OpenRouter 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    if let Some(data) = body.get("data") {
        let usage = to_finite_f64(data.get("usage")).unwrap_or(0.0);
        let limit = to_finite_f64(data.get("limit"));
        if let Some(lim) = limit {
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: "Usage (USD)".into(),
                unit: "USD".into(),
                used: Some(usage),
                total: Some(lim),
                remaining: Some((lim - usage).max(0.0)),
                resets_at: None,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        } else {
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "balance".into(),
                quota_name: "USD".into(),
                unit: "USD".into(),
                used: None,
                total: None,
                remaining: Some(usage),
                resets_at: None,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_groq(
    client: &Client,
    key: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://api.groq.com/openai/v1/models")
        .bearer_auth(key)
        .send_routed("groq", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Groq 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Groq 响应错误 ({})", resp.status())));
    }
    let headers = resp.headers();
    let mut rows = Vec::new();
    let get_h = |name: &str| -> Option<f64> {
        headers.get(name)?.to_str().ok()?.parse().ok()
    };
    if let (Some(limit), Some(rem)) = (get_h("x-ratelimit-limit-requests"), get_h("x-ratelimit-remaining-requests")) {
        rows.push(SnapshotRow {
            connection_id: connection_id.into(),
            kind: "period".into(),
            quota_name: "Requests (1m)".into(),
            unit: "req".into(),
            used: Some((limit - rem).max(0.0)),
            total: Some(limit),
            remaining: Some(rem),
            resets_at: None,
            checked_at: checked_at.into(),
            source: "live".into(),
            error: None,
        });
    }
    if let (Some(limit), Some(rem)) = (get_h("x-ratelimit-limit-tokens"), get_h("x-ratelimit-remaining-tokens")) {
        rows.push(SnapshotRow {
            connection_id: connection_id.into(),
            kind: "period".into(),
            quota_name: "Tokens (1m)".into(),
            unit: "tokens".into(),
            used: Some((limit - rem).max(0.0)),
            total: Some(limit),
            remaining: Some(rem),
            resets_at: None,
            checked_at: checked_at.into(),
            source: "live".into(),
            error: None,
        });
    }
    Ok(rows)
}

async fn fetch_vercel(
    client: &Client,
    key: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://ai-gateway.vercel.sh/v1/credits")
        .bearer_auth(key)
        .send_routed("vercel-ai-gateway", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Vercel 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Vercel 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let balance = to_finite_f64(body.get("balance")).unwrap_or(0.0);
    let total_used = to_finite_f64(body.get("total_used")).unwrap_or(0.0);
    Ok(vec![SnapshotRow {
        connection_id: connection_id.into(),
        kind: "period".into(),
        quota_name: "Credits".into(),
        unit: "USD".into(),
        used: Some(total_used),
        total: Some(balance + total_used),
        remaining: Some(balance),
        resets_at: None,
        checked_at: checked_at.into(),
        source: "live".into(),
        error: None,
    }])
}

async fn fetch_grok_cli(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://cli-chat-proxy.grok.com/v1/billing?format=credits")
        .bearer_auth(token)
        .header("x-grok-client-identifier", "grok-shell")
        .header("User-Agent", "grok-shell/1.0.44 (linux; x86_64)")
        .send_routed("grok-cli", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Grok CLI 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Grok CLI 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    if let Some(cfg) = body.get("config") {
        let unwrap_num = |v: Option<&Value>| -> f64 {
            v.and_then(|x| x.get("val").and_then(|n| n.as_f64()).or_else(|| x.as_f64())).unwrap_or(0.0)
        };
        let cap = unwrap_num(cfg.get("onDemandCap"));
        let used = unwrap_num(cfg.get("onDemandUsed"));
        let reset_at = parse_reset_time_val(cfg.pointer("/currentPeriod/end"));
        if cap > 0.0 || used > 0.0 {
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: "Weekly (On-Demand)".into(),
                unit: "credits".into(),
                used: Some(used),
                total: Some(cap),
                remaining: Some((cap - used).max(0.0)),
                resets_at: reset_at,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
        let prepaid = unwrap_num(cfg.get("prepaidBalance"));
        if prepaid > 0.0 {
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "balance".into(),
                quota_name: "Prepaid".into(),
                unit: "credits".into(),
                used: None,
                total: None,
                remaining: Some(prepaid),
                resets_at: None,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_minimax(
    client: &Client,
    provider_id: &str,
    key_or_token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let url = if provider_id == "minimax-cn" {
        "https://www.minimaxi.com/v1/api/openplatform/coding_plan/remains"
    } else {
        "https://api.minimax.io/v1/token_plan/remains"
    };
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {key_or_token}"))
        .send_routed(provider_id, Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("MiniMax 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("MiniMax 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    let models = body.pointer("/data/model_remains").or_else(|| body.pointer("/data/models")).and_then(|v| v.as_array());
    if let Some(list) = models {
        for m in list {
            let name = m.get("model_name").or_else(|| m.get("modelName")).and_then(|v| v.as_str()).unwrap_or("Model");
            let total = to_finite_f64(m.get("current_interval_total_count")).unwrap_or(0.0);
            let rem = to_finite_f64(m.get("current_interval_remains_count")).unwrap_or(0.0);
            let used = (total - rem).max(0.0);
            let reset_at = parse_reset_time_val(m.get("end_time"));
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: name.into(),
                unit: "requests".into(),
                used: Some(used),
                total: Some(total),
                remaining: Some(rem),
                resets_at: reset_at,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_ollama(
    client: &Client,
    key: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://ollama.com/api/usage")
        .bearer_auth(key)
        .send_routed("ollama", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Ollama Cloud 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Ollama Cloud 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    if let Some(limits) = body.get("limits").and_then(|v| v.as_object()) {
        for (k, v) in limits {
            let ratio = to_finite_f64(v.get("usage")).unwrap_or(0.0);
            let used_pct = (ratio * 100.0).round();
            let label = match k.as_str() {
                "session" => "Session (5h)",
                "weekly" => "Weekly (7d)",
                "monthly" => "Monthly",
                other => other,
            };
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: label.into(),
                unit: "%".into(),
                used: Some(used_pct),
                total: Some(100.0),
                remaining: Some((100.0 - used_pct).max(0.0)),
                resets_at: None,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_kiro(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let url = "https://codewhisperer.us-east-1.amazonaws.com/getUsageLimits?isEmailRequired=true&origin=AI_EDITOR&resourceType=AGENTIC_REQUEST";
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .header("x-amz-user-agent", "aws-sdk-js/1.0.0 KiroIDE")
        .send_routed("kiro", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Kiro 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Kiro 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    let reset_at = parse_reset_time_val(body.get("nextDateReset").or_else(|| body.get("resetDate")));
    if let Some(list) = body.get("usageBreakdownList").and_then(|v| v.as_array()) {
        for b in list {
            let rtype = b.get("resourceType").and_then(|v| v.as_str()).unwrap_or("Resource");
            let used = to_finite_f64(b.get("currentUsageWithPrecision")).unwrap_or(0.0);
            let limit = to_finite_f64(b.get("usageLimitWithPrecision")).unwrap_or(0.0);
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: rtype.into(),
                unit: "".into(),
                used: Some(used),
                total: Some(limit),
                remaining: Some((limit - used).max(0.0)),
                resets_at: reset_at.clone(),
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_qoder(
    client: &Client,
    provider_id: &str,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let url = if provider_id == "qoder-cn" {
        "https://openapi.qoder.com.cn/api/v2/quota/usage"
    } else {
        "https://openapi.qoder.sh/api/v2/quota/usage"
    };
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send_routed(provider_id, Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Qoder 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Qoder 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    let reset_at = parse_reset_time_val(body.get("expiresAt"));

    if let Some(user_q) = body.get("userQuota") {
        let total = to_finite_f64(user_q.get("total")).unwrap_or(0.0);
        let used = to_finite_f64(user_q.get("used")).unwrap_or(0.0);
        let rem = to_finite_f64(user_q.get("remaining")).unwrap_or(total - used);
        rows.push(SnapshotRow {
            connection_id: connection_id.into(),
            kind: "period".into(),
            quota_name: "User Quota".into(),
            unit: "credits".into(),
            used: Some(used),
            total: Some(total),
            remaining: Some(rem),
            resets_at: reset_at.clone(),
            checked_at: checked_at.into(),
            source: "live".into(),
            error: None,
        });
    }
    if let Some(org_q) = body.get("orgResourcePackage") {
        let total = to_finite_f64(org_q.get("total")).unwrap_or(0.0);
        let used = to_finite_f64(org_q.get("used")).unwrap_or(0.0);
        let rem = to_finite_f64(org_q.get("remaining")).unwrap_or(total - used);
        rows.push(SnapshotRow {
            connection_id: connection_id.into(),
            kind: "period".into(),
            quota_name: "Org Package".into(),
            unit: "credits".into(),
            used: Some(used),
            total: Some(total),
            remaining: Some(rem),
            resets_at: reset_at,
            checked_at: checked_at.into(),
            source: "live".into(),
            error: None,
        });
    }
    Ok(rows)
}

async fn fetch_commandcode(
    client: &Client,
    key: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://api.commandcode.ai/api/credits")
        .header("Authorization", format!("Bearer {key}"))
        .send_routed("commandcode", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("CommandCode 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("CommandCode 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    if let Some(credits) = body.get("credits") {
        let total = to_finite_f64(credits.get("total")).unwrap_or(0.0);
        let used = to_finite_f64(credits.get("used")).unwrap_or(0.0);
        let rem = to_finite_f64(credits.get("remaining")).unwrap_or(total - used);
        rows.push(SnapshotRow {
            connection_id: connection_id.into(),
            kind: "period".into(),
            quota_name: "Credits".into(),
            unit: "credits".into(),
            used: Some(used),
            total: Some(total),
            remaining: Some(rem),
            resets_at: None,
            checked_at: checked_at.into(),
            source: "live".into(),
            error: None,
        });
    }
    Ok(rows)
}

async fn fetch_opencode(
    client: &Client,
    provider_id: &str,
    key: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let url = if provider_id == "opencode-go" {
        "https://opencode.ai/zen/go/v1/usage"
    } else {
        "https://opencode.ai/zen/v1/usage"
    };
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {key}"))
        .send_routed(provider_id, Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("OpenCode 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("OpenCode 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    if let Some(windows) = body.get("windows").or_else(|| body.get("quotas")).and_then(|v| v.as_object()) {
        for (k, v) in windows {
            let used = to_finite_f64(v.get("used")).unwrap_or(0.0);
            let total = to_finite_f64(v.get("total")).or_else(|| to_finite_f64(v.get("limit"))).unwrap_or(100.0);
            let resets_at = parse_reset_time_val(v.get("resetAt").or_else(|| v.get("resets_at")));
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: k.clone(),
                unit: "".into(),
                used: Some(used),
                total: Some(total),
                remaining: Some((total - used).max(0.0)),
                resets_at,
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_zed(
    client: &Client,
    token: &str,
    connection_id: &str,
    checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    let resp = client
        .get("https://cloud.zed.dev/client/users/me")
        .header("Authorization", format!("Bearer {token}"))
        .send_routed("zed", Duration::from_secs(12))
        .await
        .map_err(|e| AppError::msg(format!("Zed 网络请求失败：{e}")))?;
    if !resp.status().is_success() {
        return Err(AppError::msg(format!("Zed 响应错误 ({})", resp.status())));
    }
    let body: Value = resp.json().await.map_err(|e| AppError::msg(format!("解析 JSON 失败：{e}")))?;
    let mut rows = Vec::new();
    if let Some(usage) = body.pointer("/plan/usage").and_then(|v| v.as_object()) {
        let reset_at = parse_reset_time_val(body.pointer("/subscription_period/ended_at"));
        for (k, v) in usage {
            let used = to_finite_f64(v.get("used")).unwrap_or(0.0);
            let total = to_finite_f64(v.get("limit")).unwrap_or(100.0);
            rows.push(SnapshotRow {
                connection_id: connection_id.into(),
                kind: "period".into(),
                quota_name: k.replace('_', " "),
                unit: "".into(),
                used: Some(used),
                total: Some(total),
                remaining: Some((total - used).max(0.0)),
                resets_at: reset_at.clone(),
                checked_at: checked_at.into(),
                source: "live".into(),
                error: None,
            });
        }
    }
    Ok(rows)
}

async fn fetch_generic_openai_compatible(
    _client: &Client,
    provider_id: &str,
    _credential: &str,
    _connection_id: &str,
    _checked_at: &str,
) -> AppResult<Vec<SnapshotRow>> {
    Err(AppError::msg(format!(
        "提供商 {provider_id} 采用按请求计费或无独立配额查询端点"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_reset_time_converts_unix_and_iso() {
        assert!(parse_reset_time_val(None).is_none());
        assert!(parse_reset_time_val(Some(&json!(""))).is_none());

        // ISO-8601 string returns as-is
        let iso = "2026-10-14T12:00:00Z";
        assert_eq!(parse_reset_time_val(Some(&json!(iso))), Some(iso.to_string()));

        // Unix timestamp in seconds (e.g. 1791912345)
        let ts_sec = json!(1791912345);
        let parsed = parse_reset_time_val(Some(&ts_sec)).unwrap();
        assert!(parsed.contains("2026-") || parsed.contains("T"));

        // Unix timestamp as string
        let ts_str = json!("1791912345");
        assert_eq!(parse_reset_time_val(Some(&ts_str)), Some(parsed));
    }

    #[test]
    fn to_finite_f64_handles_numbers_and_strings() {
        assert_eq!(to_finite_f64(Some(&json!(42.5))), Some(42.5));
        assert_eq!(to_finite_f64(Some(&json!("123.45"))), Some(123.45));
        assert_eq!(to_finite_f64(Some(&json!("invalid"))), None);
        assert_eq!(to_finite_f64(None), None);
    }
}

