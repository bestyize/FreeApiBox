//! 提供商目录与详情的业务逻辑（命令层只调用这里）。
//!
//! 134 家内置提供商的 `adapter_ready` 由 `resources/provider_status.json`（见 `status.rs`）决定，
//! 未就绪的状态恒为 `unsupported` 并带 `pending_reason`；连接测试在上游探测接入前如实返回 ok=false。
//! API Key 只写入系统凭据库（`CredentialVault`），数据库只存 credential_ref，任何返回值都不含明文。

pub mod catalog;
pub mod status;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sqlx::SqlitePool;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::oauth::OAuthService;
use crate::security::vault::{self, CredentialVault};
use crate::store::new_id;
use crate::store::providers::{
    self as repo, ConnectionWrite, HeaderWrite, ModelWrite, ProviderRow, ProviderWrite, SavePlan,
};
use status::{Adapter, AuthSpec};

/// 前端拿到秘密请求头时看到的占位值；保存时原样回传表示"保持不变"。
pub const SECRET_MASK: &str = "••••••••";

pub const ADAPTER_NOT_READY: &str = "该提供商的适配器尚未接入，无法测试连接";

fn parse_protocols(json: &str) -> Vec<Protocol> {
    serde_json::from_str::<Vec<String>>(json)
        .unwrap_or_default()
        .iter()
        .filter_map(|s| Protocol::parse(s))
        .collect()
}

fn parse_strings(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

fn parse_auth_modes(json: &str) -> Vec<CredentialKind> {
    parse_strings(json).iter().filter_map(|s| CredentialKind::parse(s)).collect()
}

fn derive_status(row: &ProviderRow, total: i64, active: i64) -> ConnectionStatus {
    if !row.adapter_ready {
        ConnectionStatus::Unsupported
    } else if total == 0 || active == 0 {
        ConnectionStatus::Disconnected
    } else {
        ConnectionStatus::Connected
    }
}

/// adapter 未就绪时展示给用户的原因（目录里一定有；兜底文案只在数据损坏时出现）。
fn pending_text(row: &ProviderRow) -> String {
    row.pending_reason.clone().filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "适配器尚未接入".to_string())
}

fn summary_from(row: &ProviderRow, counts: (i64, i64)) -> ProviderSummary {
    ProviderSummary {
        id: row.id.clone(),
        name: row.display_name.clone(),
        group: ProviderGroup::parse(&row.grp).unwrap_or(ProviderGroup::Custom),
        status: derive_status(row, counts.0, counts.1),
        connection_count: counts.0.max(0) as u32,
        adapter_ready: row.adapter_ready,
        protocols: parse_protocols(&row.protocols_json),
        // 上游额度抓取尚未实现，没有可靠数据时一律 null（不是 0）
        quota_hint: None,
        service_kinds: parse_strings(&row.service_kinds_json),
        website: row.website.clone(),
        color: row.color.clone(),
        text_icon: row.text_icon.clone(),
        auth_modes: parse_auth_modes(&row.auth_modes_json),
        pending_reason: (!row.adapter_ready).then(|| pending_text(row)),
    }
}

pub async fn list(pool: &SqlitePool) -> AppResult<Vec<ProviderSummary>> {
    let rows = repo::list_providers(pool).await?;
    let counts = repo::connection_counts(pool).await?;
    Ok(rows
        .iter()
        .map(|r| summary_from(r, counts.get(&r.id).copied().unwrap_or((0, 0))))
        .collect())
}

pub async fn get_detail(pool: &SqlitePool, id: &str) -> AppResult<ProviderDetail> {
    let row = repo::get_provider(pool, id).await?.ok_or_else(|| AppError::NotFound(format!("provider {id}")))?;
    let connections = repo::list_connections(pool, id).await?;
    let total = connections.len() as i64;
    let active = connections.iter().filter(|c| c.enabled && c.status == "active").count() as i64;

    Ok(ProviderDetail {
        summary: summary_from(&row, (total, active)),
        risk_notice: row.risk_notice.clone(),
        connections: connections
            .into_iter()
            .map(|c| Connection {
                id: c.id,
                provider_id: c.provider_id,
                account_label: c.account_label,
                kind: CredentialKind::parse(&c.kind).unwrap_or(CredentialKind::ApiKey),
                status: AccountStatus::parse(&c.status).unwrap_or(AccountStatus::Error),
                priority: c.priority,
                weight: c.weight,
                enabled: c.enabled,
            })
            .collect(),
        distribution: DistributionPolicy {
            round_robin: row.round_robin,
            max_concurrency: row.max_concurrency,
            max_retries: row.max_retries,
        },
        custom_headers: repo::list_headers(pool, id)
            .await?
            .into_iter()
            .map(|h| CustomHeader {
                key: h.header_key,
                // 秘密请求头的明文永不返回前端
                value: if h.secret { SECRET_MASK.to_string() } else { h.value.unwrap_or_default() },
                secret: h.secret,
            })
            .collect(),
        models: repo::list_models(pool, id)
            .await?
            .into_iter()
            .map(|m| ModelEntry {
                id: m.id,
                upstream_model_id: m.upstream_model_id,
                public_alias: m.public_alias,
                description: m.description,
                enabled: m.enabled,
                supports_thinking: m.supports_thinking,
            })
            .collect(),
        thinking_level: ThinkingLevel::parse(&row.thinking_level).unwrap_or(ThinkingLevel::Auto),
        base_url: row.base_url.clone(),
    })
}

fn invalid(msg: impl Into<String>) -> AppError {
    AppError::msg(msg)
}

fn check_ident(kind: &str, s: &str) -> AppResult<()> {
    let ok = !s.is_empty() && s.len() <= 256 && s.chars().all(|c| !c.is_control() && !c.is_whitespace());
    if ok {
        Ok(())
    } else {
        Err(invalid(format!("{kind} 标识无效（非空、不超过 256 字符、不含空白/控制字符）")))
    }
}

fn is_header_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// 保存提供商详情。`detail` 是完整状态：缺失的连接/模型/请求头会被删除（同时清理其凭据）。
/// 客户端传来的 status / adapterReady / connectionCount 等派生字段一律忽略。
pub async fn save_detail(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    detail: ProviderDetail,
) -> AppResult<ProviderDetail> {
    let existing = if detail.summary.id.is_empty() { None } else { repo::get_provider(pool, &detail.summary.id).await? };
    let Some(row) = existing else {
        return Err(if detail.summary.group == ProviderGroup::Custom {
            invalid("新建自定义提供商请使用 create_custom_provider（需要填写协议与 Base URL）")
        } else {
            AppError::NotFound(format!("provider {}", detail.summary.id))
        });
    };
    let provider_id = row.id.clone();
    let is_custom = row.kind == "custom";

    // ---- 提供商本体（仅自定义提供商允许改名/改协议；适配器随协议同步）----
    let (display_name, protocols_json, adapter) = if is_custom {
        let name = detail.summary.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(invalid("提供商名称需为 1–64 个字符"));
        }
        let [protocol] = detail.summary.protocols.as_slice() else {
            return Err(invalid("自定义提供商必须且只能选择一种协议"));
        };
        let adapter = status::adapter_for_custom_protocol(*protocol)
            .ok_or_else(|| invalid("自定义提供商协议没有可用适配器"))?;
        (Some(name), Some(serde_json::to_string(&[protocol.as_str()])?), Some(adapter.as_str()))
    } else {
        (None, None, None)
    };

    let d = &detail.distribution;
    if !(1..=1024).contains(&d.max_concurrency) {
        return Err(invalid("最大并发需在 1–1024 之间"));
    }
    if !(0..=10).contains(&d.max_retries) {
        return Err(invalid("最大重试次数需在 0–10 之间"));
    }

    // ---- 连接 ----
    let existing_conns: HashMap<String, repo::ConnectionRow> =
        repo::list_connections(pool, &provider_id).await?.into_iter().map(|c| (c.id.clone(), c)).collect();
    let mut seen = HashSet::new();
    let mut connections = Vec::with_capacity(detail.connections.len());
    for c in &detail.connections {
        let label = c.account_label.trim().to_string();
        if label.is_empty() || label.chars().count() > 128 {
            return Err(invalid("账户名称需为 1–128 个字符"));
        }
        if !(0..=1000).contains(&c.priority) || !(0..=1000).contains(&c.weight) {
            return Err(invalid("优先级与权重需在 0–1000 之间"));
        }
        let id = if c.id.is_empty() { new_id() } else { c.id.clone() };
        check_ident("连接", &id)?;
        if !seen.insert(id.clone()) {
            return Err(invalid(format!("连接 ID 重复：{id}")));
        }
        if c.kind == CredentialKind::None && (row.kind != "builtin"
            || !catalog::find(&provider_id).is_some_and(|entry| entry.no_auth)) {
            return Err(invalid("只有目录标记为免密钥的提供商可以使用免密钥连接"));
        }
        if !existing_conns.contains_key(&id) {
            if let Some(owner) = repo::connection_owner(pool, &id).await? {
                return Err(invalid(format!("连接 ID {id} 已被提供商 {owner} 使用")));
            }
        }
        // status 由服务端掌控：停用 → paused；启用 → 沿用已知的 error / needsReauth（后者只能靠重新授权清除），否则 active
        let status = if !c.enabled {
            AccountStatus::Paused
        } else {
            match existing_conns.get(&id).and_then(|e| AccountStatus::parse(&e.status)) {
                Some(AccountStatus::Error) => AccountStatus::Error,
                Some(AccountStatus::NeedsReauth) => AccountStatus::NeedsReauth,
                _ => AccountStatus::Active,
            }
        };
        connections.push(ConnectionWrite {
            id,
            account_label: label,
            kind: c.kind.as_str(),
            status: status.as_str(),
            priority: c.priority,
            weight: c.weight,
            enabled: c.enabled,
        });
    }

    // ---- 模型（别名冲突必须显式报错，禁止静默覆盖）----
    let mut model_ids = HashSet::new();
    let mut models = Vec::with_capacity(detail.models.len());
    for m in &detail.models {
        let upstream = m.upstream_model_id.trim().to_string();
        let alias = m.public_alias.trim().to_string();
        if upstream.is_empty() || upstream.len() > 256 {
            return Err(invalid("上游模型 ID 不能为空且不超过 256 字符"));
        }
        if alias.is_empty() || alias.chars().count() > 128 || alias.chars().any(|c| c.is_control()) {
            return Err(invalid(format!("模型 {upstream} 的对外别名无效")));
        }
        let id = if m.id.is_empty() { format!("{provider_id}/{upstream}") } else { m.id.clone() };
        check_ident("模型", &id)?;
        if !model_ids.insert(id.clone()) {
            return Err(invalid(format!("模型 ID 重复：{id}")));
        }
        if let Some(owner) = repo::model_owner(pool, &id).await? {
            if owner != provider_id {
                return Err(invalid(format!("模型 ID {id} 已被提供商 {owner} 使用")));
            }
        }
        models.push(ModelWrite {
            id,
            upstream_model_id: upstream,
            public_alias: alias,
            description: m.description.clone(),
            supports_thinking: m.supports_thinking,
            enabled: m.enabled,
        });
    }
    {
        let mut owners: HashMap<String, String> = repo::enabled_aliases(pool)
            .await?
            .into_iter()
            .filter(|(_, pid, _)| *pid != provider_id)
            .map(|(alias, pid, _)| (alias, pid))
            .collect();
        for m in models.iter().filter(|m| m.enabled) {
            if let Some(owner) = owners.insert(m.public_alias.clone(), provider_id.clone()) {
                let place = if owner == provider_id { "本提供商内".to_string() } else { format!("提供商 {owner} 中") };
                return Err(invalid(format!(
                    "模型别名 \"{}\" 与{place}另一个已启用模型冲突，请改名后再保存",
                    m.public_alias
                )));
            }
        }
    }

    // ---- 请求头（秘密值进凭据库）----
    let old_headers: HashMap<String, repo::HeaderRow> = repo::list_headers(pool, &provider_id)
        .await?
        .into_iter()
        .map(|h| (h.header_key.to_ascii_lowercase(), h))
        .collect();
    let mut header_keys = HashSet::new();
    let mut headers = Vec::new();
    let mut new_secrets: Vec<(String, String)> = Vec::new(); // (credential_ref, secret)
    for h in &detail.custom_headers {
        let key = h.key.trim().to_string();
        if !is_header_token(&key) {
            return Err(invalid(format!("请求头名称无效：{key}")));
        }
        if !header_keys.insert(key.to_ascii_lowercase()) {
            return Err(invalid(format!("请求头重复：{key}")));
        }
        if h.value.len() > 4096 || h.value.chars().any(|c| c == '\r' || c == '\n' || c == '\0') {
            return Err(invalid(format!("请求头 {key} 的值无效")));
        }
        if h.secret {
            let kept = old_headers
                .get(&key.to_ascii_lowercase())
                .filter(|o| o.secret && h.value == SECRET_MASK)
                .and_then(|o| o.credential_ref.clone());
            let credential_ref = match kept {
                Some(r) => r,
                None => {
                    if h.value.is_empty() || h.value == SECRET_MASK {
                        return Err(invalid(format!("秘密请求头 {key} 需要提供值")));
                    }
                    let r = format!("provider-header/{provider_id}/{}", new_id());
                    new_secrets.push((r.clone(), h.value.clone()));
                    r
                }
            };
            headers.push(HeaderWrite { key, value: None, secret: true, credential_ref: Some(credential_ref) });
        } else {
            headers.push(HeaderWrite { key, value: Some(h.value.clone()), secret: false, credential_ref: None });
        }
    }

    let plan = SavePlan {
        provider: ProviderWrite {
            id: provider_id.clone(),
            display_name,
            protocols_json,
            adapter,
            round_robin: d.round_robin,
            max_concurrency: d.max_concurrency,
            max_retries: d.max_retries,
            thinking_level: detail.thinking_level.as_str(),
        },
        connections,
        models,
        headers,
    };

    // 先写新凭据，再提交数据库，最后清理旧凭据：任何一步失败都不会丢失仍被引用的凭据。
    for (r, secret) in &new_secrets {
        vault::set(vault, r, secret).await?;
    }
    let removed = match repo::apply_save(pool, &plan).await {
        Ok(removed) => removed,
        Err(e) => {
            for (r, _) in &new_secrets {
                let _ = vault::delete(vault, r).await;
            }
            return Err(e);
        }
    };
    for r in removed {
        if let Err(e) = vault::delete(vault, &r).await {
            tracing::warn!("清理凭据失败（ref={r}）：{e}");
        }
    }

    get_detail(pool, &provider_id).await
}

// ---- 上游目标解析（供转发管线与连接测试共用）----

/// 一个提供商的上游调用目标。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    pub provider_id: String,
    pub adapter: Adapter,
    pub base_url: String,
    pub auth: AuthSpec,
    /// true：`base_url` 已经是完整的聊天端点（内置提供商，取自 provider_status.json）；
    /// false：是用户填写的 Base URL（自定义提供商），调用方需要按协议自行拼接路径。
    pub base_url_is_full_endpoint: bool,
}

/// 纯函数：由提供商行得到上游目标；未就绪时返回面向用户的原因。
pub fn target_for_row(row: &ProviderRow) -> Result<UpstreamTarget, String> {
    if !row.adapter_ready {
        return Err(pending_text(row));
    }
    if row.kind == "builtin" {
        let st = status::get(&row.id).ok_or_else(|| "该提供商尚未登记适配器状态".to_string())?;
        let adapter = st.adapter.ok_or_else(|| pending_text(row))?;
        let base_url = st.base_url.clone().ok_or_else(|| "目录中缺少上游地址".to_string())?;
        let auth = st.auth.clone().unwrap_or_else(|| status::default_auth(adapter));
        Ok(UpstreamTarget { provider_id: row.id.clone(), adapter, base_url, auth, base_url_is_full_endpoint: true })
    } else {
        let adapter = Adapter::parse(&row.adapter).ok_or_else(|| "自定义提供商的协议无效".to_string())?;
        let base_url = row.base_url.clone().ok_or_else(|| "自定义提供商尚未配置 Base URL".to_string())?;
        Ok(UpstreamTarget {
            provider_id: row.id.clone(),
            adapter,
            base_url,
            auth: status::default_auth(adapter),
            base_url_is_full_endpoint: false,
        })
    }
}

/// 解析提供商的上游目标：不存在或未就绪（adapter=null）时返回带原因的错误。
pub async fn resolve_upstream(pool: &SqlitePool, provider_id: &str) -> AppResult<UpstreamTarget> {
    let row = repo::get_provider(pool, provider_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider {provider_id}")))?;
    target_for_row(&row).map_err(AppError::msg)
}

// ---- 自定义提供商 ----

pub async fn create_custom_provider(
    pool: &SqlitePool,
    name: &str,
    protocol: Protocol,
    base_url: &str,
) -> AppResult<ProviderDetail> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 64 || name.chars().any(|c| c.is_control()) {
        return Err(invalid("提供商名称需为 1–64 个字符"));
    }
    let adapter = status::adapter_for_custom_protocol(protocol)
        .ok_or_else(|| invalid("自定义提供商协议没有可用适配器"))?;
    let base_url = status::validate_base_url(base_url)?;
    let id = format!("custom-{}", new_id());
    repo::insert_custom_provider(
        pool,
        &repo::CustomProviderInsert {
            id: &id,
            name,
            protocols_json: serde_json::to_string(&[protocol.as_str()])?,
            adapter: adapter.as_str(),
            base_url: &base_url,
        },
    )
    .await?;
    get_detail(pool, &id).await
}

/// 删除自定义提供商，并清理其全部凭据（连接的 API Key、秘密请求头）。内置提供商不可删除。
pub async fn delete_custom_provider(pool: &SqlitePool, vault: &Arc<dyn CredentialVault>, id: &str) -> AppResult<()> {
    let row = repo::get_provider(pool, id).await?.ok_or_else(|| AppError::NotFound(format!("provider {id}")))?;
    if row.kind != "custom" {
        return Err(invalid("只能删除自定义提供商，内置提供商不可删除"));
    }
    let refs = repo::delete_provider(pool, id).await?;
    // 数据库已提交；凭据清理失败只记录 ref，不回滚（孤儿凭据无引用、不会被使用）
    for r in refs {
        if let Err(e) = vault::delete(vault, &r).await {
            tracing::warn!("清理凭据失败（ref={r}）：{e}");
        }
    }
    Ok(())
}

// ---- 连接与凭据 ----

/// 规范化并校验 API Key。错误信息绝不带入密钥内容。
fn clean_api_key(raw: &str) -> AppResult<Zeroizing<String>> {
    let key = Zeroizing::new(raw.trim().to_string());
    if key.is_empty() {
        return Err(invalid("API Key 不能为空"));
    }
    if key.len() > 4096 {
        return Err(invalid("API Key 过长（超过 4096 字符）"));
    }
    if key.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid("API Key 含有空白或控制字符，请检查是否复制完整"));
    }
    Ok(key)
}

fn connection_from_row(c: repo::ConnectionRow) -> Connection {
    Connection {
        id: c.id,
        provider_id: c.provider_id,
        account_label: c.account_label,
        kind: CredentialKind::parse(&c.kind).unwrap_or(CredentialKind::ApiKey),
        status: AccountStatus::parse(&c.status).unwrap_or(AccountStatus::Error),
        priority: c.priority,
        weight: c.weight,
        enabled: c.enabled,
    }
}

/// 录入 API Key 并创建连接：密钥只进系统凭据库，数据库只存 credential_ref，返回值不含密钥。
/// 适配器未就绪（adapter=null）或不支持 API Key 的提供商会被拒绝并说明原因。
pub async fn add_connection(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    provider_id: &str,
    account_label: &str,
    api_key: &str,
) -> AppResult<Connection> {
    let row = repo::get_provider(pool, provider_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider {provider_id}")))?;
    if !row.adapter_ready {
        return Err(invalid(format!("{} 暂不能添加连接：{}", row.display_name, pending_text(&row))));
    }
    let no_auth = row.kind == "builtin" && catalog::find(provider_id).is_some_and(|entry| entry.no_auth);
    if no_auth {
        if row.adapter == "none" {
            return Err(invalid("该免密钥提供商不提供聊天连接"));
        }
        if !api_key.is_empty() {
            return Err(invalid("该提供商无需 API Key，请直接启用"));
        }
        if let Some(existing) = repo::list_connections(pool, provider_id).await?.into_iter().find(|c| c.kind == "none") {
            return Ok(connection_from_row(existing));
        }
        return Ok(connection_from_row(repo::insert_no_auth_connection(pool, &new_id(), provider_id, "免密钥连接").await?));
    }
    if !parse_auth_modes(&row.auth_modes_json).contains(&CredentialKind::ApiKey) {
        return Err(invalid(format!("{} 不支持 API Key 方式", row.display_name)));
    }
    let label = account_label.trim();
    if label.is_empty() || label.chars().count() > 128 || label.chars().any(|c| c.is_control()) {
        return Err(invalid("账户标识需为 1–128 个字符"));
    }
    let key = clean_api_key(api_key)?;

    let id = new_id();
    let credential_ref = format!("connection/{id}/{}", new_id());
    vault::set(vault, &credential_ref, &key).await?;
    match repo::insert_api_key_connection(pool, &id, &row.id, label, &credential_ref).await {
        Ok(c) => Ok(connection_from_row(c)),
        Err(e) => {
            let _ = vault::delete(vault, &credential_ref).await;
            Err(e)
        }
    }
}

/// 替换已有 API Key 连接的密钥（新密钥先写入，数据库切换引用后再清掉旧密钥）。
pub async fn update_connection_credential(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    connection_id: &str,
    api_key: &str,
) -> AppResult<()> {
    let conn = repo::get_connection(pool, connection_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("connection {connection_id}")))?;
    if CredentialKind::parse(&conn.kind) != Some(CredentialKind::ApiKey) {
        return Err(invalid("只有 API Key 连接可以更新密钥"));
    }
    let key = clean_api_key(api_key)?;
    set_connection_credential(pool, vault, &conn.id, &key).await
}

/// 为连接写入/替换凭据：明文只进系统凭据库，SQLite 只存 credential_ref。
pub async fn set_connection_credential(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    connection_id: &str,
    secret: &str,
) -> AppResult<()> {
    let conn = repo::get_connection(pool, connection_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("connection {connection_id}")))?;
    let new_ref = format!("connection/{}/{}", conn.id, new_id());
    vault::set(vault, &new_ref, secret).await?;
    if let Err(e) = repo::set_connection_credential_ref(pool, &conn.id, Some(&new_ref)).await {
        let _ = vault::delete(vault, &new_ref).await;
        return Err(e);
    }
    if let Some(old) = conn.credential_ref {
        let _ = vault::delete(vault, &old).await;
    }
    Ok(())
}

// ---- 连接测试 ----

/// 上游探测结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// 上游确认可用。
    Reachable { latency_ms: u64 },
    /// 上游探测失败。消息会原样展示给用户，**绝不能包含密钥**。
    Unreachable(String),
    /// 探测管线尚未接入：调用方必须如实报告"无法确认"，不得当成成功。
    NotImplemented,
}

/// 真实上游探测接入点：对上游模型/账户接口发起轻量健康检查，测量延迟。
pub async fn probe_connection(target: &UpstreamTarget, credential: &str) -> ProbeOutcome {
    #[cfg(test)]
    {
        let _ = (target, credential);
        ProbeOutcome::NotImplemented
    }
    #[cfg(not(test))]
    {
        probe_live(target, credential).await
    }
}

pub async fn probe_live(target: &UpstreamTarget, credential: &str) -> ProbeOutcome {

    let client = match reqwest::Client::builder().no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(6)).build() {
        Ok(c) => c,
        Err(_) => return ProbeOutcome::Unreachable("构建 HTTP 客户端失败".into()),
    };

    let start = std::time::Instant::now();
    let mut custom_body = None;
    let mut extra_headers: Vec<(&str, &str)> = Vec::new();

    let (url, method, auth_header, auth_val) = match target.provider_id.as_str() {
        "openrouter" => (
            "https://openrouter.ai/api/v1/auth/key".to_string(),
            "GET",
            "Authorization",
            format!("Bearer {credential}"),
        ),
        "anthropic" => {
            if credential.starts_with("sk-ant-") {
                (
                    "https://api.anthropic.com/v1/models".to_string(),
                    "GET",
                    "x-api-key",
                    credential.to_string(),
                )
            } else {
                extra_headers.push(("anthropic-beta", "oauth-2025-04-20"));
                (
                    "https://api.anthropic.com/api/oauth/usage".to_string(),
                    "GET",
                    "Authorization",
                    format!("Bearer {credential}"),
                )
            }
        }
        "claude" => {
            extra_headers.push(("anthropic-beta", "oauth-2025-04-20"));
            (
                "https://api.anthropic.com/api/oauth/usage".to_string(),
                "GET",
                "Authorization",
                format!("Bearer {credential}"),
            )
        }
        "antigravity" => {
            extra_headers.push(("x-request-source", "local"));
            extra_headers.push(("Content-Type", "application/json"));
            custom_body = Some(r#"{"metadata":{"ideType":9,"platform":2,"pluginType":2},"mode":1}"#.to_string());
            (
                "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist".to_string(),
                "POST",
                "Authorization",
                format!("Bearer {credential}"),
            )
        }
        "gemini-cli" => (
            "https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE".to_string(),
            "GET",
            "Authorization",
            format!("Bearer {credential}"),
        ),
        "gemini" => {
            if credential.starts_with("ya29.") {
                (
                    "https://cloudresourcemanager.googleapis.com/v1/projects?filter=lifecycleState:ACTIVE".to_string(),
                    "GET",
                    "Authorization",
                    format!("Bearer {credential}"),
                )
            } else {
                (
                    "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                    "GET",
                    "x-goog-api-key",
                    credential.to_string(),
                )
            }
        }
        "codebuddy-cn" => {
            extra_headers.push(("Host", "copilot.tencent.com"));
            extra_headers.push(("Content-Type", "application/json"));
            extra_headers.push(("User-Agent", "CLI/2.63.2 CodeBuddy/2.63.2"));
            custom_body = Some("{}".to_string());
            (
                "https://copilot.tencent.com/v2/billing/meter/get-user-resource".to_string(),
                "POST",
                "Authorization",
                format!("Bearer {credential}"),
            )
        }
        "codebuddy-intl" => {
            extra_headers.push(("Host", "www.codebuddy.ai"));
            extra_headers.push(("Content-Type", "application/json"));
            extra_headers.push(("User-Agent", "IDE/2.63.2 CodeBuddy/2.63.2"));
            custom_body = Some("{}".to_string());
            (
                "https://www.codebuddy.ai/v2/billing/meter/get-user-resource".to_string(),
                "POST",
                "Authorization",
                format!("Bearer {credential}"),
            )
        }
        "codex" => (
            "https://chatgpt.com/backend-api/wham/usage".to_string(),
            "GET",
            "Authorization",
            format!("Bearer {credential}"),
        ),
        "github" => {
            extra_headers.push(("Accept", "application/json"));
            extra_headers.extend(crate::upstream::github_compat::CLIENT_HEADERS.iter().copied());
            (
                "https://api.github.com/copilot_internal/user".to_string(),
                "GET",
                "Authorization",
                format!("token {credential}"),
            )
        }
        "deepseek" => (
            "https://api.deepseek.com/models".to_string(),
            "GET",
            "Authorization",
            format!("Bearer {credential}"),
        ),
        "groq" => (
            "https://api.groq.com/openai/v1/models".to_string(),
            "GET",
            "Authorization",
            format!("Bearer {credential}"),
        ),
        "ollama" | "ollama-local" => {
            let u = target.base_url.trim_end_matches('/');
            let tags = if let Some(p) = u.strip_suffix("/api/chat") {
                format!("{p}/api/tags")
            } else {
                format!("{u}/api/tags")
            };
            (tags, "GET", "Authorization", format!("Bearer {credential}"))
        }
        _ => {
            let u = target.base_url.trim_end_matches('/');
            let m_url = if let Some(p) = u.strip_suffix("/chat/completions") {
                format!("{p}/models")
            } else if let Some(p) = u.strip_suffix("/messages") {
                format!("{p}/models")
            } else if let Some(p) = u.strip_suffix("/responses") {
                format!("{p}/models")
            } else {
                format!("{u}/models")
            };
            let (h, v) = match &target.auth {
                AuthSpec::Scheme(status::AuthScheme::Bearer) => ("Authorization", format!("Bearer {credential}")),
                AuthSpec::Scheme(status::AuthScheme::XApiKey) => ("x-api-key", credential.to_string()),
                AuthSpec::Header { header } => (header.as_str(), credential.to_string()),
            };
            (m_url, "GET", h, v)
        }
    };

    let mut req = if method == "POST" {
        client.post(&url)
    } else {
        client.get(&url)
    };
    req = req.header("User-Agent", crate::upstream::client::user_agent());
    for (k, v) in extra_headers {
        req = req.header(k, v);
    }
    if let Some(body) = custom_body {
        req = req.body(body);
    }
    if target.auth == AuthSpec::Scheme(status::AuthScheme::XApiKey) || target.provider_id == "anthropic" {
        req = req.header("anthropic-version", "2023-06-01");
    }
    if !auth_val.is_empty() && target.provider_id != "ollama-local"
        && !catalog::find(&target.provider_id).is_some_and(|entry| entry.no_auth) {
        req = req.header(auth_header, auth_val);
    }

    match crate::proxy::http::send(&target.provider_id, req, std::time::Duration::from_secs(6)).await {
        Ok(resp) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let status = resp.status();
            if status.is_success() {
                ProbeOutcome::Reachable { latency_ms }
            } else if status.as_u16() == 401 {
                ProbeOutcome::Unreachable("上游返回 401：API Key 或令牌无效".to_string())
            } else if status.as_u16() == 403 {
                ProbeOutcome::Unreachable("上游返回 403：凭据无权访问该服务".to_string())
            } else if status.as_u16() == 429 {
                ProbeOutcome::Unreachable("上游返回 429：触发频率限制".to_string())
            } else {
                ProbeOutcome::Unreachable(format!("上游返回 HTTP {status}"))
            }
        }
        Err(e) => {
            if e.is_timeout() {
                ProbeOutcome::Unreachable("连接上游超时 (6s)".to_string())
            } else if e.is_connect() {
                ProbeOutcome::Unreachable("无法连接到上游服务器".to_string())
            } else {
                ProbeOutcome::Unreachable(format!("网络请求失败：{e}"))
            }
        }
    }
}

fn test_fail(connection_id: &str, provider_id: &str, error: impl Into<String>) -> TestResult {
    TestResult {
        connection_id: connection_id.to_string(),
        provider_id: Some(provider_id.to_string()),
        ok: false,
        latency_ms: None,
        error: Some(error.into()),
    }
}

/// OAuth 连接的测试：如实检查授权状态与令牌是否可用，**绝不**假装上游探测成功（结果恒为 ok=false，
/// 说明具体处于哪一步：需重新授权 / 令牌缺失 / 已过期无法刷新 / 令牌兑换步骤未接入 / 适配器未接入 / 探测未接入）。
async fn check_oauth_connection(
    vault: &Arc<dyn CredentialVault>,
    provider: &ProviderRow,
    conn: &repo::ConnectionRow,
) -> TestResult {
    use crate::oauth::{OAuthCatalog, TokenSet};
    let fail = |msg: String| test_fail(&conn.id, &provider.id, msg);
    if AccountStatus::parse(&conn.status) == Some(AccountStatus::NeedsReauth) {
        return fail("授权已失效，需要重新授权".to_string());
    }
    let Some(cref) = conn.credential_ref.as_deref() else {
        return fail("连接缺少授权令牌，请重新授权".to_string());
    };
    let raw = match vault::get(vault, cref).await {
        Ok(Some(s)) => Zeroizing::new(s),
        Ok(None) => return fail("系统凭据库中找不到该连接的授权令牌，请重新授权".to_string()),
        Err(e) => return fail(format!("读取系统凭据库失败：{e}")),
    };
    let Ok(tokens) = TokenSet::from_storage_json(&raw) else {
        return fail("已保存的授权令牌无法读取，请重新授权".to_string());
    };
    // 过期且无法刷新（没有 refresh token，或该提供商不支持刷新）：只能重新授权
    let refreshable = tokens.refresh_token.as_ref().is_some_and(|t| !t.is_empty())
        && OAuthCatalog::builtin_shared()
            .ok()
            .and_then(|c| c.get(&provider.id))
            .is_none_or(|cfg| cfg.supports_refresh);
    if tokens.is_expired(chrono::Utc::now()) && !refreshable {
        return fail("授权令牌已过期且无法自动刷新，需要重新授权".to_string());
    }
    let inference_token = match provider.id.as_str() {
        "github" => tokens.extra_value("copilot_token"),
        "nous" => tokens.extra_value("nous_agent_key"),
        "muse" if tokens.extra_value("muse_oauth_token").is_some() => Some(tokens.access_token.expose()),
        "muse" => None,
        _ => Some(tokens.access_token.expose()),
    };
    let Some(inference_token) = inference_token else {
        return fail("账户令牌已保存，但推理凭据尚未兑换；请重新授权或发起模型探测".to_string());
    };
    if !provider.adapter_ready {
        return fail(format!("授权令牌已保存，但{ADAPTER_NOT_READY}（{}）", pending_text(provider)));
    }
    let target = match target_for_row(provider) {
        Ok(t) => t,
        Err(_) => return fail("该提供商尚未配置上游端点，无法探测".to_string()),
    };
    // Copilot's account/usage endpoint takes the GitHub account token; its
    // inference endpoints take the separately exchanged Copilot token.
    let probe_token = if provider.id == "github" { tokens.access_token.expose() } else { inference_token };
    match probe_connection(&target, probe_token).await {
        ProbeOutcome::Reachable { latency_ms } => TestResult {
            connection_id: conn.id.clone(),
            provider_id: Some(provider.id.clone()),
            ok: true,
            latency_ms: Some(latency_ms),
            error: None,
        },
        ProbeOutcome::Unreachable(msg) => fail(msg),
        ProbeOutcome::NotImplemented => {
            fail("授权令牌已保存，但上游连通性探测尚未接入，无法确认可用".to_string())
        }
    }
}

/// 单个连接：先做配置与凭据完整性检查，再交给 `probe_connection`。
async fn check_connection(
    vault: &Arc<dyn CredentialVault>,
    provider: &ProviderRow,
    conn: &repo::ConnectionRow,
) -> TestResult {
    if CredentialKind::parse(&conn.kind) == Some(CredentialKind::Oauth) {
        return check_oauth_connection(vault, provider, conn).await;
    }
    let fail = |msg: String| test_fail(&conn.id, &provider.id, msg);
    if !provider.adapter_ready {
        return fail(format!("{ADAPTER_NOT_READY}（{}）", pending_text(provider)));
    }
    let target = match target_for_row(provider) {
        Ok(t) => t,
        Err(reason) => return fail(format!("提供商配置不完整：{reason}")),
    };
    if CredentialKind::parse(&conn.kind) != Some(CredentialKind::ApiKey) {
        if CredentialKind::parse(&conn.kind) == Some(CredentialKind::None)
            && provider.kind == "builtin"
            && catalog::find(&provider.id).is_some_and(|entry| entry.no_auth)
        {
            return match probe_connection(&target, "").await {
                ProbeOutcome::Reachable { latency_ms } => TestResult {
                    connection_id: conn.id.clone(), provider_id: Some(provider.id.clone()), ok: true,
                    latency_ms: Some(latency_ms), error: None,
                },
                ProbeOutcome::Unreachable(msg) => fail(msg),
                ProbeOutcome::NotImplemented => fail("免密钥连接已配置，但上游连通性探测尚未接入，无法确认可用".to_string()),
            };
        }
        return fail("该连接的凭据方式不受支持，当前无法测试".to_string());
    }
    let Some(cref) = conn.credential_ref.as_deref() else {
        return fail("连接缺少 API Key，请重新录入".to_string());
    };
    let secret = match vault::get(vault, cref).await {
        Ok(Some(s)) => Zeroizing::new(s),
        Ok(None) => return fail("系统凭据库中找不到该连接的 API Key，请重新录入".to_string()),
        Err(e) => return fail(format!("读取系统凭据库失败：{e}")),
    };
    match probe_connection(&target, &secret).await {
        ProbeOutcome::Reachable { latency_ms } => TestResult {
            connection_id: conn.id.clone(),
            provider_id: Some(provider.id.clone()),
            ok: true,
            latency_ms: Some(latency_ms),
            error: None,
        },
        ProbeOutcome::Unreachable(msg) => fail(msg),
        ProbeOutcome::NotImplemented => {
            fail("配置与凭据检查通过，但上游连通性探测尚未接入，无法确认可用".to_string())
        }
    }
}

/// 单项连接测试。没有适配器/探测时如实返回失败原因，不伪造成功。
pub async fn test_connection(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    connection_id: &str,
) -> AppResult<TestResult> {
    let conn = repo::get_connection(pool, connection_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("connection {connection_id}")))?;
    let provider = repo::get_provider(pool, &conn.provider_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider {}", conn.provider_id)))?;
    Ok(check_connection(vault, &provider, &conn).await)
}

pub const MAX_BATCH_TEST: usize = 200;

/// 批量测试：每个提供商返回一条或多条 TestResult（`provider_id` 标明归属）。
/// - 适配器未就绪：一条 ok=false，原因即 pending_reason；
/// - 没有可测的已启用连接：一条 ok=false，说明原因；
/// - 否则每个已启用连接一条。
pub async fn test_providers(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    ids: &[String],
) -> AppResult<Vec<TestResult>> {
    if ids.len() > MAX_BATCH_TEST {
        return Err(invalid(format!("一次最多测试 {MAX_BATCH_TEST} 个提供商")));
    }
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            continue;
        }
        let Some(provider) = repo::get_provider(pool, id).await? else {
            out.push(test_fail("", id, "提供商不存在"));
            continue;
        };
        if !provider.adapter_ready {
            out.push(test_fail("", id, format!("{ADAPTER_NOT_READY}（{}）", pending_text(&provider))));
            continue;
        }
        let conns = repo::list_connections(pool, id).await?;
        if conns.is_empty() {
            out.push(test_fail("", id, "尚未添加连接"));
            continue;
        }
        let enabled: Vec<_> = conns.iter().filter(|c| c.enabled).collect();
        if enabled.is_empty() {
            out.push(test_fail("", id, "没有已启用的连接"));
            continue;
        }
        for c in enabled {
            out.push(check_connection(vault, &provider, c).await);
        }
    }
    Ok(out)
}

fn to_model_entry(m: repo::ModelRow) -> ModelEntry {
    ModelEntry {
        id: m.id,
        upstream_model_id: m.upstream_model_id,
        public_alias: m.public_alias,
        description: m.description,
        enabled: m.enabled,
        supports_thinking: m.supports_thinking,
    }
}

/// 从上游（或预设模型库）拉取模型列表，并与数据库中现有模型合并保存：
/// 1. 若上游可用且有有效连接，尝试发送 HTTP 请求获取真实模型；
/// 2. 若上游未返回新模型或暂无连接，安全回退到预设模型库中该提供商的可用模型；
/// 3. 合并保存进数据库并保留用户此前定制的 `enabled` 状态，返回最新列表。
pub async fn fetch_models(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    oauth: &OAuthService,
    provider_id: &str,
) -> AppResult<Vec<ModelEntry>> {
    let p = repo::get_provider(pool, provider_id)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider {provider_id}")))?;

    let mut fetched = try_fetch_upstream_models(pool, vault, oauth, &p).await.unwrap_or_default();
    if fetched.is_empty() {
        let curated = catalog::curated_models_for(provider_id);
        for m in curated {
            fetched.push(ModelEntry {
                id: m.id,
                upstream_model_id: m.upstream_model_id,
                public_alias: m.public_alias,
                description: m.description,
                enabled: m.enabled,
                supports_thinking: m.supports_thinking,
            });
        }
    }

    if fetched.is_empty() {
        let existing = repo::list_models(pool, provider_id).await?;
        return Ok(existing.into_iter().map(to_model_entry).collect());
    }

    let existing = repo::list_models(pool, provider_id).await?;
    // 按稳定 id 保留用户已改的启用状态；缺 id 时退回到 upstream_model_id（用户手动加的）
    let existing_enabled: HashMap<String, bool> = existing
        .iter()
        .map(|m| (m.id.clone(), m.enabled))
        .chain(existing.iter().map(|m| (m.upstream_model_id.clone(), m.enabled)))
        .collect();

    let mut tx = pool.begin().await?;
    for (pos, m) in fetched.iter().enumerate() {
        // A manually added model can have a different internal ID. Keep its alias and settings.
        if existing.iter().any(|prev| prev.id.starts_with(&format!("{provider_id}/custom/"))
            && prev.upstream_model_id == m.upstream_model_id) {
            continue;
        }
        let enabled = existing_enabled.get(&m.id).copied().unwrap_or(m.enabled);
        sqlx::query(
            "INSERT INTO models (id, provider_id, upstream_model_id, public_alias, description, supports_thinking, enabled, position) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
             ON CONFLICT(id) DO UPDATE SET description = excluded.description, \
                supports_thinking = excluded.supports_thinking, position = excluded.position",
        )
        .bind(&m.id)
        .bind(provider_id)
        .bind(&m.upstream_model_id)
        .bind(&m.public_alias)
        .bind(&m.description)
        .bind(m.supports_thinking)
        .bind(enabled)
        .bind(pos as i64)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    let updated = repo::list_models(pool, provider_id).await?;
    Ok(updated.into_iter().map(to_model_entry).collect())
}

async fn try_fetch_upstream_models(
    pool: &SqlitePool,
    vault: &Arc<dyn CredentialVault>,
    oauth: &OAuthService,
    provider: &repo::ProviderRow,
) -> AppResult<Vec<ModelEntry>> {
    let connections = repo::list_connections(pool, &provider.id).await?;
    let active_conn = connections.iter().find(|c| c.enabled && c.status == "active");

    let mut codex_account_id = None;
    let api_key = if let Some(c) = active_conn {
        if let Some(r) = &c.credential_ref {
            if c.kind == "oauth" {
                // The vault entry holds a serialized TokenSet, never a bearer token.
                // Go through the OAuth service so an expiring token is refreshed first.
                let tokens = oauth.get_valid_token(&provider.id, r).await
                    .map_err(|e| AppError::msg(format!("OAuth 令牌不可用：{}", e.code())))?;
                if provider.id == "codex" { codex_account_id = tokens.chatgpt_account_id(); }
                let token = if provider.id == "github" {
                    tokens.extra_value("copilot_token")
                        .ok_or_else(|| AppError::msg("Copilot 推理令牌尚未兑换，请重新授权"))?
                } else { tokens.access_token.expose() };
                Some(token.to_owned())
            } else {
                vault.get(r)?
            }
        } else {
            None
        }
    } else if provider.id == "ollama-local" {
        None
    } else {
        return Ok(Vec::new());
    };

    let target = match resolve_upstream(pool, &provider.id).await {
        Ok(t) => t,
        Err(_) => return Ok(Vec::new()),
    };

    let client = reqwest::Client::builder().no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(8)).build()
        .map_err(|_| AppError::msg("创建上游客户端失败"))?;

    let (url, auth_style) = match target.adapter {
        Adapter::OpenaiCompatible | Adapter::OpenaiResponses => {
            let u = target.base_url.trim_end_matches('/');
            let m_url = if let Some(prefix) = u.strip_suffix("/chat/completions") {
                format!("{prefix}/models")
            } else if let Some(prefix) = u.strip_suffix("/responses") {
                format!("{prefix}/models")
            } else {
                format!("{u}/models")
            };
            (m_url, "bearer")
        }
        Adapter::Ollama => {
            let u = target.base_url.trim_end_matches('/');
            let tags_url = if let Some(prefix) = u.strip_suffix("/api/chat") {
                format!("{prefix}/api/tags")
            } else {
                format!("{u}/api/tags")
            };
            (tags_url, "bearer")
        }
        Adapter::AnthropicCompatible => {
            ("https://api.anthropic.com/v1/models".to_string(), "x-api-key")
        }
        Adapter::Gemini | Adapter::Vertex => {
            ("https://generativelanguage.googleapis.com/v1beta/models".to_string(), "x-goog-api-key")
        }
        // Code Assist 使用专用的项目上下文和请求信封，没有通用 GET /models 接口。
        Adapter::CodeAssist => return Ok(Vec::new()),
    };

    let mut rb = client.get(&url).header("User-Agent", if provider.id == "codex" {
        crate::upstream::client::CODEX_USER_AGENT.to_string()
    } else {
        crate::upstream::client::user_agent()
    });
    if provider.id == "github" {
        rb = rb.headers(crate::upstream::github_compat::headers());
    }
    if provider.id == "codex" {
        rb = rb.header("originator", "codex_cli_rs").header("version", crate::upstream::client::CODEX_CLI_VERSION);
        if let Some(account_id) = codex_account_id {
            rb = rb.header("ChatGPT-Account-ID", account_id);
        }
    }
    if let Some(key) = &api_key {
        match auth_style {
            "bearer" => {
                rb = rb.header("Authorization", format!("Bearer {key}"));
            }
            "x-api-key" => {
                rb = rb.header("x-api-key", key).header("anthropic-version", "2023-06-01");
            }
            "x-goog-api-key" => {
                rb = rb.header("x-goog-api-key", key);
            }
            _ => {}
        }
    }

    let resp = match crate::proxy::http::send(&provider.id, rb, std::time::Duration::from_secs(8)).await {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };
    if !resp.status().is_success() {
        return Ok(Vec::new());
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(_) => return Ok(Vec::new()),
    };
    let mut models = Vec::new();

    if let Some(arr) = body.get("data").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                let name = item.get("name").or_else(|| item.get("display_name")).and_then(|v| v.as_str()).unwrap_or(id);
                let think = item.get("thinking").is_some()
                    || id.contains("thinking")
                    || id.contains("r1")
                    || id.contains("o1")
                    || id.contains("o3");
                let alias = format!("{}/{}", provider.id, id);
                models.push(ModelEntry {
                    id: format!("{}/{}", provider.id, id),
                    upstream_model_id: id.to_string(),
                    public_alias: alias,
                    description: name.to_string(),
                    supports_thinking: think,
                    enabled: true,
                });
            }
        }
    } else if let Some(arr) = body.get("models").and_then(|v| v.as_array()) {
        for item in arr {
            let id = item.get("name").or_else(|| item.get("model")).or_else(|| item.get("slug")).or_else(|| item.get("id")).and_then(|v| v.as_str());
            if let Some(raw_id) = id {
                let clean_id = raw_id.strip_prefix("models/").unwrap_or(raw_id);
                let name = item.get("displayName").or_else(|| item.get("display_name")).and_then(|v| v.as_str()).unwrap_or(clean_id);
                let alias = format!("{}/{}", provider.id, clean_id);
                models.push(ModelEntry {
                    id: format!("{}/{}", provider.id, clean_id),
                    upstream_model_id: clean_id.to_string(),
                    public_alias: alias,
                    description: name.to_string(),
                    supports_thinking: false,
                    enabled: true,
                });
            }
        }
    }

    Ok(models)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::vault::MemoryVault;
    use crate::store;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    async fn setup() -> (SqlitePool, Arc<dyn CredentialVault>) {
        let pool = store::open_memory().await.unwrap();
        catalog::seed(&pool).await.unwrap();
        (pool, Arc::new(MemoryVault::default()))
    }

    const SECRET: &str = "sk-live-0123456789abcdef-SUPERSECRET";

    #[tokio::test]
    async fn no_auth_connection_requires_no_key_and_survives_save() {
        let (pool, vault) = setup().await;
        let summary = list(&pool).await.unwrap().into_iter().find(|p| p.id == "opencode").unwrap();
        assert_eq!(summary.auth_modes, vec![CredentialKind::None]);
        assert!(add_connection(&pool, &vault, "opencode", "", SECRET).await.is_err());
        let created = add_connection(&pool, &vault, "opencode", "", "").await.unwrap();
        assert_eq!(created.kind, CredentialKind::None);
        assert_eq!(add_connection(&pool, &vault, "opencode", "", "").await.unwrap().id, created.id);
        assert!(repo::get_connection(&pool, &created.id).await.unwrap().unwrap().credential_ref.is_none());
        let detail = get_detail(&pool, "opencode").await.unwrap();
        assert_eq!(detail.summary.status, ConnectionStatus::Connected);
        assert_eq!(save_detail(&pool, &vault, detail).await.unwrap().connections[0].kind, CredentialKind::None);
        assert!(add_connection(&pool, &vault, "opencode-zen", "", "").await.is_err());
    }

    fn conn(id: &str, label: &str) -> Connection {
        Connection {
            id: id.into(),
            provider_id: "openrouter".into(),
            account_label: label.into(),
            kind: CredentialKind::ApiKey,
            status: AccountStatus::Active,
            priority: 0,
            weight: 1,
            enabled: true,
        }
    }

    fn model(id: &str, alias: &str) -> ModelEntry {
        ModelEntry {
            id: id.into(),
            upstream_model_id: "up".into(),
            public_alias: alias.into(),
            description: String::new(),
            enabled: true,
            supports_thinking: false,
        }
    }

    // ---- 种子与目录 ----

    #[tokio::test]
    async fn seed_inserts_all_134_and_group_counts_match() {
        let (pool, _) = setup().await;
        let list = list(&pool).await.unwrap();
        assert_eq!(list.len(), 134);
        let count = |g: ProviderGroup| list.iter().filter(|p| p.group == g).count();
        assert_eq!(count(ProviderGroup::Oauth), 23);
        assert_eq!(count(ProviderGroup::Free), 24);
        assert_eq!(count(ProviderGroup::Apikey), 87);
        assert_eq!(count(ProviderGroup::Custom), 0);
        // 展示顺序：自定义 → OAuth → 免费 → API Key
        let rank = |g: ProviderGroup| match g {
            ProviderGroup::Custom => 0,
            ProviderGroup::Oauth => 1,
            ProviderGroup::Free => 2,
            ProviderGroup::Apikey => 3,
        };
        assert!(list.windows(2).all(|w| rank(w[0].group) <= rank(w[1].group)));
        assert_eq!(list[0].group, ProviderGroup::Oauth);
        // 目录元数据已带出
        let alicode = list.iter().find(|p| p.id == "alicode-intl").unwrap();
        assert_eq!(alicode.name, "Alibaba Coding");
        assert_eq!(alicode.color.as_deref(), Some("#FF6A00"));
        assert_eq!(alicode.text_icon.as_deref(), Some("ALi"));
        assert!(alicode.website.is_some());
        assert_eq!(alicode.auth_modes, vec![CredentialKind::ApiKey]);
        let chutes = list.iter().find(|p| p.id == "chutes").unwrap();
        assert_eq!(chutes.color.as_deref(), Some("#FFFFFF"), "8 位色值规范化为 6 位");
        assert_eq!(chutes.service_kinds, vec!["llm".to_string()], "未声明服务类型的按 llm 处理");
    }

    #[tokio::test]
    async fn seed_is_idempotent_and_keeps_user_data() {
        let (pool, vault) = setup().await;
        let mut d = get_detail(&pool, "openrouter").await.unwrap();
        let seeded = d.models.len();
        assert!(seeded > 0, "启动种子已预置可用模型");
        d.connections.push(conn("c-keep", "work"));
        d.models.push(model("", "or/keep"));
        d.distribution.max_concurrency = 9;
        d.thinking_level = ThinkingLevel::High;
        save_detail(&pool, &vault, d).await.unwrap();
        sqlx::query("UPDATE providers SET enabled = 0 WHERE id = 'openrouter'").execute(&pool).await.unwrap();

        catalog::seed(&pool).await.unwrap();
        catalog::seed(&pool).await.unwrap();

        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM providers").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 134, "连续 seed 不重复");
        let after = get_detail(&pool, "openrouter").await.unwrap();
        assert_eq!(after.connections.len(), 1);
        assert_eq!(after.connections[0].id, "c-keep");
        assert_eq!(after.models.len(), seeded + 1, "已存在的模型不被重复 seed，用户新增的保留");
        assert_eq!(after.distribution.max_concurrency, 9);
        assert_eq!(after.thinking_level, ThinkingLevel::High);
        let enabled: bool = sqlx::query_scalar("SELECT enabled FROM providers WHERE id = 'openrouter'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(!enabled, "seed 不得改回用户的启用开关");
    }

    #[tokio::test]
    async fn seed_does_not_overwrite_a_custom_provider_with_a_catalog_id() {
        let pool = store::open_memory().await.unwrap();
        sqlx::query(
            "INSERT INTO providers (id, kind, display_name, grp, adapter, adapter_ready, created_at, updated_at) \
             VALUES ('deepseek', 'custom', 'Mine', 'custom', 'openai-compatible', 1, 't', 't')",
        )
        .execute(&pool)
        .await
        .unwrap();
        catalog::seed(&pool).await.unwrap();
        let (name, grp): (String, String) =
            sqlx::query_as("SELECT display_name, grp FROM providers WHERE id = 'deepseek'").fetch_one(&pool).await.unwrap();
        assert_eq!((name.as_str(), grp.as_str()), ("Mine", "custom"));
    }

    #[tokio::test]
    async fn adapter_ready_matches_status_file_and_pending_always_has_reason() {
        let (pool, _) = setup().await;
        let mut ready = 0;
        for p in list(&pool).await.unwrap() {
            let st = status::get(&p.id).unwrap();
            let media_ready = crate::media::ready_provider_ids().contains(&p.id.as_str());
            assert_eq!(p.adapter_ready, st.adapter.is_some() || media_ready, "{}", p.id);
            if p.adapter_ready {
                ready += 1;
                assert!(p.pending_reason.is_none(), "{}", p.id);
                assert_eq!(p.status, ConnectionStatus::Disconnected);
            } else {
                let reason = p.pending_reason.as_deref().unwrap_or("");
                assert!(!reason.trim().is_empty(), "{} 缺少待接入原因", p.id);
                assert_eq!(Some(reason), st.reason.as_deref());
                assert_eq!(p.status, ConnectionStatus::Unsupported);
            }
        }
        let expected = status::all()
            .iter()
            .filter(|(id, s)| s.adapter.is_some() || crate::media::ready_provider_ids().contains(&id.as_str()))
            .count();
        assert_eq!(ready, expected);
        assert!(ready > 0);
        // 就绪条目的 adapter 列与状态文件一致
        let a: String = sqlx::query_scalar("SELECT adapter FROM providers WHERE id = 'anthropic'").fetch_one(&pool).await.unwrap();
        assert_eq!(a, "anthropic-compatible");
    }

    #[tokio::test]
    async fn only_oauth_like_providers_carry_a_risk_notice() {
        let (pool, _) = setup().await;
        for id in ["openrouter", "openai", "elevenlabs"] {
            assert!(get_detail(&pool, id).await.unwrap().risk_notice.is_none(), "{id}");
        }
        for id in ["claude", "antigravity", "gemini-cli", "kiro"] {
            let n = get_detail(&pool, id).await.unwrap().risk_notice.unwrap();
            assert!(n.contains("OAuth"), "{id}");
        }
    }

    /// 旧版（33 家，旧 id）数据库升级到 0002：账户、模型、请求头、历史一个不丢，id 改为目录 id。
    #[tokio::test]
    async fn migration_0002_keeps_legacy_accounts_and_renames_ids() {
        let opts = SqliteConnectOptions::new().in_memory(true).foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../../migrations/0001_init.sql")).execute(&pool).await.unwrap();
        for (id, grp) in [("nvidia-nim", "free"), ("openrouter", "free"), ("claude-code", "oauth")] {
            sqlx::query(
                "INSERT INTO providers (id, kind, display_name, grp, created_at, updated_at) VALUES (?1, 'builtin', ?1, ?2, 't', 't')",
            )
            .bind(id)
            .bind(grp)
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO providers (id, kind, display_name, grp, created_at, updated_at) VALUES ('custom-1', 'custom', 'Mine', 'custom', 't', 't')",
        )
        .execute(&pool)
        .await
        .unwrap();
        for (cid, pid) in [("c1", "nvidia-nim"), ("c2", "openrouter"), ("c3", "claude-code"), ("c4", "custom-1")] {
            sqlx::query(
                "INSERT INTO connections (id, provider_id, account_label, kind, credential_ref, created_at, updated_at) \
                 VALUES (?1, ?2, 'acct', 'apiKey', ?3, 't', 't')",
            )
            .bind(cid)
            .bind(pid)
            .bind(format!("ref-{cid}"))
            .execute(&pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO models (id, provider_id, upstream_model_id, public_alias) VALUES ('nvidia-nim/m', 'nvidia-nim', 'm', 'nv/m')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO provider_headers (provider_id, header_key, value) VALUES ('nvidia-nim', 'X-A', 'v')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO usage_requests (id, provider_id, model_id, status, created_at) VALUES ('u1', 'nvidia-nim', 'm', 'success', 't')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!("../../migrations/0002_provider_catalog.sql")).execute(&pool).await.unwrap();

        let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys").fetch_one(&pool).await.unwrap();
        assert_eq!(fk, 1, "迁移结束后必须恢复外键约束");
        let violations = sqlx::query("PRAGMA foreign_key_check").fetch_all(&pool).await.unwrap();
        assert!(violations.is_empty(), "迁移后不得有悬空外键");

        let provider_of = |cid: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, String>("SELECT provider_id FROM connections WHERE id = ?1")
                    .bind(cid)
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(provider_of("c1").await, "nvidia");
        assert_eq!(provider_of("c2").await, "openrouter");
        assert_eq!(provider_of("c3").await, "claude");
        assert_eq!(provider_of("c4").await, "custom-1");
        let m: String = sqlx::query_scalar("SELECT provider_id FROM models WHERE id = 'nvidia-nim/m'").fetch_one(&pool).await.unwrap();
        assert_eq!(m, "nvidia");
        let h: String = sqlx::query_scalar("SELECT provider_id FROM provider_headers").fetch_one(&pool).await.unwrap();
        assert_eq!(h, "nvidia");
        let u: String = sqlx::query_scalar("SELECT provider_id FROM usage_requests").fetch_one(&pool).await.unwrap();
        assert_eq!(u, "nvidia");

        // 升级后 seed：134 家齐全，连接仍在，ON DELETE CASCADE 仍然生效
        catalog::seed(&pool).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM providers").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 135, "134 家目录 + 1 家自定义");
        assert_eq!(get_detail(&pool, "nvidia").await.unwrap().connections.len(), 1);
        assert_eq!(get_detail(&pool, "claude").await.unwrap().summary.group, ProviderGroup::Oauth);
        // 旧 id 不再残留
        let legacy: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM providers WHERE id IN ('nvidia-nim', 'claude-code')")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(legacy, 0);
    }

    // ---- save_provider（整体替换语义，保留既有校验）----

    #[tokio::test]
    async fn save_connections_models_and_secret_headers() {
        let (pool, vault) = setup().await;
        let mut d = get_detail(&pool, "openrouter").await.unwrap();
        assert!(d.risk_notice.is_none());
        d.connections.push(conn("", "work"));
        d.models.push(model("", "or/gpt"));
        d.custom_headers.push(CustomHeader { key: "X-Token".into(), value: "super-secret-value".into(), secret: true });
        d.custom_headers.push(CustomHeader { key: "X-Plain".into(), value: "v".into(), secret: false });
        let saved = save_detail(&pool, &vault, d).await.unwrap();

        assert_eq!(saved.connections.len(), 1);
        assert_eq!(saved.summary.connection_count, 1);
        assert!(!saved.connections[0].id.is_empty());
        assert_eq!(saved.models.last().unwrap().id, "openrouter/up", "用户新增模型追加在预设模型之后");
        let tok = saved.custom_headers.iter().find(|h| h.key == "X-Token").unwrap();
        assert_eq!(tok.value, SECRET_MASK);
        let json = serde_json::to_string(&saved).unwrap();
        assert!(!json.contains("super-secret-value"));
        // 数据库里也没有明文
        let dump: Vec<(Option<String>,)> =
            sqlx::query_as("SELECT value FROM provider_headers").fetch_all(&pool).await.unwrap();
        assert!(dump.iter().all(|(v,)| v.as_deref() != Some("super-secret-value")));

        // 回传掩码 = 保持不变；凭据库里仍是原值
        let again = save_detail(&pool, &vault, saved.clone()).await.unwrap();
        let hdr = repo::list_headers(&pool, "openrouter").await.unwrap();
        let cref = hdr.iter().find(|h| h.secret).unwrap().credential_ref.clone().unwrap();
        assert_eq!(vault::get(&vault, &cref).await.unwrap().as_deref(), Some("super-secret-value"));
        assert_eq!(again.custom_headers.len(), 2);

        // 移除秘密头 → 凭据被清理
        let mut d2 = again.clone();
        d2.custom_headers.retain(|h| !h.secret);
        save_detail(&pool, &vault, d2).await.unwrap();
        assert_eq!(vault::get(&vault, &cref).await.unwrap(), None);
    }

    #[tokio::test]
    async fn deleting_connection_clears_its_credential() {
        let (pool, vault) = setup().await;
        let mut d = get_detail(&pool, "openrouter").await.unwrap();
        d.connections.push(conn("c-1", "a"));
        let d = save_detail(&pool, &vault, d).await.unwrap();
        set_connection_credential(&pool, &vault, "c-1", "tok-123").await.unwrap();
        let cref = repo::get_connection(&pool, "c-1").await.unwrap().unwrap().credential_ref.unwrap();
        assert_eq!(vault::get(&vault, &cref).await.unwrap().as_deref(), Some("tok-123"));

        let mut d = d;
        d.connections.clear();
        save_detail(&pool, &vault, d).await.unwrap();
        assert!(repo::get_connection(&pool, "c-1").await.unwrap().is_none());
        assert_eq!(vault::get(&vault, &cref).await.unwrap(), None);
    }

    #[tokio::test]
    async fn save_keeps_credentials_of_surviving_connections() {
        let (pool, vault) = setup().await;
        let c = add_connection(&pool, &vault, "openrouter", "keep", SECRET).await.unwrap();
        let d = get_detail(&pool, "openrouter").await.unwrap();
        save_detail(&pool, &vault, d).await.unwrap();
        let row = repo::get_connection(&pool, &c.id).await.unwrap().unwrap();
        let cref = row.credential_ref.expect("整体替换保存不得抹掉凭据引用");
        assert_eq!(vault::get(&vault, &cref).await.unwrap().as_deref(), Some(SECRET));
    }

    #[tokio::test]
    async fn alias_conflict_is_rejected_not_overwritten() {
        let (pool, vault) = setup().await;
        let mut a = get_detail(&pool, "openrouter").await.unwrap();
        a.models.push(model("", "shared/name"));
        save_detail(&pool, &vault, a).await.unwrap();

        let mut b = get_detail(&pool, "nvidia").await.unwrap();
        b.models.push(model("", "shared/name"));
        let err = save_detail(&pool, &vault, b.clone()).await.unwrap_err();
        assert!(err.to_string().contains("shared/name"));

        // 停用后不冲突
        let idx = b.models.len() - 1;
        b.models[idx].enabled = false;
        save_detail(&pool, &vault, b).await.unwrap();

        // 同一提供商内重复也被拒绝
        let mut c = get_detail(&pool, "gemini").await.unwrap();
        c.models.push(model("m1", "dup"));
        c.models.push(model("m2", "dup"));
        assert!(save_detail(&pool, &vault, c).await.is_err());
    }

    #[tokio::test]
    async fn builtin_identity_is_immutable_and_adapter_ready_is_not_client_controlled() {
        let (pool, vault) = setup().await;
        let mut d = get_detail(&pool, "openrouter").await.unwrap();
        d.summary.name = "Hacked".into();
        d.summary.adapter_ready = false;
        d.summary.pending_reason = Some("x".into());
        let saved = save_detail(&pool, &vault, d).await.unwrap();
        assert_eq!(saved.summary.name, "OpenRouter");
        assert!(saved.summary.adapter_ready);
        assert!(saved.summary.pending_reason.is_none());

        let mut unready = get_detail(&pool, "grok-web").await.unwrap();
        unready.summary.adapter_ready = true;
        let saved = save_detail(&pool, &vault, unready).await.unwrap();
        assert!(!saved.summary.adapter_ready, "客户端不能把 adapter=null 的提供商改成就绪");
    }

    #[tokio::test]
    async fn custom_provider_edits_via_save_and_creation_via_save_is_rejected() {
        let (pool, vault) = setup().await;
        let created =
            create_custom_provider(&pool, "My OpenAI", Protocol::OpenaiChat, "https://api.example.com/v1").await.unwrap();

        // 改名 + 改协议：适配器随协议同步
        let mut d = created.clone();
        d.summary.name = "Renamed".into();
        d.summary.protocols = vec![Protocol::AnthropicMessages];
        let saved = save_detail(&pool, &vault, d).await.unwrap();
        assert_eq!(saved.summary.name, "Renamed");
        assert_eq!(saved.summary.protocols, vec![Protocol::AnthropicMessages]);
        let a: String = sqlx::query_scalar("SELECT adapter FROM providers WHERE id = ?1")
            .bind(&created.summary.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(a, "anthropic-compatible");

        // 协议非法（空 / 多个）一律拒绝
        for protocols in [vec![], vec![Protocol::OpenaiChat, Protocol::Gemini]] {
            let mut bad = saved.clone();
            bad.summary.protocols = protocols;
            assert!(save_detail(&pool, &vault, bad).await.is_err());
        }

        let mut responses = saved.clone();
        responses.summary.protocols = vec![Protocol::OpenaiResponses];
        let updated = save_detail(&pool, &vault, responses).await.unwrap();
        assert_eq!(updated.summary.protocols, vec![Protocol::OpenaiResponses]);
        let adapter: String = sqlx::query_scalar("SELECT adapter FROM providers WHERE id = ?1")
            .bind(&created.summary.id).fetch_one(&pool).await.unwrap();
        assert_eq!(adapter, "openai-responses");

        // 通过 save_provider 新建自定义提供商不再允许（缺 Base URL）
        let mut fresh = saved.clone();
        fresh.summary.id = String::new();
        assert!(save_detail(&pool, &vault, fresh).await.unwrap_err().to_string().contains("create_custom_provider"));
        let mut fresh = saved.clone();
        fresh.summary.id = "custom-nope".into();
        assert!(save_detail(&pool, &vault, fresh).await.is_err());
    }

    #[tokio::test]
    async fn unknown_non_custom_provider_is_not_found() {
        let (pool, vault) = setup().await;
        let mut d = get_detail(&pool, "openrouter").await.unwrap();
        d.summary.id = "nope".into();
        d.summary.group = ProviderGroup::Oauth;
        assert!(matches!(save_detail(&pool, &vault, d).await, Err(AppError::NotFound(_))));
    }

    // ---- create / delete custom provider ----

    #[tokio::test]
    async fn create_custom_provider_validates_and_persists() {
        let (pool, _) = setup().await;
        let d = create_custom_provider(&pool, "  My Gateway  ", Protocol::Gemini, "https://gw.example.com/v1beta/").await.unwrap();
        assert!(d.summary.id.starts_with("custom-"));
        assert_eq!(d.summary.name, "My Gateway");
        assert_eq!(d.summary.group, ProviderGroup::Custom);
        assert_eq!(d.summary.protocols, vec![Protocol::Gemini]);
        assert!(d.summary.adapter_ready && d.summary.pending_reason.is_none());
        assert_eq!(d.summary.status, ConnectionStatus::Disconnected);
        assert_eq!(d.summary.auth_modes, vec![CredentialKind::ApiKey]);
        assert_eq!(d.base_url.as_deref(), Some("https://gw.example.com/v1beta"));
        assert!(d.risk_notice.is_none());
        assert_eq!(list(&pool).await.unwrap()[0].id, d.summary.id, "自定义提供商排在最前");

        // 回环地址允许 http
        create_custom_provider(&pool, "Local", Protocol::OpenaiChat, "http://127.0.0.1:11434/v1").await.unwrap();
        create_custom_provider(&pool, "Local2", Protocol::AnthropicMessages, "http://localhost:8080").await.unwrap();
        let responses = create_custom_provider(&pool, "Responses", Protocol::OpenaiResponses, "https://gw.example.com/v1").await.unwrap();
        assert_eq!(responses.summary.protocols, vec![Protocol::OpenaiResponses]);
        let adapter: String = sqlx::query_scalar("SELECT adapter FROM providers WHERE id = ?1")
            .bind(&responses.summary.id).fetch_one(&pool).await.unwrap();
        assert_eq!(adapter, "openai-responses");

        for (name, proto, url) in [
            ("", Protocol::OpenaiChat, "https://a.example.com"),
            ("   ", Protocol::OpenaiChat, "https://a.example.com"),
            (&"x".repeat(65)[..], Protocol::OpenaiChat, "https://a.example.com"),
            ("ok", Protocol::OpenaiChat, "http://a.example.com"),
            ("ok", Protocol::OpenaiChat, "a.example.com"),
            ("ok", Protocol::OpenaiChat, ""),
            ("ok", Protocol::OpenaiChat, "https://u:p@a.example.com"),
            ("ok", Protocol::OpenaiChat, "https://a.example.com/?key=1"),
        ] {
            assert!(create_custom_provider(&pool, name, proto, url).await.is_err(), "应拒绝 {name:?} {url:?}");
        }
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM providers WHERE kind = 'custom'").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 4, "被拒绝的请求不得落库");
    }

    #[tokio::test]
    async fn delete_custom_provider_clears_all_credentials_and_refuses_builtin() {
        let (pool, vault) = setup().await;
        let p = create_custom_provider(&pool, "Mine", Protocol::OpenaiChat, "https://a.example.com/v1").await.unwrap();
        let id = p.summary.id.clone();
        let c = add_connection(&pool, &vault, &id, "k1", SECRET).await.unwrap();
        let cref = repo::get_connection(&pool, &c.id).await.unwrap().unwrap().credential_ref.unwrap();
        let mut d = get_detail(&pool, &id).await.unwrap();
        d.custom_headers.push(CustomHeader { key: "X-S".into(), value: "hdr-secret".into(), secret: true });
        save_detail(&pool, &vault, d).await.unwrap();
        let href = repo::list_headers(&pool, &id).await.unwrap()[0].credential_ref.clone().unwrap();
        assert!(vault::get(&vault, &cref).await.unwrap().is_some());

        delete_custom_provider(&pool, &vault, &id).await.unwrap();
        assert!(repo::get_provider(&pool, &id).await.unwrap().is_none());
        assert!(repo::get_connection(&pool, &c.id).await.unwrap().is_none());
        assert_eq!(vault::get(&vault, &cref).await.unwrap(), None, "连接的 API Key 必须清理");
        assert_eq!(vault::get(&vault, &href).await.unwrap(), None, "秘密请求头必须清理");

        let err = delete_custom_provider(&pool, &vault, "openrouter").await.unwrap_err();
        assert!(err.to_string().contains("自定义"));
        assert!(repo::get_provider(&pool, "openrouter").await.unwrap().is_some());
        assert!(matches!(delete_custom_provider(&pool, &vault, "nope").await, Err(AppError::NotFound(_))));
    }

    // ---- add_connection / update_connection_credential ----

    #[tokio::test]
    async fn add_connection_stores_key_only_in_vault() {
        let (pool, vault) = setup().await;
        let c = add_connection(&pool, &vault, "openrouter", " work key ", &format!("  {SECRET}\n")).await.unwrap();
        assert_eq!(c.account_label, "work key");
        assert_eq!(c.kind, CredentialKind::ApiKey);
        assert!(c.enabled && c.status == AccountStatus::Active);
        assert_eq!(c.priority, 1);

        // 凭据库里是（去掉首尾空白后的）密钥，数据库里只有引用
        let row = repo::get_connection(&pool, &c.id).await.unwrap().unwrap();
        let cref = row.credential_ref.clone().unwrap();
        assert_ne!(cref, SECRET);
        assert_eq!(vault::get(&vault, &cref).await.unwrap().as_deref(), Some(SECRET));
        let dump: Vec<(String,)> = sqlx::query_as(
            "SELECT COALESCE(account_label,'') || '|' || COALESCE(credential_ref,'') || '|' || kind || '|' || status FROM connections",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(dump.iter().all(|(r,)| !r.contains("SUPERSECRET")));

        // 任何返回给前端的 JSON 都不含明文
        let detail = get_detail(&pool, "openrouter").await.unwrap();
        for json in [
            serde_json::to_string(&c).unwrap(),
            serde_json::to_string(&detail).unwrap(),
            serde_json::to_string(&list(&pool).await.unwrap()).unwrap(),
        ] {
            assert!(!json.contains("SUPERSECRET") && !json.contains(SECRET));
        }
        assert_eq!(detail.summary.connection_count, 1);
        assert_eq!(detail.summary.status, ConnectionStatus::Connected);

        // 第二个连接排在后面
        let c2 = add_connection(&pool, &vault, "openrouter", "second", "sk-other-key").await.unwrap();
        assert_eq!(c2.priority, 2);
    }

    #[tokio::test]
    async fn oauth_category_uses_declared_api_key_modes() {
        let (pool, vault) = setup().await;
        let key = add_connection(&pool, &vault, "clinepass", "team", SECRET).await.unwrap();
        assert_eq!(key.kind, CredentialKind::ApiKey);
        let err = add_connection(&pool, &vault, "claude", "team", SECRET).await.unwrap_err().to_string();
        assert!(err.contains("不支持 API Key"));
    }

    #[tokio::test]
    async fn add_connection_rejects_bad_input_without_leaking_the_key() {
        let (pool, vault) = setup().await;
        for key in ["", "   ", "\n\t", "has space inside", "line\nbreak", "nul\0byte"] {
            let err = add_connection(&pool, &vault, "openrouter", "x", key).await.unwrap_err().to_string();
            assert!(err.contains("API Key"), "{err}");
            assert!(key.trim().is_empty() || !err.contains(key.trim()), "错误信息不得回显密钥：{err}");
        }
        let too_long = "k".repeat(4097);
        let err = add_connection(&pool, &vault, "openrouter", "x", &too_long).await.unwrap_err().to_string();
        assert!(!err.contains(&too_long));
        for label in ["", "   ", "bad\nlabel"] {
            assert!(add_connection(&pool, &vault, "openrouter", label, SECRET).await.is_err());
        }
        assert!(matches!(add_connection(&pool, &vault, "nope", "x", SECRET).await, Err(AppError::NotFound(_))));
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connections").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0, "被拒绝的请求不得落库");
    }

    #[tokio::test]
    async fn add_connection_refuses_providers_without_adapter_and_explains_why() {
        let (pool, vault) = setup().await;
        for (id, expect) in [
            ("grok-web", "网页会话类暂缓"),
            ("perplexity-web", "网页会话类暂缓"),
        ] {
            let err = add_connection(&pool, &vault, id, "x", SECRET).await.unwrap_err().to_string();
            assert!(err.contains(expect), "{id}: {err}");
            assert!(!err.contains(SECRET));
        }
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM connections").fetch_one(&pool).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn media_only_providers_accept_credentials_but_are_not_chat_routable() {
        let (pool, vault) = setup().await;
        // ElevenLabs 只有媒体适配器：可以录入 Key，但聊天适配器仍为空
        assert!(status::get("elevenlabs").unwrap().adapter.is_none());
        let c = add_connection(&pool, &vault, "elevenlabs", "voice", SECRET).await.unwrap();
        assert_eq!(c.kind, CredentialKind::ApiKey);
        let detail = get_detail(&pool, "elevenlabs").await.unwrap();
        assert!(detail.summary.adapter_ready && detail.summary.pending_reason.is_none());
    }

    /// 可数条目的凭据库，用来断言失败路径不留孤儿密钥。
    #[derive(Default)]
    struct CountingVault(std::sync::Mutex<HashMap<String, String>>);
    impl CredentialVault for CountingVault {
        fn set(&self, key: &str, secret: &str) -> AppResult<()> {
            self.0.lock().unwrap().insert(key.into(), secret.into());
            Ok(())
        }
        fn get(&self, key: &str) -> AppResult<Option<String>> {
            Ok(self.0.lock().unwrap().get(key).cloned())
        }
        fn delete(&self, key: &str) -> AppResult<()> {
            self.0.lock().unwrap().remove(key);
            Ok(())
        }
    }

    #[tokio::test]
    async fn add_connection_rolls_back_vault_when_db_insert_fails() {
        let (pool, _) = setup().await;
        let counting = Arc::new(CountingVault::default());
        let vault: Arc<dyn CredentialVault> = counting.clone();
        // 让插入必然失败：把 connections 表改名
        sqlx::query("ALTER TABLE connections RENAME TO connections_gone").execute(&pool).await.unwrap();
        assert!(add_connection(&pool, &vault, "openrouter", "x", SECRET).await.is_err());
        assert!(counting.0.lock().unwrap().is_empty(), "数据库写入失败后不得残留凭据");
    }

    #[tokio::test]
    async fn update_connection_credential_replaces_and_cleans_old_secret() {
        let (pool, vault) = setup().await;
        let c = add_connection(&pool, &vault, "openrouter", "k", SECRET).await.unwrap();
        let old_ref = repo::get_connection(&pool, &c.id).await.unwrap().unwrap().credential_ref.unwrap();

        update_connection_credential(&pool, &vault, &c.id, "  sk-new-key  ").await.unwrap();
        let new_ref = repo::get_connection(&pool, &c.id).await.unwrap().unwrap().credential_ref.unwrap();
        assert_ne!(old_ref, new_ref);
        assert_eq!(vault::get(&vault, &new_ref).await.unwrap().as_deref(), Some("sk-new-key"));
        assert_eq!(vault::get(&vault, &old_ref).await.unwrap(), None);

        assert!(update_connection_credential(&pool, &vault, &c.id, "  ").await.is_err());
        assert_eq!(vault::get(&vault, &new_ref).await.unwrap().as_deref(), Some("sk-new-key"), "失败不得破坏现有密钥");
        assert!(matches!(
            update_connection_credential(&pool, &vault, "missing", "sk-x").await,
            Err(AppError::NotFound(_))
        ));

        // OAuth 连接不能录入 API Key
        sqlx::query("UPDATE connections SET kind = 'oauth' WHERE id = ?1").bind(&c.id).execute(&pool).await.unwrap();
        assert!(update_connection_credential(&pool, &vault, &c.id, "sk-x").await.is_err());
    }

    // ---- 上游目标 ----

    #[tokio::test]
    async fn resolve_upstream_for_builtin_custom_and_pending() {
        let (pool, _) = setup().await;
        let t = resolve_upstream(&pool, "openai").await.unwrap();
        assert_eq!(t.adapter, Adapter::OpenaiCompatible);
        assert_eq!(t.base_url, "https://api.openai.com/v1/chat/completions");
        assert!(t.base_url_is_full_endpoint);
        let t = resolve_upstream(&pool, "anthropic").await.unwrap();
        assert_eq!(t.adapter, Adapter::AnthropicCompatible);
        assert_eq!(t.auth, AuthSpec::Scheme(status::AuthScheme::XApiKey));

        let c = create_custom_provider(&pool, "C", Protocol::Gemini, "https://g.example.com").await.unwrap();
        let t = resolve_upstream(&pool, &c.summary.id).await.unwrap();
        assert_eq!(t.adapter, Adapter::Gemini);
        assert_eq!(t.base_url, "https://g.example.com");
        assert!(!t.base_url_is_full_endpoint);

        let err = resolve_upstream(&pool, "grok-web").await.unwrap_err().to_string();
        assert!(err.contains("网页会话类暂缓"));
        assert!(matches!(resolve_upstream(&pool, "nope").await, Err(AppError::NotFound(_))));
    }

    // ---- 测试 ----

    #[tokio::test]
    async fn test_connection_never_claims_success_without_a_probe() {
        let (pool, vault) = setup().await;
        let c = add_connection(&pool, &vault, "openrouter", "k", SECRET).await.unwrap();
        let r = test_connection(&pool, &vault, &c.id).await.unwrap();
        assert!(!r.ok && r.latency_ms.is_none());
        assert_eq!(r.provider_id.as_deref(), Some("openrouter"));
        assert!(r.error.as_deref().unwrap().contains("探测尚未接入"));
        assert!(!serde_json::to_string(&r).unwrap().contains("SUPERSECRET"));
        assert!(test_connection(&pool, &vault, "missing").await.is_err());
    }

    #[tokio::test]
    async fn test_connection_on_pending_provider_reports_reason() {
        let (pool, vault) = setup().await;
        // 适配器未就绪的连接
        oauth_conn(&pool, &vault, "grok-web", "c-old", "active", Some((Some("RT"), 3600))).await;
        let r = test_connection(&pool, &vault, "c-old").await.unwrap();
        assert!(!r.ok);
        let e = r.error.unwrap();
        assert!(e.contains("尚未接入") && e.contains("网页会话类暂缓"), "{e}");
    }

    #[tokio::test]
    async fn test_providers_reports_each_case_honestly() {
        let (pool, vault) = setup().await;
        let c = add_connection(&pool, &vault, "openrouter", "k", SECRET).await.unwrap();
        // 一个缺凭据的连接
        sqlx::query(
            "INSERT INTO connections (id, provider_id, account_label, kind, status, enabled, created_at, updated_at) \
             VALUES ('c-nokey', 'nvidia', 'nokey', 'apiKey', 'active', 1, 't', 't')",
        )
        .execute(&pool)
        .await
        .unwrap();
        // 一个凭据已从凭据库丢失的连接
        let lost = add_connection(&pool, &vault, "deepseek", "lost", "sk-lost").await.unwrap();
        let lost_ref = repo::get_connection(&pool, &lost.id).await.unwrap().unwrap().credential_ref.unwrap();
        vault::delete(&vault, &lost_ref).await.unwrap();
        // 一个已停用的连接
        let off = add_connection(&pool, &vault, "groq", "off", "sk-off").await.unwrap();
        repo::set_connection_enabled(&pool, &off.id, false).await.unwrap();

        let ids: Vec<String> = ["grok-web", "openrouter", "nvidia", "deepseek", "mistral", "groq", "missing", "grok-web"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let rs = test_providers(&pool, &vault, &ids).await.unwrap();
        assert!(rs.iter().all(|r| !r.ok), "没有真实探测，任何结果都不能是成功");
        let of = |pid: &str| -> Vec<&TestResult> { rs.iter().filter(|r| r.provider_id.as_deref() == Some(pid)).collect() };
        assert_eq!(of("grok-web").len(), 1, "重复 id 只测一次");
        assert!(of("grok-web")[0].error.as_deref().unwrap().contains("网页会话类暂缓"));
        assert_eq!(of("grok-web")[0].connection_id, "");
        assert_eq!(of("openrouter")[0].connection_id, c.id);
        assert!(of("openrouter")[0].error.as_deref().unwrap().contains("探测尚未接入"));
        assert!(of("nvidia")[0].error.as_deref().unwrap().contains("缺少 API Key"));
        assert!(of("deepseek")[0].error.as_deref().unwrap().contains("找不到"));
        assert!(of("mistral")[0].error.as_deref().unwrap().contains("尚未添加连接"));
        assert!(of("groq")[0].error.as_deref().unwrap().contains("没有已启用"));
        assert!(of("missing")[0].error.as_deref().unwrap().contains("不存在"));

        let json = serde_json::to_string(&rs).unwrap();
        assert!(!json.contains("SUPERSECRET") && !json.contains("sk-lost") && !json.contains("sk-off"));

        let many: Vec<String> = (0..=MAX_BATCH_TEST).map(|i| format!("p{i}")).collect();
        assert!(test_providers(&pool, &vault, &many).await.is_err());
    }

    #[tokio::test]
    async fn probe_hook_is_honest_by_default() {
        let (pool, _) = setup().await;
        let t = resolve_upstream(&pool, "openai").await.unwrap();
        assert_eq!(probe_connection(&t, "sk-x").await, ProbeOutcome::NotImplemented);
    }

    // ---- OAuth 连接的测试结果：如实检查授权状态，绝不假装上游探测成功 ----

    async fn oauth_conn(
        pool: &SqlitePool,
        vault: &Arc<dyn CredentialVault>,
        provider: &str,
        id: &str,
        status: &str,
        token: Option<(Option<&str>, i64)>,
    ) {
        use crate::oauth::{Secret, TokenSet, TokenStore};
        use crate::security::VaultTokenStore;
        let cref = format!("connection/{id}/r");
        sqlx::query(
            "INSERT INTO connections (id, provider_id, account_label, kind, status, credential_ref, created_at, updated_at) \
             VALUES (?1, ?2, ?1, 'oauth', ?3, ?4, 't', 't')",
        )
        .bind(id)
        .bind(provider)
        .bind(status)
        .bind(&cref)
        .execute(pool)
        .await
        .unwrap();
        if let Some((refresh, expires_in)) = token {
            let tokens = TokenSet {
                access_token: Secret::new("OAUTH-ACCESS-SECRET"),
                refresh_token: refresh.map(Secret::new),
                expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(expires_in)),
                scopes: vec![],
                extra: Default::default(),
            };
            VaultTokenStore::new(vault.clone()).save(&cref, &tokens).await.unwrap();
        }
    }

    #[tokio::test]
    async fn oauth_connection_tests_report_the_real_authorization_state() {
        let (pool, vault) = setup().await;
        oauth_conn(&pool, &vault, "claude", "ok", "active", Some((Some("RT"), 3600))).await;
        oauth_conn(&pool, &vault, "claude", "stale", "needsReauth", Some((Some("RT"), 3600))).await;
        oauth_conn(&pool, &vault, "claude", "lost", "active", None).await;
        oauth_conn(&pool, &vault, "claude", "dead", "active", Some((None, -60))).await;
        oauth_conn(&pool, &vault, "claude", "renewable", "active", Some((Some("RT"), -60))).await;
        oauth_conn(&pool, &vault, "kiro", "c-kiro-unready", "active", Some((Some("RT"), 3600))).await;
        oauth_conn(&pool, &vault, "muse", "muse-expired", "active", Some((Some("RT"), -60))).await;
        oauth_conn(&pool, &vault, "github", "gh", "active", Some((None, 3600))).await;
        sqlx::query("UPDATE connections SET credential_ref = NULL WHERE id = 'ok'").execute(&pool).await.unwrap();
        sqlx::query("UPDATE connections SET credential_ref = 'connection/ok/r' WHERE id = 'ok'").execute(&pool).await.unwrap();

        let err = |r: TestResult| {
            assert!(!r.ok, "没有真实上游探测，OAuth 连接的测试永远不能成功：{r:?}");
            assert!(r.latency_ms.is_none());
            r.error.unwrap()
        };
        let t = |id: &str| {
            let (pool, vault) = (pool.clone(), vault.clone());
            let id = id.to_string();
            async move { test_connection(&pool, &vault, &id).await.unwrap() }
        };

        // 适配器就绪的提供商：令牌可用，说明探测尚未接入
        let e = err(t("ok").await);
        assert!(e.contains("授权令牌已保存") && e.contains("无法确认可用"), "{e}");
        // 适配器未就绪的提供商：如实说明适配器尚未接入
        let e_unready = err(t("c-kiro-unready").await);
        assert!(e_unready.contains("授权令牌已保存") && e_unready.contains("适配器尚未接入"), "{e_unready}");
        assert!(err(t("stale").await).contains("需要重新授权"));
        let e = err(t("lost").await);
        assert!(e.contains("找不到") && e.contains("重新授权"), "{e}");
        assert!(err(t("dead").await).contains("已过期且无法自动刷新"));
        // 过期但可刷新：不是需要重新授权
        let e = err(t("renewable").await);
        assert!(e.contains("授权令牌已保存"), "{e}");
        // muse 不支持 refresh：过期即需重新授权，即使存着 refresh token
        assert!(err(t("muse-expired").await).contains("已过期且无法自动刷新"));
        // github：旧连接尚无 Copilot 推理令牌，不得把账户令牌送去探测
        assert!(err(t("gh").await).contains("推理凭据尚未兑换"));

        // 令牌内容绝不出现在结果里
        let all = test_providers(&pool, &vault, &["claude".into(), "github".into()]).await.unwrap();
        assert!(all.iter().all(|r| !r.ok));
        assert!(!serde_json::to_string(&all).unwrap().contains("OAUTH-ACCESS-SECRET"));
    }

    #[tokio::test]
    async fn oauth_connection_on_a_ready_adapter_still_cannot_be_confirmed_without_a_probe() {
        let (pool, vault) = setup().await;
        // 适配器就绪（自定义提供商）+ 有效令牌：只差上游探测——如实说明
        let p = create_custom_provider(&pool, "Mine", Protocol::OpenaiChat, "https://gw.example.com/v1").await.unwrap();
        oauth_conn(&pool, &vault, &p.summary.id, "mine", "active", Some((Some("RT"), 3600))).await;
        let r = test_connection(&pool, &vault, "mine").await.unwrap();
        assert!(!r.ok);
        assert!(r.error.unwrap().contains("上游连通性探测尚未接入"));
    }

    #[tokio::test]
    async fn saving_a_provider_keeps_a_needs_reauth_connection_flagged() {
        let (pool, vault) = setup().await;
        // 内置 OAuth 提供商：needsReauth 的连接不计入“活跃”，详情里如实显示
        oauth_conn(&pool, &vault, "claude", "stale", "needsReauth", Some((Some("RT"), 3600))).await;
        oauth_conn(&pool, &vault, "claude", "fine", "active", Some((Some("RT"), 3600))).await;
        let detail = get_detail(&pool, "claude").await.unwrap();
        let status_of = |id: &str| detail.connections.iter().find(|c| c.id == id).unwrap().status;
        assert_eq!(status_of("stale"), AccountStatus::NeedsReauth);
        assert_eq!(status_of("fine"), AccountStatus::Active);
        assert_eq!(detail.summary.connection_count, 2);

        // 前端回传 status=active 也不能清掉 needsReauth（只有重新授权能清）
        let p = create_custom_provider(&pool, "Mine", Protocol::OpenaiChat, "https://gw.example.com/v1").await.unwrap();
        oauth_conn(&pool, &vault, &p.summary.id, "m-stale", "needsReauth", Some((Some("RT"), 3600))).await;
        let mut d = get_detail(&pool, &p.summary.id).await.unwrap();
        d.connections[0].status = AccountStatus::Active;
        d.connections[0].account_label = "renamed".into();
        let saved = save_detail(&pool, &vault, d).await.unwrap();
        assert_eq!(saved.connections[0].status, AccountStatus::NeedsReauth);
        assert_eq!(saved.connections[0].account_label, "renamed");
        // 只有需要重新授权的连接：不显示为“已连接”
        assert_eq!(saved.summary.status, ConnectionStatus::Disconnected);
    }
}
