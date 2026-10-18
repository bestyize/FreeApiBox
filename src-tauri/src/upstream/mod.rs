//! 上游层：与真实模型供应商通信。归属：转发管线。
//!
//! - [`Adapter`] trait（PRODUCT_DESIGN §5.1）：`capabilities` / `invoke` / `stream` / `list_models`。
//!   适配器：[`openai_compat::OpenAiCompatAdapter`]（`/chat/completions`）、
//!   [`anthropic_compat::AnthropicCompatAdapter`]（`/v1/messages`）、
//!   [`responses_compat::ResponsesAdapter`]（`/responses`）、
//!   [`gemini_compat::GeminiAdapter`]（`/v1beta/models/<m>:generateContent`，头 `x-goog-api-key`）、
//!   [`vertex_compat::VertexAdapter`]（Vertex express 模式，API Key）、
//!   [`ollama_compat::OllamaAdapter`]（`/api/chat`，NDJSON）。不同供应商的差异（base URL、路径、
//!   鉴权头）由 [`endpoint::ResolvedEndpoint`] 配置给出，而不是写死在代码里。
//! - [`sse_decode`]：上游 SSE 字节流 → 帧 → [`crate::protocols::StreamEvent`] 状态机。
//! - 安全：密钥只通过 [`Secret`] 携带（Debug 脱敏、释放时清零）；错误类型不包含 URL、请求头或正文。

pub mod anthropic_compat;
pub mod auth;
pub mod client;
pub mod code_assist;
pub mod codebuddy_compat;
pub mod endpoint;
pub mod gemini_compat;
pub(crate) mod github_compat;
mod iflow_signing;
pub mod ollama_compat;
pub mod openai_compat;
pub(crate) mod opencode_compat;
pub mod responses_compat;
pub mod sse_decode;
pub mod vertex_compat;

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use url::Url;
use zeroize::Zeroizing;

pub use auth::AuthStyle;
pub use client::{ClientOptions, UpstreamClient};
pub use endpoint::{NotReady, ResolvedEndpoint};

use crate::protocols::ProtocolKind;

pub const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";
/// 成功响应体上限（非流式）。
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// 非 2xx 响应体读取上限；超出部分丢弃。
pub const MAX_ERROR_BODY_BYTES: usize = 256 * 1024;

// ───────────────────────── 基础类型 ─────────────────────────

/// 携带秘密字符串：Debug 脱敏，释放时清零。
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(Zeroizing::new(s.into()))
    }

    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdapterKind {
    OpenAiCompatible,
    AnthropicCompatible,
    /// OpenAI Responses 上游（`POST <base>/responses`）。
    OpenAiResponses,
    /// Google AI Studio 的 Gemini API（`x-goog-api-key`）。
    Gemini,
    /// Google Code Assist OAuth（Gemini CLI / Antigravity）的 v1internal 信封。
    CodeAssist,
    /// Vertex AI，**仅 express 模式**（API Key）。服务账号 / OAuth 访问令牌的配置尚未接入。
    Vertex,
    Ollama,
}

impl AdapterKind {
    pub const ALL: [AdapterKind; 7] = [
        AdapterKind::OpenAiCompatible,
        AdapterKind::AnthropicCompatible,
        AdapterKind::OpenAiResponses,
        AdapterKind::Gemini,
        AdapterKind::CodeAssist,
        AdapterKind::Vertex,
        AdapterKind::Ollama,
    ];

    pub fn id(self) -> &'static str {
        match self {
            AdapterKind::OpenAiCompatible => "openai-compatible",
            AdapterKind::AnthropicCompatible => "anthropic-compatible",
            AdapterKind::OpenAiResponses => "openai-responses",
            AdapterKind::Gemini => "gemini",
            AdapterKind::CodeAssist => "code-assist",
            AdapterKind::Vertex => "vertex",
            AdapterKind::Ollama => "ollama",
        }
    }

    pub fn from_id(id: &str) -> Option<Self> {
        let id = id.trim();
        Self::ALL.into_iter().find(|k| k.id() == id)
    }

    /// 该适配器与上游交谈使用的协议。
    pub fn native_protocol(self) -> ProtocolKind {
        match self {
            AdapterKind::OpenAiCompatible => ProtocolKind::OpenAiChat,
            AdapterKind::AnthropicCompatible => ProtocolKind::AnthropicMessages,
            AdapterKind::OpenAiResponses => ProtocolKind::OpenAiResponses,
            AdapterKind::Gemini | AdapterKind::CodeAssist => ProtocolKind::Gemini,
            AdapterKind::Vertex => ProtocolKind::Vertex,
            AdapterKind::Ollama => ProtocolKind::Ollama,
        }
    }

    pub fn default_auth(self) -> AuthStyle {
        match self {
            AdapterKind::OpenAiCompatible | AdapterKind::OpenAiResponses | AdapterKind::Ollama => AuthStyle::Bearer,
            AdapterKind::AnthropicCompatible => AuthStyle::XApiKey,
            // Gemini 的 `?key=` 查询参数形式不使用：密钥一律走请求头
            AdapterKind::Gemini | AdapterKind::Vertex => AuthStyle::Header(gemini_compat::API_KEY_HEADER.into()),
            AdapterKind::CodeAssist => AuthStyle::Bearer,
        }
    }

    pub fn adapter(self) -> &'static dyn Adapter {
        match self {
            AdapterKind::OpenAiCompatible => &openai_compat::OpenAiCompatAdapter,
            AdapterKind::AnthropicCompatible => &anthropic_compat::AnthropicCompatAdapter,
            AdapterKind::OpenAiResponses => &responses_compat::ResponsesAdapter,
            AdapterKind::Gemini => &gemini_compat::GeminiAdapter,
            AdapterKind::CodeAssist => &code_assist::CodeAssistAdapter,
            AdapterKind::Vertex => &vertex_compat::VertexAdapter,
            AdapterKind::Ollama => &ollama_compat::OllamaAdapter,
        }
    }

    /// 上游流的分帧方式：Ollama 是 NDJSON，其余是 SSE。
    pub fn framing(self) -> StreamFraming {
        match self {
            AdapterKind::Ollama => StreamFraming::Ndjson,
            _ => StreamFraming::Sse,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamFraming {
    Sse,
    Ndjson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    pub streaming: bool,
    pub tools: bool,
    pub vision: bool,
    pub reasoning: bool,
    pub list_models: bool,
}

/// 「该配置尚未接入」的标记（放在 `UpstreamError::Config` 文案里）。网关据此返回 501 而不是 500。
pub const NOT_READY_MARKER: &str = "[adapter-not-ready]";

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// 本地配置问题（密钥格式、URL 等）；不会重试。
    #[error("upstream configuration error: {0}")]
    Config(String),
    #[error("could not connect to the upstream")]
    Connect,
    #[error("the upstream request timed out")]
    Timeout,
    #[error("{0}")]
    Network(String),
    #[error("{0}")]
    Malformed(String),
}

/// 一次出站调用所需的全部信息（每个账号一份）。
#[derive(Debug, Clone)]
pub struct UpstreamTarget {
    pub provider_id: String,
    pub connection_id: String,
    pub endpoint: ResolvedEndpoint,
    pub api_key: Option<Secret>,
    /// 用户在提供商里配置的 Custom Headers（秘密头的值已从凭据库取出）。
    pub extra_headers: Vec<(String, Secret)>,
    pub timeout: Duration,
}

impl UpstreamTarget {
    /// 所有秘密值（用于从错误信息里擦除）。过短的值不参与，避免误伤普通文本。
    pub fn secrets(&self) -> Vec<String> {
        self.api_key
            .iter()
            .map(|s| s.expose().to_string())
            .chain(self.extra_headers.iter().map(|(_, v)| v.expose().to_string()))
            .filter(|s| s.len() >= 6)
            .collect()
    }
}

impl UpstreamError {
    /// 配置本身是合法的，但对应的接入方式尚未实现（例如 Vertex 的服务账号 / OAuth 令牌）。不会重试、不影响账号健康。
    pub fn not_ready(reason: impl std::fmt::Display) -> Self {
        UpstreamError::Config(format!("{NOT_READY_MARKER} {reason}"))
    }
}

#[derive(Clone)]
pub struct UpstreamRequest {
    /// 已是适配器原生协议的 JSON。
    pub body: Value,
    /// 上游真实模型 ID。Gemini / Vertex 的模型在 URL 路径里，其余协议已写在 `body` 中。
    pub model: String,
    pub stream: bool,
    /// 入口协议与上游协议相同（透传）。
    pub passthrough: bool,
    /// 额外转发的请求头（仅 `anthropic-version` / `anthropic-beta`，且仅透传时）。
    pub extra_headers: Vec<(HeaderName, HeaderValue)>,
}

// 请求 / 响应正文可能含用户内容，Debug 输出只给出体量，绝不打印正文。
impl std::fmt::Debug for UpstreamRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamRequest")
            .field("body", &"<omitted>")
            .field("model", &self.model)
            .field("stream", &self.stream)
            .field("passthrough", &self.passthrough)
            .field("extra_headers", &self.extra_headers.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Clone)]
pub struct UpstreamReply {
    pub status: u16,
    pub retry_after: Option<Duration>,
    pub content_type: Option<String>,
    pub body: Bytes,
}

impl std::fmt::Debug for UpstreamReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamReply")
            .field("status", &self.status)
            .field("retry_after", &self.retry_after)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl UpstreamReply {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

pub struct UpstreamStream {
    pub status: u16,
    pub body: BoxStream<'static, Result<Bytes, UpstreamError>>,
}

pub enum StreamOpen {
    /// 上游返回 2xx，响应体是 SSE 字节流。
    Stream(UpstreamStream),
    /// 上游返回了非 2xx，附带已读取（有上限）的响应体。
    Rejected(UpstreamReply),
}

// ───────────────────────── Adapter ─────────────────────────

#[async_trait]
pub trait Adapter: Send + Sync {
    fn kind(&self) -> AdapterKind;

    fn capabilities(&self) -> Capabilities;

    /// 聊天 / 消息端点 URL。
    fn endpoint_url(&self, target: &UpstreamTarget) -> Url;

    /// 本次请求的完整 URL。默认就是 [`endpoint_url`](Self::endpoint_url)；模型在路径里的协议（Gemini / Vertex）覆盖它。
    /// URL 里**不得**出现密钥。
    fn request_url(&self, target: &UpstreamTarget, _req: &UpstreamRequest) -> Url {
        self.endpoint_url(target)
    }

    /// 模型列表端点 URL。
    fn models_url(&self, target: &UpstreamTarget) -> Url;

    /// 发送前的目标校验（例如 Vertex 拒绝服务账号 / OAuth 令牌）。失败时不会发出任何请求。
    fn validate_target(&self, _target: &UpstreamTarget) -> Result<(), UpstreamError> {
        Ok(())
    }

    /// `Accept` 头：默认流式为 `text/event-stream`，非流式为 `application/json`。
    fn accept(&self, stream: bool) -> &'static str {
        if stream {
            "text/event-stream"
        } else {
            "application/json"
        }
    }

    /// 适配器特有的请求头（鉴权头与自定义头之外）。
    fn protocol_headers(&self, _target: &UpstreamTarget, _req: &UpstreamRequest) -> HeaderMap {
        HeaderMap::new()
    }

    /// 发送前对请求体做适配器级调整。
    fn prepare_body(&self, _body: &mut Value, _req: &UpstreamRequest, _target: &UpstreamTarget) {}

    /// 非流式调用：任何 HTTP 状态都以 `Ok(UpstreamReply)` 返回，由路由层分类；只有传输失败才是 `Err`。
    async fn invoke(
        &self,
        client: &UpstreamClient,
        target: &UpstreamTarget,
        req: UpstreamRequest,
    ) -> Result<UpstreamReply, UpstreamError> {
        let resp = send(self, client, target, req, false).await?;
        reply_from(resp).await
    }

    /// 流式调用：2xx 返回字节流；非 2xx 返回 `Rejected`（尚未向客户端写出任何字节，可以回退）。
    async fn stream(
        &self,
        client: &UpstreamClient,
        target: &UpstreamTarget,
        req: UpstreamRequest,
    ) -> Result<StreamOpen, UpstreamError> {
        use futures_util::StreamExt;
        let resp = send(self, client, target, req, true).await?;
        if resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.bytes_stream().map(|r| r.map_err(|e| client::classify_error(&e))).boxed();
            Ok(StreamOpen::Stream(UpstreamStream { status, body }))
        } else {
            Ok(StreamOpen::Rejected(reply_from(resp).await?))
        }
    }

    /// 上游模型 ID 列表。
    async fn list_models(&self, client: &UpstreamClient, target: &UpstreamTarget) -> Result<Vec<String>, UpstreamError> {
        self.validate_target(target)?;
        let mut headers = build_headers(self, target, None, false)?;
        headers.remove(CONTENT_TYPE);
        let resp = client.get(&target.provider_id, self.models_url(target), headers, target.timeout).await?;
        let status = resp.status();
        let body = client::read_body(resp, MAX_ERROR_BODY_BYTES * 4, true).await?;
        if !status.is_success() {
            return Err(UpstreamError::Network(format!("the upstream answered the model list request with HTTP {}", status.as_u16())));
        }
        let v: Value = serde_json::from_slice(&body)
            .map_err(|_| UpstreamError::Malformed("the upstream model list is not valid JSON".into()))?;
        let items = v.get("data").and_then(Value::as_array).or_else(|| v.as_array());
        Ok(items
            .map(|a| a.iter().filter_map(|m| m.get("id").and_then(Value::as_str).map(str::to_string)).collect())
            .unwrap_or_default())
    }
}

const FORBIDDEN_CUSTOM_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "user-agent",
    "proxy-authorization",
    "proxy-connection",
];

fn build_headers<A: Adapter + ?Sized>(
    adapter: &A,
    target: &UpstreamTarget,
    req: Option<&UpstreamRequest>,
    stream: bool,
) -> Result<HeaderMap, UpstreamError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static(adapter.accept(stream)));
    if let Some(r) = req {
        headers.extend(adapter.protocol_headers(target, r));
    } else {
        // 模型列表等无请求体场景：只需要协议版本头
        let empty = UpstreamRequest { body: Value::Null, model: String::new(), stream: false, passthrough: false, extra_headers: vec![] };
        headers.extend(adapter.protocol_headers(target, &empty));
    }
    match (&target.api_key, target.endpoint.auth.needs_key()) {
        (Some(key), true) => target.endpoint.auth.apply(&mut headers, key.expose())?,
        (None, true) => return Err(UpstreamError::Config("no credential is available for this connection".into())),
        _ => {}
    }
    for (name, value) in &target.extra_headers {
        let lname = name.to_ascii_lowercase();
        if FORBIDDEN_CUSTOM_HEADERS.contains(&lname.as_str()) {
            continue;
        }
        let (Ok(n), Ok(mut v)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value.expose())) else {
            return Err(UpstreamError::Config(format!("custom header \"{name}\" is not valid")));
        };
        v.set_sensitive(true);
        headers.insert(n, v);
    }
    if let Some(r) = req {
        for (n, v) in &r.extra_headers {
            headers.insert(n.clone(), v.clone());
        }
    }
    // CodeBuddy uses a provider-specific OpenAI-compatible gateway (9Router).
    // Keep these headers provider-scoped and never apply them to user-defined endpoints.
    if codebuddy_compat::is_codebuddy(&target.provider_id) {
        let ide = if target.provider_id == "codebuddy-cn" { "CLI" } else { "IDE" };
        headers.insert("x-product", HeaderValue::from_static("SaaS"));
        headers.insert("x-ide-type", HeaderValue::from_static(ide));
        headers.insert("x-ide-name", HeaderValue::from_static(ide));
        headers.insert("x-requested-with", HeaderValue::from_static("XMLHttpRequest"));
        headers.insert("x-codebuddy-request", HeaderValue::from_static("1"));
    }
    if target.provider_id == "iflow" {
        let key = target.api_key.as_ref().ok_or_else(||
            UpstreamError::Config("iFlow requires an access token to sign requests".into()))?;
        iflow_signing::add_signature_headers(&mut headers, key.expose())?;
    }
    if matches!(target.provider_id.as_str(), "minimax-code" | "minimax-code-global") {
        // The MiniMax Code agent gateway expects Mavis metadata even on
        // requests with a valid OAuth bearer token.
        headers.insert("x-mavis-agent-id", HeaderValue::from_static("main"));
        headers.insert("x-api-key", HeaderValue::from_static("sk-xxx"));
        let session = uuid::Uuid::new_v4().to_string();
        headers.insert("x-mavis-session-id", HeaderValue::from_str(&session)
            .expect("UUID session is a valid header"));
        let seconds = chrono::Local::now().offset().local_minus_utc().to_string();
        headers.insert("x-mavis-timezone-offset", HeaderValue::from_str(&seconds)
            .expect("numeric timezone offset is a valid header"));
    }
    if target.provider_id == "claude" {
        // Claude OAuth requires the Claude Code beta and OAuth feature flags.
        // Keep caller beta flags (e.g. prompt caching), without duplicates.
        const REQUIRED: &[&str] = &[
            "claude-code-20250219", "oauth-2025-04-20",
            "interleaved-thinking-2025-05-14", "context-management-2025-06-27",
        ];
        let mut flags: Vec<String> = REQUIRED.iter().map(|s| s.to_string()).collect();
        if let Some(value) = headers.get("anthropic-beta") {
            if let Ok(raw) = value.to_str() {
                for flag in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    if !flags.iter().any(|existing| existing == flag) { flags.push(flag.to_string()); }
                }
            }
        }
        headers.insert("anthropic-beta", HeaderValue::from_str(&flags.join(","))
            .map_err(|_| UpstreamError::Config("invalid Anthropic beta header".into()))?);
    }
    if target.provider_id == "github" {
        headers.extend(github_compat::headers());
    }
    // Keep OpenCode Free's v2 wire headers separate from paid Zen and custom endpoints.
    opencode_compat::add_headers(target, &mut headers);
    if target.provider_id == "codex" {
        headers.insert("originator", HeaderValue::from_static("codex_cli_rs"));
        headers.insert("version", HeaderValue::from_static(client::CODEX_CLI_VERSION));
        headers.insert("session_id", HeaderValue::from_str(&target.connection_id)
            .map_err(|_| UpstreamError::Config("invalid connection id".into()))?);
        if let Some(r) = req {
            if responses_compat::codex_uses_lite(&r.body, &r.model) {
                headers.insert("x-openai-internal-codex-responses-lite", HeaderValue::from_static("true"));
            }
        }
    }
    Ok(headers)
}

async fn send<A: Adapter + ?Sized>(
    adapter: &A,
    client: &UpstreamClient,
    target: &UpstreamTarget,
    mut req: UpstreamRequest,
    stream: bool,
) -> Result<reqwest::Response, UpstreamError> {
    adapter.validate_target(target)?;
    let headers = build_headers(adapter, target, Some(&req), stream)?;
    let url = adapter.request_url(target, &req);
    let mut body = std::mem::take(&mut req.body);
    adapter.prepare_body(&mut body, &req, target);
    opencode_compat::prepare_body(&mut body, target);
    let bytes = Bytes::from(serde_json::to_vec(&body).map_err(|_| UpstreamError::Config("request body could not be serialised".into()))?);
    let total = if stream { None } else { Some(target.timeout) };
    // 日志里只有主机与路径：查询串（如 `?alt=sse`）与凭据都不记录
    tracing::debug!(provider = %target.provider_id, url = %endpoint::display_url(&url), stream, "upstream request");
    client.post_json(&target.provider_id, url, headers, bytes, total, target.timeout).await
}

async fn reply_from(resp: reqwest::Response) -> Result<UpstreamReply, UpstreamError> {
    let status = resp.status().as_u16();
    let retry_after = resp.headers().get(reqwest::header::RETRY_AFTER).and_then(client::parse_retry_after);
    let content_type = resp.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_string);
    let ok = resp.status().is_success();
    let body = client::read_body(resp, if ok { MAX_RESPONSE_BYTES } else { MAX_ERROR_BODY_BYTES }, !ok).await?;
    Ok(UpstreamReply { status, retry_after, content_type, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copilot_ide_headers_cover_every_native_transport_and_model_lists() {
        for kind in [AdapterKind::OpenAiCompatible, AdapterKind::AnthropicCompatible, AdapterKind::OpenAiResponses] {
            let mut target = UpstreamTarget { provider_id: "github".into(), connection_id: "c".into(),
                endpoint: ResolvedEndpoint::new(kind, Url::parse("https://api.githubcopilot.com").unwrap(), AuthStyle::Bearer),
                api_key: Some(Secret::new("copilot-test-token")), extra_headers: vec![], timeout: Duration::from_secs(10) };
            for stream in [false, true] {
                let headers = build_headers(kind.adapter(), &target, None, stream).unwrap();
                assert_eq!(headers["editor-version"], "vscode/1.110.0");
                assert_eq!(headers["editor-plugin-version"], "copilot-chat/0.38.0");
                assert_eq!(headers["copilot-integration-id"], "vscode-chat");
                assert_eq!(headers["authorization"], "Bearer copilot-test-token");
            }
            target.provider_id = "custom-other".into();
            let headers = build_headers(kind.adapter(), &target, None, false).unwrap();
            assert!(!headers.contains_key("editor-version"));
            assert!(!headers.contains_key("copilot-integration-id"));
        }
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("sk-very-secret-value");
        assert!(!format!("{s:?}").contains("very-secret"));
        assert_eq!(s.expose(), "sk-very-secret-value");
    }

    #[test]
    fn debug_output_never_contains_bodies_or_keys() {
        let req = UpstreamRequest {
            body: serde_json::json!({"messages": [{"role": "user", "content": "TOP-SECRET-PROMPT"}]}),
            model: "m".into(),
            stream: false,
            passthrough: true,
            extra_headers: vec![],
        };
        assert!(!format!("{req:?}").contains("TOP-SECRET-PROMPT"));
        let reply = UpstreamReply { status: 500, retry_after: None, content_type: None, body: Bytes::from_static(b"TOP-SECRET-REPLY") };
        assert!(!format!("{reply:?}").contains("TOP-SECRET-REPLY"));
        let target = UpstreamTarget {
            provider_id: "p".into(),
            connection_id: "c".into(),
            endpoint: ResolvedEndpoint::new(
                AdapterKind::OpenAiCompatible,
                Url::parse("https://api.example.com/v1").unwrap(),
                AuthStyle::Bearer,
            ),
            api_key: Some(Secret::new("sk-debug-secret-key")),
            extra_headers: vec![("X-Token".into(), Secret::new("hdr-debug-secret"))],
            timeout: Duration::from_secs(1),
        };
        let dbg = format!("{target:?}");
        assert!(!dbg.contains("sk-debug-secret-key") && !dbg.contains("hdr-debug-secret"), "{dbg}");
    }

    #[test]
    fn claude_oauth_merges_required_beta_with_client_flags() {
        let target = UpstreamTarget { provider_id: "claude".into(), connection_id: "c".into(),
            endpoint: ResolvedEndpoint::new(AdapterKind::AnthropicCompatible,
                Url::parse("https://api.anthropic.com/v1/messages").unwrap(), AuthStyle::Bearer),
            api_key: Some(Secret::new("secret")), extra_headers: vec![], timeout: Duration::from_secs(10) };
        let req = UpstreamRequest { body: serde_json::json!({}), model: "claude-sonnet".into(),
            stream: true, passthrough: true,
            extra_headers: vec![(HeaderName::from_static("anthropic-beta"), HeaderValue::from_static("custom-beta,oauth-2025-04-20"))] };
        let headers = build_headers(&anthropic_compat::AnthropicCompatAdapter, &target, Some(&req), true).unwrap();
        let beta = headers.get("anthropic-beta").unwrap().to_str().unwrap();
        assert!(beta.contains("claude-code-20250219") && beta.contains("context-management-2025-06-27"));
        assert!(beta.contains("custom-beta"));
        assert_eq!(beta.matches("oauth-2025-04-20").count(), 1);
    }

    #[test]
    fn adapter_kind_ids_roundtrip() {
        for k in AdapterKind::ALL {
            assert_eq!(AdapterKind::from_id(k.id()), Some(k));
            assert_eq!(k.adapter().kind(), k);
        }
        assert_eq!(AdapterKind::from_id("none"), None);
        assert_eq!(AdapterKind::Vertex.native_protocol(), ProtocolKind::Vertex);
        assert_eq!(AdapterKind::Ollama.framing(), StreamFraming::Ndjson);
        assert_eq!(AdapterKind::Gemini.framing(), StreamFraming::Sse);
        assert_eq!(AdapterKind::Gemini.default_auth(), AuthStyle::Header("x-goog-api-key".into()));
    }
}
