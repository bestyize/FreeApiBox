//! 出站 HTTP 客户端。
//!
//! 红线：
//! - 默认 `User-Agent` 为 `RouterDesktop/<版本>`；Codex 使用对应 CLI 的身份头。
//! - 不禁用 TLS 证书校验，不跟随重定向（避免把自定义密钥头带到其它主机）。
//! - 错误只暴露分类，不携带 URL / 请求头 / 正文。

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use url::Url;

use super::UpstreamError;
use crate::proxy::{ProxyPool, Route};

pub const USER_AGENT_PREFIX: &str = "RouterDesktop";
pub const CODEX_CLI_VERSION: &str = "0.159.0";
pub const CODEX_USER_AGENT: &str = "codex_cli_rs/0.159.0";
pub const CLAUDE_USER_AGENT: &str = "claude-cli/2.1.280 (external, sdk-cli)";
pub const CODEBUDDY_CN_USER_AGENT: &str = "CLI/2.108.1 CodeBuddy/2.108.1";
pub const CODEBUDDY_INTL_USER_AGENT: &str = "IDE/2.108.1 CodeBuddy/2.108.1";
pub const MINIMAX_CODE_USER_AGENT: &str = "MiniMaxAgent";

pub fn user_agent() -> String {
    format!("{USER_AGENT_PREFIX}/{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Clone)]
pub struct ClientOptions {
    pub connect_timeout: Duration,
    /// 忽略环境代理；生产默认开启，由应用代理池明确选路。
    pub no_proxy: bool,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self { connect_timeout: Duration::from_secs(15), no_proxy: true }
    }
}

#[derive(Clone)]
pub struct UpstreamClient {
    http: reqwest::Client,
    /// 代理池：生产直连客户端忽略环境代理，代理节点由池配置决定。
    pool: Option<Arc<ProxyPool>>,
}

impl std::fmt::Debug for UpstreamClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UpstreamClient")
    }
}

/// 把 reqwest 错误归类成不含 URL 的 [`UpstreamError`]。
pub(crate) fn classify_error(e: &reqwest::Error) -> UpstreamError {
    if e.is_timeout() {
        UpstreamError::Timeout
    } else if e.is_connect() {
        UpstreamError::Connect
    } else if e.is_body() || e.is_decode() {
        UpstreamError::Network("the connection was closed or reset while receiving the response".into())
    } else if e.is_redirect() {
        UpstreamError::Network("the upstream attempted a redirect, which is not followed".into())
    } else {
        UpstreamError::Network("the request could not be completed".into())
    }
}

impl UpstreamClient {
    pub fn new() -> Result<Self, UpstreamError> {
        Self::with_options(ClientOptions::default())
    }

    pub fn with_options(opts: ClientOptions) -> Result<Self, UpstreamError> {
        let mut b = reqwest::Client::builder()
            .user_agent(user_agent())
            .connect_timeout(opts.connect_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .pool_idle_timeout(Duration::from_secs(60));
        if opts.no_proxy {
            b = b.no_proxy();
        }
        let http = b.build().map_err(|_| UpstreamError::Config("failed to build the HTTP client".into()))?;
        Ok(Self { http, pool: None })
    }

    /// 接入代理池：之后的出站请求按池配置选路。
    pub fn with_pool(mut self, pool: Arc<ProxyPool>) -> Self {
        self.pool = Some(pool);
        self
    }

    /// 按代理池给出的尝试顺序发送。代理连不上（`is_connect`）才换下一个节点并记失败；
    /// 其它错误（上游超时、响应错误）与代理无关，原样返回。
    async fn send_routed<F, Fut>(&self, provider_id: &str, url: &Url, mut attempt: F) -> Result<reqwest::Response, UpstreamError>
    where
        F: FnMut(reqwest::Client) -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, SendFailure>>,
    {
        let routes = match &self.pool {
            Some(pool) => pool.plan_for_url(provider_id, url),
            None => vec![Route::Direct],
        };
        if routes.is_empty() {
            tracing::warn!(provider = %provider_id, "代理池已开启但没有可用节点，已阻止直连");
            return Err(UpstreamError::Connect);
        }
        let mut last = UpstreamError::Connect;
        for route in routes {
            let (client, node) = match route {
                Route::Direct => (self.http.clone(), None),
                Route::Proxy { node_id, client } => (client, Some(node_id)),
            };
            match attempt(client).await {
                Ok(resp) if node.is_some() && resp.status().as_u16() == 407 => {
                    if let (Some(pool), Some(id)) = (&self.pool, &node) {
                        pool.report_failure(id, "代理认证失败（HTTP 407）");
                    }
                    last = UpstreamError::Network("proxy authentication failed (HTTP 407)".into());
                    continue;
                }
                Ok(resp) => {
                    if let (Some(pool), Some(id)) = (&self.pool, &node) {
                        pool.report_success(id);
                    }
                    return Ok(resp);
                }
                Err(SendFailure { error, connect_failed }) => {
                    if let (Some(pool), Some(id)) = (&self.pool, &node) {
                        if connect_failed {
                            pool.report_failure(id, "无法连接到代理，或代理拒绝了连接");
                            last = error;
                            continue;
                        }
                    }
                    return Err(error);
                }
            }
        }
        Err(last)
    }

    pub(crate) async fn post_json(
        &self,
        provider_id: &str,
        url: Url,
        mut headers: HeaderMap,
        body: Bytes,
        total_timeout: Option<Duration>,
        header_timeout: Duration,
    ) -> Result<reqwest::Response, UpstreamError> {
        let agent = match provider_id {
            "opencode" if super::opencode_compat::free_user_agent(provider_id, &url).is_some() =>
                super::opencode_compat::free_user_agent(provider_id, &url).expect("checked endpoint").to_string(),
            "codex" => CODEX_USER_AGENT.to_string(),
            "github" => super::github_compat::USER_AGENT.to_string(),
            "claude" => CLAUDE_USER_AGENT.to_string(),
            "codebuddy-cn" => CODEBUDDY_CN_USER_AGENT.to_string(),
            "codebuddy-intl" => CODEBUDDY_INTL_USER_AGENT.to_string(),
            "minimax-code" | "minimax-code-global" => MINIMAX_CODE_USER_AGENT.to_string(),
            _ => user_agent(),
        };
        headers.insert(USER_AGENT, HeaderValue::from_str(&agent).expect("static user agent"));
        self.send_routed(provider_id, &url, |http| {
            let mut rb = http.post(url.clone()).headers(headers.clone()).body(body.clone());
            if let Some(t) = total_timeout {
                rb = rb.timeout(t);
            }
            async move {
                match tokio::time::timeout(header_timeout, rb.send()).await {
                    Ok(Ok(resp)) => Ok(resp),
                    Ok(Err(e)) => Err(SendFailure::from(e)),
                    Err(_) => Err(SendFailure { error: UpstreamError::Timeout, connect_failed: false }),
                }
            }
        })
        .await
    }

    pub(crate) async fn get(
        &self,
        provider_id: &str,
        url: Url,
        mut headers: HeaderMap,
        timeout: Duration,
    ) -> Result<reqwest::Response, UpstreamError> {
        let agent = super::opencode_compat::free_user_agent(provider_id, &url).map(str::to_string)
            .unwrap_or_else(|| if provider_id == "github" { super::github_compat::USER_AGENT.to_string() } else { user_agent() });
        headers.insert(USER_AGENT, HeaderValue::from_str(&agent).expect("static user agent"));
        self.send_routed(provider_id, &url, |http| {
            let rb = http.get(url.clone()).headers(headers.clone()).timeout(timeout);
            async move { rb.send().await.map_err(SendFailure::from) }
        })
        .await
    }
}

/// 一次发送失败：`connect_failed` 为真表示请求尚未送达（连不上代理 / 隧道失败），可安全换节点重试。
pub(crate) struct SendFailure {
    error: UpstreamError,
    connect_failed: bool,
}

impl From<reqwest::Error> for SendFailure {
    fn from(e: reqwest::Error) -> Self {
        Self { connect_failed: e.is_connect(), error: classify_error(&e) }
    }
}

/// 读取响应体。`truncate = true` 时超过 `limit` 的部分被丢弃（用于错误响应）；否则超限返回错误。
pub(crate) async fn read_body(resp: reqwest::Response, limit: usize, truncate: bool) -> Result<Bytes, UpstreamError> {
    let mut stream = resp.bytes_stream();
    let mut buf = BytesMut::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| classify_error(&e))?;
        if buf.len() + chunk.len() > limit {
            if truncate {
                let room = limit - buf.len();
                buf.extend_from_slice(&chunk[..room]);
                break;
            }
            return Err(UpstreamError::Malformed("the upstream response is too large".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}

/// `Retry-After`：整数秒或 HTTP-date。
pub(crate) fn parse_retry_after(v: &HeaderValue) -> Option<Duration> {
    let s = v.to_str().ok()?.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let when = chrono::DateTime::parse_from_rfc2822(s).ok()?;
    let delta = when.with_timezone(&chrono::Utc) - chrono::Utc::now();
    Some(Duration::from_secs(delta.num_seconds().max(0) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agent_is_fixed() {
        assert_eq!(user_agent(), format!("RouterDesktop/{}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn opencode_headers_are_selected_only_for_free_inference() {
        let free = Url::parse("https://opencode.ai/inference/v1/chat/completions").unwrap();
        assert_eq!(super::super::opencode_compat::free_user_agent("opencode", &free), Some("opencode/latest/2.0.26/cli"));
        assert!(super::super::opencode_compat::free_user_agent("opencode-zen", &free).is_none());
        assert!(super::super::opencode_compat::free_user_agent("custom", &free).is_none());
        let paid = Url::parse("https://opencode.ai/zen/v1/chat/completions").unwrap();
        assert!(super::super::opencode_compat::free_user_agent("opencode", &paid).is_none());
    }

    #[tokio::test]
    async fn final_http_sender_keeps_opencode_user_agent_on_the_wire() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            let mut chunk = [0u8; 1024];
            while !received.windows(4).any(|part| part == b"\r\n\r\n") {
                let n = socket.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                received.extend_from_slice(&chunk[..n]);
            }
            socket.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}").await.unwrap();
            String::from_utf8(received).unwrap().to_lowercase()
        });
        let client = UpstreamClient {
            http: reqwest::Client::builder().no_proxy().resolve("opencode.ai", addr).build().unwrap(),
            pool: None,
        };
        // DNS points the genuine hostname at the local test server; no public request is sent.
        let url = Url::parse(&format!("http://opencode.ai:{}/inference/v1/chat/completions", addr.port())).unwrap();
        client.post_json("opencode", url, HeaderMap::new(), Bytes::from_static(b"{}"),
            Some(Duration::from_secs(3)), Duration::from_secs(3)).await.unwrap();
        let request = server.await.unwrap();
        assert!(request.contains("user-agent: opencode/latest/2.0.26/cli\r\n"));
        assert!(!request.contains("user-agent: routerdesktop/"));
    }

    #[test]
    fn retry_after_forms() {
        assert_eq!(parse_retry_after(&HeaderValue::from_static("7")), Some(Duration::from_secs(7)));
        assert_eq!(parse_retry_after(&HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT")), Some(Duration::ZERO));
        assert_eq!(parse_retry_after(&HeaderValue::from_static("soon")), None);
        let future = (chrono::Utc::now() + chrono::Duration::seconds(90)).to_rfc2822();
        let d = parse_retry_after(&HeaderValue::from_str(&future).unwrap()).unwrap();
        assert!(d.as_secs() >= 88 && d.as_secs() <= 90, "{d:?}");
    }
}
