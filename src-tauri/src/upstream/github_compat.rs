//! GitHub Copilot IDE headers, aligned with 9Router's GitHub transport.
use reqwest::header::{HeaderMap, HeaderValue};

pub(crate) const USER_AGENT: &str = "GitHubCopilotChat/0.38.0";
pub(crate) const CLIENT_HEADERS: &[(&str, &str)] = &[
    ("editor-version", "vscode/1.110.0"),
    ("editor-plugin-version", "copilot-chat/0.38.0"),
    ("user-agent", USER_AGENT),
    ("x-github-api-version", "2025-04-01"),
];

pub(crate) fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    for &(name, value) in CLIENT_HEADERS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert("copilot-integration-id", HeaderValue::from_static("vscode-chat"));
    headers.insert("openai-intent", HeaderValue::from_static("conversation-panel"));
    headers.insert("x-vscode-user-agent-library-version", HeaderValue::from_static("electron-fetch"));
    headers.insert("x-initiator", HeaderValue::from_static("user"));
    headers.insert("x-request-id", HeaderValue::from_str(&uuid::Uuid::new_v4().to_string())
        .expect("UUID is a valid header"));
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[test]
    fn ide_headers_are_complete_and_request_ids_are_unique() {
        let first = headers();
        let second = headers();
        assert_eq!(first["editor-version"], "vscode/1.110.0");
        assert_eq!(first["editor-plugin-version"], "copilot-chat/0.38.0");
        assert_eq!(first["user-agent"], USER_AGENT);
        assert_eq!(first["copilot-integration-id"], "vscode-chat");
        assert_ne!(first["x-request-id"], second["x-request-id"]);
        assert!(!first.contains_key("authorization"));
    }

    #[tokio::test]
    async fn final_get_and_post_requests_keep_the_copilot_identity() {
        for post in [false, true] {
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
            let client = crate::upstream::UpstreamClient::new().unwrap();
            let url = url::Url::parse(&format!("http://{addr}/models")).unwrap();
            let timeout = Duration::from_secs(3);
            if post {
                client.post_json("github", url, headers(), bytes::Bytes::from_static(b"{}"), Some(timeout), timeout).await.unwrap();
            } else {
                client.get("github", url, headers(), timeout).await.unwrap();
            }
            let request = server.await.unwrap();
            assert!(request.contains("editor-version: vscode/1.110.0\r\n"));
            assert!(request.contains("user-agent: githubcopilotchat/0.38.0\r\n"));
            assert!(!request.contains("user-agent: routerdesktop/"));
        }
    }
}
