//! URL-free diagnostics for the request-to-response-headers phase. The caller's
//! client retains its timeout, redirect and authentication policy unchanged.
use reqwest::{RequestBuilder, Response};
use std::{
    error::Error,
    fmt,
    time::{Duration, Instant},
};

pub(super) async fn send(request: RequestBuilder) -> Result<Response, Failure> {
    let started = Instant::now();
    request.send().await.map_err(|error| Failure {
        error: error.without_url(),
        elapsed: started.elapsed(),
    })
}

pub(super) struct Failure {
    error: reqwest::Error,
    elapsed: Duration,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "relay HTTP request failed (timeout={}, connect={}, elapsed_ms={})",
            self.error.is_timeout(),
            self.error.is_connect(),
            self.elapsed.as_millis(),
        )
    }
}

impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn assert_private(failure: &Failure) {
        for text in [failure.to_string(), format!("{failure:?}")] {
            assert!(!text.contains("http://"));
            assert!(!text.contains("private-mailbox"));
            assert!(!text.contains("private-token"));
            assert!(text.contains("elapsed_ms="));
        }
        assert!(failure.error.url().is_none());
    }

    #[tokio::test]
    async fn response_wait_timeout_is_distinct_from_connect_and_keeps_its_source() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let failure = send(client.get(format!(
            "http://{address}/private-mailbox?token=private-token"
        )))
        .await
        .unwrap_err();
        server.abort();
        let _ = server.await;
        assert!(failure.error.is_timeout());
        assert!(!failure.error.is_connect());
        assert!(failure.elapsed >= Duration::from_millis(200));
        assert_private(&failure);
        let wrapped = anyhow::Error::new(failure);
        let source = wrapped
            .chain()
            .find_map(|cause| cause.downcast_ref::<reqwest::Error>())
            .unwrap();
        assert!(source.is_timeout());
    }

    #[tokio::test]
    async fn connection_refusal_is_classified_without_rendering_the_url() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let failure = send(client.get(format!(
            "http://{address}/private-mailbox?token=private-token"
        )))
        .await
        .unwrap_err();
        assert!(!failure.error.is_timeout());
        assert!(failure.error.is_connect());
        assert_private(&failure);
    }
}
