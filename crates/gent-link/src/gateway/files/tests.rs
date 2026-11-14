use super::*;
use crate::gateway::metadata::tests::Server;

#[test]
fn file_inputs_require_exact_origins_and_the_published_file_schema() {
    let id = uuid::Uuid::new_v4().to_string();
    let runtime = Runtime::new(&[format!("{id}=https://files.example")], |_| Ok(())).unwrap();
    assert!(runtime.enabled());
    for origin in [
        "http://files.example",
        "https://files.example/",
        "https://files.example/path",
        "https://*.example",
        "https://files.example:443",
        "https://127.0.0.1",
        "https://files.example?q=1",
    ] {
        assert!(Runtime::new(&[format!("{id}={origin}")], |_| Ok(())).is_err());
    }
    assert!(
        Runtime::new(&[format!("{id}=https://files.example")], |_| anyhow::bail!(
            "inactive"
        ))
        .is_err()
    );
    assert!(Runtime::new(&vec![format!("{id}=https://files.example"); 2], |_| Ok(())).is_err());
    endpoint("https://files.example/data?signature=secret%2Bvalue").unwrap();
    for url in [
        "https://user:pass@files.example/data",
        "https://files.example./data",
        "https://files.example/data#frag",
        "https://[::1]/data",
        "https://files.example:8443/data",
        "https://files.example/a/../data",
    ] {
        assert!(endpoint(url).is_err());
    }
    let schema = serde_json::to_value(tool()).unwrap();
    assert_eq!(schema["_meta"]["openai/fileParams"], json!(["file"]));
    let file = &schema["inputSchema"]["properties"]["file"];
    assert_eq!(file["required"], json!(["download_url", "file_id"]));
    assert_eq!(file["properties"].as_object().unwrap().len(), 4);
    assert_eq!(schema["annotations"]["readOnlyHint"], false);
    assert!(
        serde_json::from_value::<Input>(
            json!({"request_id":"x","file":{"download_url":"x","file_id":"y"}})
        )
        .is_ok()
    );
    for extra in [
        json!({"path":"/etc/passwd"}),
        json!({"file_name":null}),
        json!({"mime_type":123}),
    ] {
        let mut input = json!({"request_id":"x","file":{"download_url":"x","file_id":"y"}});
        input["file"]
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(serde_json::from_value::<Input>(input).is_err());
    }
}

#[tokio::test]
async fn downloads_verify_tls_bound_bodies_and_never_follow_redirects() {
    let server = Server::start().await;
    let url = endpoint("https://metadata.example/file?signature=private").unwrap();
    let bytes = vec![39; MAX_BYTES];
    server.reply("/file?signature=private", &bytes);
    assert_eq!(*response(&server.client(&url), &url).await.unwrap(), bytes);
    for raw in [
        b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/private\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
        b"HTTP/1.1 206 Partial Content\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".to_vec(),
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BYTES + 1
        )
        .into_bytes(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort".to_vec(),
    ] {
        server.raw_reply("/file?signature=private", raw);
        assert!(response(&server.client(&url), &url).await.is_err());
    }
    let mut unbounded = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
    unbounded.resize(unbounded.len() + MAX_BYTES + 1, 42);
    server.raw_reply("/file?signature=private", unbounded);
    assert!(response(&server.client(&url), &url).await.is_err());
    server.reply("/file?signature=private", b"");
    assert!(
        response(&server.client(&url), &url)
            .await
            .unwrap()
            .is_empty()
    );
    for request in server.requests.lock().unwrap().iter() {
        let request = request.to_ascii_lowercase();
        assert!(request.starts_with("get /file?signature=private "));
        for header in ["authorization:", "cookie:", "referer:", "gent/"] {
            assert!(!request.contains(header));
        }
    }
    // Existing metadata tests exercise public-address classification and pinned
    // TLS trust. The file path uses those same production builders and validator.
    assert!(super::super::metadata::destinations(vec!["127.0.0.1:443".parse().unwrap()]).is_err());
}
