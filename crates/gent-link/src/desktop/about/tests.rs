use super::*;
use axum::{Router, routing::get};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::TcpListener;

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn release() -> Value {
    json!({
        "tag_name": "v1.2.3",
        "html_url": format!("{REPOSITORY}/releases/tag/v1.2.3"),
        "target_commitish": SHA,
        "draft": false, "prerelease": false,
        "body":"New release notes.\r\n\r\n<!-- gent-release-notes:end -->\r\n\r\n### Published crates\r\n- fixture",
    })
}

fn parse(data: Value) -> Option<Release> {
    serde_json::from_value::<GitHubRelease>(data)
        .ok()?
        .published()
}

#[test]
fn revision_link_requires_an_exact_clean_release_target() {
    let mut build = build_info::current();
    build.version = "1.2.3".into();
    build.commit = SHA.into();
    build.dirty = false;
    let mut data = release();
    let tag = data["html_url"].clone();
    let commit_url = format!("{REPOSITORY}/commit/{SHA}");
    assert_eq!(
        parse(data.clone()).unwrap().page(&build)["revision_url"],
        tag
    );
    build.dirty = true;
    assert_eq!(
        parse(data.clone()).unwrap().page(&build)["revision_url"],
        commit_url
    );
    build.dirty = false;
    for target in [
        "main",
        &SHA[..12],
        "1123456789abcdef0123456789abcdef01234567",
    ] {
        data["target_commitish"] = json!(target);
        let page = parse(data.clone()).unwrap().page(&build);
        assert_eq!(page["revision_url"], commit_url);
        assert_eq!(page["latest_release"]["url"], tag);
    }
    assert_eq!(Release::bundled().page(&build)["revision_url"], commit_url);
    build.commit = "unknown".into();
    assert!(Release::bundled().page(&build)["revision_url"].is_null());
}

#[test]
fn only_published_canonical_stable_tags_and_authored_notes_are_displayed() {
    for (field, value) in [
        ("draft", json!(true)),
        ("prerelease", json!(true)),
        ("html_url", json!("https://example.org/releases/tag/v1.2.3")),
        (
            "html_url",
            json!(format!("{REPOSITORY}/releases/tag/v1.2.4")),
        ),
        ("body", Value::Null),
        ("body", json!("\n### Published crates\n- fixture")),
    ] {
        let mut data = release();
        data[field] = value;
        assert!(parse(data).is_none(), "{field}");
    }
    for tag in [
        "1.2.3",
        "v1.02.3",
        "v1.2.3-rc.1",
        "v1.2.3/else",
        "v1.2",
        "v1.2.3.4",
    ] {
        let mut data = release();
        data["tag_name"] = json!(tag);
        data["html_url"] = json!(format!("{REPOSITORY}/releases/tag/{tag}"));
        assert!(parse(data).is_none(), "{tag}");
    }
    let mut marked = release();
    marked["body"] = json!(
        "Authored.\n\n### Published crates\nAuthored detail.\n<!-- gent-release-notes:end -->\nFooter."
    );
    assert_eq!(
        parse(marked).unwrap().notes,
        "Authored.\n\n### Published crates\nAuthored detail."
    );
    for footer in [
        "<!-- gent-release-notes:end -->",
        "**Full Changelog**: https://github.com/sam0x17/gent/compare/v1.2.2...v1.2.3",
        "### Published crates",
    ] {
        let mut data = release();
        data["body"] = json!(format!(
            "First.\r\n\r\n- Second.\r\n\r\n{footer}\r\n\r\nExtra."
        ));
        assert_eq!(parse(data).unwrap().notes, "First.\n\n- Second.");
    }
}

#[tokio::test]
async fn cache_handles_cold_offline_new_release_and_failed_refresh() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/latest", listener.local_addr().unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let app = Router::new().route(
        "/latest",
        get(move || {
            let attempt = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                match attempt {
                    0 => (axum::http::StatusCode::SERVICE_UNAVAILABLE, String::new()),
                    1 => (axum::http::StatusCode::OK, release().to_string()),
                    _ => (axum::http::StatusCode::OK, "{malformed".into()),
                }
            }
        }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut cache = Cache::default();
    for _ in 0..2 {
        let release = cache.resolve(&endpoint).await;
        assert_eq!(release.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(release.notes, BUNDLED_NOTES.trim());
        assert!(!release.notes.is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    cache.retry_at = None;
    for _ in 0..2 {
        let page = cache.resolve(&endpoint).await.page(&build_info::current());
        assert_eq!(
            page["latest_release"],
            json!({"version":"1.2.3","url":format!("{REPOSITORY}/releases/tag/v1.2.3"),"notes":"New release notes."})
        );
        assert_eq!(page["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(page["actions"][0]["kind"], "check_update");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    cache.retry_at = None;
    assert_eq!(cache.resolve(&endpoint).await.version, "1.2.3");
    assert_eq!(cache.resolve(&endpoint).await.notes, "New release notes.");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    server.abort();
}

#[tokio::test]
async fn unresponsive_server_returns_bundled_notes_within_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/latest", listener.local_addr().unwrap());
    let mut cache = Cache::default();
    let release = tokio::time::timeout(Duration::from_secs(4), cache.resolve(&endpoint))
        .await
        .unwrap();
    assert_eq!(release.notes, BUNDLED_NOTES.trim());
}
