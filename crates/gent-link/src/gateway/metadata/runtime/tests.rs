use super::*;
use crate::gateway::{assertion, registry};
use gent_daemon::config;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

const ID: &str = "https://metadata.example/client.json";
const RESOURCE: &str = "https://node.example/mcp";
const CALLBACK: &str = "https://host.example/callback";

fn policy() -> Policy {
    let mut policy = assertion::tests::policy();
    policy.client_id = ID.into();
    policy
}

fn second_policy() -> Policy {
    let keys = serde_json::to_value(policy()).unwrap()["keys"].clone();
    Policy::from_jwks(
        &serde_json::to_vec(&serde_json::json!({"keys":[keys[1]]})).unwrap(),
        ID,
    )
    .unwrap()
}

struct Fixture {
    _temp: tempfile::TempDir,
    home: PathBuf,
    registry: Registry,
    local: String,
    runtime: Arc<Runtime>,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "cimd").unwrap();
        let added = registry::add_client(
            &home,
            "metadata",
            "test/conversation",
            &home.join("client.json"),
            24,
            Some(Registration {
                resource: RESOURCE.into(),
                redirect_uris: vec![CALLBACK.into()],
                assertion: Some(policy()),
            }),
            None,
        )
        .unwrap();
        let local = added["client"].as_str().unwrap().to_string();
        let registry = Registry::open(&home).unwrap();
        let runtime = Runtime::new(
            registry.clone(),
            RESOURCE.into(),
            std::slice::from_ref(&local),
        )
        .await
        .unwrap();
        Self {
            _temp: temp,
            home,
            registry,
            local,
            runtime,
        }
    }
    async fn expire(&self) {
        let mut cache = self.runtime.clients[ID].cache.lock().await;
        cache.fresh = None;
        cache.retry = None;
        cache.attempts.clear();
    }
}

#[test]
fn cache_headers_bound_freshness_and_require_revalidation_when_uncertain() {
    use reqwest::header::{HeaderMap, HeaderValue};
    for (value, age, expected) in [
        ("public, max-age=3600", "100", 60),
        ("max-age=30", "10", 20),
        ("max-age=30", "31", 0),
        ("max-age=\"20\"", "0", 20),
        ("max-age=20, no-cache", "0", 0),
        ("max-age=20, No-Store", "0", 0),
        ("no-cache=\"field\"", "0", 0),
        ("max-age=20, max-age=20", "0", 0),
        ("max-age", "0", 0),
        ("max-age=\"20", "0", 0),
        ("max-age=+20", "0", 0),
        ("max-age=20", "+1", 0),
        ("max-age=20", "bad", 0),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert("cache-control", HeaderValue::from_str(value).unwrap());
        headers.insert("age", HeaderValue::from_str(age).unwrap());
        assert_eq!(freshness(&headers).as_secs(), expected, "{value} / {age}");
    }
    let mut headers = HeaderMap::new();
    assert_eq!(freshness(&headers), CACHE_TTL);
    headers.insert(
        "expires",
        HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
    );
    assert_eq!(freshness(&headers), Duration::ZERO);
    headers.remove("expires");
    headers.insert("cache-control", HeaderValue::from_static("max-age=3600"));
    headers.insert(
        "date",
        HeaderValue::from_static("Sun, 06 Nov 1994 08:49:37 GMT"),
    );
    assert_eq!(freshness(&headers), Duration::ZERO);
    headers.insert("date", HeaderValue::from_static("invalid"));
    assert_eq!(freshness(&headers), Duration::ZERO);
    headers.remove("date");
    headers.append("age", HeaderValue::from_static("0"));
    headers.append("age", HeaderValue::from_static("0"));
    assert_eq!(freshness(&headers), Duration::ZERO);
}

#[tokio::test]
async fn owner_selection_cache_revision_and_revocation_bound_runtime_fetches() {
    let f = Fixture::new().await;
    assert!(f.runtime.enabled());
    assert!(
        !Runtime::new(f.registry.clone(), RESOURCE.into(), &[])
            .await
            .unwrap()
            .enabled()
    );
    for selected in [
        vec![f.local.clone(), f.local.clone()],
        vec!["missing".into()],
        vec![f.local.clone(); 33],
    ] {
        assert!(
            Runtime::new(f.registry.clone(), RESOURCE.into(), &selected)
                .await
                .is_err()
        );
    }
    assert!(
        Runtime::new(
            f.registry.clone(),
            "https://other.example/mcp".into(),
            std::slice::from_ref(&f.local)
        )
        .await
        .is_err()
    );
    f.runtime
        .prepare_using("https://unapproved.example/client.json", None, |_| async {
            panic!("unselected URL fetched")
        })
        .await
        .unwrap();
    assert!(
        f.runtime
            .prepare_using(ID, Some("https://host.example/other"), |_| async {
                panic!("unapproved callback fetched")
            })
            .await
            .is_err()
    );
    let calls = AtomicUsize::new(0);
    let fetch = |_: Registration| async {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok((policy(), Duration::from_secs(600)))
    };
    f.runtime
        .prepare_using(ID, Some(CALLBACK), fetch)
        .await
        .unwrap();
    f.runtime.prepare_using(ID, None, fetch).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let fresh = f.runtime.clients[ID].cache.lock().await.fresh.unwrap();
    assert!(fresh.0.duration_since(Instant::now()) <= CACHE_TTL);
    let changed = second_policy();
    f.registry
        .set_verified_signing_keys(&f.local, changed, 0)
        .unwrap();
    f.runtime.prepare_using(ID, None, fetch).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        f.registry.signing_keys(&f.local).unwrap()["key_revision"],
        2
    );
    f.registry.revoke(&f.local).unwrap();
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async { panic!("revoked client fetched") })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn failed_cancelled_and_concurrent_refreshes_do_not_reuse_stale_metadata() {
    let f = Fixture::new().await;
    let entered = Arc::new(Notify::new());
    let waiting = entered.clone();
    let runtime = f.runtime.clone();
    let task = tokio::spawn(async move {
        runtime
            .prepare_using(ID, None, |_| async {
                entered.notify_one();
                std::future::pending::<()>().await;
                unreachable!()
            })
            .await
    });
    waiting.notified().await;
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async { panic!("concurrent fetch") })
            .await
            .unwrap_err()
            .is::<registry::Busy>()
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async { panic!("cancel backoff bypassed") })
            .await
            .unwrap_err()
            .is::<registry::Busy>()
    );
    f.expire().await;
    let state = std::fs::read(f.home.join("gateway/state.json")).unwrap();
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async { anyhow::bail!("offline") })
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(f.home.join("gateway/state.json")).unwrap(),
        state
    );
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async { panic!("failure backoff bypassed") })
            .await
            .is_err()
    );
    f.expire().await;
    for _ in 0..2 {
        f.runtime
            .prepare_using(ID, None, |_| async { Ok((policy(), Duration::ZERO)) })
            .await
            .unwrap();
    }
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async { panic!("attempt budget bypassed") })
            .await
            .unwrap_err()
            .is::<registry::Busy>()
    );
    f.expire().await;
    let permit = f.runtime.fetches.acquire_many(4).await.unwrap();
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async { panic!("global capacity bypassed") })
            .await
            .unwrap_err()
            .is::<registry::Busy>()
    );
    drop(permit);
    f.runtime
        .prepare_using(ID, None, |_| async { Ok((policy(), CACHE_TTL)) })
        .await
        .unwrap();
}

#[tokio::test]
async fn runtime_uses_tls_metadata_and_does_not_commit_a_racing_or_invalid_refresh() {
    use crate::gateway::metadata::tests::{Server, published};
    use serde_json::json;
    let f = Fixture::new().await;
    let server = Server::start().await;
    server.reply("/client.json", &serde_json::to_vec(&published()).unwrap());
    let keys = serde_json::to_value(policy()).unwrap()["keys"].clone();
    server.reply(
        "/jwks.json",
        &serde_json::to_vec(&json!({"keys":[keys[1]]})).unwrap(),
    );
    f.runtime
        .prepare_using(ID, None, |r| server.import_registration(r))
        .await
        .unwrap();
    assert_eq!(
        f.registry.signing_keys(&f.local).unwrap()["key_ids"],
        json!(["fixture-b"])
    );
    assert_eq!(server.requests.lock().unwrap().len(), 2);
    f.runtime
        .prepare_using(ID, None, |r| server.import_registration(r))
        .await
        .unwrap();
    assert_eq!(server.requests.lock().unwrap().len(), 2);
    f.expire().await;
    let state = std::fs::read(f.home.join("gateway/state.json")).unwrap();
    let mut changed = published();
    changed["redirect_uris"] = json!(["https://host.example/new"]);
    server.reply("/client.json", &serde_json::to_vec(&changed).unwrap());
    assert!(
        f.runtime
            .prepare_using(ID, None, |r| server.import_registration(r))
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(f.home.join("gateway/state.json")).unwrap(),
        state
    );
    f.expire().await;
    assert!(
        f.runtime
            .prepare_using(ID, None, |_| async {
                // The publisher response was obtained for revision 1, but a local
                // update commits a different set before the runtime can apply it.
                f.registry
                    .set_verified_signing_keys(&f.local, policy(), 1)
                    .unwrap();
                let stale = second_policy();
                Ok((stale, CACHE_TTL))
            })
            .await
            .is_err()
    );
    assert_eq!(
        f.registry.signing_keys(&f.local).unwrap()["key_revision"],
        2
    );
    assert!(f.runtime.clients[ID].cache.lock().await.fresh.is_none());
}
