use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
const ORIGIN: &str = "https://node.example";

fn target() -> DownloadTarget {
    DownloadTarget {
        file: Uuid::new_v4().to_string(),
        origin: ORIGIN.into(),
        expires_at: auth::now().unwrap() + 3600,
    }
}
fn signed_change(token: &str, credential: &str, key: &str, value: Value) -> String {
    let mut claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(token.split_once('.').unwrap().0)
            .unwrap(),
    )
    .unwrap();
    claims[key] = value;
    let bytes = serde_json::to_vec(&claims).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(credential.as_bytes()).unwrap();
    mac.update(b"gent-file-download-v1\0");
    mac.update(&bytes);
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&bytes),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

#[test]
fn download_tokens_bind_file_origin_registry_and_agent_without_exporting_credentials() {
    let f = Fixture::new();
    let credential = f.bind("private-source");
    let other = f.bind("other");
    let target = target();
    let meta = json!({"test/conversation":"private-source"});
    let (token, expiry) = f
        .registry
        .issue_download_local(&f.permit(), &meta, &credential, &target)
        .unwrap();
    assert!(expiry <= auth::now().unwrap() + 300);
    let result = Registry::open(&f.home)
        .unwrap()
        .check_download_local(&token, ORIGIN)
        .unwrap();
    assert_eq!(result.file, target.file);
    assert_eq!(result.credential, credential);
    assert!(
        f.registry
            .issue_download_local(&f.permit(), &meta, &other, &target)
            .is_err()
    );
    assert!(
        f.registry
            .check_download_local(&token, "https://other.example")
            .is_err()
    );
    let (payload, signature) = token.split_once('.').unwrap();
    let raw = URL_SAFE_NO_PAD.decode(payload).unwrap();
    let text = String::from_utf8(raw.clone()).unwrap();
    assert!(!text.contains(&credential));
    assert!(!text.contains("private-source"));
    let mut changed: Value = serde_json::from_slice(&raw).unwrap();
    changed["file"] = json!(Uuid::new_v4().to_string());
    let forged = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&changed).unwrap()),
        signature
    );
    assert!(f.registry.check_download_local(&forged, ORIGIN).is_err());
    for bad in [
        "".to_string(),
        format!("{token}.extra"),
        format!("{payload}.{}", URL_SAFE_NO_PAD.encode([0; 32])),
        "x".repeat(4097),
    ] {
        assert!(f.registry.check_download_local(&bad, ORIGIN).is_err());
    }
    for (key, value) in [
        ("version", json!(2)),
        ("registry", json!(Uuid::new_v4().to_string())),
        ("file", json!("../file")),
        ("expires_at", json!(auth::now().unwrap() + 301)),
        ("expires_at", json!(1)),
        ("issued_at", json!(auth::now().unwrap() + 600)),
    ] {
        assert!(
            f.registry
                .check_download_local(&signed_change(&token, &credential, key, value), ORIGIN)
                .is_err(),
            "{key}"
        );
    }
    f.registry.revoke(&f.id).unwrap();
    assert!(f.registry.check_download_local(&token, ORIGIN).is_err());
}

#[test]
fn download_minting_and_fetch_reject_expired_authority_missing_bindings_and_backward_clock() {
    let f = Fixture::new();
    let credential = f.bind("a");
    let meta = json!({"test/conversation":"a"});
    let mut target = target();
    target.expires_at = 1;
    assert!(
        f.registry
            .issue_download_local(&f.permit(), &meta, &credential, &target)
            .is_err()
    );
    target.expires_at = auth::now().unwrap() + 10;
    let (token, expiry) = f
        .registry
        .issue_download_local(&f.permit(), &meta, &credential, &target)
        .unwrap();
    assert_eq!(expiry, target.expires_at);
    let mut state = f.registry.read().unwrap();
    let old = state.clock;
    state.clock = auth::now().unwrap() + 600;
    f.registry.save(&state).unwrap();
    assert!(f.registry.check_download_local(&token, ORIGIN).is_err());
    state.clock = old;
    state.clients.get_mut(&f.id).unwrap().bindings.clear();
    f.registry.save(&state).unwrap();
    assert!(f.registry.check_download_local(&token, ORIGIN).is_err());
}
