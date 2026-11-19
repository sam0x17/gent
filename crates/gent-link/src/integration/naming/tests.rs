use super::*;
use crate::integration::{Bindings, Host, record_hook};
use futures_util::{SinkExt, StreamExt};
use gent_daemon::config;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
use tokio::net::UnixListener;
use tokio_tungstenite::tungstenite::Message;

fn temp() -> tempfile::TempDir {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[test]
fn titles_are_labels_and_never_inferred_from_prompt_content() {
    assert_eq!(title(&json!("  cit  ")).as_deref(), Some("cit"));
    for value in [
        Value::Null,
        json!(4),
        json!("  "),
        json!("cit\nsecret"),
        json!("bad\u{1b}title"),
    ] {
        assert!(title(&value).is_none());
    }
    let long = title(&json!(format!("{}🐈", "é".repeat(63)))).unwrap();
    assert_eq!(long, "é".repeat(63));
    config::label(&long).unwrap();
}

fn transcript(root: &Path, session: &str, rows: &[Value]) -> PathBuf {
    let path = root.join(format!("{session}.jsonl"));
    let bytes = rows.iter().map(|r| format!("{r}\n")).collect::<String>();
    config::write_private(&path, bytes.as_bytes()).unwrap();
    path
}

#[test]
fn claude_titles_use_only_bound_metadata_and_prefer_custom_titles() {
    let root = temp();
    let session = uuid::Uuid::now_v7().to_string();
    let path = transcript(
        root.path(),
        &session,
        &[
            json!({"type":"user","sessionId":session,"message":{"content":"never a title"}}),
            json!({"type":"ai-title","sessionId":session,"aiTitle":"generated"}),
            json!({"type":"custom-title","sessionId":"another","customTitle":"wrong chat"}),
            json!({"type":"custom-title","sessionId":session,"customTitle":"cit"}),
            json!({"type":"ai-title","sessionId":session,"aiTitle":"later generated"}),
        ],
    );
    let mut event = json!({"session_id":session,"transcript_path":path});
    assert_eq!(claude_title(&event).as_deref(), Some("cit"));
    let directory = root.path().join(&session);
    config::private_dir(&directory).unwrap();
    config::write_private(
        &directory.join("custom-title.json"),
        br#"{"customTitle":"sidecar title"}"#,
    )
    .unwrap();
    assert_eq!(claude_title(&event).as_deref(), Some("sidecar title"));
    event["agent_id"] = json!("child");
    assert!(claude_title(&event).is_none());
    event.as_object_mut().unwrap().remove("agent_id");
    event["session_id"] = json!(uuid::Uuid::now_v7().to_string());
    assert!(claude_title(&event).is_none());
}

#[test]
fn claude_title_reads_allow_groups_but_reject_world_writes_links_and_partial_records() {
    let root = temp();
    let session = uuid::Uuid::now_v7().to_string();
    let path = transcript(root.path(), &session, &[]);
    let event = json!({"session_id":session,"transcript_path":path});
    let record = json!({"type":"ai-title","sessionId":session,"aiTitle":"fresh"});
    let mut bytes = vec![b'x'; TAIL_BYTES as usize + 10];
    bytes.extend(format!("\n{record}\n{{\"type\":\"custom-title\"").bytes());
    config::write_private(&path, &bytes).unwrap();
    assert_eq!(claude_title(&event).as_deref(), Some("fresh"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    assert_eq!(claude_title(&event).as_deref(), Some("fresh"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(claude_title(&event).is_none());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let other = root.path().join("original");
    fs::rename(&path, &other).unwrap();
    symlink(&other, &path).unwrap();
    assert!(claude_title(&event).is_none());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&other, &path).unwrap();
    assert!(claude_title(&event).is_none());
}

#[tokio::test]
async fn hook_titles_follow_exact_call_bindings_and_explicit_names_bypass_discovery() {
    let root = temp();
    config::private_dir(root.path()).unwrap();
    config::initialize(root.path(), "naming").unwrap();
    let session = uuid::Uuid::now_v7().to_string();
    let path = transcript(
        root.path(),
        &session,
        &[json!({"type":"custom-title","sessionId":session,"customTitle":"cit"})],
    );
    let args = json!({"provider":"claude-code"});
    let event = json!({"hook_event_name":"PreToolUse", "session_id":session,
        "transcript_path":path,"tool_use_id":"call","tool_name":"mcp__gent__gent_register","tool_input":args});
    record_hook(root.path(), &event, crate::integration::now().unwrap()).unwrap();
    let mut bindings = Bindings::new(root.path(), Host::ClaudeCode).unwrap();
    let meta = json!({"claudecode/toolUseId":"call"});
    let credential = bindings
        .credential("claude-code", &meta, "gent_register", &args)
        .unwrap();
    let source = bindings
        .registration_name(&meta, &credential, &args)
        .unwrap();
    assert_eq!(source.resolve(&credential, "claude-code").await, "cit");
    assert!(
        bindings
            .registration_name(&meta, "another-key", &args)
            .is_err()
    );
    assert!(
        bindings
            .registration_name(&meta, &credential, &json!({"provider":"other"}))
            .is_err()
    );
    assert!(
        bindings
            .registration_name(
                &json!({"claudecode/toolUseId":"missing"}),
                &credential,
                &args
            )
            .is_err()
    );
    let mut explicit = event.clone();
    explicit["tool_use_id"] = json!("explicit");
    explicit["tool_input"]["name"] = json!("my alias");
    record_hook(root.path(), &explicit, crate::integration::now().unwrap()).unwrap();
    let ticket = bindings
        .ticket(
            &json!({"claudecode/toolUseId":"explicit"}),
            "gent_register",
            &explicit["tool_input"],
        )
        .unwrap();
    assert!(ticket.registration_name.is_none());
}

#[tokio::test]
async fn codex_reads_only_the_bound_thread_title_and_falls_back_on_unavailable_metadata() {
    let root = temp();
    config::private_dir(root.path()).unwrap();
    let endpoint = root.path().join("host.sock");
    let listener = UnixListener::bind(&endpoint).unwrap();
    fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o600)).unwrap();
    let thread = uuid::Uuid::now_v7().to_string();
    let expected = thread.clone();
    let task = tokio::spawn(async move {
        for response in [
            json!({"thread":{"id":expected,"name":"cit","preview":"private prompt"}}),
            json!({"thread":{"id":"another-thread","name":"wrong chat"}}),
            json!({"thread":{"id":expected,"name":null,"preview":"never use preview"}}),
        ] {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(Message::Text(text))) = stream.next().await {
                let call: Value = serde_json::from_str(&text).unwrap();
                if call["method"] == "initialized" {
                    continue;
                }
                let result = match call["method"].as_str().unwrap() {
                    "initialize" => json!({}),
                    "thread/read" => {
                        assert_eq!(
                            call["params"],
                            json!({"threadId":expected,"includeTurns":false})
                        );
                        response.clone()
                    }
                    other => panic!("unexpected native operation: {other}"),
                };
                stream
                    .send(Message::Text(
                        json!({"id":call["id"],"result":result}).to_string().into(),
                    ))
                    .await
                    .unwrap();
                if call["method"] == "thread/read" {
                    break;
                }
            }
        }
    });
    let source = || Source::Codex {
        endpoint: endpoint.clone(),
        thread: thread.clone(),
    };
    assert_eq!(source().resolve("first", "codex").await, "cit");
    let fallback = Source::Title(None).resolve("first", "codex").await;
    assert_eq!(source().resolve("first", "codex").await, fallback);
    assert_eq!(source().resolve("first", "codex").await, fallback);
    task.await.unwrap();
    assert_eq!(source().resolve("first", "codex").await, fallback);
    assert_ne!(
        Source::Title(None).resolve("second", "codex").await,
        fallback
    );
    assert!(fallback.starts_with("codex-"));
}
