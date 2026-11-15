use super::*;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

fn transcript() -> (String, Vec<Value>) {
    let session = uuid::Uuid::new_v4().to_string();
    let user = uuid::Uuid::new_v4().to_string();
    let assistant = uuid::Uuid::new_v4().to_string();
    let duration = uuid::Uuid::new_v4().to_string();
    let rows = vec![
        json!({"type":"queue-operation","sessionId":session,"operation":"enqueue","content":"PRIVATE_PROMPT"}),
        json!({"type":"queue-operation","sessionId":session,"operation":"dequeue"}),
        json!({"type":"user","sessionId":session,"cwd":"/work","uuid":user,"parentUuid":null,"message":{"role":"user","content":"PRIVATE_PROMPT"}}),
        json!({"type":"api-request","sessionId":session}),
        json!({"type":"assistant","sessionId":session,"cwd":"/work","uuid":assistant,"parentUuid":user,"message":{"role":"assistant","stop_reason":"end_turn","content":[{"type":"text","text":"PRIVATE_RESPONSE"}]}}),
        json!({"type":"system","subtype":"turn_duration","sessionId":session,"uuid":duration,"parentUuid":assistant}),
    ];
    (session, rows)
}
fn bytes(rows: &[Value]) -> Vec<u8> {
    rows.iter()
        .map(|r| r.to_string() + "\n")
        .collect::<String>()
        .into_bytes()
}

#[test]
fn only_complete_linear_history_without_retained_input_allows_recovery() {
    let (session, rows) = transcript();
    inspect(bytes(&rows).as_slice(), &session, Path::new("/work")).unwrap();
    for case in [
        "incomplete",
        "queue",
        "foreign",
        "scope",
        "fork",
        "duplicate",
        "failed",
        "compacted",
        "request",
        "unknown_queue",
    ] {
        let mut bad = rows.clone();
        match case {
            "incomplete" => {
                bad.pop();
            }
            "queue" => {
                bad.remove(1);
            }
            "foreign" => bad[4]["sessionId"] = json!(uuid::Uuid::new_v4().to_string()),
            "scope" => bad[4]["cwd"] = json!("/other"),
            "fork" => bad[4]["parentUuid"] = Value::Null,
            "duplicate" => bad.push(bad[4].clone()),
            "failed" => bad[4]["isApiErrorMessage"] = true.into(),
            "compacted" => bad[5]["subtype"] = "compact_boundary".into(),
            "request" => bad.push(json!({"type":"api-request","sessionId":session})),
            "unknown_queue" => bad[1]["operation"] = "clear".into(),
            _ => unreachable!(),
        }
        let error = inspect(bytes(&bad).as_slice(), &session, Path::new("/work")).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE_"), "{case}");
    }
    let mut truncated = bytes(&rows);
    truncated.pop();
    assert!(inspect(truncated.as_slice(), &session, Path::new("/work")).is_err());
    assert!(
        inspect(
            b"PRIVATE_INVALID_JSON\n".as_slice(),
            &session,
            Path::new("/work")
        )
        .is_err()
    );
}

#[test]
fn stable_owned_history_is_required_without_creating_or_modifying_files() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("native.jsonl");
    let (session, rows) = transcript();
    fs::write(&path, bytes(&rows)).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let evidence = read(&path, &session, Path::new("/work")).unwrap();
    evidence.verify().unwrap();
    let alias = root.path().join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(evidence.verify().is_err());
    fs::remove_file(&alias).unwrap();
    let evidence = read(&path, &session, Path::new("/work")).unwrap();
    fs::write(&path, b"{}").unwrap();
    assert!(evidence.verify().is_err());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&alias, &path).unwrap();
    assert!(read(&path, &session, Path::new("/work")).is_err());
    assert!(!alias.exists());
}

#[test]
fn delayed_parent_writes_are_resolved_but_cycles_and_missing_parents_refuse() {
    let (session, rows) = transcript();
    let mut delayed = rows.clone();
    delayed.swap(2, 4);
    // A completed terminal response must still follow the final request.
    let request = delayed.remove(3);
    delayed.insert(2, request);
    inspect(bytes(&delayed).as_slice(), &session, Path::new("/work")).unwrap();
    for case in ["cycle", "missing", "branch", "unknown"] {
        let mut changed = rows.clone();
        match case {
            "cycle" => changed[2]["parentUuid"] = changed[4]["uuid"].clone(),
            "missing" => changed[2]["parentUuid"] = uuid::Uuid::new_v4().to_string().into(),
            "branch" => {
                let mut branch = changed[4].clone();
                branch["uuid"] = uuid::Uuid::new_v4().to_string().into();
                changed.push(branch);
            }
            "unknown" => changed.push(json!({"type":"future-native-work"})),
            _ => unreachable!(),
        }
        assert!(
            inspect(bytes(&changed).as_slice(), &session, Path::new("/work")).is_err(),
            "{case}"
        );
    }
}
