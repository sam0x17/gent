use super::*;
use serde_json::json;
use std::io::Write;

#[test]
fn capture_and_recheck_native_transcript_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let session = Uuid::new_v4().to_string();
    let project = dir.path().join("projects/private-project");
    fs::create_dir_all(&project).unwrap();
    let file = project.join(format!("{session}.jsonl"));
    let ts = "2026-11-23T07:00:00.000Z";
    let at = chrono::DateTime::parse_from_rfc3339(ts)
        .unwrap()
        .timestamp_millis();
    let goal = || {
        json!({"type":"attachment","sessionId":session,"uuid":Uuid::new_v4(),"timestamp":ts,
        "attachment":{"type":"goal_status","condition":"private objective","met":false}})
    };
    let error = json!({"type":"assistant","isApiErrorMessage":true,"uuid":Uuid::new_v4(),
        "timestamp":ts,"sessionId":session,"message":{"content":"private provider body"}});
    let base = format!("{}\n{error}\n", goal());
    let append = |row: &Value| {
        writeln!(
            fs::OpenOptions::new().append(true).open(&file).unwrap(),
            "{row}"
        )
        .unwrap();
    };
    fs::write(&file, &base).unwrap();
    assert!(
        super::capture(dir.path(), &session, &file, at + 1, at + 5)
            .unwrap()
            .is_none(),
        "accepted the previous turn's provider error"
    );
    let capture = || capture(dir.path(), &session, &file, at, at).unwrap();
    let failure = Record {
        source: capture().unwrap(),
        turn: Uuid::new_v4(),
        failed_at: at / 1000,
        reason: Failure::RateLimit,
    };
    assert!(!serde_json::to_string(&failure).unwrap().contains("private"));
    append(&json!({"type":"system","subtype":"stop_hook_summary","sessionId":session}));
    append(&json!({"type":"user","isSidechain":true,"sessionId":session}));
    assert!(
        failure
            .current(dir.path(), &session, None)
            .unwrap()
            .is_some()
    );

    for change in [
        goal(), // A new invocation can reuse exactly the same condition.
        json!({"type":"system","subtype":"local_command","sessionId":session,"timestamp":ts}),
        json!({"type":"queue-operation","operation":"enqueue","sessionId":session,"timestamp":ts}),
        json!({"type":"api-request","sessionId":session,"timestamp":ts}),
        json!({"type":"user","sessionId":session,"timestamp":ts,"message":{"content":"private input"}}),
        json!({"type":"assistant","sessionId":session,"timestamp":ts,"message":{"stop_reason":"end_turn"}}),
        json!({"type":"attachment","sessionId":session,"attachment":{"type":"goal_status","met":true}}),
        json!({"type":"system","sessionId":session,"subtype":"compact_boundary"}),
        json!({"type":"last-prompt","sessionId":session,"explicit":true,"leafUuid":null}),
    ] {
        fs::write(&file, &base).unwrap();
        append(&change);
        assert!(
            failure
                .current(dir.path(), &session, None)
                .unwrap()
                .is_none()
        );
    }
    fs::write(&file, &base).unwrap();
    append(&goal());
    append(&error);
    assert!(
        failure
            .current(dir.path(), &session, None)
            .unwrap()
            .is_none(),
        "the same error under a replacement goal revived the old record"
    );
    fs::write(&file, &base).unwrap();
    append(&json!({"type":"user","sessionId":session,"timestamp":"2026-11-23T07:00:00.001Z"}));
    assert!(
        capture().is_none(),
        "delayed capture accepted later native input"
    );
    fs::write(&file, &base).unwrap();
    fs::rename(&file, file.with_extension("old")).unwrap();
    fs::write(&file, &base).unwrap();
    assert!(
        failure
            .current(dir.path(), &session, None)
            .unwrap()
            .is_none()
    );
}
