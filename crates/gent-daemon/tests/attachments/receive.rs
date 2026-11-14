use super::*;
use gent_protocol::file_objects::IncomingFile;
use zeroize::Zeroizing;

fn file() -> IncomingFile {
    IncomingFile {
        request_id: Uuid::now_v7().to_string(),
        source_id: "a".repeat(64),
        name: "remote.bin".into(),
        media_type: "application/octet-stream".into(),
    }
}
fn status(file: &IncomingFile) -> AgentOp {
    AgentOp::FileReceiveStatus { file: file.clone() }
}
fn import(file: &IncomingFile, bytes: &[u8]) -> AgentOp {
    AgentOp::FileReceiveData {
        file: file.clone(),
        bytes: Zeroizing::new(bytes.to_vec()),
    }
}

#[test]
fn remote_import_is_atomic_idempotent_isolated_and_has_no_plaintext_handoff() {
    let mut f = Fixture::new();
    let file = file();
    assert_eq!(ok(f.call(0, status(&file)))["state"], "upload");
    f.db().execute_batch("CREATE TRIGGER fail_import BEFORE INSERT ON file_imports BEGIN SELECT RAISE(ABORT,'injected import failure'); END;").unwrap();
    assert!(error(f.call(0, import(&file, b"file bytes"))).contains("injected"));
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_objects", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
    f.db().execute_batch("DROP TRIGGER fail_import").unwrap();
    let first = ok(f.call(0, import(&file, b"file bytes")));
    let id = first["file"]["id"].as_str().unwrap();
    assert_eq!(first["duplicate"], false);
    f.store = Store::open(f.home.path()).unwrap();
    assert_eq!(ok(f.call(0, status(&file)))["file"], first["file"]);
    assert_eq!(
        ok(f.call(0, import(&file, b"file bytes")))["file"],
        first["file"]
    );
    assert!(error(f.call(0, import(&file, b"other bytes"))).contains("different content"));
    for field in [0, 1, 2] {
        let mut changed = file.clone();
        match field {
            0 => changed.source_id = "b".repeat(64),
            1 => changed.name = "other.bin".into(),
            _ => changed.media_type = "text/plain".into(),
        }
        assert!(error(f.call(0, status(&changed))).contains("different content"));
    }
    assert_eq!(ok(f.call(1, status(&file)))["state"], "upload");
    assert_eq!(
        error(f.call(
            1,
            AgentOp::FileRead {
                file_id: id.into(),
                chunk_index: 0
            }
        )),
        "file unavailable"
    );
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_handoffs", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
    assert!(!f.home.path().join("handoffs").exists());
    let mut expired = file.clone();
    expired.request_id = Uuid::from_u128(0x01800000_0000_7000_8000_000000000000).to_string();
    assert!(matches!(f.call(0, status(&expired)), Response::Error(_)));
    f.db()
        .execute("UPDATE file_objects SET expires_at=1", [])
        .unwrap();
    assert_eq!(error(f.call(0, status(&file))), "file unavailable");
    assert_eq!(
        error(f.call(0, import(&file, b"file bytes"))),
        "file unavailable"
    );
}

#[test]
fn remote_import_cannot_alias_local_requests_or_decode_in_memory_operation() {
    let mut f = Fixture::new();
    let mut file = file();
    let native = f.source(0, "native.bin", b"same");
    if let AgentOp::FileImport { request_id, .. } = &native {
        file.request_id = request_id.clone();
    }
    ok(f.call(0, native));
    assert!(error(f.call(0, status(&file))).contains("different content"));
    assert!(
        serde_json::from_value::<AgentOp>(
            json!({"op":"file_receive_data","file":file,"bytes":[1,2]})
        )
        .is_err()
    );
    assert!(serde_json::to_value(import(&file, b"private")).is_err());
}
