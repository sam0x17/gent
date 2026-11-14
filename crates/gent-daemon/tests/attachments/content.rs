use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use gent_protocol::file_objects::{CHUNK_BYTES, MAX_IMAGE_VIEW_BYTES};
use sha2::{Digest, Sha256};

fn read(id: &str, index: u32) -> AgentOp {
    AgentOp::FileRead {
        file_id: id.into(),
        chunk_index: index,
    }
}
fn view(id: &str) -> AgentOp {
    AgentOp::FileView { file_id: id.into() }
}
fn decode(value: &Value) -> Vec<u8> {
    STANDARD
        .decode(value["data_base64"].as_str().unwrap())
        .unwrap()
}
fn import(f: &mut Fixture, bytes: &[u8], mime: &str) -> String {
    let mut op = f.source(0, "source.bin", bytes);
    if let AgentOp::FileImport { media_type, .. } = &mut op {
        *media_type = mime.into();
    }
    ok(f.call(0, op))["file"]["id"].as_str().unwrap().into()
}

#[test]
fn bounded_chunks_reassemble_after_restart_including_empty_files() {
    let mut f = Fixture::new();
    for size in [0, CHUNK_BYTES, 2 * CHUNK_BYTES + 17] {
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let id = import(&mut f, &bytes, "application/octet-stream");
        let first = ok(f.call(0, read(&id, 0)));
        f.store = Store::open(f.home.path()).unwrap();
        assert_eq!(first, ok(f.call(0, read(&id, 0))));
        let mut recovered = Vec::new();
        let count = size.div_ceil(CHUNK_BYTES).max(1) as u32;
        for index in 0..count {
            let chunk = ok(f.call(0, read(&id, index)));
            assert_eq!(chunk["file"], first["file"]);
            assert_eq!(chunk["chunk_index"], index);
            assert_eq!(chunk["offset"], recovered.len());
            assert_eq!(chunk["chunks_total"], count);
            let part = decode(&chunk);
            assert!(part.len() <= CHUNK_BYTES);
            assert_eq!(chunk["byte_length"], part.len());
            assert_eq!(
                chunk["next_chunk_index"],
                json!((index + 1 < count).then_some(index + 1))
            );
            recovered.extend(part);
        }
        assert_eq!(recovered, bytes);
        assert_eq!(first["file"]["byte_length"], recovered.len());
        assert_eq!(
            first["file"]["sha256"],
            format!("{:x}", Sha256::digest(&recovered))
        );
        for index in [count, u32::MAX] {
            assert!(error(f.call(0, read(&id, index))).contains("index"));
        }
    }
}

#[test]
fn content_reads_recheck_agent_message_policy_and_expiry_without_exporting() {
    let mut f = Fixture::new();
    let id = import(&mut f, b"image content fixture", "image/png");
    let send = f.send(1, vec![id.clone()]);
    ok(f.call(0, send));
    let message = f.inbox(1).remove(0);
    let incoming = &message.attachments[0].id;
    for op in [read(&id, 0), view(&id)] {
        assert_eq!(error(f.call(1, op)), "file unavailable");
    }
    for op in [read(incoming, 0), view(incoming)] {
        assert_eq!(decode(&ok(f.call(1, op.clone()))), b"image content fixture");
        assert_eq!(error(f.call(2, op)), "file unavailable");
    }
    for op in [read("absent", u32::MAX), view("../../owner.key")] {
        assert_eq!(error(f.call(1, op)), "file unavailable");
    }
    ok(f.call(
        1,
        AgentOp::Ack {
            message_id: message.id,
        },
    ));
    ok(f.call(1, view(incoming)));
    let mut policy = config::load(f.home.path()).unwrap().policy;
    policy.rules.push(Rule {
        actor: Selector::Agent(f.agents[1].clone()),
        peer: Selector::Agent(f.agents[0].clone()),
        permission: Permission::Receive,
        effect: Effect::Deny,
    });
    f.policy(policy);
    for op in [read(incoming, 0), view(incoming)] {
        assert_eq!(error(f.call(1, op)), "file unavailable");
    }
    assert_eq!(decode(&ok(f.call(0, view(&id)))), b"image content fixture");
    f.db()
        .execute("UPDATE file_objects SET expires_at=1", [])
        .unwrap();
    for op in [read(&id, 0), view(&id)] {
        assert_eq!(error(f.call(0, op)), "file unavailable");
    }
    assert_eq!(
        f.db()
            .query_row("SELECT COUNT(*) FROM file_exports", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
}

#[test]
fn image_views_bound_size_media_and_verify_whole_files() {
    let mut f = Fixture::new();
    let bytes = vec![19; MAX_IMAGE_VIEW_BYTES];
    let id = import(&mut f, &bytes, "image/png");
    let viewed = ok(f.call(0, view(&id)));
    assert_eq!(decode(&viewed), bytes);
    assert!(serde_json::to_vec(&Response::Ok(viewed)).unwrap().len() < MAX_FRAME_BYTES);
    f.db()
        .execute("UPDATE file_objects SET complete=0 WHERE id=?1", [&id])
        .unwrap();
    for op in [read(&id, 0), view(&id)] {
        assert!(error(f.call(0, op)).contains("incomplete"));
    }
    f.db()
        .execute("UPDATE file_objects SET complete=1 WHERE id=?1", [&id])
        .unwrap();
    f.db().execute("UPDATE file_chunks SET ciphertext=zeroblob(length(ciphertext)) WHERE object_id=?1 AND position=1", [&id]).unwrap();
    assert_eq!(decode(&ok(f.call(0, read(&id, 0)))), bytes[..CHUNK_BYTES]);
    for op in [read(&id, 1), view(&id)] {
        assert!(error(f.call(0, op)).contains("authentication"));
    }
    let large = import(&mut f, &vec![7; MAX_IMAGE_VIEW_BYTES + 1], "image/webp");
    assert!(error(f.call(0, view(&large))).contains("4 MiB"));
    for mime in ["image/svg+xml", "text/html", "application/octet-stream"] {
        let id = import(&mut f, b"<svg/>", mime);
        assert!(error(f.call(0, view(&id))).contains("requires PNG"));
        assert_eq!(decode(&ok(f.call(0, read(&id, 0)))), b"<svg/>");
    }
}
