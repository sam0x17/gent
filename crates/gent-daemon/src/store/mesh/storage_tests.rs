use super::*;

fn pending(mesh: &Mesh, i: usize) -> MeshEnvelope {
    let body: Vec<u8> = mesh.stores[i]
        .db
        .query_row(
            "SELECT body FROM mesh_jobs WHERE done=0 ORDER BY rowid LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn compacted(mesh: &Mesh, i: usize) {
    let (count,compact): (u64,u64) = mesh.stores[i].db.query_row("SELECT COUNT(*),COALESCE(SUM(done=1 AND length(body)=0 AND length(fingerprint)=32),0) FROM mesh_jobs",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert!(count > 0);
    assert_eq!(count, compact);
}

#[tokio::test]
async fn completed_mesh_jobs_keep_conflict_detection_after_compaction_and_restart() {
    let mut mesh = Mesh::new().await;
    mesh.stores[1].mesh_tick().unwrap();
    for _ in 0..4 {
        mesh.round(false);
    }
    let offer = pending(&mesh, 0);
    let target = (1..3)
        .find(|i| mesh.stores[*i].identity.node.id() == offer.target)
        .unwrap();
    let source = 3 - target;
    for _ in 0..20 {
        mesh.round(true);
    }
    let counts: Vec<_> = (0..3)
        .map(|i| {
            (
                mesh.count(i, "mesh_jobs"),
                mesh.count(i, "key_packages"),
                mesh.count(i, "streams"),
            )
        })
        .collect();
    for i in 0..3 {
        compacted(&mesh, i);
        mesh.reopen(i);
    }
    mesh.import(0, source, offer.clone()).unwrap();
    mesh.import(target, 0, offer.clone()).unwrap();
    let mut changed = offer;
    changed.signal = MeshSignal::Offer {
        key_package: "different".into(),
    };
    assert!(
        mesh.import(0, source, changed.clone())
            .unwrap_err()
            .to_string()
            .contains("conflicting mesh signal")
    );
    assert!(
        mesh.import(target, 0, changed)
            .unwrap_err()
            .to_string()
            .contains("conflicting mesh signal")
    );
    for _ in 0..3 {
        mesh.round(true);
    }
    for (i, before) in counts.into_iter().enumerate() {
        assert_eq!(
            (
                mesh.count(i, "mesh_jobs"),
                mesh.count(i, "key_packages"),
                mesh.count(i, "streams")
            ),
            before
        );
        assert_eq!(mesh.count(i, "network_links"), 2);
        compacted(&mesh, i);
    }
}

#[tokio::test]
async fn migrated_pending_jobs_survive_crypto_commit_followed_by_completion_failure() {
    let mut mesh = Mesh::new().await;
    mesh.stores[1].mesh_tick().unwrap();
    mesh.stores[2].mesh_tick().unwrap();
    for _ in 0..4 {
        mesh.round(false);
    }
    mesh.stores[0].mesh_tick().unwrap();
    for _ in 0..4 {
        mesh.round(false);
    }
    let offer = pending(&mesh, 1);
    let id = offer.id().to_string();
    let body = serde_json::to_vec(&offer).unwrap();
    mesh.stores[1].db.execute_batch("DROP INDEX mesh_jobs_compaction; ALTER TABLE mesh_jobs DROP COLUMN fingerprint; PRAGMA user_version=9;").unwrap();
    mesh.reopen(1);
    mesh.stores[1].maintain().unwrap();
    assert_eq!(
        mesh.stores[1]
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        26
    );
    assert_eq!(serde_json::to_vec(&pending(&mesh, 1)).unwrap(), body);
    let streams = mesh.count(1, "streams");
    let events = mesh.count(1, "network_events");
    let packages = mesh.count(1, "key_packages");
    mesh.stores[1].db.execute_batch("CREATE TRIGGER fail_mesh_completion BEFORE UPDATE OF done ON mesh_jobs BEGIN SELECT RAISE(ABORT,'completion failure'); END;").unwrap();
    mesh.stores[1].mesh_tick().unwrap();
    assert_eq!(mesh.count(1, "streams"), streams + 1);
    assert_eq!(mesh.count(1, "network_events"), events);
    assert_eq!(serde_json::to_vec(&pending(&mesh, 1)).unwrap(), body);
    let outgoing: Option<Vec<u8>> = mesh.stores[1]
        .db
        .query_row("SELECT outgoing FROM mesh_peers", [], |r| r.get(0))
        .unwrap();
    assert!(outgoing.is_none());
    mesh.reopen(1);
    mesh.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_mesh_completion; UPDATE mesh_jobs SET retry_at=0;")
        .unwrap();
    for _ in 0..20 {
        mesh.round(true);
    }
    assert_eq!(mesh.count(1, "streams"), streams + 2); // original outgoing plus peer's incoming
    assert_eq!(mesh.count(1, "key_packages"), packages);
    for i in 0..3 {
        assert_eq!(mesh.count(i, "network_links"), 2);
        compacted(&mesh, i);
    }
    mesh.import(1, 0, offer).unwrap();
    assert_eq!(
        mesh.stores[1]
            .db
            .query_row(
                "SELECT length(body) FROM mesh_jobs WHERE id=?1",
                [id],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
}
