use super::*;
use crate::messages::owner_preparation::{Envelope, Plan, Step};

fn key(mesh: &Mesh, i: usize) -> String {
    config::read_private(&mesh.homes[i].path().join("owner.key")).unwrap()
}
async fn linked() -> Mesh {
    let mut mesh = Mesh::new().await;
    for _ in 0..25 {
        mesh.round(true);
        if (0..3)
            .all(|i| mesh.count(i, "network_links") == 2 && mesh.count(i, "network_events") == 0)
        {
            break;
        }
    }
    for i in 0..3 {
        assert_eq!(mesh.count(i, "network_links"), 2);
    }
    mesh
}
fn start(mesh: &mut Mesh, from: usize, to: usize, id: Uuid) {
    let credential = key(mesh, from);
    let target = mesh.stores[to].identity.node.id().to_owned();
    mesh.stores[from]
        .start_owner_preparation(&credential, id, &target)
        .unwrap();
}
fn status(mesh: &Mesh, i: usize, id: Uuid) -> Value {
    mesh.stores[i]
        .owner_preparation_status(&key(mesh, i), id)
        .unwrap()
}
fn round(mesh: &mut Mesh) {
    for store in &mut mesh.stores {
        store
            .db
            .execute("UPDATE owner_preparation_jobs SET retry_at=0", [])
            .unwrap();
        store.owner_preparation_tick().unwrap();
    }
    mesh.round(true);
}
fn ready(mesh: &mut Mesh, from: usize, id: Uuid) {
    for _ in 0..100 {
        round(mesh);
        if status(mesh, from, id)["readiness_recorded"] == true {
            return;
        }
    }
    panic!(
        "preparation did not finish: {:?}",
        (0..3).map(|i| status(mesh, i, id)).collect::<Vec<_>>()
    );
}
fn candidate(mesh: &Mesh, i: usize, id: Uuid) -> gent_crypto::succession::SignedOwnerCandidate {
    let bytes: Vec<u8> = mesh.stores[i]
        .db
        .query_row(
            "SELECT candidate FROM owner_preparation_plans WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    gent_crypto::succession::SignedOwnerCandidate::decode(&bytes).unwrap()
}
fn incoming(mesh: &Mesh, target: usize, sender: usize, envelope: &Envelope) -> Result<()> {
    let store = &mesh.stores[target];
    let tx = store.db.unchecked_transaction()?;
    store
        .network_session(&tx, store.identity.state(&tx)?)
        .import_owner_preparation(mesh.stores[sender].identity.node.id(), envelope)?;
    tx.commit()?;
    Ok(())
}
fn begin(mesh: &Mesh, id: Uuid) -> Envelope {
    let state = mesh.stores[0].identity.state(&mesh.stores[0].db).unwrap();
    let source = mesh.stores[0].identity.node.id().to_owned();
    let successor = mesh.stores[1].identity.node.id().to_owned();
    Envelope {
        version: 1,
        origin: source.clone(),
        target: successor.clone(),
        plan: Plan {
            id,
            anchor: state.anchor().clone(),
            base: state.checkpoint().clone(),
            source,
            successor,
            expires_at: now() as u64 + 900,
        },
        candidate: None,
        step: Step::Begin,
    }
}

#[tokio::test]
async fn encrypted_preparation_survives_restarts_and_supports_repeated_three_node_transfers() {
    let mut mesh = linked().await;
    for (epoch, from, to) in [(1, 0, 1), (2, 1, 2), (3, 2, 0)] {
        let id = Uuid::new_v4();
        start(&mut mesh, from, to, id);
        for _ in 0..3 {
            round(&mut mesh);
            for i in 0..3 {
                mesh.reopen(i);
            }
        }
        ready(&mut mesh, from, id);
        assert_eq!(candidate(&mesh, from, id), candidate(&mesh, to, id));
        for i in 0..3 {
            assert_eq!(
                mesh.stores[i]
                    .identity
                    .state(&mesh.stores[i].db)
                    .unwrap()
                    .owner_epoch(),
                epoch - 1
            );
            assert_eq!(status(&mesh, i, id)["signing_frozen"], false);
        }
        mesh.stores[from].require_provisioning_owner().unwrap();
        let source = key(&mesh, from);
        let target = key(&mesh, to);
        let proposal = candidate(&mesh, from, id);
        let authorization = mesh.stores[from]
            .authorize_owner_handoff(&source, &proposal)
            .unwrap();
        mesh.stores[from]
            .queue_owner_handoff_delivery(&source, &id.to_string())
            .unwrap();
        for _ in 0..100 {
            mesh.round(false);
            if mesh.stores[to]
                .owner_handoff_import_status(&target, &id.to_string())
                .is_ok_and(|s| s["pages_complete"] == true)
            {
                break;
            }
        }
        assert_eq!(
            mesh.stores[to]
                .owner_handoff_import_status(&target, &id.to_string())
                .unwrap()["pages_complete"],
            true
        );
        mesh.stores[to]
            .accept_owner_handoff(&target, &id.to_string(), &authorization)
            .unwrap();
        mesh.stores[to]
            .activate_owner_handoff(&target, &id.to_string())
            .unwrap();
        for _ in 0..100 {
            mesh.round(false);
            if mesh
                .stores
                .iter()
                .all(|store| store.identity.state(&store.db).unwrap().owner_epoch() == epoch)
            {
                break;
            }
        }
        for i in 0..3 {
            mesh.reopen(i);
            assert_eq!(
                mesh.stores[i]
                    .identity
                    .state(&mesh.stores[i].db)
                    .unwrap()
                    .owner_epoch(),
                epoch
            );
        }
        assert!(mesh.stores[from].require_provisioning_owner().is_err());
    }
}

#[tokio::test]
async fn preparation_effects_resume_when_each_response_outbox_commit_fails() {
    for (phase, node) in [
        ("candidate", 1),
        ("package", 0),
        ("prepared", 1),
        ("grant", 0),
        ("invitation", 1),
        ("confirmed", 2),
        ("ready", 1),
    ] {
        let mut mesh = linked().await;
        let id = Uuid::new_v4();
        mesh.stores[node].db.execute_batch(&format!("CREATE TRIGGER fail_response BEFORE INSERT ON network_events WHEN json_extract(NEW.body,'$.event.envelope.step.step')='{phase}' BEGIN SELECT RAISE(ABORT,'response failure'); END;")).unwrap();
        start(&mut mesh, 0, 1, id);
        let mut failed = false;
        for _ in 0..50 {
            round(&mut mesh);
            failed=mesh.stores[node].db.query_row("SELECT EXISTS(SELECT 1 FROM owner_preparation_jobs WHERE error LIKE '%response failure%') OR EXISTS(SELECT 1 FROM owner_preparation_plans WHERE error LIKE '%response failure%')",[],|r|r.get(0)).unwrap();
            if failed {
                break;
            }
        }
        assert!(failed, "did not reach {phase} failure");
        let saved = std::fs::read(
            mesh.homes[1]
                .path()
                .join(format!("owner-candidates/{id}.key")),
        )
        .unwrap();
        let packages: Vec<_> = (0..3).map(|i| mesh.count(i, "key_packages")).collect();
        for i in 0..3 {
            mesh.reopen(i);
        }
        mesh.stores[node]
            .db
            .execute_batch("DROP TRIGGER fail_response")
            .unwrap();
        ready(&mut mesh, 0, id);
        assert_eq!(
            saved,
            std::fs::read(
                mesh.homes[1]
                    .path()
                    .join(format!("owner-candidates/{id}.key"))
            )
            .unwrap()
        );
        assert_eq!(status(&mesh, 0, id)["signing_frozen"], false);
        // Completed work is inert, including native restarts and exact retries.
        let after: Vec<_> = (0..3).map(|i| mesh.count(i, "key_packages")).collect();
        for i in 0..3 {
            assert!(after[i] >= packages[i]);
            mesh.reopen(i);
        }
        start(&mut mesh, 0, 1, id);
        for _ in 0..3 {
            round(&mut mesh);
        }
        assert_eq!(
            after,
            (0..3)
                .map(|i| mesh.count(i, "key_packages"))
                .collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn preparation_rejects_wrong_credentials_roles_candidates_and_conflicting_retries() {
    let mut mesh = linked().await;
    let id = Uuid::new_v4();
    let target = mesh.stores[1].identity.node.id().to_owned();
    assert!(
        mesh.stores[0]
            .start_owner_preparation("wrong", id, &target)
            .is_err()
    );
    let joined = key(&mesh, 2);
    assert!(
        mesh.stores[2]
            .start_owner_preparation(&joined, id, &target)
            .is_err()
    );
    assert_eq!(mesh.count(0, "owner_preparation_plans"), 0);
    let envelope = begin(&mesh, id);
    assert!(incoming(&mesh, 1, 2, &envelope).is_err());
    let mut spoof = envelope.clone();
    spoof.origin = mesh.stores[2].identity.node.id().into();
    spoof.plan.source = spoof.origin.clone();
    assert!(incoming(&mesh, 1, 2, &spoof).is_err());
    let mut future = envelope.clone();
    future.plan.expires_at += 900;
    assert!(incoming(&mesh, 1, 0, &future).is_err());
    assert_eq!(mesh.count(1, "owner_preparation_plans"), 0);
    // Saving an authenticated Begin and its job is one transaction.
    mesh.stores[1].db.execute_batch("CREATE TRIGGER fail_admit BEFORE INSERT ON owner_preparation_jobs BEGIN SELECT RAISE(ABORT,'admission failure'); END;").unwrap();
    assert!(incoming(&mesh, 1, 0, &envelope).is_err());
    assert_eq!(mesh.count(1, "owner_preparation_plans"), 0);
    mesh.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_admit")
        .unwrap();
    incoming(&mesh, 1, 0, &envelope).unwrap();
    incoming(&mesh, 1, 0, &envelope).unwrap();
    assert_eq!(mesh.count(1, "owner_preparation_jobs"), 1);
    let mut changed = envelope.clone();
    changed.plan.expires_at -= 1;
    assert!(incoming(&mesh, 1, 0, &changed).is_err());
    // A successor cannot introduce itself on the source without a local plan.
    mesh.stores[1].owner_preparation_tick().unwrap();
    let mut proposal = envelope.clone();
    proposal.origin = target.clone();
    proposal.target = proposal.plan.source.clone();
    proposal.step = Step::Candidate;
    proposal.candidate = Some(candidate(&mesh, 1, id));
    assert!(incoming(&mesh, 0, 1, &proposal).is_err());
    assert_eq!(mesh.count(0, "owner_preparation_plans"), 0);
    // A forged candidate is rejected before either plan or job admission.
    let mut offer = proposal.clone();
    offer.origin = envelope.origin.clone();
    offer.target = mesh.stores[2].identity.node.id().into();
    offer.step = Step::Offer;
    offer.candidate.as_mut().unwrap().key_signature[0] ^= 1;
    assert!(incoming(&mesh, 2, 0, &offer).is_err());
    assert_eq!(mesh.count(2, "owner_preparation_plans"), 0);
}

#[tokio::test]
async fn preparation_becomes_stale_without_stopping_signing_when_configuration_changes() {
    let mut mesh = linked().await;
    let id = Uuid::new_v4();
    start(&mut mesh, 0, 1, id);
    ready(&mut mesh, 0, id);
    let proposal = candidate(&mesh, 0, id);
    let credential = key(&mesh, 0);
    mesh.stores[0]
        .execute(Request::Owner {
            credential: credential.clone(),
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::RenameNode {
                    name: "changed-during-preparation".into(),
                },
            },
        })
        .unwrap();
    for _ in 0..10 {
        round(&mut mesh);
    }
    assert_eq!(status(&mesh, 0, id)["current"], false);
    assert!(
        mesh.stores[0]
            .authorize_owner_handoff(&credential, &proposal)
            .is_err()
    );
    mesh.stores[0].require_provisioning_owner().unwrap();
    let next = Uuid::new_v4();
    start(&mut mesh, 0, 1, next);
    ready(&mut mesh, 0, next);
    assert_ne!(
        proposal.candidate.owner_key,
        candidate(&mesh, 0, next).candidate.owner_key
    );
}

#[tokio::test]
async fn preparation_schema_migrates_old_storage_and_refuses_current_storage_loss() {
    let mut mesh = linked().await;
    mesh.stores[0].db.execute_batch("DROP TABLE owner_preparation_jobs; DROP TABLE owner_preparation_plans; PRAGMA user_version=24;").unwrap();
    mesh.reopen(0);
    assert_eq!(mesh.count(0, "owner_preparation_jobs"), 0);
    assert_eq!(
        mesh.stores[0]
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))
            .unwrap(),
        25
    );
    mesh.stores[0]
        .db
        .execute_batch("DROP TABLE owner_preparation_jobs;")
        .unwrap();
    assert!(Store::open(mesh.homes[0].path()).is_err());
}

#[tokio::test]
async fn preparation_start_is_atomic_and_full_plan_storage_preserves_exact_retries() {
    let mut mesh = linked().await;
    let source = key(&mesh, 0);
    let target = mesh.stores[1].identity.node.id().to_owned();
    let id = Uuid::new_v4();
    mesh.stores[0].db.execute_batch("CREATE TRIGGER fail_start BEFORE INSERT ON network_events BEGIN SELECT RAISE(ABORT,'start failure'); END;").unwrap();
    assert!(
        mesh.stores[0]
            .start_owner_preparation(&source, id, &target)
            .is_err()
    );
    assert_eq!(mesh.count(0, "owner_preparation_plans"), 0);
    mesh.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_start")
        .unwrap();
    start(&mut mesh, 0, 1, id);
    for _ in 1..64 {
        start(&mut mesh, 0, 1, Uuid::new_v4());
    }
    assert!(
        mesh.stores[0]
            .start_owner_preparation(&source, Uuid::new_v4(), &target)
            .is_err()
    );
    assert_eq!(mesh.count(0, "owner_preparation_plans"), 64);
    mesh.reopen(0);
    start(&mut mesh, 0, 1, id);
    let other = mesh.stores[2].identity.node.id().to_owned();
    assert!(
        mesh.stores[0]
            .start_owner_preparation(&source, id, &other)
            .is_err()
    );
    assert_eq!(mesh.count(0, "owner_preparation_plans"), 64);
    mesh.stores[0].require_provisioning_owner().unwrap();
}
