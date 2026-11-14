use super::*;
use crate::encrypted::{Received, ordered::OrderedEndpoint};

fn queued(pair: &mut Pair) -> (SignedOwnerCandidate, SignedOwnerTransition, Vec<u8>) {
    let candidate = prepare(pair);
    prepare_readiness(pair, &candidate);
    let key = credential(pair, 0);
    let authorization = pair.stores[0]
        .authorize_owner_handoff(&key, &candidate)
        .unwrap();
    pair.stores[0]
        .queue_owner_handoff_delivery(&key, &candidate.candidate.id)
        .unwrap();
    let group = pair.stores[0]
        .db
        .query_row(
            "SELECT group_id FROM owner_deliveries WHERE id=?1",
            [&candidate.candidate.id],
            |r| r.get(0),
        )
        .unwrap();
    (candidate, authorization, group)
}

fn publish(pair: &Pair, group: &[u8], timestamp: u64) -> Option<gent_crypto::stream::Packet> {
    let mut endpoint =
        OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node).unwrap();
    endpoint
        .prepare_configuration(group, None, timestamp)
        .unwrap()
        .or_else(|| endpoint.prepare_owner_handoff(group, timestamp).unwrap())
}

fn receive(pair: &Pair, packet: &gent_crypto::stream::Packet, timestamp: u64) -> Vec<Received> {
    let mut endpoint =
        OrderedEndpoint::open_runtime(pair.homes[1].path(), &pair.stores[1].identity.node).unwrap();
    endpoint.stage_configuration(packet, timestamp).unwrap();
    endpoint
        .drain_configuration(packet.group(), 1, timestamp)
        .unwrap()
}

#[tokio::test]
async fn authentic_transport_cannot_import_an_unsigned_or_changed_journal() {
    use crate::encrypted::ordered::configuration::handoff::test_packets;
    for variant in 0..5 {
        let mut pair = Pair::new().await;
        let (candidate, authorization, group) = queued(&mut pair);
        let id = &candidate.candidate.id;
        let manifest = pair.stores[0]
            .owner_handoff_manifest(&credential(&pair, 0), id)
            .unwrap();
        let timestamp = now() as u64;
        let mut record = json!({"version":1,"handoff":{"kind":"manifest","id":id,"authorization":authorization,"manifest":manifest}});
        match variant {
            0 => record["handoff"]["authorization"]["signature"][0] = json!(0),
            1 => record["handoff"]["manifest"]["candidate"][0] = json!(0),
            2 => record["handoff"]["id"] = json!(Uuid::new_v4().to_string()),
            3 => record = json!({"version":1,"handoff":{"kind":"message","id":id,"text":"bypass"}}),
            4 => {
                let packet = publish(&pair, &group, timestamp).unwrap();
                receive(&pair, &packet, timestamp);
                record = json!({"version":1,"handoff":{"kind":"page","id":id,"index":0,"data":STANDARD.encode(b"tampered")}});
            }
            _ => unreachable!(),
        }
        // Ensure a deterministic mutation even if the original byte was zero.
        if variant == 0 {
            record["handoff"]["authorization"]["signature"][0] =
                json!(authorization.signature[0] ^ 1);
        }
        if variant == 1 {
            record["handoff"]["manifest"]["candidate"][0] = json!(manifest.candidate[0] ^ 1);
        }
        let packet = test_packets::publish(
            &mut OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node)
                .unwrap(),
            &group,
            &serde_json::to_vec(&record).unwrap(),
            timestamp,
        )
        .unwrap();
        assert!(pair.stores[1].sync_receive(&packet).is_err());
        let next =
            OrderedEndpoint::open_runtime(pair.homes[1].path(), &pair.stores[1].identity.node)
                .unwrap()
                .configuration_status(&group, timestamp)
                .unwrap()
                .next;
        assert_eq!(next, packet.sequence());
        assert_eq!(
            pair.stores[1]
                .db
                .query_row("SELECT COUNT(*) FROM owner_journal_pages", [], |r| r
                    .get::<_, usize>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            pair.stores[1]
                .identity
                .state(&pair.stores[1].db)
                .unwrap()
                .checkpoint(),
            &candidate.candidate.base
        );
    }
}

#[tokio::test]
async fn signed_history_precedes_delivery_and_cyclic_handoffs_use_the_current_epoch() {
    let mut pair = Pair::new().await;
    configure(
        &mut pair,
        0,
        &Uuid::new_v4().to_string(),
        ConfigurationEdit::Renew,
    )
    .unwrap();
    // The successor already accepted this checkpoint by a trusted local route,
    // but its predecessor stream still owes the historical record.
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    pair.stores[1]
        .identity
        .apply(&pair.stores[1].db, state.signed().clone())
        .unwrap();
    let (candidate, authorization, group) = queued(&mut pair);
    let packet = publish(&pair, &group, now() as u64).unwrap();
    assert!(matches!(
        receive(&pair, &packet, now() as u64)[0],
        Received::ConfigurationPart { complete: true, .. }
    ));
    owner_activation_tests::configuration_only(&mut pair, 0, 1);
    let key = credential(&pair, 1);
    pair.stores[1]
        .accept_owner_handoff(&key, &candidate.candidate.id, &authorization)
        .unwrap();
    pair.stores[1]
        .activate_owner_handoff(&key, &candidate.candidate.id)
        .unwrap();
    pair.pump();
    for (from, to) in [(1, 0), (0, 1)] {
        let (candidate, _, _) = owner_activation_tests::complete(&mut pair, from, to);
        let id = &candidate.candidate.id;
        pair.stores[from]
            .queue_owner_handoff_delivery(&credential(&pair, from), id)
            .unwrap();
        let wire: Vec<u8> = pair.stores[from].db.query_row("SELECT c.grant FROM owner_deliveries d JOIN configuration_streams c USING(group_id) WHERE d.id=?1", [id], |r| r.get(0)).unwrap();
        let grant = gent_crypto::SignedConfigurationGrant::decode(&wire).unwrap();
        assert_eq!(
            grant.grant.owner_transitions.len()
                + usize::from(grant.grant.owner_candidate.is_some()),
            pair.stores[from]
                .identity
                .state(&pair.stores[from].db)
                .unwrap()
                .owner_epoch() as usize
        );
        owner_activation_tests::configuration_only(&mut pair, from, to);
        pair.stores[to]
            .activate_owner_handoff(&credential(&pair, to), id)
            .unwrap();
        pair.pump();
    }
}

#[tokio::test]
async fn encrypted_delivery_resumes_after_expiry_and_restart_without_activating() {
    let mut pair = Pair::new().await;
    let origin = pair.stores[0].identity.node.id().to_owned();
    let result = serde_json::to_vec(&crate::messages::EditResult::Rejected {
        reason: "r".repeat(1024),
    })
    .unwrap();
    let fingerprint = hash(&serde_json::to_string(&ConfigurationEdit::Renew).unwrap());
    pair.stores[0].db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<600) INSERT INTO configuration_edits SELECT ?1,printf('00000000-0000-4000-8000-%012x',x),?1,?2,?3,?4,1 FROM n", params![origin, fingerprint, br#"{"op":"renew"}"#.as_slice(), result]).unwrap();
    let (candidate, authorization, group) = queued(&mut pair);
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let id = &candidate.candidate.id;
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    let timestamp = state.state().expires_at + 1;
    let manifest = pair.stores[0].owner_handoff_manifest(&keys[0], id).unwrap();
    assert!(manifest.pages.len() >= 3);
    assert!(
        OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node)
            .unwrap()
            .send(
                &pair.group(),
                Uuid::new_v4(),
                b"ordinary traffic",
                timestamp
            )
            .is_err()
    );
    let mut records = 0;
    while let Some(packet) = publish(&pair, &group, timestamp) {
        assert!(
            !packet
                .encode()
                .unwrap()
                .windows(id.len())
                .any(|w| w == id.as_bytes())
        );
        if records == 1 {
            pair.reopen(0);
            pair.reopen(1);
        }
        let received = receive(&pair, &packet, timestamp);
        assert_eq!(received, vec![Received::OwnerHandoff]);
        // An exact packet replay cannot allocate another import or ratchet.
        assert!(receive(&pair, &packet, timestamp).is_empty());
        let receipt =
            OrderedEndpoint::open_runtime(pair.homes[1].path(), &pair.stores[1].identity.node)
                .unwrap()
                .receipt(&group, timestamp)
                .unwrap();
        OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node)
            .unwrap()
            .confirm(&receipt, pair.stores[1].identity.node.id(), timestamp)
            .unwrap();
        records += 1;
    }
    assert_eq!(records, manifest.pages.len() + 1);
    assert_eq!(
        pair.stores[0]
            .queue_owner_handoff_delivery(&keys[0], id)
            .unwrap()["publication_complete"],
        true
    );
    assert_eq!(
        pair.stores[1]
            .owner_handoff_import_status(&keys[1], id)
            .unwrap()["pages_complete"],
        true
    );
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .checkpoint(),
        &candidate.candidate.base
    );
    assert_eq!(status(&mut pair, 1)["completed_candidates"], 0);
    pair.stores[1]
        .accept_owner_handoff(&keys[1], id, &authorization)
        .unwrap();
    pair.stores[1].activate_owner_handoff(&keys[1], id).unwrap();
}

#[tokio::test]
async fn publication_and_receive_failures_preserve_ratchets_cursors_and_retries() {
    let mut pair = Pair::new().await;
    let (candidate, _, group) = queued(&mut pair);
    let timestamp = now() as u64;
    let before = OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node)
        .unwrap()
        .configuration_status(&group, timestamp)
        .unwrap();
    pair.stores[0].db.execute_batch("CREATE TRIGGER fail_delivery BEFORE UPDATE ON owner_deliveries BEGIN SELECT RAISE(ABORT,'delivery failure'); END;").unwrap();
    assert!(
        OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node)
            .unwrap()
            .prepare_owner_handoff(&group, timestamp)
            .is_err()
    );
    assert_eq!(
        OrderedEndpoint::open_runtime(pair.homes[0].path(), &pair.stores[0].identity.node)
            .unwrap()
            .configuration_status(&group, timestamp)
            .unwrap(),
        before
    );
    pair.stores[0]
        .db
        .execute_batch("DROP TRIGGER fail_delivery")
        .unwrap();
    let packet = publish(&pair, &group, timestamp).unwrap();
    assert_eq!(packet.sequence(), before.head + 1);
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_import BEFORE INSERT ON owner_journals BEGIN SELECT RAISE(ABORT,'import failure'); END;").unwrap();
    assert!(pair.stores[1].sync_receive(&packet).is_err());
    let receiver =
        OrderedEndpoint::open_runtime(pair.homes[1].path(), &pair.stores[1].identity.node)
            .unwrap()
            .configuration_status(&group, timestamp)
            .unwrap();
    assert_eq!(receiver.next, packet.sequence());
    assert_eq!(receiver.pending, 1);
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_import")
        .unwrap();
    pair.reopen(1);
    assert_eq!(
        pair.stores[1].sync_next(&group).unwrap(),
        packet.sequence() + 1
    );
    let packet = publish(&pair, &group, timestamp).unwrap();
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_page BEFORE INSERT ON owner_journal_pages BEGIN SELECT RAISE(ABORT,'page failure'); END;").unwrap();
    assert!(pair.stores[1].sync_receive(&packet).is_err());
    assert_eq!(
        pair.stores[1]
            .owner_handoff_import_status(&credential(&pair, 1), &candidate.candidate.id)
            .unwrap()["received"],
        0
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_page")
        .unwrap();
    assert_eq!(
        pair.stores[1].sync_next(&group).unwrap(),
        packet.sequence() + 1
    );
    assert_eq!(
        pair.stores[1]
            .owner_handoff_import_status(&credential(&pair, 1), &candidate.candidate.id)
            .unwrap()["pages_complete"],
        true
    );
}

#[tokio::test]
async fn delivery_requires_issued_authority_local_owner_and_exact_prepared_candidate() {
    let mut pair = Pair::new().await;
    let key = credential(&pair, 0);
    let unissued = prepare(&mut pair);
    assert!(
        pair.stores[0]
            .queue_owner_handoff_delivery(&key, &unissued.candidate.id)
            .is_err()
    );
    let (candidate, _, group) = queued(&mut pair);
    let id = &candidate.candidate.id;
    assert!(
        pair.stores[0]
            .queue_owner_handoff_delivery(&pair.keys[0], id)
            .is_err()
    );
    assert!(
        pair.stores[1]
            .queue_owner_handoff_delivery(&credential(&pair, 1), id)
            .is_err()
    );
    let original: Vec<u8> = pair.stores[1]
        .db
        .query_row(
            "SELECT candidate FROM owner_candidates WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    pair.stores[1]
        .db
        .execute(
            "UPDATE owner_candidates SET candidate=?1 WHERE id=?2",
            params![unissued.encode().unwrap(), id],
        )
        .unwrap();
    let packet = publish(&pair, &group, now() as u64).unwrap();
    assert!(pair.stores[1].sync_receive(&packet).is_err());
    pair.stores[1]
        .db
        .execute(
            "UPDATE owner_candidates SET candidate=?1 WHERE id=?2",
            params![original, id],
        )
        .unwrap();
    pair.stores[1].sync_next(&group).unwrap();
    owner_activation_tests::configuration_only(&mut pair, 0, 1);
    assert_eq!(
        pair.stores[1]
            .owner_handoff_import_status(&credential(&pair, 1), id)
            .unwrap()["pages_complete"],
        true
    );
}

#[tokio::test]
async fn delivery_after_local_activation_accepts_only_existing_identical_artifacts() {
    let mut pair = Pair::new().await;
    let candidate = prepare(&mut pair);
    let authorization = issue(&mut pair, &candidate);
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let id = &candidate.candidate.id;
    pair.stores[1]
        .accept_owner_handoff(&keys[1], id, &authorization)
        .unwrap();
    pair.stores[1].activate_owner_handoff(&keys[1], id).unwrap();
    configure(
        &mut pair,
        1,
        &Uuid::new_v4().to_string(),
        ConfigurationEdit::Renew,
    )
    .unwrap();
    // These are newly encrypted application records carrying already imported
    // artifacts, not packet replays caught by the ordered receive layer.
    pair.stores[0]
        .queue_owner_handoff_delivery(&keys[0], id)
        .unwrap();
    owner_activation_tests::configuration_only(&mut pair, 0, 1);
    let page = pair.stores[0].owner_handoff_page(&keys[0], id, 0).unwrap();
    pair.stores[1]
        .db
        .execute(
            "DELETE FROM owner_journal_pages WHERE id=?1 AND page=0",
            [id],
        )
        .unwrap();
    assert!(
        pair.stores[1]
            .import_owner_handoff_page(&keys[1], id, 0, &page)
            .unwrap_err()
            .to_string()
            .contains("cannot repair")
    );
}

#[tokio::test]
async fn delivery_schema_migrates_and_missing_current_storage_fails_closed() {
    let mut pair = Pair::new().await;
    let (candidate, _, _) = queued(&mut pair);
    pair.stores[0]
        .db
        .execute_batch("DROP TABLE owner_deliveries; PRAGMA user_version=23;")
        .unwrap();
    pair.reopen(0);
    assert_eq!(status(&mut pair, 0)["signing_frozen"], true);
    pair.stores[0]
        .queue_owner_handoff_delivery(&credential(&pair, 0), &candidate.candidate.id)
        .unwrap();
    pair.reopen(0);
    assert_eq!(status(&mut pair, 0)["delivery"]["jobs"], 1);
    pair.stores[0]
        .db
        .execute_batch("DROP TABLE owner_deliveries")
        .unwrap();
    assert!(
        Store::open(pair.homes[0].path())
            .err()
            .unwrap()
            .to_string()
            .contains("delivery storage is missing")
    );
}
