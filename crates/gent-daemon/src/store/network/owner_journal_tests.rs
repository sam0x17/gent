use super::*;
use gent_crypto::succession::journal::{MAX_BYTES, Manifest, PAGE_BYTES};

fn count(pair: &Pair, i: usize, table: &str) -> u64 {
    pair.stores[i]
        .db
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

fn signed_snapshot(
    pair: &Pair,
    candidate: &SignedOwnerCandidate,
    entries: usize,
    body: &[u8],
) -> (Manifest, SignedOwnerTransition) {
    let manifest = Manifest::new(candidate, entries, body).unwrap();
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    let authorization = state
        .authorize_owner_candidate_with_journal(
            pair.stores[0].identity.owner.as_ref().unwrap(),
            candidate,
            manifest.digest().unwrap(),
            now() as u64,
        )
        .unwrap();
    (manifest, authorization)
}

#[tokio::test]
async fn completed_and_lost_results_transfer_without_applying_edits_or_installing_authority() {
    let mut pair = Pair::new().await;
    let applied = Uuid::new_v4().to_string();
    let rejected = Uuid::new_v4().to_string();
    configure(
        &mut pair,
        1,
        &applied,
        ConfigurationEdit::RenameNode {
            name: "journal-test".into(),
        },
    )
    .unwrap();
    configure(
        &mut pair,
        1,
        &rejected,
        ConfigurationEdit::DeleteGroup {
            name: "does-not-exist".into(),
        },
    )
    .unwrap();
    pair.pump();
    let saved: Vec<u8> = pair.stores[1]
        .db
        .query_row(
            "SELECT result FROM configuration_edits WHERE id=?1",
            [&rejected],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&saved).unwrap()["state"],
        "rejected"
    );
    // Model the lost result while retaining its accepted configuration revision.
    pair.stores[1]
        .db
        .execute(
            "UPDATE configuration_edits SET result=NULL WHERE id=?1",
            [&applied],
        )
        .unwrap();
    let candidate = prepare(&mut pair);
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let before = [
        count(&pair, 1, "configuration_edits"),
        count(&pair, 1, "authority_digests"),
    ];
    let authorization = issue(&mut pair, &candidate);
    let manifest = pair.stores[0]
        .owner_handoff_manifest(&keys[0], &candidate.candidate.id)
        .unwrap();
    let body = pair.stores[0]
        .owner_handoff_page(&keys[0], &candidate.candidate.id, 0)
        .unwrap();
    let decisions: Vec<Value> = serde_json::from_slice(&body).unwrap();
    assert!(
        decisions
            .iter()
            .any(|d| d["id"] == applied && d["result"]["state"] == "applied")
    );
    assert!(
        decisions
            .iter()
            .any(|d| d["id"] == rejected && d["result"]["state"] == "rejected")
    );
    assert_eq!(manifest.entries, decisions.len());
    pair.reopen(1);
    pair.stores[1]
        .accept_owner_handoff(&keys[1], &candidate.candidate.id, &authorization)
        .unwrap();
    assert_eq!(
        before,
        [
            count(&pair, 1, "configuration_edits"),
            count(&pair, 1, "authority_digests")
        ]
    );
    assert!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT result IS NULL FROM configuration_edits WHERE id=?1",
                [&applied],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    assert_eq!(
        pair.stores[1]
            .identity
            .state(&pair.stores[1].db)
            .unwrap()
            .checkpoint(),
        &candidate.candidate.base
    );
    assert!(
        !pair.stores[1]
            .identity
            .is_current_owner(&pair.stores[1].identity.state(&pair.stores[1].db).unwrap())
    );
}

#[tokio::test]
async fn partial_out_of_order_transfer_survives_restart_and_authenticates_every_retry() {
    let mut pair = Pair::new().await;
    let origin = pair.stores[0].identity.node.id().to_owned();
    let result = serde_json::to_vec(&crate::messages::EditResult::Rejected {
        reason: "r".repeat(1024),
    })
    .unwrap();
    let fingerprint = hash(&serde_json::to_string(&ConfigurationEdit::Renew).unwrap());
    // Many independently keyed, completed decisions exercise a multi-page journal.
    pair.stores[0].db.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<600) INSERT INTO configuration_edits SELECT ?1,printf('00000000-0000-4000-8000-%012x',x),?1,?2,?3,?4,1 FROM n", params![origin, fingerprint, br#"{"op":"renew"}"#.as_slice(), result]).unwrap();
    let candidate = prepare(&mut pair);
    let id = &candidate.candidate.id;
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let authorization = pair.stores[0]
        .authorize_owner_handoff(&keys[0], &candidate)
        .unwrap();
    let manifest = pair.stores[0].owner_handoff_manifest(&keys[0], id).unwrap();
    assert!(manifest.pages.len() >= 3);
    assert!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], id, &authorization)
            .is_err()
    );
    let initial = pair.stores[1]
        .begin_owner_handoff_import(&keys[1], id, &authorization, &manifest)
        .unwrap();
    assert_eq!(initial["received"], 0);
    for index in (1..manifest.pages.len()).rev() {
        let page = pair.stores[0]
            .owner_handoff_page(&keys[0], id, index)
            .unwrap();
        let mut damaged = page.clone();
        damaged[0] ^= 1;
        assert!(
            pair.stores[1]
                .import_owner_handoff_page(&keys[1], id, index, &damaged)
                .is_err()
        );
        let progress = pair.stores[1]
            .import_owner_handoff_page(&keys[1], id, index, &page)
            .unwrap();
        assert_eq!(progress["pages_complete"], false);
        pair.reopen(1);
        assert_eq!(
            pair.stores[1]
                .import_owner_handoff_page(&keys[1], id, index, &page)
                .unwrap(),
            progress
        );
        assert!(
            pair.stores[1]
                .accept_owner_handoff(&keys[1], id, &authorization)
                .is_err()
        );
    }
    pair.reopen(0);
    assert_eq!(
        pair.stores[0].owner_handoff_manifest(&keys[0], id).unwrap(),
        manifest
    );
    let progress = pair.stores[1]
        .begin_owner_handoff_import(&keys[1], id, &authorization, &manifest)
        .unwrap();
    assert_eq!(progress["missing"], json!([0]));
    let page = pair.stores[0].owner_handoff_page(&keys[0], id, 0).unwrap();
    assert!(
        pair.stores[1]
            .import_owner_handoff_page(&keys[1], id, manifest.pages.len(), &page)
            .is_err()
    );
    pair.stores[1].db.execute_batch("CREATE TRIGGER fail_page BEFORE INSERT ON owner_journal_pages BEGIN SELECT RAISE(ABORT,'journal failure'); END;").unwrap();
    assert!(
        pair.stores[1]
            .import_owner_handoff_page(&keys[1], id, 0, &page)
            .is_err()
    );
    assert_eq!(
        pair.stores[1]
            .owner_handoff_import_status(&keys[1], id)
            .unwrap(),
        progress
    );
    pair.stores[1]
        .db
        .execute_batch("DROP TRIGGER fail_page;")
        .unwrap();
    assert_eq!(
        pair.stores[1]
            .import_owner_handoff_page(&keys[1], id, 0, &page)
            .unwrap()["pages_complete"],
        true
    );
    let complete = pair.stores[1]
        .accept_owner_handoff(&keys[1], id, &authorization)
        .unwrap();
    pair.reopen(1);
    assert_eq!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], id, &authorization)
            .unwrap()
            .encode()
            .unwrap(),
        complete.encode().unwrap()
    );
    assert!(
        pair.stores[1]
            .identity
            .apply(&pair.stores[1].db, complete)
            .is_err()
    );
}

#[tokio::test]
async fn signed_but_conflicting_or_malformed_journals_roll_back_the_final_page() {
    let mut pair = Pair::new().await;
    let request = Uuid::new_v4().to_string();
    configure(
        &mut pair,
        1,
        &request,
        ConfigurationEdit::RenameNode {
            name: "known-result".into(),
        },
    )
    .unwrap();
    pair.pump();
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    let (entries, body) = crate::store::configuration::storage::handoff::snapshot(
        &pair.stores[0].db,
        state.checkpoint(),
    )
    .unwrap();
    let original: Vec<Value> = serde_json::from_slice(&body).unwrap();
    let index = original.iter().position(|d| d["id"] == request).unwrap();
    let key = credential(&pair, 1);
    for change in 0..10 {
        let candidate = prepare(&mut pair);
        let id = &candidate.candidate.id;
        let mut changed = original.clone();
        match change {
            0 => changed[index]["writer"] = json!(Uuid::new_v4().to_string()),
            1 => changed[index]["fingerprint"] = json!("f".repeat(64)),
            2 => changed[index]["summary"] = json!({"op":"renew"}),
            3 => changed[index]["result"] = json!({"state":"rejected","reason":"different"}),
            4 => {
                let byte = changed[index]["result"]["checkpoint"]["state_hash"][0]
                    .as_u64()
                    .unwrap();
                changed[index]["result"]["checkpoint"]["state_hash"][0] = json!(byte ^ 1);
            }
            5 => changed.push(changed[index].clone()),
            6 => {
                changed[index]["result"]["checkpoint"]["revision"] =
                    json!(state.checkpoint().revision + 1)
            }
            7 => changed[index]["summary"]["extra"] = json!(true),
            8 => changed.reverse(),
            _ => {}
        }
        let mut changed = serde_jcs::to_vec(&changed).unwrap();
        if change == 9 {
            changed.push(b' ');
        }
        let count = if change == 5 { entries + 1 } else { entries };
        let (manifest, authorization) = signed_snapshot(&pair, &candidate, count, &changed);
        pair.stores[1]
            .begin_owner_handoff_import(&key, id, &authorization, &manifest)
            .unwrap();
        assert!(
            pair.stores[1]
                .import_owner_handoff_page(&key, id, 0, &changed)
                .is_err(),
            "mutation {change}"
        );
        assert_eq!(
            pair.stores[1]
                .owner_handoff_import_status(&key, id)
                .unwrap()["received"],
            0
        );
        assert!(
            pair.stores[1]
                .accept_owner_handoff(&key, id, &authorization)
                .is_err()
        );
    }
    assert_eq!(count(&pair, 1, "owner_journal_pages"), 0);
    assert_eq!(status(&mut pair, 1)["completed_candidates"], 0);
}

#[tokio::test]
async fn authorization_and_page_storage_commit_together_or_leave_the_owner_unfrozen() {
    let mut pair = Pair::new().await;
    let key = credential(&pair, 0);
    let candidate = prepare(&mut pair);
    for table in ["owner_journals", "owner_journal_pages"] {
        pair.stores[0].db.execute_batch(&format!("CREATE TRIGGER fail_journal BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'journal failure'); END;")).unwrap();
        assert!(
            pair.stores[0]
                .authorize_owner_handoff(&key, &candidate)
                .is_err()
        );
        assert_eq!(status(&mut pair, 0)["signing_frozen"], false);
        for table in ["owner_handoffs", "owner_journals", "owner_journal_pages"] {
            assert_eq!(count(&pair, 0, table), 0);
        }
        pair.stores[0]
            .identity
            .signing_owner(&pair.stores[0].db)
            .unwrap();
        pair.stores[0]
            .db
            .execute_batch("DROP TRIGGER fail_journal;")
            .unwrap();
        pair.reopen(0);
    }
    issue(&mut pair, &candidate);
    assert_eq!(status(&mut pair, 0)["signing_frozen"], true);
}

#[tokio::test]
async fn legacy_decisions_allow_missing_old_digests_but_never_overwrite_known_evidence() {
    let mut pair = Pair::new().await;
    let id = Uuid::new_v4().to_string();
    configure(&mut pair, 0, &id, ConfigurationEdit::Renew).unwrap();
    let checkpoint = pair.stores[0]
        .identity
        .state(&pair.stores[0].db)
        .unwrap()
        .checkpoint()
        .clone();
    configure(
        &mut pair,
        0,
        &Uuid::new_v4().to_string(),
        ConfigurationEdit::Renew,
    )
    .unwrap();
    pair.pump();
    pair.stores[0]
        .db
        .execute(
            "UPDATE configuration_edits SET edit=?1,compact=0 WHERE id=?2",
            params![serde_json::to_vec(&ConfigurationEdit::Renew).unwrap(), id],
        )
        .unwrap();
    // A later-enrolled successor may have no pre-enrollment digest evidence.
    pair.stores[1]
        .db
        .execute(
            "DELETE FROM authority_history WHERE revision=?1",
            [checkpoint.revision],
        )
        .unwrap();
    pair.stores[1]
        .db
        .execute(
            "DELETE FROM authority_digests WHERE revision=?1",
            [checkpoint.revision],
        )
        .unwrap();
    let before = count(&pair, 1, "authority_digests");
    let candidate = prepare(&mut pair);
    let authorization = issue(&mut pair, &candidate);
    let key = credential(&pair, 1);
    assert_eq!(count(&pair, 1, "authority_digests"), before);
    let conflict = [17u8; 32];
    pair.stores[1]
        .db
        .execute(
            "INSERT INTO authority_digests(revision,digest) VALUES(?1,?2)",
            params![checkpoint.revision, conflict.as_slice()],
        )
        .unwrap();
    assert!(
        pair.stores[1]
            .accept_owner_handoff(&key, &candidate.candidate.id, &authorization)
            .unwrap_err()
            .to_string()
            .contains("accepted authority")
    );
    assert_eq!(
        pair.stores[1]
            .db
            .query_row(
                "SELECT digest FROM authority_digests WHERE revision=?1",
                [checkpoint.revision],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
        conflict
    );
    assert_eq!(status(&mut pair, 1)["completed_candidates"], 0);
    pair.stores[1]
        .db
        .execute(
            "UPDATE authority_digests SET digest=?1 WHERE revision=?2",
            params![checkpoint.state_hash.as_slice(), checkpoint.revision],
        )
        .unwrap();
    pair.stores[1]
        .accept_owner_handoff(&key, &candidate.candidate.id, &authorization)
        .unwrap();
}

#[tokio::test]
async fn import_reserves_full_byte_budget_and_rejects_agents_and_changed_manifests() {
    let mut pair = Pair::new().await;
    let key = credential(&pair, 1);
    let mut first = None;
    for iteration in 0..3 {
        let candidate = prepare(&mut pair);
        let mut manifest = Manifest::new(&candidate, 0, b"[]").unwrap();
        manifest.bytes = MAX_BYTES;
        manifest.pages = vec![
            gent_crypto::succession::journal::Page {
                bytes: PAGE_BYTES,
                digest: [1; 32]
            };
            MAX_BYTES / PAGE_BYTES
        ];
        let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
        let authorization = state
            .authorize_owner_candidate_with_journal(
                pair.stores[0].identity.owner.as_ref().unwrap(),
                &candidate,
                manifest.digest().unwrap(),
                now() as u64,
            )
            .unwrap();
        assert!(
            pair.stores[1]
                .begin_owner_handoff_import(
                    &pair.keys[1],
                    &candidate.candidate.id,
                    &authorization,
                    &manifest
                )
                .is_err()
        );
        let result = pair.stores[1].begin_owner_handoff_import(
            &key,
            &candidate.candidate.id,
            &authorization,
            &manifest,
        );
        if iteration < 2 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().to_string().contains("budget exhausted"));
        }
        if first.is_none() {
            first = Some((candidate, manifest, authorization));
        }
    }
    let (candidate, manifest, authorization) = first.unwrap();
    let id = &candidate.candidate.id;
    pair.reopen(1);
    pair.stores[1]
        .begin_owner_handoff_import(&key, id, &authorization, &manifest)
        .unwrap();
    assert_eq!(
        status(&mut pair, 1)["journal_transfer"]["reserved_bytes"],
        2 * MAX_BYTES
    );
    assert_eq!(count(&pair, 1, "owner_journal_pages"), 0);
    assert!(
        pair.stores[1]
            .import_owner_handoff_page(&pair.keys[1], id, 0, b"[]")
            .is_err()
    );
    assert!(
        pair.stores[1]
            .owner_handoff_import_status(&pair.keys[1], id)
            .is_err()
    );
    let (changed, auth) = signed_snapshot(&pair, &candidate, 0, b"[]");
    assert!(
        pair.stores[1]
            .begin_owner_handoff_import(&key, id, &auth, &changed)
            .is_err()
    );
    let other = prepare(&mut pair);
    assert!(
        pair.stores[1]
            .begin_owner_handoff_import(&key, &other.candidate.id, &authorization, &manifest)
            .is_err()
    );
}

#[tokio::test]
async fn source_corruption_blocks_export_without_restoring_signing() {
    let mut pair = Pair::new().await;
    let candidate = prepare(&mut pair);
    let id = &candidate.candidate.id;
    let key = credential(&pair, 0);
    issue(&mut pair, &candidate);
    assert!(
        pair.stores[0]
            .owner_handoff_manifest(&pair.keys[0], id)
            .is_err()
    );
    assert!(
        pair.stores[0]
            .owner_handoff_page(&pair.keys[0], id, 0)
            .is_err()
    );
    pair.stores[0]
        .db
        .execute(
            "UPDATE owner_journal_pages SET body=x'00' WHERE id=?1",
            [id],
        )
        .unwrap();
    assert!(pair.stores[0].owner_handoff_page(&key, id, 0).is_err());
    assert!(
        pair.stores[0]
            .identity
            .signing_owner(&pair.stores[0].db)
            .is_err()
    );
    pair.stores[0]
        .db
        .execute("DELETE FROM owner_journal_pages WHERE id=?1", [id])
        .unwrap();
    assert!(pair.stores[0].owner_handoff_page(&key, id, 0).is_err());
    pair.stores[0]
        .db
        .execute("DELETE FROM owner_journals WHERE id=?1", [id])
        .unwrap();
    assert!(Store::open(pair.homes[0].path()).is_err());
    assert!(
        pair.stores[0]
            .identity
            .signing_owner(&pair.stores[0].db)
            .is_err()
    );
}

#[tokio::test]
async fn schema_eighteen_migration_preserves_legacy_fence_keys_and_completed_candidate() {
    let mut pair = Pair::new().await;
    let candidate = prepare(&mut pair);
    let keys = [credential(&pair, 0), credential(&pair, 1)];
    let identity = pair
        .homes
        .each_ref()
        .map(|h| std::fs::read(h.path().join("identity.key")).unwrap());
    let state = pair.stores[0].identity.state(&pair.stores[0].db).unwrap();
    let authorization = state
        .authorize_owner_candidate(
            pair.stores[0].identity.owner.as_ref().unwrap(),
            &candidate,
            now() as u64,
        )
        .unwrap();
    pair.stores[0]
        .db
        .execute(
            "INSERT INTO owner_handoffs VALUES(?1,?2,?3,?4)",
            params![
                candidate.candidate.id,
                state.signed().encode().unwrap(),
                candidate.encode().unwrap(),
                authorization.encode().unwrap()
            ],
        )
        .unwrap();
    pair.stores[0]
        .db
        .execute(
            "UPDATE owner_handoff_control SET issued=?1",
            [&candidate.candidate.id],
        )
        .unwrap();
    let complete = pair.stores[1]
        .accept_owner_handoff(&keys[1], &candidate.candidate.id, &authorization)
        .unwrap();
    for (i, identity) in identity.iter().enumerate() {
        pair.stores[i].db.execute_batch("DROP TABLE owner_journal_pages; DROP TABLE owner_journals; PRAGMA user_version=18;").unwrap();
        pair.reopen(i);
        assert_eq!(
            std::fs::read(pair.homes[i].path().join("identity.key")).unwrap(),
            *identity
        );
        assert_eq!(
            pair.stores[i]
                .identity
                .state(&pair.stores[i].db)
                .unwrap()
                .checkpoint(),
            state.checkpoint()
        );
        assert_eq!(count(&pair, i, "owner_journals"), 0);
        assert_eq!(
            pair.stores[i]
                .db
                .pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            21
        );
    }
    assert_eq!(status(&mut pair, 0)["signing_frozen"], true);
    assert_eq!(
        pair.stores[0]
            .authorize_owner_handoff(&keys[0], &candidate)
            .unwrap(),
        authorization
    );
    assert_eq!(
        pair.stores[1]
            .accept_owner_handoff(&keys[1], &candidate.candidate.id, &authorization)
            .unwrap()
            .encode()
            .unwrap(),
        complete.encode().unwrap()
    );
    assert!(
        pair.stores[1]
            .identity
            .apply(&pair.stores[1].db, complete)
            .is_err()
    );
}
