use super::*;
use gent_crypto::ReplacedNode;

fn issue(
    f: &mut Fixture,
    configure: bool,
    target: Option<&str>,
    continuation: Option<&str>,
) -> Invitation {
    let bytes = f
        .store
        .create_invitation_with_replacement(
            &f.credential,
            &Uuid::now_v7().to_string(),
            configure,
            continuation,
            target,
        )
        .unwrap();
    let invitation = Invitation::decode(&bytes).unwrap();
    f.store
        .activate_invitation(&f.credential, &invitation.offer().offer.id)
        .unwrap();
    invitation
}
fn old_node(f: &mut Fixture, configure: bool) -> NodeIdentity {
    let node = NodeIdentity::generate().unwrap();
    let invitation = f.issue(configure, None);
    let mut client = handshake(&mut f.store, &invitation, &node, "old").unwrap();
    let request = enroll_request(&mut f.store, &mut client, &node, "old");
    send(&mut f.store, &mut client, &request).unwrap();
    node
}
fn replacement(
    f: &mut Fixture,
    client: &mut Client,
    node: &NodeIdentity,
    target: ReplacedNode,
) -> Invocation {
    let state = snapshot(send(&mut f.store, client, &invocation(PairingOp::Snapshot)).unwrap());
    let request = node
        .request_replacement(
            state.anchor(),
            state.checkpoint(),
            "new",
            target,
            now() as u64,
        )
        .unwrap();
    invocation(PairingOp::Enroll {
        request: STANDARD.encode(request.encode().unwrap()),
    })
}
fn checkpoint(f: &Fixture) -> gent_crypto::Checkpoint {
    f.store
        .identity
        .state(&f.store.db)
        .unwrap()
        .checkpoint()
        .clone()
}
fn count(f: &Fixture, table: &str) -> usize {
    f.store
        .db
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap()
}

#[test]
fn replacement_offer_is_explicit_scoped_and_cannot_increase_old_privileges() {
    for (old_admin, requested_admin) in [(false, false), (false, true), (true, false), (true, true)]
    {
        let mut f = Fixture::new();
        let old = old_node(&mut f, old_admin);
        let invitation = issue(&mut f, requested_admin, Some(old.id()), None);
        let target = invitation.offer().offer.replaces.clone().unwrap();
        assert_eq!(target.signing_key, old.public_key());
        assert_eq!(
            invitation.offer().offer.can_configure,
            old_admin && requested_admin
        );
        assert!(handshake(&mut f.store, &invitation, &old, "old").is_err());
        let node = NodeIdentity::generate().unwrap();
        let mut client = handshake(&mut f.store, &invitation, &node, "new").unwrap();
        let before = checkpoint(&f);
        let ordinary = enroll_request(&mut f.store, &mut client, &node, "new");
        let operations = count(&f, "invitation_operations");
        assert!(send(&mut f.store, &mut client, &ordinary).is_err());
        assert_eq!(count(&f, "invitation_operations"), operations);
        let mut wrong = target.clone();
        wrong.signing_key = NodeIdentity::generate().unwrap().public_key();
        let wrong = replacement(&mut f, &mut client, &node, wrong);
        assert!(send(&mut f.store, &mut client, &wrong).is_err());
        let request = replacement(&mut f, &mut client, &node, target.clone());
        let success = send(&mut f.store, &mut client, &request).unwrap();
        assert_eq!(checkpoint(&f).revision, before.revision + 1);
        assert_eq!(count(&f, "node_removals"), 1);
        assert_eq!(
            f.store.identity.state(&f.store.db).unwrap().state().nodes[node.id()].can_configure,
            old_admin && requested_admin
        );
        f.reopen();
        client = handshake(&mut f.store, &invitation, &node, "new").unwrap();
        assert_eq!(
            send(&mut f.store, &mut client, &request).unwrap()["checkpoint"],
            success["checkpoint"]
        );
        let other = NodeIdentity::generate().unwrap();
        assert!(handshake(&mut f.store, &invitation, &other, "new").is_err());
        f.store
            .execute(Request::Owner {
                credential: f.credential.clone(),
                action: OwnerOp::RemoveNode {
                    node_id: node.id().into(),
                },
            })
            .unwrap();
        assert!(handshake(&mut f.store, &invitation, &node, "new").is_err());
        assert!(
            f.store
                .create_invitation(
                    &f.credential,
                    &Uuid::now_v7().to_string(),
                    old_admin && requested_admin,
                    Some(node.id())
                )
                .is_err()
        );
    }
}

#[test]
fn competing_offers_privilege_changes_and_owner_replacement_fail_before_retirement() {
    let mut f = Fixture::new();
    let old = old_node(&mut f, true);
    let issuer = f.store.identity.node.id().to_owned();
    assert!(
        f.store
            .create_invitation_with_replacement(
                &f.credential,
                &Uuid::now_v7().to_string(),
                true,
                None,
                Some(&issuer)
            )
            .is_err()
    );
    let first = issue(&mut f, true, Some(old.id()), None);
    let second = issue(&mut f, true, Some(old.id()), None);
    let a = NodeIdentity::generate().unwrap();
    let b = NodeIdentity::generate().unwrap();
    let mut one = handshake(&mut f.store, &first, &a, "new").unwrap();
    let mut two = handshake(&mut f.store, &second, &b, "new").unwrap();
    f.store
        .execute(Request::Owner {
            credential: f.credential.clone(),
            action: OwnerOp::DelegateConfiguration {
                node_id: old.id().into(),
                allow: false,
            },
        })
        .unwrap();
    let before = checkpoint(&f);
    assert!(send(&mut f.store, &mut one, &invocation(PairingOp::Snapshot)).is_err());
    assert_eq!(checkpoint(&f), before);
    assert_eq!(count(&f, "node_removals"), 0);
    f.store
        .execute(Request::Owner {
            credential: f.credential.clone(),
            action: OwnerOp::DelegateConfiguration {
                node_id: old.id().into(),
                allow: true,
            },
        })
        .unwrap();
    let one_request = replacement(
        &mut f,
        &mut one,
        &a,
        first.offer().offer.replaces.clone().unwrap(),
    );
    let two_request = replacement(
        &mut f,
        &mut two,
        &b,
        second.offer().offer.replaces.clone().unwrap(),
    );
    send(&mut f.store, &mut one, &one_request).unwrap();
    let after = checkpoint(&f);
    assert!(send(&mut f.store, &mut two, &two_request).is_err());
    assert_eq!(checkpoint(&f), after);
    assert_eq!(count(&f, "node_removals"), 1);
}

#[test]
fn replacement_and_invitation_journal_failures_retry_without_losing_the_retirement_mapping() {
    let mut f = Fixture::new();
    let old = old_node(&mut f, true);
    let invite = issue(&mut f, true, Some(old.id()), None);
    let new = NodeIdentity::generate().unwrap();
    let mut client = handshake(&mut f.store, &invite, &new, "new").unwrap();
    let request = replacement(
        &mut f,
        &mut client,
        &new,
        invite.offer().offer.replaces.clone().unwrap(),
    );
    let before = checkpoint(&f);
    f.store.db.execute_batch("CREATE TRIGGER fail_removal BEFORE INSERT ON node_removals BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(send(&mut f.store, &mut client, &request).is_err());
    assert_eq!(checkpoint(&f), before);
    assert_eq!(count(&f, "node_removals"), 0);
    f.store.db.execute_batch("DROP TRIGGER fail_removal; CREATE TRIGGER fail_result BEFORE UPDATE ON invitation_operations BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
    assert!(send(&mut f.store, &mut client, &request).is_err());
    assert_eq!(checkpoint(&f).revision, before.revision + 1);
    assert_eq!(count(&f, "node_removals"), 1);
    f.store
        .db
        .execute_batch("DROP TRIGGER fail_result;")
        .unwrap();
    f.reopen();
    let mut client = handshake(&mut f.store, &invite, &new, "new").unwrap();
    send(&mut f.store, &mut client, &request).unwrap();
    assert_eq!(checkpoint(&f).revision, before.revision + 1);
    let continued = issue(&mut f, true, None, Some(new.id()));
    assert_eq!(
        continued.offer().offer.replaces,
        invite.offer().offer.replaces
    );
    let mut client = handshake(&mut f.store, &continued, &new, "new").unwrap();
    let snapshot =
        snapshot(send(&mut f.store, &mut client, &invocation(PairingOp::Snapshot)).unwrap());
    let signed = new
        .request_replacement(
            snapshot.anchor(),
            snapshot.checkpoint(),
            "new",
            invite.offer().offer.replaces.clone().unwrap(),
            now() as u64,
        )
        .unwrap();
    send(
        &mut f.store,
        &mut client,
        &invocation(PairingOp::Enroll {
            request: STANDARD.encode(signed.encode().unwrap()),
        }),
    )
    .unwrap();
    assert_eq!(checkpoint(&f).revision, before.revision + 1);
    // Continuation cannot omit the old target even though the new identity is enrolled.
    let plain = enroll_request(&mut f.store, &mut client, &new, "new");
    assert!(send(&mut f.store, &mut client, &plain).is_err());
}

#[tokio::test]
async fn encrypted_replacement_resumes_each_pairing_step_and_continues_after_offer_revocation() {
    for step in 1..=8 {
        let mut peer = EncryptedPeer::new(true);
        let old = old_node(&mut peer.fixture, true);
        peer.invitation = issue(&mut peer.fixture, true, Some(old.id()), None);
        let target = peer.invitation.offer().offer.replaces.clone();
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("new");
        peer.fail_after = Some(step);
        assert!(joined(&home, &mut peer).await.is_err());
        let seed = fs::read(config::pending_join(&home).unwrap().join("join.key")).unwrap();
        let saved: Value = serde_json::from_slice(&seed[40..]).unwrap();
        let node = saved["node"].as_str().unwrap();
        peer.fail_after = None;
        peer.fixture.reopen();
        if step == 2 || step == 4 {
            peer.fixture
                .store
                .revoke_invitation(&peer.fixture.credential, &peer.invitation.offer().offer.id)
                .unwrap();
            peer.invitation = issue(&mut peer.fixture, true, None, Some(node));
            assert_eq!(peer.invitation.offer().offer.replaces, target);
        }
        joined(&home, &mut peer).await.unwrap();
        assert_eq!(
            &fs::read(home.join("identity.key")).unwrap()[8..40],
            &seed[8..40]
        );
        assert_eq!(pairing::installed_replacement(&home).unwrap(), target);
        assert_eq!(count(&peer.fixture, "node_removals"), 1);
        assert_eq!(checkpoint(&peer.fixture).revision, 2);
        drop(Store::open(&home).unwrap());
    }
}
