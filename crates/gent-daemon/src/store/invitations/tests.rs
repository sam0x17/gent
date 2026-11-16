use super::*;
use crate::pairing::{self, Peer, ServiceRelay, Snapshot};
use gent_crypto::{
    NodeIdentity, SignedState,
    invitation::{Invitation, channel::Initiator},
};
use std::{fs, os::unix::fs::PermissionsExt};
mod replacement;

struct Fixture {
    home: tempfile::TempDir,
    store: Store,
    credential: String,
}

#[test]
fn named_invitation_binds_claim_and_reuses_only_the_original_node() {
    let mut f = Fixture::new();
    let request = Uuid::now_v7().to_string();
    let issuer = f.store.identity.node.id().to_string();
    let bytes = f
        .store
        .create_invitation_at(
            &request,
            true,
            None,
            None,
            Some(("laptop", &issuer)),
            now() as u64,
        )
        .unwrap();
    let invitation = Invitation::decode(&bytes).unwrap();
    assert_eq!(
        *bytes,
        *f.store
            .create_invitation_at(
                &request,
                true,
                None,
                None,
                Some(("laptop", &issuer)),
                now() as u64
            )
            .unwrap()
    );
    assert!(
        f.store
            .create_invitation_at(
                &request,
                true,
                None,
                None,
                Some(("different", &issuer)),
                now() as u64
            )
            .is_err()
    );
    f.store
        .activate_invitation(&f.credential, &invitation.offer().offer.id)
        .unwrap();
    let node = NodeIdentity::generate().unwrap();
    let wrong = ClaimedNode {
        id: node.id().into(),
        key: node.public_key(),
        name: "different".into(),
    };
    assert!(
        f.store
            .claim_invitation(invitation.offer(), &wrong, now() as u64)
            .is_err()
    );
    assert!(handshake(&mut f.store, &invitation, &node, "different").is_err());
    handshake(&mut f.store, &invitation, &node, "laptop").unwrap();
    f.reopen();
    handshake(&mut f.store, &invitation, &node, "laptop").unwrap();
    let second = NodeIdentity::generate().unwrap();
    assert!(handshake(&mut f.store, &invitation, &second, "laptop").is_err());
}
impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut cfg = config::initialize(home.path(), "invitation-test").unwrap();
        cfg.cluster.local_only = false;
        cfg.service = Some(config::ServiceConfig {
            origin: "https://accounts.example/".into(),
            account_id: Uuid::new_v4().to_string(),
        });
        cfg.relay = Some(config::RelayConfig {
            endpoint: "https://relay.example/".into(),
            credential_file: "relay.key".into(),
        });
        config::write_private(
            &home.path().join("relay.key"),
            format!("gent_t1.{}.{}", now(), config::secret()).as_bytes(),
        )
        .unwrap();
        config::save(home.path(), &cfg).unwrap();
        let store = Store::open(home.path()).unwrap();
        let credential = config::read_private(&home.path().join("owner.key")).unwrap();
        Self {
            home,
            store,
            credential,
        }
    }
    fn reopen(&mut self) {
        self.store = Store::open(self.home.path()).unwrap();
    }
    fn issue(&mut self, configure: bool, continuation: Option<&str>) -> Invitation {
        let bytes = self
            .store
            .create_invitation(
                &self.credential,
                &Uuid::now_v7().to_string(),
                configure,
                continuation,
            )
            .unwrap();
        let invitation = Invitation::decode(&bytes).unwrap();
        self.store
            .activate_invitation(&self.credential, &invitation.offer().offer.id)
            .unwrap();
        invitation
    }
}

struct Client {
    channel: Channel,
    session: Session,
}
fn handshake(
    store: &mut Store,
    invitation: &Invitation,
    node: &NodeIdentity,
    name: &str,
) -> Result<Client> {
    let (init, hello) = Initiator::start(invitation, now() as u64)?;
    let (pending, reply) = store.begin_invitation(&invitation.offer().offer.id, &hello)?;
    let (channel, claim) = init.finish(&reply, node, name, now() as u64)?;
    let session = store.accept_invitation(pending, &claim)?;
    Ok(Client { channel, session })
}
fn invocation(action: PairingOp) -> Invocation {
    Invocation {
        id: Uuid::new_v4().to_string(),
        action: Action::Pair { action },
    }
}
fn send(store: &mut Store, client: &mut Client, request: &Invocation) -> Result<Value> {
    let wire = client.channel.seal(&request.encode()?, now() as u64)?;
    let reply = store.invitation_call(&mut client.session, &wire)?;
    let plaintext = client.channel.open(&reply, now() as u64)?;
    match serde_json::from_slice::<Response>(&plaintext)? {
        Response::Ok(value) => Ok(value),
        Response::Error(error) => anyhow::bail!(error),
    }
}
fn snapshot(value: Value) -> VerifiedState {
    let snapshot: Snapshot = serde_json::from_value(value).unwrap();
    VerifiedState::restore(
        snapshot.anchor,
        snapshot.checkpoint,
        SignedState::decode(&STANDARD.decode(snapshot.state).unwrap()).unwrap(),
    )
    .unwrap()
}
fn enroll_request(
    store: &mut Store,
    client: &mut Client,
    node: &NodeIdentity,
    name: &str,
) -> Invocation {
    let state = snapshot(send(store, client, &invocation(PairingOp::Snapshot)).unwrap());
    let request = node
        .request_enrollment(state.anchor(), state.checkpoint(), name, now() as u64)
        .unwrap();
    invocation(PairingOp::Enroll {
        request: STANDARD.encode(request.encode().unwrap()),
    })
}

#[test]
fn ordinary_invitations_cannot_replace_existing_members_even_with_configuration_rights() {
    for configure in [false, true] {
        let mut fixture = Fixture::new();
        let old = NodeIdentity::generate().unwrap();
        let invite = fixture.issue(true, None);
        let mut original = handshake(&mut fixture.store, &invite, &old, "old").unwrap();
        let enrollment = enroll_request(&mut fixture.store, &mut original, &old, "old");
        send(&mut fixture.store, &mut original, &enrollment).unwrap();
        let new = NodeIdentity::generate().unwrap();
        let invite = fixture.issue(configure, None);
        let mut client = handshake(&mut fixture.store, &invite, &new, "new").unwrap();
        let before = snapshot(
            send(
                &mut fixture.store,
                &mut client,
                &invocation(PairingOp::Snapshot),
            )
            .unwrap(),
        );
        let request = new
            .request_replacement(
                before.anchor(),
                before.checkpoint(),
                "new",
                gent_crypto::ReplacedNode {
                    id: old.id().into(),
                    signing_key: old.public_key(),
                },
                now() as u64,
            )
            .unwrap();
        let count = |store: &Store, table: &str| {
            store
                .db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| {
                    r.get::<_, usize>(0)
                })
                .unwrap()
        };
        let operations = count(&fixture.store, "invitation_operations");
        let request = invocation(PairingOp::Enroll {
            request: STANDARD.encode(request.encode().unwrap()),
        });
        assert!(send(&mut fixture.store, &mut client, &request).is_err());
        assert_eq!(count(&fixture.store, "invitation_operations"), operations);
        assert_eq!(count(&fixture.store, "node_removals"), 0);
        assert_eq!(
            fixture
                .store
                .identity
                .state(&fixture.store.db)
                .unwrap()
                .checkpoint(),
            before.checkpoint()
        );
        let ordinary = enroll_request(&mut fixture.store, &mut client, &new, "new");
        send(&mut fixture.store, &mut client, &ordinary).unwrap();
        assert_eq!(
            fixture
                .store
                .identity
                .state(&fixture.store.db)
                .unwrap()
                .state()
                .nodes
                .len(),
            3
        );
    }
}

#[test]
fn local_rpc_requires_owner_authority_and_listing_excludes_invitation_secrets() {
    let mut fixture = Fixture::new();
    let create = InvitationOp::Create {
        replace_node: None,
        request_id: Uuid::now_v7().to_string(),
        can_configure: true,
        continuation: None,
    };
    assert!(
        fixture
            .store
            .execute(Request::Owner {
                credential: "wrong".into(),
                action: OwnerOp::Invitation {
                    action: create.clone()
                }
            })
            .is_err()
    );
    let invoke = |fixture: &mut Fixture, action| {
        fixture.store.execute(Request::Owner {
            credential: fixture.credential.clone(),
            action: OwnerOp::Invitation { action },
        })
    };
    let result = invoke(&mut fixture, create.clone()).unwrap();
    let bytes = STANDARD
        .decode(result["private_invitation"].as_str().unwrap())
        .unwrap();
    let invitation = Invitation::decode(&bytes).unwrap();
    assert_eq!(invoke(&mut fixture, create).unwrap(), result);
    let id = invitation.offer().offer.id.clone();
    let listing = invoke(&mut fixture, InvitationOp::List).unwrap();
    assert_eq!(listing["invitations"][0]["phase"], "draft");
    assert_eq!(listing["invitations"][0].as_object().unwrap().len(), 5);
    assert!(!listing.to_string().contains("private_invitation"));
    invoke(&mut fixture, InvitationOp::Activate { id: id.clone() }).unwrap();
    invoke(&mut fixture, InvitationOp::Revoke { id: id.clone() }).unwrap();
    assert!(invoke(&mut fixture, InvitationOp::Activate { id: id.clone() }).is_err());
    assert_eq!(
        invoke(&mut fixture, InvitationOp::List).unwrap()["invitations"][0]["phase"],
        "revoked"
    );
    let expired = Uuid::new_v7(uuid::Timestamp::from_unix(
        uuid::NoContext,
        now() as u64 - 901,
        0,
    ))
    .to_string();
    invoke(&mut fixture, InvitationOp::Revoke { id: expired }).unwrap();
}

#[test]
fn creation_is_owner_only_durable_idempotent_and_keeps_activation_separate() {
    let mut fixture = Fixture::new();
    let request = Uuid::now_v7().to_string();
    assert!(
        fixture
            .store
            .create_invitation("wrong", &request, true, None)
            .is_err()
    );
    let bytes = fixture
        .store
        .create_invitation(&fixture.credential, &request, true, None)
        .unwrap();
    let invite = Invitation::decode(&bytes).unwrap();
    let id = &invite.offer().offer.id;
    let (_, hello) = Initiator::start(&invite, now() as u64).unwrap();
    assert!(fixture.store.begin_invitation(id, &hello).is_err());
    fixture.reopen();
    assert_eq!(
        *fixture
            .store
            .create_invitation(&fixture.credential, &request, true, None)
            .unwrap(),
        *bytes
    );
    assert!(
        fixture
            .store
            .create_invitation(&fixture.credential, &request, false, None)
            .is_err()
    );
    fixture
        .store
        .activate_invitation(&fixture.credential, id)
        .unwrap();
    fixture
        .store
        .activate_invitation(&fixture.credential, id)
        .unwrap();
    fixture.store.begin_invitation(id, &hello).unwrap();
    assert_eq!(
        fixture
            .store
            .db
            .query_row("SELECT COUNT(*) FROM invitations", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("\"private\""));
}

#[test]
fn claims_survive_restarts_and_competing_store_instances_cannot_choose_two_nodes() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(true, None);
    let id = invitation.offer().offer.id.clone();
    let nodes = [
        NodeIdentity::generate().unwrap(),
        NodeIdentity::generate().unwrap(),
    ];
    let mut pending = Vec::new();
    for node in &nodes {
        let (init, hello) = Initiator::start(&invitation, now() as u64).unwrap();
        let (session, reply) = fixture.store.begin_invitation(&id, &hello).unwrap();
        let (_, claim) = init.finish(&reply, node, "joined", now() as u64).unwrap();
        pending.push((session, claim));
    }
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = pending
        .into_iter()
        .map(|(pending, claim)| {
            let home = fixture.home.path().to_owned();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = Store::open(&home).unwrap();
                barrier.wait();
                store.accept_invitation(pending, &claim).is_ok()
            })
        })
        .collect();
    let accepted: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(accepted.iter().filter(|ok| **ok).count(), 1);
    fixture.reopen();
    let winner = accepted.iter().position(|ok| *ok).unwrap();
    handshake(&mut fixture.store, &invitation, &nodes[winner], "joined").unwrap();
    assert!(
        handshake(
            &mut fixture.store,
            &invitation,
            &nodes[1 - winner],
            "joined"
        )
        .is_err()
    );
    assert!(handshake(&mut fixture.store, &invitation, &nodes[winner], "renamed").is_err());
    assert_eq!(
        record(&fixture.store.db, &id).unwrap().claim.unwrap().key,
        nodes[winner].public_key()
    );
}

#[test]
fn failed_claim_and_request_reservations_have_no_enrollment_side_effects() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(true, None);
    let node = NodeIdentity::generate().unwrap();
    fixture.store.db.execute_batch("CREATE TRIGGER fail_claim BEFORE UPDATE OF claim ON invitations BEGIN SELECT RAISE(ABORT,'injected claim failure'); END;").unwrap();
    assert!(handshake(&mut fixture.store, &invitation, &node, "joined").is_err());
    assert!(
        record(&fixture.store.db, &invitation.offer().offer.id)
            .unwrap()
            .claim
            .is_none()
    );
    fixture
        .store
        .db
        .execute_batch("DROP TRIGGER fail_claim")
        .unwrap();
    fixture.reopen();
    let mut client = handshake(&mut fixture.store, &invitation, &node, "joined").unwrap();
    let request = enroll_request(&mut fixture.store, &mut client, &node, "joined");
    fixture.store.db.execute_batch("CREATE TRIGGER fail_reserve BEFORE INSERT ON invitation_operations WHEN NEW.kind='enroll' BEGIN SELECT RAISE(ABORT,'injected reservation failure'); END;").unwrap();
    assert!(send(&mut fixture.store, &mut client, &request).is_err());
    assert!(
        !fixture
            .store
            .identity
            .state(&fixture.store.db)
            .unwrap()
            .state()
            .nodes
            .contains_key(node.id())
    );
    fixture
        .store
        .db
        .execute_batch("DROP TRIGGER fail_reserve")
        .unwrap();
    send(&mut fixture.store, &mut client, &request).unwrap();
}

#[test]
fn committed_enrollment_recovers_after_journal_failure_without_duplicate_membership() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(false, None);
    let node = NodeIdentity::generate().unwrap();
    let mut client = handshake(&mut fixture.store, &invitation, &node, "joined").unwrap();
    let request = enroll_request(&mut fixture.store, &mut client, &node, "joined");
    fixture.store.db.execute_batch("CREATE TRIGGER fail_result BEFORE UPDATE OF done ON invitation_operations WHEN NEW.kind='enroll' BEGIN SELECT RAISE(ABORT,'injected result failure'); END;").unwrap();
    assert!(send(&mut fixture.store, &mut client, &request).is_err());
    let state = fixture.store.identity.state(&fixture.store.db).unwrap();
    assert_eq!(state.state().nodes.len(), 2);
    assert!(!state.state().nodes[node.id()].can_configure);
    let checkpoint = state.checkpoint().clone();
    assert!(
        record(&fixture.store.db, &invitation.offer().offer.id)
            .unwrap()
            .history_floor
            .is_none()
    );
    fixture
        .store
        .db
        .execute_batch("DROP TRIGGER fail_result")
        .unwrap();
    fixture.reopen();
    let mut client = handshake(&mut fixture.store, &invitation, &node, "joined").unwrap();
    send(&mut fixture.store, &mut client, &request).unwrap();
    assert_eq!(
        fixture
            .store
            .identity
            .state(&fixture.store.db)
            .unwrap()
            .checkpoint(),
        &checkpoint
    );
    let conflict = Invocation {
        id: request.id,
        action: Action::Pair {
            action: PairingOp::Snapshot,
        },
    };
    assert!(send(&mut fixture.store, &mut client, &conflict).is_err());
}

#[test]
fn scope_checks_reject_other_nodes_history_legacy_agents_and_owner_rpc() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(true, None);
    let node = NodeIdentity::generate().unwrap();
    let mut client = handshake(&mut fixture.store, &invitation, &node, "joined").unwrap();
    let outsider = NodeIdentity::generate().unwrap();
    let foreign = enroll_request(&mut fixture.store, &mut client, &outsider, "joined");
    assert!(send(&mut fixture.store, &mut client, &foreign).is_err());
    let request = enroll_request(&mut fixture.store, &mut client, &node, "joined");
    let enrolled = snapshot(send(&mut fixture.store, &mut client, &request).unwrap());
    for action in [
        PairingOp::Configuration {
            request_id: Uuid::new_v4().to_string(),
            peer: outsider.id().into(),
            key_package: String::new(),
        },
        PairingOp::Data {
            request_id: Uuid::new_v4().to_string(),
            peer: node.id().into(),
            key_package: String::new(),
            legacy_agents: vec![Uuid::new_v4().to_string()],
        },
        PairingOp::History {
            revision: enrolled.checkpoint().revision - 1,
            digest: [0; 32],
        },
        PairingOp::AcceptData {
            peer: outsider.id().into(),
            packet: String::new(),
            outgoing_group: String::new(),
        },
    ] {
        assert!(send(&mut fixture.store, &mut client, &invocation(action)).is_err());
    }
    let bytes = serde_jcs::to_vec(&json!({"id":Uuid::new_v4().to_string(),"action":{"kind":"pair","action":{"op":"set_policy","policy":{}}}})).unwrap();
    let ciphertext = client.channel.seal(&bytes, now() as u64).unwrap();
    let reply = fixture
        .store
        .invitation_call(&mut client.session, &ciphertext)
        .unwrap();
    assert!(matches!(
        serde_json::from_slice::<Response>(&client.channel.open(&reply, now() as u64).unwrap())
            .unwrap(),
        Response::Error(_)
    ));
    let value = send(
        &mut fixture.store,
        &mut client,
        &invocation(PairingOp::Snapshot),
    )
    .unwrap();
    assert!(value["relay"].is_null());
    let owner_token =
        config::read_relay_credential(&fixture.home.path().join("relay.key")).unwrap();
    assert!(!value.to_string().contains(&owner_token));
    let packet = node
        .sign_stream_packet(
            Uuid::new_v4().as_bytes(),
            0,
            [0; 32],
            b"not an admitted data group",
        )
        .unwrap();
    let error = send(
        &mut fixture.store,
        &mut client,
        &invocation(PairingOp::AcceptData {
            peer: node.id().into(),
            packet: STANDARD.encode(packet.encode().unwrap()),
            outgoing_group: STANDARD.encode(Uuid::new_v4().as_bytes()),
        }),
    )
    .unwrap_err();
    assert!(error.to_string().contains("outgoing data group"));
}

#[test]
fn revocation_privilege_changes_service_changes_and_retirement_deny_existing_sessions() {
    for change in 0..4 {
        let mut fixture = Fixture::new();
        let invitation = fixture.issue(true, None);
        let node = NodeIdentity::generate().unwrap();
        let mut client = handshake(&mut fixture.store, &invitation, &node, "joined").unwrap();
        let request = enroll_request(&mut fixture.store, &mut client, &node, "joined");
        send(&mut fixture.store, &mut client, &request).unwrap();
        match change {
            0 => fixture
                .store
                .revoke_invitation(&fixture.credential, &invitation.offer().offer.id)
                .unwrap(),
            1 | 2 => {
                let state = fixture.store.identity.state(&fixture.store.db).unwrap();
                let owner = fixture
                    .store
                    .identity
                    .signing_owner(&fixture.store.db)
                    .unwrap();
                let update = if change == 1 {
                    state
                        .delegate_configuration(&owner, node.id(), false, now() as u64)
                        .unwrap()
                } else {
                    state.revoke_node(&owner, node.id(), now() as u64).unwrap()
                };
                fixture
                    .store
                    .identity
                    .apply(&fixture.store.db, update)
                    .unwrap();
            }
            3 => {
                fixture.store.config.service.as_mut().unwrap().account_id =
                    Uuid::new_v4().to_string()
            }
            _ => unreachable!(),
        }
        assert!(send(&mut fixture.store, &mut client, &request).is_err());
        assert!(handshake(&mut fixture.store, &invitation, &node, "joined").is_err());
    }
}

#[test]
fn expiry_cleanup_commits_its_clock_and_cannot_recreate_old_creation_requests() {
    let mut fixture = Fixture::new();
    let request = Uuid::now_v7().to_string();
    let bytes = fixture
        .store
        .create_invitation(&fixture.credential, &request, true, None)
        .unwrap();
    let invitation = Invitation::decode(&bytes).unwrap();
    let before = now() as u64;
    let expires = invitation.offer().offer.expires_at;
    fixture.store.db.execute_batch("CREATE TRIGGER fail_cleanup BEFORE DELETE ON invitations BEGIN SELECT RAISE(ABORT,'injected cleanup failure'); END;").unwrap();
    assert!(observe(&fixture.store.db, expires).is_err());
    assert_eq!(
        fixture
            .store
            .db
            .query_row("SELECT floor FROM invitation_clock", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        expires
    );
    fixture
        .store
        .db
        .execute_batch("DROP TRIGGER fail_cleanup")
        .unwrap();
    fixture.reopen();
    assert!(
        fixture
            .store
            .create_invitation_at(&request, true, None, None, None, before)
            .is_err()
    );
    assert_eq!(
        fixture
            .store
            .db
            .query_row("SELECT COUNT(*) FROM invitations", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert!(
        fixture
            .store
            .activate_invitation(&fixture.credential, &invitation.offer().offer.id)
            .is_err()
    );
}

/// This fixture uses the real pairing engine and encrypted dispatcher. The
/// account-service step is deliberately synthetic; no network credential claim.
struct EncryptedPeer {
    fixture: Fixture,
    invitation: Invitation,
    client: Option<Client>,
    calls: usize,
    fail_after: Option<usize>,
    fail_kind: Option<&'static str>,
    last: Option<Invocation>,
}
impl EncryptedPeer {
    fn new(configure: bool) -> Self {
        let mut fixture = Fixture::new();
        let invitation = fixture.issue(configure, None);
        Self {
            fixture,
            invitation,
            client: None,
            calls: 0,
            fail_after: None,
            fail_kind: None,
            last: None,
        }
    }
    fn finish(&mut self, request: &Invocation) -> Result<Value> {
        send(
            &mut self.fixture.store,
            self.client.as_mut().unwrap(),
            request,
        )
    }
}
impl Peer for EncryptedPeer {
    async fn prepare_node(&mut self, node: &NodeIdentity, name: &str) -> Result<()> {
        self.client = Some(handshake(
            &mut self.fixture.store,
            &self.invitation,
            node,
            name,
        )?);
        Ok(())
    }
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        self.calls += 1;
        let request = invocation(action);
        let result = send(
            &mut self.fixture.store,
            self.client
                .as_mut()
                .context("missing prepared invitation node")?,
            &request,
        );
        let fail_kind = self.fail_kind == Some(super::dispatch::kind(&request.action));
        self.last = Some(request);
        let value = result?;
        if self.fail_after == Some(self.calls) || fail_kind {
            anyhow::bail!("lost encrypted pairing response after commit")
        }
        Ok(value)
    }
    async fn prepare_service(&mut self, service: &ServiceRelay) -> Result<()> {
        ensure!(
            service.account == *self.fixture.store.config.service.as_ref().unwrap(),
            "wrong fixture service"
        );
        Ok(())
    }
    async fn provision_service(
        &mut self,
        runtime: &Path,
        _home: &Path,
        service: &ServiceRelay,
    ) -> Result<()> {
        let mut config = config::load(runtime)?;
        config.cluster.local_only = false;
        config.service = Some(service.account.clone());
        config.relay = Some(config::RelayConfig {
            endpoint: service.relay_endpoint.clone(),
            credential_file: "relay.key".into(),
        });
        config::write_private(
            &runtime.join("relay.key"),
            format!("gent_t1.{}.{}", now(), config::secret()).as_bytes(),
        )?;
        config::save(runtime, &config)
    }
}
async fn joined(home: &Path, peer: &mut EncryptedPeer) -> Result<Value> {
    let cluster = peer.invitation.offer().offer.anchor.cluster_id.clone();
    let replacement = peer.invitation.offer().offer.replaces.clone();
    pairing::join(
        home,
        pairing::Options {
            replace_node: replacement.as_ref().map(|target| target.id.as_str()),
            cluster: &cluster,
            name: "joined",
            relay_endpoint: None,
        },
        peer,
    )
    .await
}

#[tokio::test]
async fn complete_encrypted_pairing_preserves_node_only_keys_and_requires_exact_finish_retries() {
    for configure in [true, false] {
        let mut peer = EncryptedPeer::new(configure);
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("joined");
        peer.fail_after = Some(2);
        assert!(joined(&home, &mut peer).await.is_err());
        let premature_finish = Invocation {
            id: Uuid::new_v4().to_string(),
            action: Action::Finish,
        };
        assert!(peer.finish(&premature_finish).is_err());
        peer.fail_after = None;
        joined(&home, &mut peer).await.unwrap();
        let keys = fs::read(home.join("identity.key")).unwrap();
        assert_eq!(&keys[..8], b"GENTKEY2");
        let node = config::load(&home).unwrap().node.id;
        assert_eq!(
            peer.fixture
                .store
                .identity
                .state(&peer.fixture.store.db)
                .unwrap()
                .state()
                .nodes[&node]
                .can_configure,
            configure
        );
        let finish = Invocation {
            id: Uuid::new_v4().to_string(),
            action: Action::Finish,
        };
        let first = peer.finish(&finish).unwrap();
        peer.fixture.reopen();
        let identity =
            NodeIdentity::from_secret_bytes(&node, keys[8..40].try_into().unwrap()).unwrap();
        peer.prepare_node(&identity, "joined").await.unwrap();
        assert_eq!(peer.finish(&finish).unwrap(), first);
        assert!(peer.finish(&premature_finish).is_err());
        assert!(
            peer.finish(&Invocation {
                id: Uuid::new_v4().to_string(),
                action: Action::Finish
            })
            .is_err()
        );
        assert!(peer.finish(&invocation(PairingOp::Snapshot)).is_err());
        assert_eq!(
            record(&peer.fixture.store.db, &peer.invitation.offer().offer.id)
                .unwrap()
                .phase,
            "complete"
        );
    }
}

#[tokio::test]
async fn lost_responses_resume_the_staged_join_without_duplicate_streams_or_new_keys() {
    for boundary in [2, 4, 7] {
        let mut peer = EncryptedPeer::new(true);
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("joined");
        peer.fail_after = Some(boundary);
        assert!(joined(&home, &mut peer).await.is_err());
        let seed = fs::read(config::pending_join(&home).unwrap().join("join.key")).unwrap();
        peer.fail_after = None;
        peer.fixture.reopen();
        joined(&home, &mut peer).await.unwrap();
        assert_eq!(
            &seed[8..40],
            &fs::read(home.join("identity.key")).unwrap()[8..40]
        );
        assert_eq!(
            peer.fixture
                .store
                .identity
                .state(&peer.fixture.store.db)
                .unwrap()
                .state()
                .nodes
                .len(),
            2
        );
        assert_eq!(
            peer.fixture
                .store
                .db
                .query_row("SELECT COUNT(*) FROM configuration_streams", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            peer.fixture
                .store
                .db
                .query_row("SELECT COUNT(*) FROM network_links", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
    }
}

fn pending_node(home: &Path) -> NodeIdentity {
    let bytes = fs::read(config::pending_join(home).unwrap().join("join.key")).unwrap();
    let seed: Value = serde_json::from_slice(&bytes[40..]).unwrap();
    NodeIdentity::from_secret_bytes(
        seed["node"].as_str().unwrap(),
        bytes[8..40].try_into().unwrap(),
    )
    .unwrap()
}

#[test]
fn admitted_attempts_cannot_be_reconstructed_after_restart_or_hello_substitution() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(true, None);
    let id = &invitation.offer().offer.id;
    let (_, hello) = Initiator::start(&invitation, now() as u64).unwrap();
    assert!(
        !fixture
            .store
            .invitation_attempt_seen(id, &hello.attempt)
            .unwrap()
    );
    let (_pending, _lost_reply) = fixture.store.begin_invitation(id, &hello).unwrap();
    fixture.reopen();
    for _ in 0..3 {
        assert!(
            fixture
                .store
                .invitation_attempt_seen(id, &hello.attempt)
                .unwrap()
        );
        assert!(fixture.store.begin_invitation(id, &hello).is_err());
    }
    let (_, mut changed) = Initiator::start(&invitation, now() as u64).unwrap();
    changed.attempt = hello.attempt;
    assert!(fixture.store.begin_invitation(id, &changed).is_err());
    assert_eq!(record(&fixture.store.db, id).unwrap().attempts, 1);
    let (_, fresh) = Initiator::start(&invitation, now() as u64).unwrap();
    fixture.store.begin_invitation(id, &fresh).unwrap();
    assert_eq!(record(&fixture.store.db, id).unwrap().attempts, 2);
    observe(&fixture.store.db, invitation.offer().offer.expires_at).unwrap();
    assert_eq!(
        fixture
            .store
            .db
            .query_row("SELECT COUNT(*) FROM invitation_attempts", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn attempt_reservation_and_budget_commit_together_before_exposing_the_reply() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(true, None);
    let id = &invitation.offer().offer.id;
    let (_, mut bad) = Initiator::start(&invitation, now() as u64).unwrap();
    bad.noise[0] ^= 1;
    assert!(fixture.store.begin_invitation(id, &bad).is_err());
    assert!(
        !fixture
            .store
            .invitation_attempt_seen(id, &bad.attempt)
            .unwrap()
    );
    assert_eq!(record(&fixture.store.db, id).unwrap().attempts, 0);
    for sql in [
        "CREATE TRIGGER fail_attempt BEFORE INSERT ON invitation_attempts BEGIN SELECT RAISE(ABORT,'injected reservation failure'); END;",
        "CREATE TRIGGER fail_attempt BEFORE UPDATE OF attempts ON invitations BEGIN SELECT RAISE(ABORT,'injected counter failure'); END;",
    ] {
        let (_, hello) = Initiator::start(&invitation, now() as u64).unwrap();
        fixture.store.db.execute_batch(sql).unwrap();
        let count = record(&fixture.store.db, id).unwrap().attempts;
        assert!(fixture.store.begin_invitation(id, &hello).is_err());
        assert!(
            !fixture
                .store
                .invitation_attempt_seen(id, &hello.attempt)
                .unwrap()
        );
        assert_eq!(record(&fixture.store.db, id).unwrap().attempts, count);
        fixture
            .store
            .db
            .execute_batch("DROP TRIGGER fail_attempt")
            .unwrap();
        fixture.reopen();
        fixture.store.begin_invitation(id, &hello).unwrap();
    }
}

#[test]
fn competing_stores_admit_the_same_handshake_at_most_once() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(false, None);
    let (_, hello) = Initiator::start(&invitation, now() as u64).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let home = fixture.home.path().to_owned();
            let id = invitation.offer().offer.id.clone();
            let hello = Hello {
                attempt: hello.attempt.clone(),
                noise: hello.noise.clone(),
            };
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = Store::open(&home).unwrap();
                barrier.wait();
                store.begin_invitation(&id, &hello).is_ok()
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|ok| **ok).count(), 1);
    assert_eq!(
        record(&fixture.store.db, &invitation.offer().offer.id)
            .unwrap()
            .attempts,
        1
    );
}

#[test]
fn migration_closes_only_legacy_used_offers_and_missing_attempt_journal_fails_closed() {
    let mut fixture = Fixture::new();
    let used = fixture.issue(true, None);
    let unused = fixture.issue(false, None);
    let (_, hello) = Initiator::start(&used, now() as u64).unwrap();
    fixture
        .store
        .begin_invitation(&used.offer().offer.id, &hello)
        .unwrap();
    let keys = fs::read(fixture.home.path().join("identity.key")).unwrap();
    fixture
        .store
        .db
        .execute_batch("DROP TABLE invitation_attempts; PRAGMA user_version=14;")
        .unwrap();
    fixture.reopen();
    let used_row = record(&fixture.store.db, &used.offer().offer.id).unwrap();
    assert_eq!(used_row.phase, "revoked");
    assert!(used_row.secret.is_none());
    assert_eq!(
        record(&fixture.store.db, &unused.offer().offer.id)
            .unwrap()
            .phase,
        "issued"
    );
    assert_eq!(
        fs::read(fixture.home.path().join("identity.key")).unwrap(),
        keys
    );
    let (_, hello) = Initiator::start(&unused, now() as u64).unwrap();
    fixture
        .store
        .begin_invitation(&unused.offer().offer.id, &hello)
        .unwrap();
    fixture
        .store
        .db
        .execute_batch("DROP TABLE invitation_attempts;")
        .unwrap();
    assert!(Store::open(fixture.home.path()).is_err());
}

#[tokio::test]
async fn committed_grants_and_links_recover_after_failed_journal_completion() {
    for kind in ["configuration", "data", "accept"] {
        let mut peer = EncryptedPeer::new(true);
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("joined");
        peer.fixture.store.db.execute_batch(&format!("CREATE TRIGGER fail_result BEFORE UPDATE OF done ON invitation_operations WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(ABORT,'injected result failure'); END;")).unwrap();
        assert!(joined(&home, &mut peer).await.is_err());
        let request = peer.last.take().unwrap();
        assert_eq!(super::dispatch::kind(&request.action), kind);
        let done: bool = peer
            .fixture
            .store
            .db
            .query_row(
                "SELECT done FROM invitation_operations WHERE invitation=?1 AND id=?2",
                params![peer.invitation.offer().offer.id, request.id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!done);
        if kind == "accept" {
            assert_eq!(
                peer.fixture
                    .store
                    .db
                    .query_row("SELECT COUNT(*) FROM network_links", [], |r| r
                        .get::<_, u64>(0))
                    .unwrap(),
                1
            );
        }
        let node = pending_node(&home);
        peer.fixture
            .store
            .db
            .execute_batch("DROP TRIGGER fail_result")
            .unwrap();
        peer.fixture.reopen();
        peer.prepare_node(&node, "joined").await.unwrap();
        peer.finish(&request).unwrap();
        assert!(
            peer.fixture
                .store
                .db
                .query_row(
                    "SELECT done FROM invitation_operations WHERE invitation=?1 AND id=?2",
                    params![peer.invitation.offer().offer.id, request.id],
                    |r| r.get::<_, bool>(0)
                )
                .unwrap()
        );
        joined(&home, &mut peer).await.unwrap();
        assert_eq!(
            peer.fixture
                .store
                .db
                .query_row("SELECT COUNT(*) FROM configuration_streams", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            peer.fixture
                .store
                .db
                .query_row("SELECT COUNT(*) FROM network_links", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            &*node.expose_secret(),
            &fs::read(home.join("identity.key")).unwrap()[8..40]
        );
    }
}

#[tokio::test]
async fn explicit_continuation_recovers_original_node_and_crypto_requests_across_offers() {
    for boundary in [4, 7] {
        let mut peer = EncryptedPeer::new(true);
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("joined");
        peer.fail_after = Some(boundary);
        assert!(joined(&home, &mut peer).await.is_err());
        let node = pending_node(&home);
        let original = peer.invitation.offer().offer.id.clone();
        peer.fixture
            .store
            .revoke_invitation(&peer.fixture.credential, &original)
            .unwrap();
        peer.fixture.reopen();
        assert!(handshake(&mut peer.fixture.store, &peer.invitation, &node, "joined").is_err());
        let replacement = peer.fixture.issue(true, Some(node.id()));
        assert_ne!(replacement.offer().offer.id, original);
        assert!(
            handshake(
                &mut peer.fixture.store,
                &replacement,
                &NodeIdentity::generate().unwrap(),
                "joined"
            )
            .is_err()
        );
        peer.invitation = replacement;
        peer.fail_after = None;
        joined(&home, &mut peer).await.unwrap();
        assert_eq!(
            &*node.expose_secret(),
            &fs::read(home.join("identity.key")).unwrap()[8..40]
        );
        assert_eq!(
            peer.fixture
                .store
                .db
                .query_row("SELECT COUNT(*) FROM configuration_streams", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            peer.fixture
                .store
                .db
                .query_row("SELECT COUNT(*) FROM network_links", [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            peer.fixture
                .store
                .identity
                .state(&peer.fixture.store.db)
                .unwrap()
                .state()
                .nodes
                .len(),
            2
        );
    }
}

#[test]
fn migration_preserves_state_and_refuses_missing_established_invitation_journals() {
    let mut fixture = Fixture::new();
    let keys = fs::read(fixture.home.path().join("identity.key")).unwrap();
    fixture.store.db.execute_batch("DROP TABLE invitation_attempts; DROP TABLE invitation_operations; DROP TABLE invitations; DROP TABLE invitation_clock; PRAGMA user_version=13;").unwrap();
    fixture.reopen();
    assert_eq!(
        fixture
            .store
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))
            .unwrap(),
        26
    );
    assert_eq!(
        fs::read(fixture.home.path().join("identity.key")).unwrap(),
        keys
    );
    let invitation = fixture.issue(true, None);
    fixture
        .store
        .db
        .execute_batch("DROP TABLE invitation_operations;")
        .unwrap();
    assert!(Store::open(fixture.home.path()).is_err());
    assert!(
        fixture
            .store
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM invitations WHERE id=?1)",
                [&invitation.offer().offer.id],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
}

#[test]
fn invitation_and_handshake_capacity_preserve_retries_revocation_and_expiry_cleanup() {
    let mut fixture = Fixture::new();
    let request = Uuid::now_v7().to_string();
    let original = fixture
        .store
        .create_invitation(&fixture.credential, &request, true, None)
        .unwrap();
    let invitation = Invitation::decode(&original).unwrap();
    fixture
        .store
        .activate_invitation(&fixture.credential, &invitation.offer().offer.id)
        .unwrap();
    fixture
        .store
        .db
        .execute("UPDATE invitations SET attempts=?1", [MAX_ATTEMPTS - 1])
        .unwrap();
    let (_, hello) = Initiator::start(&invitation, now() as u64).unwrap();
    fixture
        .store
        .begin_invitation(&invitation.offer().offer.id, &hello)
        .unwrap();
    let (_, hello) = Initiator::start(&invitation, now() as u64).unwrap();
    assert!(
        fixture
            .store
            .begin_invitation(&invitation.offer().offer.id, &hello)
            .is_err()
    );
    for _ in 1..MAX_INVITATIONS {
        fixture
            .store
            .create_invitation(
                &fixture.credential,
                &Uuid::now_v7().to_string(),
                false,
                None,
            )
            .unwrap();
    }
    assert!(
        fixture
            .store
            .create_invitation(
                &fixture.credential,
                &Uuid::now_v7().to_string(),
                false,
                None
            )
            .is_err()
    );
    assert_eq!(
        *fixture
            .store
            .create_invitation(&fixture.credential, &request, true, None)
            .unwrap(),
        *original
    );
    fixture
        .store
        .revoke_invitation(&fixture.credential, &invitation.offer().offer.id)
        .unwrap();
    assert!(
        fixture
            .store
            .create_invitation(&fixture.credential, &request, true, None)
            .is_err()
    );
    let expires: u64 = fixture
        .store
        .db
        .query_row("SELECT MAX(expires) FROM invitations", [], |r| r.get(0))
        .unwrap();
    observe(&fixture.store.db, expires).unwrap();
    assert_eq!(
        fixture
            .store
            .db
            .query_row("SELECT COUNT(*) FROM invitations", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert!(
        fixture
            .store
            .create_invitation_at(&request, true, None, None, None, expires)
            .is_err()
    );
}

#[test]
fn pending_handshake_cannot_claim_after_revocation() {
    let mut fixture = Fixture::new();
    let invitation = fixture.issue(true, None);
    let node = NodeIdentity::generate().unwrap();
    let (init, hello) = Initiator::start(&invitation, now() as u64).unwrap();
    let (pending, reply) = fixture
        .store
        .begin_invitation(&invitation.offer().offer.id, &hello)
        .unwrap();
    let (_, claim) = init.finish(&reply, &node, "joined", now() as u64).unwrap();
    fixture
        .store
        .revoke_invitation(&fixture.credential, &invitation.offer().offer.id)
        .unwrap();
    fixture.reopen();
    assert!(fixture.store.accept_invitation(pending, &claim).is_err());
    let row = record(&fixture.store.db, &invitation.offer().offer.id).unwrap();
    assert_eq!(row.phase, "revoked");
    assert!(row.claim.is_none() && row.secret.is_none());
    assert_eq!(
        fixture
            .store
            .identity
            .state(&fixture.store.db)
            .unwrap()
            .state()
            .nodes
            .len(),
        1
    );
}

fn fill_operations(db: &Connection, id: &str, count: u64) {
    // Fill capacity directly; only boundary requests exercise the real channel.
    db.execute(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?2)
         INSERT INTO invitation_operations(invitation,id,fingerprint,kind,done)
         SELECT ?1,'fixture-'||x,zeroblob(32),'snapshot',1 FROM n",
        params![id, count],
    )
    .unwrap();
}

#[test]
fn per_invitation_and_global_operation_limits_preserve_exact_retries() {
    for global in [false, true] {
        let mut fixture = Fixture::new();
        let invitation = fixture.issue(true, None);
        let node = NodeIdentity::generate().unwrap();
        let mut client = handshake(&mut fixture.store, &invitation, &node, "joined").unwrap();
        if global {
            let mut remaining = MAX_OPERATIONS - 1;
            while remaining > 0 {
                let other = fixture.issue(true, None);
                let count = remaining.min(MAX_INVITATION_OPERATIONS);
                fill_operations(&fixture.store.db, &other.offer().offer.id, count);
                remaining -= count;
            }
        } else {
            fill_operations(
                &fixture.store.db,
                &invitation.offer().offer.id,
                MAX_INVITATION_OPERATIONS - 1,
            );
        }
        let request = invocation(PairingOp::Snapshot);
        let original = send(&mut fixture.store, &mut client, &request).unwrap();
        let error = send(
            &mut fixture.store,
            &mut client,
            &invocation(PairingOp::Snapshot),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(if global { "capacity" } else { "budget" })
        );
        fixture.reopen();
        client = handshake(&mut fixture.store, &invitation, &node, "joined").unwrap();
        assert_eq!(
            send(&mut fixture.store, &mut client, &request).unwrap(),
            original
        );
        let conflict = Invocation {
            id: request.id,
            action: Action::Finish,
        };
        assert!(
            send(&mut fixture.store, &mut client, &conflict)
                .unwrap_err()
                .to_string()
                .contains("another input")
        );
    }
}

#[tokio::test]
async fn stream_budgets_preserve_retries_and_do_not_create_extra_groups() {
    for kind in ["configuration", "data", "accept"] {
        let mut peer = EncryptedPeer::new(true);
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("joined");
        peer.fail_kind = Some(kind);
        assert!(joined(&home, &mut peer).await.is_err());
        let original = peer.last.take().unwrap();
        assert_eq!(super::dispatch::kind(&original.action), kind);
        let result = peer.finish(&original).unwrap();
        let Action::Pair { action } = &original.action else {
            panic!("expected pairing request")
        };
        let mut last = invocation(action.clone());
        for _ in 1..MAX_GRANTS {
            last = invocation(action.clone());
            assert_eq!(peer.finish(&last).unwrap(), result);
        }
        let error = peer.finish(&invocation(action.clone())).unwrap_err();
        assert!(error.to_string().contains("stream budget"));
        peer.fixture.reopen();
        let node = pending_node(&home);
        peer.prepare_node(&node, "joined").await.unwrap();
        assert_eq!(peer.finish(&original).unwrap(), result);
        assert_eq!(peer.finish(&last).unwrap(), result);
        assert_eq!(peer.fixture.store.db.query_row(
            "SELECT COUNT(DISTINCT group_id) FROM invitation_operations WHERE invitation=?1 AND kind=?2",
            params![peer.invitation.offer().offer.id, kind], |r| r.get::<_, u64>(0)
        ).unwrap(), 1);
        assert_eq!(
            peer.fixture
                .store
                .db
                .query_row(
                    "SELECT COUNT(*) FROM invitation_operations WHERE invitation=?1 AND kind=?2",
                    params![peer.invitation.offer().offer.id, kind],
                    |r| r.get::<_, u64>(0)
                )
                .unwrap(),
            MAX_GRANTS
        );
    }
}
