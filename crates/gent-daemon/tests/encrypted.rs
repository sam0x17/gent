use gent_crypto::{NodeIdentity, OwnerKey, VerifiedState};
use gent_daemon::encrypted::{EncryptedEndpoint, MAX_PAYLOAD_BYTES, Outgoing, Received};
use openmls::prelude::{
    tls_codec::{Deserialize as _, Serialize as _},
    *,
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

struct Fixture {
    owner: OwnerKey,
    nodes: [NodeIdentity; 3],
    homes: [tempfile::TempDir; 3],
    state: VerifiedState,
    now: u64,
}

impl Fixture {
    fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nodes = std::array::from_fn(|_| NodeIdentity::generate().unwrap());
        let homes = std::array::from_fn(|_| {
            let home = tempfile::tempdir().unwrap();
            fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
            home
        });
        let owner = OwnerKey::generate().unwrap();
        let mut state = owner
            .create_cluster("MLS test", &nodes[0], "first", now)
            .unwrap();
        for node in &nodes[1..] {
            let request = node
                .request_enrollment(state.anchor(), state.checkpoint(), "peer", now)
                .unwrap();
            let update = state
                .enroll(&owner, &request, request.fingerprint().unwrap(), now)
                .unwrap();
            state.apply_chain(&[update], now).unwrap();
        }
        let result = Self {
            owner,
            nodes,
            homes,
            state,
            now,
        };
        for i in 0..3 {
            result.endpoint(i).initialize(&result.state, now).unwrap();
        }
        result
    }
    fn endpoint(&self, index: usize) -> EncryptedEndpoint<'_> {
        EncryptedEndpoint::open(self.homes[index].path(), &self.nodes[index]).unwrap()
    }
    fn db(&self, index: usize) -> Connection {
        Connection::open(self.homes[index].path().join("mls.sqlite3")).unwrap()
    }
    fn invite(&self, count: usize) -> Outgoing {
        let packages: Vec<_> = (1..count)
            .map(|i| {
                self.endpoint(i)
                    .key_package(Uuid::new_v4(), self.now)
                    .unwrap()
            })
            .collect();
        let peers: Vec<_> = packages
            .iter()
            .enumerate()
            .map(|(i, package)| (self.nodes[i + 1].id(), package.as_slice()))
            .collect();
        self.endpoint(0)
            .create_group(Uuid::new_v4(), &peers, self.now)
            .unwrap()
    }
    fn group(&self, count: usize) -> Outgoing {
        let invitation = self.invite(count);
        let roster: Vec<_> = self.nodes[..count].iter().map(NodeIdentity::id).collect();
        for i in 1..count {
            self.endpoint(i)
                .join(&invitation, &roster, self.now)
                .unwrap();
        }
        invitation
    }
}

#[test]
fn offline_delivery_restart_and_idempotent_binary_replies() {
    let fixture = Fixture::new();
    let request = Uuid::new_v4();
    let package = fixture
        .endpoint(1)
        .key_package(request, fixture.now)
        .unwrap();
    assert_eq!(
        package,
        fixture
            .endpoint(1)
            .key_package(request, fixture.now)
            .unwrap()
    );
    let peers = [(fixture.nodes[1].id(), package.as_slice())];
    let request = Uuid::new_v4();
    let invitation = fixture
        .endpoint(0)
        .create_group(request, &peers, fixture.now)
        .unwrap();
    assert_eq!(
        invitation,
        fixture
            .endpoint(0)
            .create_group(request, &peers, fixture.now)
            .unwrap()
    );
    let marker = b"offline private screenshot marker";
    let message_id = Uuid::new_v4();
    let message = fixture
        .endpoint(0)
        .send(&invitation.group_id, message_id, marker, fixture.now)
        .unwrap();
    assert!(
        !message
            .bytes
            .windows(marker.len())
            .any(|window| window == marker)
    );
    assert_eq!(
        message,
        fixture
            .endpoint(0)
            .send(&invitation.group_id, message_id, marker, fixture.now)
            .unwrap()
    );
    assert!(
        fixture
            .endpoint(0)
            .send(&invitation.group_id, message_id, b"different", fixture.now)
            .is_err()
    );
    assert!(
        fixture
            .endpoint(0)
            .rotate(&invitation.group_id, message_id, fixture.now)
            .is_err()
    );
    let roster = [fixture.nodes[0].id(), fixture.nodes[1].id()];
    fixture
        .endpoint(1)
        .join(&invitation, &roster, fixture.now)
        .unwrap();
    fixture
        .endpoint(1)
        .join(&invitation, &roster, fixture.now)
        .unwrap();
    assert!(
        matches!(fixture.endpoint(1).receive(&message.group_id, &message.bytes, fixture.now).unwrap(), Received::Application { id, .. } if id == message_id)
    );
    assert_eq!(
        fixture.endpoint(1).inbox(&message.group_id, 0, 10).unwrap()[0]
            .1
            .body,
        marker
    );
    assert_eq!(
        fixture
            .endpoint(1)
            .receive(&message.group_id, &message.bytes, fixture.now)
            .unwrap(),
        Received::Duplicate
    );
    let bytes: Vec<u8> = (0..MAX_PAYLOAD_BYTES).map(|n| n as u8).collect();
    let reply = fixture
        .endpoint(1)
        .send(&message.group_id, Uuid::new_v4(), &bytes, fixture.now)
        .unwrap();
    fixture
        .endpoint(0)
        .receive(&reply.group_id, &reply.bytes, fixture.now)
        .unwrap();
    assert!(
        fixture.endpoint(0).inbox(&reply.group_id, 0, 1).unwrap()[0]
            .1
            .body
            == bytes
    );
    let queued = fixture.endpoint(0).outbox(0, 10).unwrap();
    assert_eq!(queued.len(), 2);
    assert_eq!(queued[1].1, message);
}

#[test]
fn key_packages_require_the_owner_approved_key_and_cluster() {
    let fixture = Fixture::new();
    let package = fixture
        .endpoint(1)
        .key_package(Uuid::new_v4(), fixture.now)
        .unwrap();
    assert!(
        fixture
            .endpoint(0)
            .create_group(
                Uuid::new_v4(),
                &[(fixture.nodes[2].id(), &package)],
                fixture.now
            )
            .is_err()
    );
    let provider = OpenMlsRustCrypto::default();
    let honest = KeyPackageIn::tls_deserialize_exact(&package)
        .unwrap()
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap();
    let attacker = NodeIdentity::generate().unwrap();
    // Valid MLS signatures, but the attacker claims the victim's credential ID.
    let substituted = KeyPackage::builder()
        .build(
            honest.ciphersuite(),
            &provider,
            &attacker,
            CredentialWithKey {
                credential: honest.leaf_node().credential().clone(),
                signature_key: attacker.public_key().to_vec().into(),
            },
        )
        .unwrap()
        .key_package()
        .tls_serialize_detached()
        .unwrap();
    assert!(
        fixture
            .endpoint(0)
            .create_group(
                Uuid::new_v4(),
                &[(fixture.nodes[1].id(), &substituted)],
                fixture.now
            )
            .is_err()
    );
    let other = Fixture::new();
    let foreign = other
        .endpoint(1)
        .key_package(Uuid::new_v4(), other.now)
        .unwrap();
    assert!(
        fixture
            .endpoint(0)
            .create_group(
                Uuid::new_v4(),
                &[(other.nodes[1].id(), &foreign)],
                fixture.now
            )
            .is_err()
    );
    let mut tampered = package.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        fixture
            .endpoint(0)
            .create_group(
                Uuid::new_v4(),
                &[(fixture.nodes[1].id(), &tampered)],
                fixture.now
            )
            .is_err()
    );
    assert!(fixture.endpoint(0).outbox(0, 10).unwrap().is_empty());
    fixture
        .endpoint(0)
        .create_group(
            Uuid::new_v4(),
            &[(fixture.nodes[1].id(), &package)],
            fixture.now,
        )
        .unwrap();
}

#[test]
fn failed_welcome_validation_does_not_consume_join_keys() {
    let fixture = Fixture::new();
    let invitation = fixture.invite(3);
    let too_few = [fixture.nodes[0].id(), fixture.nodes[1].id()];
    assert!(
        fixture
            .endpoint(1)
            .join(&invitation, &too_few, fixture.now)
            .is_err()
    );
    let roster: Vec<_> = fixture.nodes.iter().map(NodeIdentity::id).collect();
    let mut oversized_group = invitation.clone();
    oversized_group.group_id = vec![0; 257];
    assert!(
        fixture
            .endpoint(1)
            .join(&oversized_group, &roster, fixture.now)
            .is_err()
    );
    let mut wrong_group = invitation.clone();
    wrong_group.group_id[0] ^= 1;
    assert!(
        fixture
            .endpoint(1)
            .join(&wrong_group, &roster, fixture.now)
            .is_err()
    );
    fixture
        .endpoint(1)
        .join(&invitation, &roster, fixture.now)
        .unwrap();
    let db = fixture.db(1);
    let remaining: i64 = db
        .query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        remaining, 0,
        "successful join must consume its private key package"
    );
}

#[test]
fn tampering_reordering_cross_group_delivery_and_replays() {
    let fixture = Fixture::new();
    let group = fixture.group(2).group_id;
    let other_group = fixture.group(2).group_id;
    let one = fixture
        .endpoint(0)
        .send(&group, Uuid::new_v4(), b"one", fixture.now)
        .unwrap();
    let two = fixture
        .endpoint(0)
        .send(&group, Uuid::new_v4(), b"two", fixture.now)
        .unwrap();
    let mut tampered = one.bytes.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(
        fixture
            .endpoint(1)
            .receive(&group, &tampered, fixture.now)
            .is_err()
    );
    let mut trailing = one.bytes.clone();
    trailing.push(0);
    assert!(
        fixture
            .endpoint(1)
            .receive(&group, &trailing, fixture.now)
            .is_err()
    );
    assert!(
        fixture
            .endpoint(1)
            .receive(&other_group, &one.bytes, fixture.now)
            .is_err()
    );
    fixture
        .endpoint(1)
        .receive(&group, &two.bytes, fixture.now)
        .unwrap();
    fixture
        .endpoint(1)
        .receive(&group, &one.bytes, fixture.now)
        .unwrap();
    let inbox = fixture.endpoint(1).inbox(&group, 0, 10).unwrap();
    assert_eq!(inbox.len(), 2);
    assert_eq!(inbox[0].1.body, b"two");
    assert_eq!(inbox[1].1.body, b"one");
    // Bypass only Gent's receipt cache to check MLS replay defense after reload.
    fixture.db(1).execute("DELETE FROM receipts", []).unwrap();
    assert!(
        fixture
            .endpoint(1)
            .receive(&group, &one.bytes, fixture.now)
            .is_err()
    );
    assert_eq!(fixture.endpoint(1).inbox(&group, 0, 10).unwrap().len(), 2);
}

fn state_digest(db: &Connection) -> Vec<u8> {
    let mut hash = Sha256::new();
    let mut statement = db
        .prepare("SELECT group_data FROM openmls_group_data ORDER BY group_id,data_type")
        .unwrap();
    for row in statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
    {
        let row = row.unwrap();
        hash.update(row.len().to_le_bytes());
        hash.update(row);
    }
    hash.finalize().to_vec()
}

#[test]
fn failed_queue_writes_roll_back_ratchets_and_inbox_together() {
    let fixture = Fixture::new();
    let group = fixture.group(2).group_id;
    let db = fixture.db(0);
    let before = state_digest(&db);
    db.execute_batch("CREATE TRIGGER fail_outbox BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected outbox failure'); END;").unwrap();
    let id = Uuid::new_v4();
    assert!(
        fixture
            .endpoint(0)
            .send(&group, id, b"durable", fixture.now)
            .is_err()
    );
    assert_eq!(state_digest(&db), before);
    assert_eq!(fixture.endpoint(0).outbox(0, 10).unwrap().len(), 1);
    db.execute_batch("DROP TRIGGER fail_outbox;").unwrap();
    let message = fixture
        .endpoint(0)
        .send(&group, id, b"durable", fixture.now)
        .unwrap();
    let db = fixture.db(1);
    let before = state_digest(&db);
    db.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END;").unwrap();
    assert!(
        fixture
            .endpoint(1)
            .receive(&group, &message.bytes, fixture.now)
            .is_err()
    );
    assert_eq!(state_digest(&db), before);
    assert!(fixture.endpoint(1).inbox(&group, 0, 10).unwrap().is_empty());
    db.execute_batch("DROP TRIGGER fail_receipt;").unwrap();
    fixture
        .endpoint(1)
        .receive(&group, &message.bytes, fixture.now)
        .unwrap();
    assert_eq!(fixture.endpoint(1).inbox(&group, 0, 10).unwrap().len(), 1);
}

#[test]
fn epoch_rotation_discards_old_decryption_state() {
    let fixture = Fixture::new();
    let group = fixture.group(2).group_id;
    let old = fixture
        .endpoint(0)
        .send(
            &group,
            Uuid::new_v4(),
            b"undelivered old epoch",
            fixture.now,
        )
        .unwrap();
    let commit = fixture
        .endpoint(0)
        .rotate(&group, Uuid::new_v4(), fixture.now)
        .unwrap();
    assert_eq!(
        fixture
            .endpoint(1)
            .receive(&group, &commit.bytes, fixture.now)
            .unwrap(),
        Received::Commit
    );
    assert!(
        fixture
            .endpoint(1)
            .receive(&group, &old.bytes, fixture.now)
            .is_err()
    );
    let current = fixture
        .endpoint(0)
        .send(&group, Uuid::new_v4(), b"new epoch", fixture.now)
        .unwrap();
    fixture
        .endpoint(1)
        .receive(&group, &current.bytes, fixture.now)
        .unwrap();
    assert_eq!(
        fixture.endpoint(1).inbox(&group, 0, 10).unwrap()[0].1.body,
        b"new epoch"
    );
}

#[test]
fn concurrent_senders_reload_ratchets_and_share_idempotent_results() {
    let fixture = Fixture::new();
    let group = fixture.group(2).group_id;
    let id = Uuid::new_v4();
    let (one, two) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            fixture
                .endpoint(0)
                .send(&group, id, b"retry", fixture.now)
                .unwrap()
        });
        let second = scope.spawn(|| {
            fixture
                .endpoint(0)
                .send(&group, id, b"retry", fixture.now)
                .unwrap()
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(one, two);
    fixture
        .endpoint(1)
        .receive(&group, &one.bytes, fixture.now)
        .unwrap();
    let (one, two) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            fixture
                .endpoint(0)
                .send(&group, Uuid::new_v4(), b"first writer", fixture.now)
                .unwrap()
        });
        let second = scope.spawn(|| {
            fixture
                .endpoint(0)
                .send(&group, Uuid::new_v4(), b"second writer", fixture.now)
                .unwrap()
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    fixture
        .endpoint(1)
        .receive(&group, &two.bytes, fixture.now)
        .unwrap();
    fixture
        .endpoint(1)
        .receive(&group, &one.bytes, fixture.now)
        .unwrap();
    assert_eq!(fixture.endpoint(1).inbox(&group, 0, 10).unwrap().len(), 3);
    assert_eq!(fixture.endpoint(0).outbox(0, 10).unwrap().len(), 4);
}

#[test]
fn failed_commit_and_join_storage_leave_retries_usable() {
    let fixture = Fixture::new();
    let invitation = fixture.invite(2);
    let roster = [fixture.nodes[0].id(), fixture.nodes[1].id()];
    let receiver = fixture.db(1);
    receiver.execute_batch("CREATE TRIGGER fail_join BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'injected join failure'); END;").unwrap();
    assert!(
        fixture
            .endpoint(1)
            .join(&invitation, &roster, fixture.now)
            .is_err()
    );
    receiver.execute_batch("DROP TRIGGER fail_join;").unwrap();
    fixture
        .endpoint(1)
        .join(&invitation, &roster, fixture.now)
        .unwrap();
    let sender = fixture.db(0);
    let before = state_digest(&sender);
    sender.execute_batch("CREATE TRIGGER fail_commit BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT,'injected commit failure'); END;").unwrap();
    let request = Uuid::new_v4();
    assert!(
        fixture
            .endpoint(0)
            .rotate(&invitation.group_id, request, fixture.now)
            .is_err()
    );
    assert_eq!(state_digest(&sender), before);
    sender.execute_batch("DROP TRIGGER fail_commit;").unwrap();
    let commit = fixture
        .endpoint(0)
        .rotate(&invitation.group_id, request, fixture.now)
        .unwrap();
    let before = state_digest(&receiver);
    receiver.execute_batch("CREATE TRIGGER fail_commit BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'injected receive failure'); END;").unwrap();
    assert!(
        fixture
            .endpoint(1)
            .receive(&invitation.group_id, &commit.bytes, fixture.now)
            .is_err()
    );
    assert_eq!(state_digest(&receiver), before);
    receiver.execute_batch("DROP TRIGGER fail_commit;").unwrap();
    fixture
        .endpoint(1)
        .receive(&invitation.group_id, &commit.bytes, fixture.now)
        .unwrap();
    let fresh = fixture
        .endpoint(0)
        .send(
            &invitation.group_id,
            Uuid::new_v4(),
            b"after recovery",
            fixture.now,
        )
        .unwrap();
    fixture
        .endpoint(1)
        .receive(&invitation.group_id, &fresh.bytes, fixture.now)
        .unwrap();
}

#[test]
fn revoked_node_cannot_send_or_decrypt_new_epochs() {
    let fixture = Fixture::new();
    let group = fixture.group(3).group_id;
    let queued = fixture
        .endpoint(1)
        .send(
            &group,
            Uuid::new_v4(),
            b"from soon revoked node",
            fixture.now,
        )
        .unwrap();
    let removal = fixture
        .state
        .revoke_node(&fixture.owner, fixture.nodes[1].id(), fixture.now)
        .unwrap();
    for index in [0, 2] {
        fixture
            .endpoint(index)
            .apply_authority(std::slice::from_ref(&removal))
            .unwrap();
    }
    assert!(
        fixture
            .endpoint(0)
            .receive(&group, &queued.bytes, fixture.now)
            .is_err()
    );
    assert!(
        fixture
            .endpoint(0)
            .send(&group, Uuid::new_v4(), b"must rotate first", fixture.now)
            .is_err()
    );
    let commit = fixture
        .endpoint(0)
        .remove_revoked(&group, Uuid::new_v4(), fixture.now)
        .unwrap();
    fixture
        .endpoint(2)
        .receive(&group, &commit.bytes, fixture.now)
        .unwrap();
    let fresh = fixture
        .endpoint(0)
        .send(&group, Uuid::new_v4(), b"only surviving nodes", fixture.now)
        .unwrap();
    fixture
        .endpoint(2)
        .receive(&group, &fresh.bytes, fixture.now)
        .unwrap();
    // The removed endpoint deliberately retains old authority and old epoch keys.
    assert!(
        fixture
            .endpoint(1)
            .receive(&group, &fresh.bytes, fixture.now)
            .is_err()
    );
    fixture.endpoint(1).apply_authority(&[removal]).unwrap();
    assert!(
        fixture
            .endpoint(1)
            .send(&group, Uuid::new_v4(), b"revoked", fixture.now)
            .is_err()
    );
    assert!(
        fixture
            .endpoint(1)
            .key_package(Uuid::new_v4(), fixture.now)
            .is_err()
    );
}

#[test]
fn authority_expiry_rollback_and_wrong_node_fail_closed() {
    let fixture = Fixture::new();
    let group = fixture.group(2).group_id;
    assert!(
        fixture
            .endpoint(0)
            .send(
                &group,
                Uuid::new_v4(),
                b"expired",
                fixture.state.state().expires_at
            )
            .is_err()
    );
    let renewed = fixture
        .state
        .renew(&fixture.owner, fixture.now + 1)
        .unwrap();
    fixture
        .endpoint(0)
        .apply_authority(std::slice::from_ref(&renewed))
        .unwrap();
    assert!(fixture.endpoint(0).apply_authority(&[renewed]).is_err());
    assert!(
        fixture
            .endpoint(0)
            .initialize(&fixture.state, fixture.now)
            .is_err()
    );
    let mut wrong = EncryptedEndpoint::open(fixture.homes[0].path(), &fixture.nodes[1]).unwrap();
    assert!(
        wrong
            .send(&group, Uuid::new_v4(), b"wrong identity", fixture.now + 1)
            .is_err()
    );
    fixture
        .endpoint(0)
        .send(&group, Uuid::new_v4(), b"renewed", fixture.now + 1)
        .unwrap();
}

#[test]
fn limits_and_private_database_storage() {
    let fixture = Fixture::new();
    let group = fixture.group(2).group_id;
    assert!(
        fixture
            .endpoint(0)
            .send(&group, Uuid::nil(), b"nil", fixture.now)
            .is_err()
    );
    assert!(
        fixture
            .endpoint(0)
            .send(
                &group,
                Uuid::new_v4(),
                &vec![0; MAX_PAYLOAD_BYTES + 1],
                fixture.now
            )
            .is_err()
    );
    assert!(
        fixture
            .endpoint(1)
            .receive(&group, &vec![0; 2 * 1024 * 1024 + 1], fixture.now)
            .is_err()
    );
    let path = fixture.homes[0].path().join("mls.sqlite3");
    assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0);
    let future = fixture.db(0);
    future.pragma_update(None, "user_version", 999).unwrap();
    assert!(EncryptedEndpoint::open(fixture.homes[0].path(), &fixture.nodes[0]).is_err());
    future.pragma_update(None, "user_version", 1).unwrap();
    drop(future);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(EncryptedEndpoint::open(fixture.homes[0].path(), &fixture.nodes[0]).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let extra = tempfile::tempdir().unwrap();
    fs::set_permissions(extra.path(), fs::Permissions::from_mode(0o700)).unwrap();
    symlink(path, extra.path().join("mls.sqlite3")).unwrap();
    assert!(EncryptedEndpoint::open(extra.path(), &fixture.nodes[0]).is_err());
}
