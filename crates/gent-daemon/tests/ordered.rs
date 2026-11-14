use gent_crypto::{NodeIdentity, OwnerKey, VerifiedState, stream::Packet};
use gent_daemon::encrypted::{
    EncryptedEndpoint, MAX_PAYLOAD_BYTES, Received,
    ordered::{MAX_PENDING_BYTES, MAX_PENDING_DISTANCE, OrderedEndpoint, Staged},
};
use rusqlite::Connection;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
#[path = "ordered/confirmation.rs"]
mod confirmation;
#[path = "ordered/storage.rs"]
mod storage;

struct World {
    owner: OwnerKey,
    nodes: [NodeIdentity; 3],
    homes: [tempfile::TempDir; 3],
    state: VerifiedState,
    now: u64,
}
impl World {
    fn new() -> Self {
        let owner = OwnerKey::generate().unwrap();
        let nodes = std::array::from_fn(|_| NodeIdentity::generate().unwrap());
        let homes = std::array::from_fn(|_| {
            let home = tempfile::tempdir().unwrap();
            fs::set_permissions(home.path(), fs::Permissions::from_mode(0o700)).unwrap();
            home
        });
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = owner
            .create_cluster("ordered proof", &nodes[0], "first", now)
            .unwrap();
        for node in &nodes[1..] {
            let request = node
                .request_enrollment(state.anchor(), state.checkpoint(), "peer", now)
                .unwrap();
            let next = state
                .enroll(&owner, &request, request.fingerprint().unwrap(), now)
                .unwrap();
            state.apply_chain(&[next], now).unwrap();
        }
        let world = Self {
            owner,
            nodes,
            homes,
            state,
            now,
        };
        for i in 0..3 {
            world.endpoint(i).initialize(&world.state, now).unwrap();
        }
        world
    }
    fn endpoint(&self, i: usize) -> OrderedEndpoint<'_> {
        OrderedEndpoint::open(self.homes[i].path(), &self.nodes[i]).unwrap()
    }
    fn raw(&self, i: usize) -> EncryptedEndpoint<'_> {
        EncryptedEndpoint::open(self.homes[i].path(), &self.nodes[i]).unwrap()
    }
    fn db(&self, i: usize) -> Connection {
        Connection::open(self.homes[i].path().join("mls.sqlite3")).unwrap()
    }
    fn invite(&self, from: usize, to: &[usize], id: Uuid) -> (Packet, Vec<Vec<u8>>) {
        let packages: Vec<_> = to
            .iter()
            .map(|i| {
                self.endpoint(*i)
                    .key_package(Uuid::new_v4(), self.now)
                    .unwrap()
            })
            .collect();
        let peers: Vec<_> = to
            .iter()
            .zip(&packages)
            .map(|(i, kp)| (self.nodes[*i].id(), kp.as_slice()))
            .collect();
        (
            self.endpoint(from).create(id, &peers, self.now).unwrap(),
            packages,
        )
    }
    fn stream(&self, from: usize, to: &[usize]) -> Packet {
        let (packet, _) = self.invite(from, to, Uuid::new_v4());
        let roster: Vec<_> = std::iter::once(from)
            .chain(to.iter().copied())
            .map(|i| self.nodes[i].id())
            .collect();
        for i in to {
            self.endpoint(*i)
                .join(&packet, self.nodes[from].id(), &roster, self.now)
                .unwrap();
        }
        packet
    }
}

#[test]
fn reordered_epochs_and_messages_survive_offline_restarts() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let group = origin.group();
    let one = w
        .endpoint(0)
        .send(group, Uuid::new_v4(), b"before first refresh", w.now)
        .unwrap();
    let two = w.endpoint(0).rotate(group, Uuid::new_v4(), w.now).unwrap();
    let three = w
        .endpoint(0)
        .send(group, Uuid::new_v4(), b"between refreshes", w.now)
        .unwrap();
    let four = w.endpoint(0).rotate(group, Uuid::new_v4(), w.now).unwrap();
    let five = w
        .endpoint(0)
        .send(group, Uuid::new_v4(), b"after second refresh", w.now)
        .unwrap();
    for packet in [&five, &four, &three, &two] {
        w.endpoint(1).stage(packet, w.now).unwrap();
    }
    assert!(w.endpoint(1).drain(group, 128, w.now).unwrap().is_empty());
    let status = w.endpoint(1).status(group, w.now).unwrap();
    assert_eq!((status.head, status.pending, status.next), (0, 4, 1));
    assert_eq!(w.endpoint(1).stage(&two, w.now).unwrap(), Staged::Duplicate);
    assert_eq!(
        w.endpoint(0).outbox(group, Some(0), 1, w.now).unwrap(),
        std::slice::from_ref(&one)
    );
    w.endpoint(1).stage(&one, w.now).unwrap();
    let applied = w.endpoint(1).drain(group, 128, w.now).unwrap();
    assert_eq!(applied.len(), 5);
    assert_eq!(
        applied.iter().filter(|r| **r == Received::Commit).count(),
        2
    );
    let bodies: Vec<_> = w
        .endpoint(1)
        .inbox(group, 0, 10)
        .unwrap()
        .into_iter()
        .map(|(_, m)| m.body)
        .collect();
    assert_eq!(
        bodies,
        [
            b"before first refresh".to_vec(),
            b"between refreshes".to_vec(),
            b"after second refresh".to_vec()
        ]
    );
    assert_eq!(
        w.endpoint(1).status(group, w.now).unwrap().digest,
        five.digest().unwrap()
    );
    assert_eq!(w.endpoint(1).stage(&one, w.now).unwrap(), Staged::Duplicate);
    assert_eq!(
        w.endpoint(1).stage(&origin, w.now).unwrap(),
        Staged::Duplicate
    );
}

#[test]
fn opposite_directions_and_concurrent_refreshes_do_not_fork() {
    let w = World::new();
    let ab = w.stream(0, &[1]);
    let ba = w.stream(1, &[0]);
    std::thread::scope(|scope| {
        for (from, group) in [(0, ab.group()), (1, ba.group())] {
            let w = &w;
            scope.spawn(move || {
                for _ in 0..4 {
                    w.endpoint(from)
                        .send(group, Uuid::new_v4(), b"concurrent reply", w.now)
                        .unwrap();
                    w.endpoint(from)
                        .rotate(group, Uuid::new_v4(), w.now)
                        .unwrap();
                }
            });
        }
    });
    let id = Uuid::new_v4();
    let (first, second) = std::thread::scope(|scope| {
        let one = scope.spawn(|| w.endpoint(0).rotate(ab.group(), id, w.now).unwrap());
        let two = scope.spawn(|| w.endpoint(0).rotate(ab.group(), id, w.now).unwrap());
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_eq!(first, second);
    std::thread::scope(|scope| {
        for _ in 0..2 {
            scope.spawn(|| {
                w.endpoint(0)
                    .rotate(ab.group(), Uuid::new_v4(), w.now)
                    .unwrap()
            });
        }
    });
    for (from, to, group) in [(0, 1, ab.group()), (1, 0, ba.group())] {
        let queue = w.endpoint(from).outbox(group, Some(0), 128, w.now).unwrap();
        for packet in queue.iter().rev() {
            w.endpoint(to).stage(packet, w.now).unwrap();
        }
        assert_eq!(
            w.endpoint(to).drain(group, 128, w.now).unwrap().len(),
            queue.len()
        );
        assert_eq!(
            w.endpoint(to).status(group, w.now).unwrap().head,
            queue.len() as u64
        );
        assert_eq!(w.endpoint(to).inbox(group, 0, 10).unwrap().len(), 4);
    }
    assert!(
        w.endpoint(1)
            .send(ab.group(), Uuid::new_v4(), b"wrong direction", w.now)
            .is_err()
    );
    assert!(
        w.endpoint(1)
            .rotate(ab.group(), Uuid::new_v4(), w.now)
            .is_err()
    );
    assert!(
        w.raw(0)
            .send(ab.group(), Uuid::new_v4(), b"bypass", w.now)
            .is_err()
    );
    assert!(w.raw(0).rotate(ab.group(), Uuid::new_v4(), w.now).is_err());
    assert!(
        w.raw(1)
            .receive(ab.group(), first.ciphertext(), w.now)
            .is_err()
    );
}

#[test]
fn writer_pin_rejects_relay_substitution_forks_and_wrong_welcome_creator() {
    let w = World::new();
    let (origin, _) = w.invite(0, &[1, 2], Uuid::new_v4());
    let roster: Vec<_> = w.nodes.iter().map(NodeIdentity::id).collect();
    let false_creator = w.nodes[2]
        .sign_stream_packet(origin.group(), 0, [0; 32], origin.ciphertext())
        .unwrap();
    assert!(
        w.endpoint(1)
            .join(&false_creator, w.nodes[2].id(), &roster, w.now)
            .is_err()
    );
    w.endpoint(1)
        .join(&origin, w.nodes[0].id(), &roster, w.now)
        .unwrap();
    w.endpoint(1)
        .join(&origin, w.nodes[0].id(), &roster, w.now)
        .unwrap();
    let message = w
        .endpoint(0)
        .send(origin.group(), Uuid::new_v4(), b"authentic", w.now)
        .unwrap();
    let forged = w.nodes[2]
        .sign_stream_packet(
            origin.group(),
            1,
            origin.digest().unwrap(),
            message.ciphertext(),
        )
        .unwrap();
    assert!(w.endpoint(1).stage(&forged, w.now).is_err());
    let fork = w.nodes[0]
        .sign_stream_packet(origin.group(), 1, [1; 32], message.ciphertext())
        .unwrap();
    assert!(w.endpoint(1).stage(&fork, w.now).is_err());
    w.endpoint(1).stage(&message, w.now).unwrap();
    let equivocation = w.nodes[0]
        .sign_stream_packet(
            origin.group(),
            1,
            origin.digest().unwrap(),
            b"conflicting ciphertext",
        )
        .unwrap();
    assert!(w.endpoint(1).stage(&equivocation, w.now).is_err());
    w.endpoint(1).drain(origin.group(), 128, w.now).unwrap();
    assert!(w.endpoint(1).stage(&equivocation, w.now).is_err());
    assert_eq!(w.endpoint(1).inbox(origin.group(), 0, 10).unwrap().len(), 1);
}

#[test]
fn ordering_storage_failures_roll_back_mls_and_stream_checkpoints() {
    let w = World::new();
    let db = w.db(0);
    db.execute_batch("CREATE TRIGGER fail_packet BEFORE INSERT ON stream_outbox BEGIN SELECT RAISE(ABORT,'injected packet failure'); END;").unwrap();
    let kp = w.endpoint(1).key_package(Uuid::new_v4(), w.now).unwrap();
    let peers = [(w.nodes[1].id(), kp.as_slice())];
    let id = Uuid::new_v4();
    assert!(w.endpoint(0).create(id, &peers, w.now).is_err());
    let groups: i64 = db
        .query_row("SELECT COUNT(*) FROM openmls_group_data", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(groups, 0);
    db.execute_batch("DROP TRIGGER fail_packet;").unwrap();
    let origin = w.endpoint(0).create(id, &peers, w.now).unwrap();
    assert_eq!(w.endpoint(0).create(id, &peers, w.now).unwrap(), origin);
    let receiver = w.db(1);
    receiver.execute_batch("CREATE TRIGGER fail_origin BEFORE INSERT ON stream_seen BEGIN SELECT RAISE(ABORT,'injected origin failure'); END;").unwrap();
    let roster = [w.nodes[0].id(), w.nodes[1].id()];
    assert!(
        w.endpoint(1)
            .join(&origin, w.nodes[0].id(), &roster, w.now)
            .is_err()
    );
    receiver.execute_batch("DROP TRIGGER fail_origin;").unwrap();
    w.endpoint(1)
        .join(&origin, w.nodes[0].id(), &roster, w.now)
        .unwrap();
    db.execute_batch("CREATE TRIGGER fail_head BEFORE INSERT ON stream_seen BEGIN SELECT RAISE(ABORT,'injected head failure'); END;").unwrap();
    let id = Uuid::new_v4();
    assert!(
        w.endpoint(0)
            .send(origin.group(), id, b"transaction", w.now)
            .is_err()
    );
    assert_eq!(w.endpoint(0).status(origin.group(), w.now).unwrap().head, 0);
    assert_eq!(
        w.endpoint(0)
            .outbox(origin.group(), None, 10, w.now)
            .unwrap()
            .len(),
        1
    );
    db.execute_batch("DROP TRIGGER fail_head;").unwrap();
    let message = w
        .endpoint(0)
        .send(origin.group(), id, b"transaction", w.now)
        .unwrap();
    assert_eq!(message.sequence(), 1);
    w.endpoint(1).stage(&message, w.now).unwrap();
    receiver.execute_batch("CREATE TRIGGER fail_head BEFORE INSERT ON stream_seen BEGIN SELECT RAISE(ABORT,'injected head failure'); END;").unwrap();
    assert!(w.endpoint(1).drain(origin.group(), 10, w.now).is_err());
    let status = w.endpoint(1).status(origin.group(), w.now).unwrap();
    assert_eq!((status.head, status.pending), (0, 1));
    assert!(
        w.endpoint(1)
            .inbox(origin.group(), 0, 10)
            .unwrap()
            .is_empty()
    );
    receiver.execute_batch("DROP TRIGGER fail_head;").unwrap();
    w.endpoint(1).drain(origin.group(), 10, w.now).unwrap();
    assert_eq!(
        w.endpoint(1).inbox(origin.group(), 0, 10).unwrap()[0]
            .1
            .body,
        b"transaction"
    );
}

#[test]
fn backlog_can_reach_a_removal_commit_without_reviving_revoked_nodes() {
    let w = World::new();
    let origin = w.stream(0, &[1, 2]);
    let group = origin.group();
    w.endpoint(0)
        .send(group, Uuid::new_v4(), b"historical", w.now)
        .unwrap();
    w.endpoint(0).rotate(group, Uuid::new_v4(), w.now).unwrap();
    w.endpoint(0)
        .send(group, Uuid::new_v4(), b"also historical", w.now)
        .unwrap();
    let removal = w
        .state
        .revoke_node(&w.owner, w.nodes[1].id(), w.now)
        .unwrap();
    for i in [0, 2] {
        w.endpoint(i)
            .apply_authority(std::slice::from_ref(&removal))
            .unwrap();
    }
    assert!(
        w.endpoint(0)
            .send(group, Uuid::new_v4(), b"must remove first", w.now)
            .is_err()
    );
    w.endpoint(0)
        .remove_revoked(group, Uuid::new_v4(), w.now)
        .unwrap();
    let fresh = w
        .endpoint(0)
        .send(group, Uuid::new_v4(), b"new membership", w.now)
        .unwrap();
    let packets = w.endpoint(0).outbox(group, Some(0), 10, w.now).unwrap();
    for packet in packets.iter().rev() {
        w.endpoint(2).stage(packet, w.now).unwrap();
    }
    assert_eq!(w.endpoint(2).drain(group, 128, w.now).unwrap().len(), 5);
    assert_eq!(w.endpoint(2).inbox(group, 0, 10).unwrap().len(), 3);
    assert_eq!(
        w.endpoint(2).status(group, w.now).unwrap().digest,
        fresh.digest().unwrap()
    );
    w.endpoint(1).apply_authority(&[removal]).unwrap();
    assert!(w.endpoint(1).stage(&fresh, w.now).is_err());
    assert!(w.endpoint(1).drain(group, 10, w.now).is_err());
}

#[test]
fn authority_is_rechecked_when_buffered_packets_are_applied() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let message = w
        .endpoint(0)
        .send(origin.group(), Uuid::new_v4(), b"pending", w.now)
        .unwrap();
    w.endpoint(1).stage(&message, w.now).unwrap();
    let other = w.stream(2, &[1]);
    let other_message = w
        .endpoint(2)
        .send(other.group(), Uuid::new_v4(), b"surviving writer", w.now)
        .unwrap();
    w.endpoint(1).stage(&other_message, w.now).unwrap();
    assert!(
        w.endpoint(1)
            .drain(origin.group(), 10, w.state.state().expires_at)
            .is_err()
    );
    let revoked = w
        .state
        .revoke_node(&w.owner, w.nodes[0].id(), w.now)
        .unwrap();
    w.endpoint(1).apply_authority(&[revoked]).unwrap();
    assert!(w.endpoint(1).drain(origin.group(), 10, w.now).is_err());
    assert!(w.endpoint(1).stage(&message, w.now).is_err());
    assert!(
        w.endpoint(1)
            .inbox(origin.group(), 0, 10)
            .unwrap()
            .is_empty()
    );
    let head: i64 = w
        .db(1)
        .query_row(
            "SELECT head FROM streams WHERE group_id=?1",
            [origin.group()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(head, 0);
    let pending: usize = w
        .db(1)
        .query_row("SELECT COUNT(*) FROM stream_pending", [], |row| row.get(0))
        .unwrap();
    assert_eq!(pending, 1, "revoked writer must release its pending quota");
    assert_eq!(
        w.endpoint(1).drain(other.group(), 10, w.now).unwrap().len(),
        1
    );
}

#[test]
fn receive_window_and_global_pending_quota_bound_unprocessed_data() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let distant = w.nodes[0]
        .sign_stream_packet(
            origin.group(),
            MAX_PENDING_DISTANCE + 1,
            [1; 32],
            b"distant",
        )
        .unwrap();
    assert!(w.endpoint(1).stage(&distant, w.now).is_err());
    let body = vec![42; MAX_PAYLOAD_BYTES];
    let first = w
        .endpoint(0)
        .send(origin.group(), Uuid::new_v4(), &body, w.now)
        .unwrap();
    let mut refused = None;
    for _ in 0..12 {
        let packet = w
            .endpoint(0)
            .send(origin.group(), Uuid::new_v4(), &body, w.now)
            .unwrap();
        if w.endpoint(1).stage(&packet, w.now).is_err() {
            refused = Some(packet);
            break;
        }
    }
    let refused = refused.expect("bounded receive queue must refuse excessive data");
    let used: usize = w
        .db(1)
        .query_row(
            "SELECT SUM(length(packet)) FROM stream_pending",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(used <= MAX_PENDING_BYTES);
    // A full future-packet queue must still admit the missing next packet so it
    // can make progress. Otherwise backpressure creates a permanent deadlock.
    w.endpoint(1).stage(&first, w.now).unwrap();
    w.endpoint(1).drain(origin.group(), 128, w.now).unwrap();
    w.endpoint(1).stage(&refused, w.now).unwrap();
    w.endpoint(1).drain(origin.group(), 128, w.now).unwrap();
}

#[test]
fn malformed_signed_suffix_does_not_undo_committed_prefix() {
    let w = World::new();
    let origin = w.stream(0, &[1]);
    let first = w
        .endpoint(0)
        .send(origin.group(), Uuid::new_v4(), b"must survive", w.now)
        .unwrap();
    let malformed = w.nodes[0]
        .sign_stream_packet(
            origin.group(),
            2,
            first.digest().unwrap(),
            b"signed but not MLS",
        )
        .unwrap();
    w.endpoint(1).stage(&malformed, w.now).unwrap();
    w.endpoint(1).stage(&first, w.now).unwrap();
    assert!(w.endpoint(1).drain(origin.group(), 128, w.now).is_err());
    assert_eq!(w.endpoint(1).status(origin.group(), w.now).unwrap().head, 1);
    assert_eq!(
        w.endpoint(1).inbox(origin.group(), 0, 10).unwrap()[0]
            .1
            .body,
        b"must survive"
    );
}

#[test]
fn outer_writer_cannot_relabel_another_members_mls_message() {
    let w = World::new();
    let origin = w.stream(0, &[1, 2]);
    // Simulate an authorized remote member bypassing Gent's local API. The
    // receiving endpoint must still authenticate the actual MLS sender.
    w.db(1).execute("DELETE FROM streams", []).unwrap();
    let other = w
        .raw(1)
        .send(
            origin.group(),
            Uuid::new_v4(),
            b"different MLS sender",
            w.now,
        )
        .unwrap();
    let wrapped = w.nodes[0]
        .sign_stream_packet(origin.group(), 1, origin.digest().unwrap(), &other.bytes)
        .unwrap();
    w.endpoint(2).stage(&wrapped, w.now).unwrap();
    assert!(w.endpoint(2).drain(origin.group(), 10, w.now).is_err());
    assert_eq!(w.endpoint(2).status(origin.group(), w.now).unwrap().head, 0);
    assert!(
        w.endpoint(2)
            .inbox(origin.group(), 0, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn raw_groups_upgrade_storage_but_cannot_be_adopted_into_streams() {
    let w = World::new();
    let kp = w.raw(1).key_package(Uuid::new_v4(), w.now).unwrap();
    let peers = [(w.nodes[1].id(), kp.as_slice())];
    let request = Uuid::new_v4();
    let invitation = w.raw(0).create_group(request, &peers, w.now).unwrap();
    w.raw(1)
        .join(&invitation, &[w.nodes[0].id(), w.nodes[1].id()], w.now)
        .unwrap();
    let message = w
        .raw(0)
        .send(
            &invitation.group_id,
            Uuid::new_v4(),
            b"old proof database",
            w.now,
        )
        .unwrap();
    w.db(1).execute_batch("DROP TABLE streams; DROP TABLE stream_outbox; DROP TABLE stream_seen; DROP TABLE stream_pending; PRAGMA user_version=1;").unwrap();
    w.raw(1)
        .receive(&invitation.group_id, &message.bytes, w.now)
        .unwrap();
    assert_eq!(
        w.db(1)
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        17
    );
    assert!(w.endpoint(0).create(request, &peers, w.now).is_err());
    let wrapped = w.nodes[0]
        .sign_stream_packet(&invitation.group_id, 0, [0; 32], &invitation.bytes)
        .unwrap();
    assert!(
        w.endpoint(1)
            .join(
                &wrapped,
                w.nodes[0].id(),
                &[w.nodes[0].id(), w.nodes[1].id()],
                w.now
            )
            .is_err()
    );
}
