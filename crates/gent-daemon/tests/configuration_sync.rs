use base64::{Engine as _, engine::general_purpose::STANDARD};
use gent_crypto::{
    MAX_STATE_BYTES, MAX_STATE_LIFETIME, NodeIdentity, OwnerKey, SignedState, VerifiedState,
    stream::Packet,
};
use gent_daemon::encrypted::{
    Received,
    ordered::{
        MAX_PENDING_BYTES, OrderedEndpoint,
        configuration::{ConfigurationInvitation, MAX_FRAGMENT_BYTES},
    },
};
use gent_protocol::{Effect, Permission, Policy, Rule, Selector};
use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
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
            .create_cluster("configuration test", &nodes[0], "owner node", now)
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
        let f = Self {
            owner,
            nodes,
            homes,
            state,
            now,
        };
        for i in 0..3 {
            f.endpoint(i).initialize(&f.state, now).unwrap();
        }
        f
    }
    fn endpoint(&self, i: usize) -> OrderedEndpoint<'_> {
        OrderedEndpoint::open(self.homes[i].path(), &self.nodes[i]).unwrap()
    }
    fn db(&self, i: usize) -> Connection {
        Connection::open(self.homes[i].path().join("mls.sqlite3")).unwrap()
    }
    fn configuration(&self, to: usize) -> ConfigurationInvitation {
        let kp = self
            .endpoint(to)
            .key_package(Uuid::new_v4(), self.now)
            .unwrap();
        let invitation = self
            .endpoint(0)
            .create_configuration(
                &self.owner,
                Uuid::new_v4(),
                (self.nodes[to].id(), &kp),
                self.now,
            )
            .unwrap();
        self.endpoint(to)
            .join_configuration(&invitation, self.now)
            .unwrap();
        invitation
    }
    fn data(&self, from: usize, to: usize) -> Packet {
        let kp = self
            .endpoint(to)
            .key_package(Uuid::new_v4(), self.now)
            .unwrap();
        let invitation = self
            .endpoint(from)
            .create(Uuid::new_v4(), &[(self.nodes[to].id(), &kp)], self.now)
            .unwrap();
        self.endpoint(to)
            .join(
                &invitation,
                self.nodes[from].id(),
                &[self.nodes[from].id(), self.nodes[to].id()],
                self.now,
            )
            .unwrap();
        invitation
    }
    fn publish_all(&self, group: &[u8], now: u64) -> Vec<Packet> {
        let mut packets = Vec::new();
        while let Some(packet) = self
            .endpoint(0)
            .next_configuration(group, Uuid::new_v4(), now)
            .unwrap()
        {
            packets.push(packet);
        }
        packets
    }
    // Simulate a compromised authorized writer constructing its own MLS payloads.
    // The receiver must reject these without relying on the sender's API checks.
    fn malicious_send(&self, group: &[u8], body: &[u8]) -> Packet {
        self.db(0)
            .execute(
                "UPDATE streams SET purpose='data' WHERE group_id=?1",
                [group],
            )
            .unwrap();
        let packet = self
            .endpoint(0)
            .send(group, Uuid::new_v4(), body, self.now)
            .unwrap();
        self.db(0)
            .execute(
                "UPDATE streams SET purpose='configuration' WHERE group_id=?1",
                [group],
            )
            .unwrap();
        packet
    }
}

#[test]
fn expired_nodes_verify_history_before_ordinary_delivery_resumes() {
    let f = Fixture::new();
    let config = f.configuration(1);
    let data = f.data(0, 1);
    let reply = f.data(1, 0);
    let queued = f
        .endpoint(0)
        .send(data.group(), Uuid::new_v4(), b"ordinary traffic", f.now)
        .unwrap();
    let mut state = f.state.clone();
    let mut updates = Vec::new();
    for day in 1..=3 {
        let next = state
            .renew(&f.owner, f.now + day * MAX_STATE_LIFETIME)
            .unwrap();
        state.advance_history(std::slice::from_ref(&next)).unwrap();
        updates.push(next);
    }
    f.endpoint(0).apply_authority(&updates).unwrap();
    let now = f.now + 3 * MAX_STATE_LIFETIME;
    assert!(f.endpoint(1).stage(&queued, now).is_err());
    assert!(
        f.endpoint(1)
            .send(reply.group(), Uuid::new_v4(), b"expired", now)
            .is_err()
    );
    for index in 0..3 {
        let request = Uuid::new_v4();
        let packet = f
            .endpoint(0)
            .next_configuration(config.packet.group(), request, now)
            .unwrap()
            .unwrap();
        assert_eq!(
            f.endpoint(0)
                .next_configuration(config.packet.group(), request, now)
                .unwrap(),
            Some(packet.clone())
        );
        f.endpoint(1).stage_configuration(&packet, now).unwrap();
        assert_eq!(
            f.endpoint(1)
                .drain_configuration(packet.group(), 10, now)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            f.endpoint(1)
                .authority_state()
                .unwrap()
                .checkpoint()
                .revision,
            f.state.checkpoint().revision + index + 1
        );
        if index < 2 {
            assert!(
                f.endpoint(1)
                    .send(reply.group(), Uuid::new_v4(), b"still expired", now)
                    .is_err()
            );
        }
    }
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        state.checkpoint()
    );
    f.endpoint(1).stage(&queued, now).unwrap();
    f.endpoint(1).drain(data.group(), 10, now).unwrap();
    f.endpoint(1)
        .send(reply.group(), Uuid::new_v4(), b"fresh", now)
        .unwrap();
    assert!(
        f.endpoint(1)
            .inbox(config.packet.group(), 0, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn owner_grants_and_stream_purposes_prevent_freshness_bypass() {
    let f = Fixture::new();
    let kp = f.endpoint(1).key_package(Uuid::new_v4(), f.now).unwrap();
    let wrong = OwnerKey::generate().unwrap();
    assert!(
        f.endpoint(0)
            .create_configuration(&wrong, Uuid::new_v4(), (f.nodes[1].id(), &kp), f.now)
            .is_err()
    );
    let invitation = f
        .endpoint(0)
        .create_configuration(&f.owner, Uuid::new_v4(), (f.nodes[1].id(), &kp), f.now)
        .unwrap();
    let mut substituted = invitation.clone();
    substituted.grant.grant.reader = f.nodes[2].id().into();
    assert!(
        f.endpoint(1)
            .join_configuration(&substituted, f.now)
            .is_err()
    );
    assert!(
        f.endpoint(2)
            .join_configuration(&invitation, f.now)
            .is_err()
    );
    f.endpoint(1)
        .join_configuration(&invitation, f.now)
        .unwrap();
    let group = invitation.packet.group();
    assert!(
        f.endpoint(0)
            .send(group, Uuid::new_v4(), b"ordinary message", f.now)
            .is_err()
    );
    assert!(f.endpoint(1).stage(&invitation.packet, f.now).is_err());
    assert!(f.endpoint(1).drain(group, 10, f.now).is_err());
    let data = f.data(0, 1);
    assert!(f.endpoint(1).stage_configuration(&data, f.now).is_err());
    assert!(
        f.endpoint(1)
            .drain_configuration(data.group(), 10, f.now)
            .is_err()
    );
    let bad = f.malicious_send(group, b"ordinary chat text is not configuration");
    f.endpoint(1)
        .stage_configuration(&bad, f.now + MAX_STATE_LIFETIME)
        .unwrap();
    assert!(
        f.endpoint(1)
            .drain_configuration(group, 10, f.now + MAX_STATE_LIFETIME)
            .is_err()
    );
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert!(f.endpoint(1).inbox(group, 0, 10).unwrap().is_empty());
}

fn fragment(record: &SignedState, offset: usize) -> Vec<u8> {
    let wire = record.encode().unwrap();
    let end = (offset + MAX_FRAGMENT_BYTES).min(wire.len());
    serde_json::to_vec(&json!({"version":1,"revision":record.state.revision,"digest":Sha256::digest(&wire).to_vec(),"total":wire.len(),"offset":offset,"data":STANDARD.encode(&wire[offset..end])})).unwrap()
}

#[test]
fn authenticated_writer_cannot_forge_owner_policy() {
    let f = Fixture::new();
    let invitation = f.configuration(1);
    let group = invitation.packet.group();
    let mut invalid = f.state.renew(&f.owner, f.now + 1).unwrap();
    invalid.state.name = "forged private policy".into();
    let packet = f.malicious_send(group, &fragment(&invalid, 0));
    f.endpoint(1)
        .stage_configuration(&packet, f.now + MAX_STATE_LIFETIME)
        .unwrap();
    assert!(
        f.endpoint(1)
            .drain_configuration(group, 10, f.now + MAX_STATE_LIFETIME)
            .is_err()
    );
    assert_eq!(
        f.endpoint(1)
            .configuration_status(group, f.now + MAX_STATE_LIFETIME)
            .unwrap()
            .head,
        0
    );
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert_eq!(
        f.db(1)
            .query_row("SELECT COUNT(*) FROM authority_history", [], |row| row
                .get::<_, usize>(0))
            .unwrap(),
        1
    );
}

#[test]
fn configuration_writer_cannot_remove_the_reader_through_an_epoch_commit() {
    let f = Fixture::new();
    let invitation = f.configuration(1);
    let group = invitation.packet.group();
    let refresh = f
        .endpoint(0)
        .rotate_configuration(group, Uuid::new_v4(), f.now)
        .unwrap();

    // The sender has a later owner revision, but the reader has not accepted it.
    // Use the data API to construct a valid MLS removal that the configuration
    // API itself would refuse to publish to this revoked reader.
    let removal = f
        .state
        .revoke_node(&f.owner, f.nodes[1].id(), f.now + 1)
        .unwrap();
    f.endpoint(0).apply_authority(&[removal]).unwrap();
    f.db(0)
        .execute(
            "UPDATE streams SET purpose='data' WHERE group_id=?1",
            [group],
        )
        .unwrap();
    let packet = f
        .endpoint(0)
        .remove_revoked(group, Uuid::new_v4(), f.now + 1)
        .unwrap();

    let expired = f.now + MAX_STATE_LIFETIME;
    f.endpoint(1)
        .stage_configuration(&refresh, expired)
        .unwrap();
    f.endpoint(1).stage_configuration(&packet, expired).unwrap();
    assert_eq!(
        f.endpoint(1)
            .drain_configuration(group, 1, expired)
            .unwrap(),
        vec![Received::Commit]
    );
    // Reopen and retry to check that neither the MLS commit nor the stream head
    // survives rejection. An approved encryption refresh remains committed.
    for _ in 0..2 {
        let error = f
            .endpoint(1)
            .drain_configuration(group, 1, expired)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("configuration stream membership cannot change")
        );
        assert_eq!(
            f.endpoint(1)
                .configuration_status(group, expired)
                .unwrap()
                .head,
            1
        );
        assert_eq!(
            f.endpoint(1).authority_state().unwrap().checkpoint(),
            f.state.checkpoint()
        );
    }
}

#[test]
fn configuration_and_crypto_commit_together_after_storage_failures() {
    let f = Fixture::new();
    let kp = f.endpoint(1).key_package(Uuid::new_v4(), f.now).unwrap();
    f.db(0).execute_batch("CREATE TRIGGER fail_grant BEFORE INSERT ON configuration_streams BEGIN SELECT RAISE(ABORT,'injected grant failure'); END;").unwrap();
    let request = Uuid::new_v4();
    assert!(
        f.endpoint(0)
            .create_configuration(&f.owner, request, (f.nodes[1].id(), &kp), f.now)
            .is_err()
    );
    assert_eq!(
        f.db(0)
            .query_row("SELECT COUNT(*) FROM streams", [], |r| r.get::<_, usize>(0))
            .unwrap(),
        0
    );
    f.db(0).execute_batch("DROP TRIGGER fail_grant;").unwrap();
    let invitation = f
        .endpoint(0)
        .create_configuration(&f.owner, request, (f.nodes[1].id(), &kp), f.now)
        .unwrap();
    f.db(1).execute_batch("CREATE TRIGGER fail_grant BEFORE INSERT ON configuration_streams BEGIN SELECT RAISE(ABORT,'injected grant failure'); END;").unwrap();
    assert!(
        f.endpoint(1)
            .join_configuration(&invitation, f.now)
            .is_err()
    );
    f.db(1).execute_batch("DROP TRIGGER fail_grant;").unwrap();
    f.endpoint(1)
        .join_configuration(&invitation, f.now)
        .unwrap();
    let update = f.state.renew(&f.owner, f.now + 1).unwrap();
    f.endpoint(0).apply_authority(&[update]).unwrap();
    f.db(0).execute_batch("CREATE TRIGGER fail_progress BEFORE UPDATE ON configuration_streams BEGIN SELECT RAISE(ABORT,'injected publication failure'); END;").unwrap();
    let request = Uuid::new_v4();
    let group = invitation.packet.group();
    assert!(
        f.endpoint(0)
            .next_configuration(group, request, f.now + 1)
            .is_err()
    );
    assert_eq!(
        f.endpoint(0)
            .configuration_status(group, f.now + 1)
            .unwrap()
            .head,
        0
    );
    f.db(0)
        .execute_batch("DROP TRIGGER fail_progress;")
        .unwrap();
    let packet = f
        .endpoint(0)
        .next_configuration(group, request, f.now + 1)
        .unwrap()
        .unwrap();
    f.endpoint(1)
        .stage_configuration(&packet, f.now + 1)
        .unwrap();
    // This fails after the new authority and history have been written.
    f.db(1).execute_batch("CREATE TRIGGER fail_progress BEFORE UPDATE ON configuration_streams BEGIN SELECT RAISE(ABORT,'injected receive failure'); END;").unwrap();
    assert!(
        f.endpoint(1)
            .drain_configuration(group, 10, f.now + 1)
            .is_err()
    );
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert_eq!(
        f.endpoint(1)
            .configuration_status(group, f.now + 1)
            .unwrap()
            .head,
        0
    );
    assert_eq!(
        f.db(1)
            .query_row("SELECT COUNT(*) FROM authority_history", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        1
    );
    f.db(1)
        .execute_batch("DROP TRIGGER fail_progress;")
        .unwrap();
    f.endpoint(1)
        .drain_configuration(group, 10, f.now + 1)
        .unwrap();
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.endpoint(0).authority_state().unwrap().checkpoint()
    );
}

#[test]
fn large_policy_reassembles_across_restarts_and_epoch_changes() {
    let f = Fixture::new();
    let invitation = f.configuration(1);
    let group = invitation.packet.group();
    let members: Vec<_> = (0..4096).map(|_| Uuid::new_v4().to_string()).collect();
    let mut policy = Policy::default();
    for i in 0..8 {
        policy
            .groups
            .insert(format!("private-configuration-marker-{i}"), members.clone());
    }
    policy.rules.push(Rule {
        actor: Selector::All,
        peer: Selector::All,
        permission: Permission::Enumerate,
        effect: Effect::Allow,
    });
    let now = f.now + MAX_STATE_LIFETIME + 1;
    let update = f.state.set_policy(&f.owner, policy.clone(), now).unwrap();
    assert!(update.encode().unwrap().len() > 1024 * 1024);
    f.endpoint(0).apply_authority(&[update]).unwrap();
    let first = f
        .endpoint(0)
        .next_configuration(group, Uuid::new_v4(), now)
        .unwrap()
        .unwrap();
    let refresh = f
        .endpoint(0)
        .rotate_configuration(group, Uuid::new_v4(), now)
        .unwrap();
    let rest = f.publish_all(group, now);
    for packet in rest.iter().rev().chain(std::iter::once(&refresh)) {
        assert!(packet.encode().unwrap().len() <= 1024 * 1024);
        f.endpoint(1).stage_configuration(packet, now).unwrap();
    }
    assert!(
        f.endpoint(1)
            .drain_configuration(group, 10, now)
            .unwrap()
            .is_empty()
    );
    f.endpoint(1).stage_configuration(&first, now).unwrap();
    assert!(matches!(
        f.endpoint(1).drain_configuration(group, 1, now).unwrap()[0],
        Received::ConfigurationPart {
            complete: false,
            ..
        }
    ));
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert!(
        f.endpoint(1)
            .authority_state()
            .unwrap()
            .require_fresh(now)
            .is_err()
    );
    f.endpoint(1).drain_configuration(group, 128, now).unwrap();
    let accepted = f.endpoint(1).authority_state().unwrap();
    accepted.require_fresh(now).unwrap();
    assert_eq!(accepted.state().policy.groups, policy.groups);
    assert_eq!(accepted.state().policy.rules, policy.rules);
    assert_eq!(
        accepted.checkpoint(),
        f.endpoint(0).authority_state().unwrap().checkpoint()
    );
    assert!(f.endpoint(1).inbox(group, 0, 10).unwrap().is_empty());
    assert_eq!(
        f.db(1)
            .query_row("SELECT COUNT(*) FROM configuration_fragments", [], |r| {
                r.get::<_, usize>(0)
            })
            .unwrap(),
        0
    );
}

#[test]
fn already_known_history_is_idempotent_but_owner_forks_are_rejected() {
    let f = Fixture::new();
    let invitation = f.configuration(1);
    let group = invitation.packet.group();
    let update = f.state.renew(&f.owner, f.now + 1).unwrap();
    for i in [0, 1] {
        f.endpoint(i)
            .apply_authority(std::slice::from_ref(&update))
            .unwrap();
    }
    for packet in f.publish_all(group, f.now + 1) {
        f.endpoint(1)
            .stage_configuration(&packet, f.now + 1)
            .unwrap();
    }
    f.endpoint(1)
        .drain_configuration(group, 10, f.now + 1)
        .unwrap();
    let current = f.endpoint(0).authority_state().unwrap();
    let a = current.renew(&f.owner, f.now + 2).unwrap();
    let mut changed = Policy::default();
    changed
        .groups
        .insert("conflicting-owner-history".into(), vec![]);
    let b = current.set_policy(&f.owner, changed, f.now + 2).unwrap();
    f.endpoint(0).apply_authority(&[a]).unwrap();
    f.endpoint(1).apply_authority(&[b]).unwrap();
    let saved = f.endpoint(1).authority_state().unwrap();
    for packet in f.publish_all(group, f.now + 2) {
        f.endpoint(1)
            .stage_configuration(&packet, f.now + 2)
            .unwrap();
    }
    assert!(
        f.endpoint(1)
            .drain_configuration(group, 10, f.now + 2)
            .is_err()
    );
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        saved.checkpoint()
    );
}

#[test]
fn revoked_readers_do_not_receive_new_configuration_and_retired_writers_stay_blocked() {
    let f = Fixture::new();
    let one = f.configuration(1);
    let two = f.configuration(2);
    let removal = f
        .state
        .revoke_node(&f.owner, f.nodes[1].id(), f.now + 1)
        .unwrap();
    f.endpoint(0).apply_authority(&[removal]).unwrap();
    assert!(
        f.endpoint(0)
            .next_configuration(one.packet.group(), Uuid::new_v4(), f.now + 1)
            .is_err()
    );
    let packets = f.publish_all(two.packet.group(), f.now + 1);
    for packet in &packets {
        f.endpoint(2)
            .stage_configuration(packet, f.now + 1)
            .unwrap();
    }
    f.endpoint(2)
        .drain_configuration(two.packet.group(), 10, f.now + 1)
        .unwrap();
    assert!(
        !f.endpoint(2)
            .authority_state()
            .unwrap()
            .state()
            .nodes
            .contains_key(f.nodes[1].id())
    );
    let revoke_writer = f
        .state
        .revoke_node(&f.owner, f.nodes[0].id(), f.now + 1)
        .unwrap();
    f.endpoint(1).apply_authority(&[revoke_writer]).unwrap();
    assert!(
        f.endpoint(1)
            .stage_configuration(&one.packet, f.now + MAX_STATE_LIFETIME)
            .is_err()
    );
    assert!(
        f.endpoint(1)
            .configuration_status(one.packet.group(), f.now + MAX_STATE_LIFETIME)
            .is_err()
    );
}

#[test]
fn full_application_queue_cannot_starve_expired_configuration_recovery() {
    let f = Fixture::new();
    let configuration = f.configuration(1);
    let mut used = 0;
    for _ in 0..8 {
        let remaining = MAX_PENDING_BYTES - used;
        if remaining < 2048 {
            break;
        }
        let stream = f.data(0, 1);
        let size = ((remaining - 1024) * 3 / 4).min(2 * 1024 * 1024);
        // Valid writer signatures on opaque traffic, as checked before decrypting.
        let packet = f.nodes[0]
            .sign_stream_packet(stream.group(), 1, stream.digest().unwrap(), &vec![7; size])
            .unwrap();
        f.endpoint(1).stage(&packet, f.now).unwrap();
        used += packet.encode().unwrap().len();
    }
    assert!(MAX_PENDING_BYTES - used < 2048);
    let now = f.now + MAX_STATE_LIFETIME + 1;
    let renewal = f.state.renew(&f.owner, now).unwrap();
    f.endpoint(0).apply_authority(&[renewal]).unwrap();
    let packet = f
        .endpoint(0)
        .next_configuration(configuration.packet.group(), Uuid::new_v4(), now)
        .unwrap()
        .unwrap();
    assert!(packet.encode().unwrap().len() > MAX_PENDING_BYTES - used);
    f.endpoint(1).stage_configuration(&packet, now).unwrap();
    f.endpoint(1)
        .drain_configuration(packet.group(), 10, now)
        .unwrap();
    f.endpoint(1)
        .authority_state()
        .unwrap()
        .require_fresh(now)
        .unwrap();
}

#[test]
fn partial_record_reservations_are_bounded_and_existing_records_can_progress() {
    let f = Fixture::new();
    let mut configurations = Vec::new();
    for _ in 0..5 {
        configurations.push(f.configuration(1));
    }
    let body = |offset| {
        serde_json::to_vec(&json!({"version":1,"revision":f.state.checkpoint().revision+1,"digest":vec![1;32],"total":MAX_STATE_BYTES,"offset":offset,"data":STANDARD.encode(vec![0;MAX_FRAGMENT_BYTES])})).unwrap()
    };
    for (i, config) in configurations.iter().enumerate() {
        let packet = f.malicious_send(config.packet.group(), &body(0));
        f.endpoint(1).stage_configuration(&packet, f.now).unwrap();
        let result = f.endpoint(1).drain_configuration(packet.group(), 10, f.now);
        assert_eq!(result.is_ok(), i < 4);
    }
    let reserved: usize = f
        .db(1)
        .query_row("SELECT SUM(total) FROM configuration_fragments", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(reserved, 8 * 1024 * 1024);
    let first = &configurations[0];
    let packet = f.malicious_send(first.packet.group(), &body(MAX_FRAGMENT_BYTES));
    f.endpoint(1).stage_configuration(&packet, f.now).unwrap();
    f.endpoint(1)
        .drain_configuration(packet.group(), 10, f.now)
        .unwrap();
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    let revoked = f
        .state
        .revoke_node(&f.owner, f.nodes[0].id(), f.now + 1)
        .unwrap();
    f.endpoint(1).apply_authority(&[revoked]).unwrap();
    assert_eq!(
        f.db(1)
            .query_row("SELECT COUNT(*) FROM configuration_fragments", [], |r| {
                r.get::<_, usize>(0)
            })
            .unwrap(),
        0
    );
}

#[test]
fn version_two_streams_upgrade_without_losing_ciphertext() {
    let f = Fixture::new();
    let stream = f.data(0, 1);
    let packet = f
        .endpoint(0)
        .send(
            stream.group(),
            Uuid::new_v4(),
            b"before schema upgrade",
            f.now,
        )
        .unwrap();
    f.endpoint(1).stage(&packet, f.now).unwrap();
    f.db(1).execute_batch("ALTER TABLE streams DROP COLUMN purpose; DROP TABLE authority_history; DROP TABLE configuration_streams; DROP TABLE configuration_fragments; DROP TABLE configuration_requests; PRAGMA user_version=2;").unwrap();
    f.endpoint(1).drain(stream.group(), 10, f.now).unwrap();
    assert_eq!(
        f.endpoint(1).inbox(stream.group(), 0, 10).unwrap()[0]
            .1
            .body,
        b"before schema upgrade"
    );
    assert_eq!(
        f.endpoint(1).authority_state().unwrap().checkpoint(),
        f.state.checkpoint()
    );
    assert_eq!(
        f.db(1)
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        3
    );
    let configuration = f.configuration(1);
    assert_eq!(
        f.endpoint(1)
            .configuration_status(configuration.packet.group(), f.now)
            .unwrap()
            .head,
        0
    );
}
