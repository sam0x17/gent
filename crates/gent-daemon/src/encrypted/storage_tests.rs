use super::*;
use gent_crypto::OwnerKey;
use std::os::unix::fs::PermissionsExt;

#[test]
fn database_full_does_not_advance_mls_ratchet_or_reserve_request() {
    let homes = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    for home in &homes {
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let nodes = [
        NodeIdentity::generate().unwrap(),
        NodeIdentity::generate().unwrap(),
    ];
    let owner = OwnerKey::generate().unwrap();
    let now = crate::store::now() as u64;
    let mut state = owner
        .create_cluster("storage", &nodes[0], "first", now)
        .unwrap();
    let request = nodes[1]
        .request_enrollment(state.anchor(), state.checkpoint(), "second", now)
        .unwrap();
    let update = state
        .enroll(&owner, &request, request.fingerprint().unwrap(), now)
        .unwrap();
    state.apply_chain(&[update], now).unwrap();
    let mut sender = EncryptedEndpoint::open(homes[0].path(), &nodes[0]).unwrap();
    let mut receiver = EncryptedEndpoint::open(homes[1].path(), &nodes[1]).unwrap();
    sender.initialize(&state, now).unwrap();
    receiver.initialize(&state, now).unwrap();
    let package = receiver.key_package(Uuid::new_v4(), now).unwrap();
    let invitation = sender
        .create_group(Uuid::new_v4(), &[(nodes[1].id(), &package)], now)
        .unwrap();
    receiver
        .join(&invitation, &[nodes[0].id(), nodes[1].id()], now)
        .unwrap();
    sender.db.execute_batch("CREATE TABLE quota_fixture(body BLOB); INSERT INTO quota_fixture VALUES(zeroblob(1048576));").unwrap();
    let pages: u64 = sender
        .db
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    sender
        .db
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    let request = Uuid::new_v4();
    let body = vec![42; 64 * 1024];
    let path = homes[0].path().join("mls.sqlite3");
    let before = std::fs::read(&path).unwrap();
    // OpenMLS wraps some storage errors as internal library errors. Check the
    // complete saved ratchet and retry state, rather than its display text.
    assert!(
        sender
            .send(&invitation.group_id, request, &body, now)
            .is_err()
    );
    assert!(std::fs::read(&path).unwrap() == before);
    assert_eq!(
        sender
            .db
            .query_row(
                "SELECT COUNT(*) FROM outbox WHERE id=?1",
                [request.to_string()],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    sender.db.execute("DELETE FROM quota_fixture", []).unwrap();
    let sent = sender
        .send(&invitation.group_id, request, &body, now)
        .unwrap();
    drop(sender);
    let mut sender = EncryptedEndpoint::open(homes[0].path(), &nodes[0]).unwrap();
    assert_eq!(
        sender
            .send(&invitation.group_id, request, &body, now)
            .unwrap(),
        sent
    );
    let received = receiver.receive(&sent.group_id, &sent.bytes, now).unwrap();
    assert!(matches!(received, Received::Application { .. }));
}
