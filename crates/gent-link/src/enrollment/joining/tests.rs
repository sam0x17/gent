use super::*;
use gent_daemon::store::Store;

fn invitations(root: &Path) -> (Invitation, Invitation) {
    let owner = root.join("owner");
    let mut cfg = config::initialize(&owner, "personal").unwrap();
    cfg.cluster.local_only = false;
    cfg.service = Some(config::ServiceConfig {
        origin: "https://account.example/".into(),
        account_id: uuid::Uuid::new_v4().to_string(),
    });
    cfg.relay = Some(config::RelayConfig {
        endpoint: "https://relay.example/".into(),
        credential_file: "relay.key".into(),
    });
    config::save(&owner, &cfg).unwrap();
    gent_daemon::entitlements::grant_test(&owner, &cfg);
    let credential = config::read_private(&owner.join("owner.key")).unwrap();
    let mut store = Store::open(&owner).unwrap();
    let mut issue = || {
        Invitation::decode(
            &store
                .create_invitation(&credential, &uuid::Uuid::now_v7().to_string(), true, None)
                .unwrap(),
        )
        .unwrap()
    };
    (issue(), issue())
}

#[test]
fn no_code_retry_recovers_a_crash_between_native_replacement_and_pending_record() {
    let root = tempfile::tempdir().unwrap();
    let (old, new) = invitations(root.path());
    let home = root.path().join("joining");
    let directory = storage::directory(&home).unwrap();
    let old_file = directory.join("old.gent-invite");
    let new_file = directory.join("new.gent-invite");
    config::write_private(&old_file, &old.encode().unwrap()).unwrap();
    config::write_private(&new_file, &new.encode().unwrap()).unwrap();
    crate::invitations::prepare_code_join(&home, old.offer(), "laptop", "login").unwrap();
    let journal = directory.join("pending-join.json");
    storage::write(
        &journal,
        &Pending {
            account: old.offer().offer.service.account_id.clone(),
            session: "login".into(),
            service: old.offer().offer.service.account_origin.clone(),
            file: old_file.clone(),
            name: "laptop".into(),
            cluster: old.offer().offer.anchor.cluster_id.clone(),
        },
    )
    .unwrap();
    assert_eq!(pending(&home).unwrap(), Some((old_file, "laptop".into())));
    let before = std::fs::read(&journal).unwrap();
    // Replacement is committed; simulate losing the subsequent UI-record write.
    crate::invitations::prepare_code_join(&home, new.offer(), "laptop", "new-login").unwrap();
    assert_eq!(std::fs::read(&journal).unwrap(), before);
    assert_eq!(pending(&home).unwrap(), Some((new_file, "laptop".into())));
    // Superseded, renamed and foreign invitations cannot roll the journal back.
    assert!(crate::invitations::prepare_code_join(&home, old.offer(), "laptop", "login").is_err());
    assert!(
        crate::invitations::prepare_code_join(&home, new.offer(), "different", "new-login")
            .is_err()
    );
    let foreign_root = tempfile::tempdir().unwrap();
    let (foreign, _) = invitations(foreign_root.path());
    assert!(
        crate::invitations::prepare_code_join(&home, foreign.offer(), "laptop", "new-login")
            .is_err()
    );
    assert_eq!(
        crate::invitations::installation(&home)
            .unwrap()
            .unwrap()
            .offer,
        *new.offer()
    );
}
