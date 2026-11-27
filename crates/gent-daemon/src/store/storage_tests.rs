use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn database_full_preserves_request_atomicity_and_cleanup_releases_capacity() {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    config::initialize(home.path(), "storage-test").unwrap();
    let mut store = Store::open(home.path()).unwrap();
    let owner = config::read_private(&home.path().join("owner.key")).unwrap();
    let keys = [config::secret(), config::secret()];
    let agents: Vec<String> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            store
                .execute(Request::Agent {
                    credential: key.clone(),
                    action: AgentOp::Register {
                        name: format!("agent-{i}"),
                        provider: "test".into(),
                    },
                })
                .unwrap()["agent"]["id"]
                .as_str()
                .unwrap()
                .into()
        })
        .collect();
    store
        .execute(Request::Owner {
            credential: owner.clone(),
            action: OwnerOp::SetPolicy {
                policy: Policy {
                    rules: [Permission::Enumerate, Permission::Send, Permission::Receive]
                        .map(|permission| Rule {
                            actor: Selector::All,
                            peer: Selector::All,
                            permission,
                            effect: Effect::Allow,
                        })
                        .into(),
                    ..Default::default()
                },
            },
        })
        .unwrap();
    // Occupy pages with disposable fixture data, then cap this real connection.
    store.db.execute_batch("CREATE TABLE quota_fixture(body BLOB); INSERT INTO quota_fixture VALUES(zeroblob(1048576));").unwrap();
    let pages: u64 = store
        .db
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    store
        .db
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    let request_id = uuid::Uuid::now_v7().to_string();
    let operation = || Request::Agent {
        credential: keys[0].clone(),
        action: AgentOp::Send {
            recipient: agents[1].clone(),
            request_id: request_id.clone(),
            text: "x".repeat(MAX_TEXT_BYTES),
            files: vec![],
            file_ids: vec![],
        },
    };
    let checkpoint: Vec<u8> = store
        .db
        .query_row("SELECT checkpoint FROM authority", [], |r| r.get(0))
        .unwrap();
    let error = store.execute(operation()).unwrap_err();
    assert!(error.to_string().contains("full"), "{error:#}");
    for table in ["messages", "exchanges"] {
        assert_eq!(
            store
                .db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                    .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(
        store
            .db
            .query_row("SELECT checkpoint FROM authority", [], |r| r
                .get::<_, Vec<u8>>(0))
            .unwrap(),
        checkpoint
    );
    let status = store
        .execute(Request::Owner {
            credential: owner.clone(),
            action: OwnerOp::FilesStatus,
        })
        .unwrap();
    assert_eq!(status["database"]["journal_mode"], "delete");
    store
        .execute(Request::Owner {
            credential: owner,
            action: OwnerOp::HistoryClean { dry_run: false },
        })
        .unwrap();
    store.db.execute("DELETE FROM quota_fixture", []).unwrap();
    let sent = store.execute(operation()).unwrap();
    assert_eq!(
        store.execute(operation()).unwrap()["message_id"],
        sent["message_id"]
    );
    drop(store);
    let mut store = Store::open(home.path()).unwrap();
    assert_eq!(
        store.execute(operation()).unwrap()["message_id"],
        sent["message_id"]
    );
    assert_eq!(
        crate::storage::usage(&store.db).unwrap()["max_bytes"],
        crate::storage::MAX_DATABASE_BYTES
    );
}

#[tokio::test]
async fn pending_recipient_and_eligibility_polls_leave_cluster_transport_asleep() -> Result<()> {
    use std::time::Duration;
    let home = tempfile::tempdir()?;
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700))?;
    config::initialize(home.path(), "wake-test")?;
    let mut store = Store::open(home.path())?;
    let owner = config::read_private(&home.path().join("owner.key"))?;
    let key = config::secret();
    store.execute(Request::Agent {
        credential: key.clone(),
        action: AgentOp::Register {
            name: "local".into(),
            provider: "codex".into(),
        },
    })?;
    // Registration legitimately scheduled publication.
    tokio::time::timeout(Duration::from_secs(1), store.sync_wakeup.notified()).await?;
    for _ in 0..2 {
        let demand = store.execute(Request::Owner {
            credential: owner.clone(),
            action: OwnerOp::WakePendingAgents { after: None },
        })?;
        assert_eq!(demand["agents"], json!([]));
        let eligibility = store.execute(Request::Agent {
            credential: key.clone(),
            action: AgentOp::WakePending,
        })?;
        assert_eq!(eligibility["pending"], json!([]));
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), store.sync_wakeup.notified())
            .await
            .is_err()
    );
    Ok(())
}
