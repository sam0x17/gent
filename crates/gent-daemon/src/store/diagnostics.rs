//! A snapshot for local owner diagnosis. No migrations, clock writes, config
//! projection, network requests or sync wakeups occur through this operation.
use super::*;

impl Store {
    pub(super) fn diagnose(&mut self) -> Result<Value> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let state = self.identity.state(&tx)?;
        let observed = now();
        let floor: i64 = tx.query_row(
            "SELECT floor FROM request_clock WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        let member = state
            .state()
            .nodes
            .get(self.identity.node.id())
            .is_some_and(|n| n.signing_key == self.identity.node.public_key());
        let value = json!({
            "version": 1, "process_id": std::process::id(),
            "node_id": self.identity.node.id(), "cluster_id": state.state().cluster_id,
            "authority": {"revision": state.checkpoint().revision, "expires_at": state.state().expires_at,
                "fresh": state.require_fresh(observed.max(floor) as u64).is_ok(),
                "member": member, "owner": self.identity.is_current_owner(&state),
                "owner_epoch": state.owner_epoch(),
                "signing_frozen": handoff::frozen(&tx, &state)?,
                "clock_ahead": floor > observed},
            "config_saved": !runtime::projection_pending(&tx)?,
            "relay": {"configured": self.config.relay.is_some(), "health": self.sync_health.snapshot()}
        });
        tx.commit()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn idle_status_and_removal_polls_do_not_write_or_wake_transport() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("node");
        config::initialize(&home, "diagnostic").unwrap();
        let mut store = Store::open(&home).unwrap();
        let key = config::read_private(&home.join("owner.key")).unwrap();
        store
            .db
            .execute("UPDATE request_clock SET floor=?1", [now() - 60])
            .unwrap();
        let before = fs::read(home.join("state.sqlite3")).unwrap();
        let changes = store.db.total_changes();
        for action in [
            OwnerOp::Status,
            OwnerOp::Nodes,
            OwnerOp::NodeRemovals {
                after: None,
                pending_only: true,
            },
        ] {
            assert!(
                store
                    .execute(Request::Owner {
                        credential: "wrong".into(),
                        action: action.clone()
                    })
                    .is_err()
            );
            store
                .execute(Request::Owner {
                    credential: key.clone(),
                    action,
                })
                .unwrap();
        }
        assert_eq!(store.db.total_changes(), changes);
        assert_eq!(fs::read(home.join("state.sqlite3")).unwrap(), before);
        // State-changing requests still commit their monotonic admission clock.
        store
            .execute(Request::Owner {
                credential: key.clone(),
                action: OwnerOp::RenameNode {
                    name: "renamed".into(),
                },
            })
            .unwrap();
        let clock: i64 = store
            .db
            .query_row("SELECT floor FROM request_clock", [], |r| r.get(0))
            .unwrap();
        assert!(clock >= now() - 1);
        // A status request can still repair a pending filesystem projection.
        runtime::queue_projection(&store.db).unwrap();
        let status = store
            .execute(Request::Owner {
                credential: key,
                action: OwnerOp::Status,
            })
            .unwrap();
        assert_eq!(status["config_saved"], true);
    }

    #[test]
    fn diagnosis_requires_owner_and_preserves_clock_database_and_pending_projection() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        config::initialize(dir.path(), "diagnostic").unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let key = config::read_private(&dir.path().join("owner.key")).unwrap();
        runtime::queue_projection(&store.db).unwrap();
        store
            .db
            .execute("UPDATE request_clock SET floor=?1", [now() + 3600])
            .unwrap();
        let before = fs::read(dir.path().join("state.sqlite3")).unwrap();
        let config_before = fs::read(config::path(dir.path())).unwrap();
        let changes = store.db.total_changes();
        assert!(
            store
                .execute(Request::Owner {
                    credential: "wrong".into(),
                    action: OwnerOp::Diagnose
                })
                .is_err()
        );
        for _ in 0..2 {
            let value = store
                .execute(Request::Owner {
                    credential: key.clone(),
                    action: OwnerOp::Diagnose,
                })
                .unwrap();
            assert_eq!(value["authority"]["clock_ahead"], true);
            assert_eq!(value["config_saved"], false);
            assert_eq!(value["authority"]["member"], true);
            assert_eq!(value["relay"]["health"]["last_success_at"], Value::Null);
            assert!(!value.to_string().contains(&key));
        }
        assert_eq!(store.db.total_changes(), changes);
        assert_eq!(fs::read(dir.path().join("state.sqlite3")).unwrap(), before);
        assert_eq!(fs::read(config::path(dir.path())).unwrap(), config_before);
        assert!(runtime::projection_pending(&store.db).unwrap());
    }
}
