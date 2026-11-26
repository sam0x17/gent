use super::*;
use gent_protocol::{
    babysitter::ChatOrigin,
    notifications::Failure,
    stats::{Babysitter, NodeContribution, Traffic},
};

fn contribution(store: &Store) -> Result<NodeContribution> {
    store
        .network_session(&store.db, store.identity.state(&store.db)?)
        .usage_stats_export()
}

#[tokio::test]
async fn usage_stats_needs_owner_and_stays_read_only_with_pending_projection() -> Result<()> {
    let mut pair = Pair::new().await;
    let db = &pair.stores[0].db;
    runtime::queue_projection(db)?;
    let changes = db.total_changes();
    db.busy_timeout(std::time::Duration::ZERO)?;
    let mut writer = Connection::open(db.path().unwrap())?;
    let lock = writer.transaction_with_behavior(TransactionBehavior::Immediate)?;
    assert!(
        pair.stores[0]
            .execute(Request::Owner {
                credential: config::secret(),
                action: OwnerOp::Stats,
            })
            .is_err()
    );
    assert_eq!(pair.owner(0, OwnerOp::Stats)?["scope"], "cluster");
    assert_eq!(pair.stores[0].db.total_changes(), changes);
    assert!(runtime::projection_pending(&pair.stores[0].db)?);
    lock.rollback()?;
    Ok(())
}

#[tokio::test]
async fn usage_counts_original_sends_bytes_and_names_across_replication_and_cleanup() -> Result<()>
{
    let mut pair = Pair::new().await;
    let send = AgentOp::Send {
        recipient: pair.agents[1].clone(),
        request_id: Uuid::now_v7().to_string(),
        text: "é\0!".into(),
        files: ["AQ==", "AgM=", "BAUG"]
            .into_iter()
            .map(|s| FilePart {
                name: "test.bin".into(),
                media_type: "application/octet-stream".into(),
                data_base64: s.into(),
            })
            .collect(),
        file_ids: vec![],
    };
    assert_eq!(pair.agent(0, send.clone())?["duplicate"], false);
    assert_eq!(pair.agent(0, send)?["duplicate"], true);
    send_attachment(&mut pair, &[4; 7]);
    pair.pump();
    let expected = Traffic {
        messages: 2,
        text_bytes: 15,
        attachment_bytes: 13,
        bytes: 28,
    };
    let local = contribution(&pair.stores[0])?;
    assert_eq!(local.outbound, expected);
    assert_eq!(local.senders.len(), 1);
    assert_eq!(local.senders[0].chat_id, pair.agents[0]);
    assert_eq!(local.senders[0].name, "agent-0");
    assert_eq!(contribution(&pair.stores[1])?.outbound, Traffic::default());
    // Simulate first tracking install with retained local sends and incoming copies.
    for i in 0..2 {
        pair.stores[i]
            .db
            .execute_batch("DELETE FROM usage_tracking; DELETE FROM usage_senders;")?;
        pair.reopen(i);
    }
    assert_eq!(contribution(&pair.stores[0])?.outbound, expected);
    assert_eq!(contribution(&pair.stores[1])?.outbound, Traffic::default());
    pair.agent(
        0,
        AgentOp::Rename {
            name: "renamed sender".into(),
            expected_generation: 1,
        },
    )?;
    pair.stores[0]
        .db
        .execute("UPDATE exchanges SET expires_at=0", [])?;
    pair.owner(0, OwnerOp::HistoryClean { dry_run: false })?;
    assert_eq!(
        pair.stores[0]
            .db
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, u64>(0))?,
        0
    );
    pair.reopen(0);
    let retained = contribution(&pair.stores[0])?;
    assert_eq!(retained.outbound, expected);
    assert_eq!(retained.senders[0].name, "renamed sender");
    assert_eq!(retained.senders[0].traffic, expected);
    Ok(())
}

#[tokio::test]
async fn usage_counts_confirmed_submissions_once_and_excludes_goal_opt_out() -> Result<()> {
    let mut p = Pair::new().await;
    std::fs::remove_file(p.homes[0].path().join("test-entitlement"))?;
    let at = now();
    let goal = |id: char| AgentOp::BabysitterClaim {
        goal: id.to_string().repeat(64),
        turn: Uuid::new_v4(),
        failed_at: at,
        reason: Failure::Capacity,
    };
    let attempt = serde_json::from_value(p.agent(0, goal('a'))?["claim"].clone())?;
    p.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(false),
        },
    )?;
    p.agent(
        0,
        AgentOp::BabysitterSubmitted {
            attempt,
            scope: None,
        },
    )?;
    assert_eq!(
        contribution(&p.stores[0])?.babysitter,
        Babysitter::default()
    );
    p.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(true),
        },
    )?;
    let attempt = serde_json::from_value(p.agent(0, goal('b'))?["claim"].clone())?;
    for _ in 0..2 {
        p.agent(
            0,
            AgentOp::BabysitterSubmitted {
                attempt,
                scope: None,
            },
        )?;
    }
    config::set_ordinary_babysitter_enabled(p.homes[0].path(), true)?;
    let turn = Uuid::new_v4();
    let ordinary = p.agent(
        0,
        AgentOp::BabysitterChatClaim {
            turn,
            failed_at: at,
            reason: Failure::ToolSchema,
            origin: ChatOrigin::Operator {
                turn,
                started_at: at - 1,
                client_id: None,
                additional_client_ids: vec![],
            },
        },
    )?;
    let attempt = serde_json::from_value(ordinary["claim"].clone())?;
    assert_eq!(
        p.agent(0, AgentOp::BabysitterChatSubmitted { attempt })?["submitted"],
        false
    );
    assert_eq!(
        p.agent(0, AgentOp::BabysitterChatCheck { attempt })?["eligible"],
        true
    );
    for _ in 0..2 {
        assert_eq!(
            p.agent(0, AgentOp::BabysitterChatSubmitted { attempt })?["submitted"],
            true
        );
    }
    p.reopen(0);
    assert_eq!(
        contribution(&p.stores[0])?.babysitter,
        Babysitter {
            ordinary_submitted: 1,
            goal_submitted: 1
        }
    );
    p.stores[0].db.execute("DELETE FROM usage_tracking", [])?;
    p.reopen(0);
    assert_eq!(
        contribution(&p.stores[0])?.babysitter,
        Babysitter {
            ordinary_submitted: 1,
            goal_submitted: 0
        }
    );
    p.stores[0]
        .db
        .execute("DELETE FROM babysitter_chat_attempts", [])?;
    assert_eq!(contribution(&p.stores[0])?.babysitter.ordinary_submitted, 1);
    Ok(())
}
