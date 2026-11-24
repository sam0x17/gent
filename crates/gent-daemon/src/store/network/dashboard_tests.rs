use super::*;

#[tokio::test]
async fn dashboard_pages_include_every_publisher_once() {
    let mut pair = Pair::new().await;
    let board: gent_protocol::dashboard::Board =
        serde_json::from_value(json!({"title":"Run","widgets":[
            {"id":"state","kind":"text","label":"Status","value":"Working"}
        ]}))
        .unwrap();
    let mut publishers = std::collections::BTreeSet::new();
    for i in 1..=33 {
        let credential = format!("{i:064x}");
        let register = Request::Agent {
            credential: credential.clone(),
            action: AgentOp::Register {
                name: format!("Run {i}"),
                provider: "test".into(),
            },
        };
        let entry = pair.stores[0].execute(register).unwrap();
        publishers.insert(entry["agent"]["id"].as_str().unwrap().to_owned());
        pair.stores[0]
            .execute(Request::Agent {
                credential,
                action: AgentOp::DashboardDefine {
                    expected_revision: 0,
                    board: board.clone(),
                },
            })
            .unwrap();
    }
    let first = pair.owner(0, OwnerOp::Dashboards { after: None }).unwrap();
    assert_eq!(first["rows"].as_array().unwrap().len(), 32);
    let next = first["next"].as_str().unwrap();
    assert_eq!(first["rows"][31]["agent"], next);
    let last = pair
        .owner(
            0,
            OwnerOp::Dashboards {
                after: Some(next.into()),
            },
        )
        .unwrap();
    assert_eq!(last["rows"].as_array().unwrap().len(), 1);
    assert!(last["next"].is_null());
    for page in [first, last] {
        for entry in page["rows"].as_array().unwrap() {
            assert!(publishers.remove(entry["agent"].as_str().unwrap()));
        }
    }
    assert!(publishers.is_empty());
}

#[tokio::test]
async fn dashboard_lifecycle_replicates_and_routes_button_to_publisher() {
    let mut pair = Pair::new().await;
    let policy = Policy::cluster_default();
    pair.owner(0, OwnerOp::SetPolicy { policy }).unwrap();
    directory_push_tests::negotiate(&mut pair);
    let board = serde_json::from_value(json!({"title":"Training","widgets":[
        {"id":"trend","label":"Loss","kind":"graph","value":[1.0,0.5]},
        {"id":"inspect","label":"Inspect","kind":"button","value":"Report the latest checkpoint."}
    ]}))
    .unwrap();
    let define = AgentOp::DashboardDefine {
        expected_revision: 0,
        board,
    };
    for _ in 0..2 {
        assert_eq!(pair.agent(1, define.clone()).unwrap()["revision"], 1);
    }
    pair.pump();
    assert_eq!(
        pair.owner(0, OwnerOp::Dashboards { after: None }).unwrap()["rows"][0]["board"]["title"],
        "Training"
    );
    let id = pair.agents[1].clone();
    let click = OwnerOp::DashboardClick {
        agent: id.clone(),
        revision: 1,
        widget: "inspect".into(),
        request_id: Uuid::now_v7().to_string(),
    };
    let sent = pair.owner(0, click.clone()).unwrap();
    assert_eq!(
        pair.owner(0, click).unwrap()["message_id"],
        sent["message_id"]
    );
    pair.pump();
    let message: String = pair.stores[1]
        .db
        .query_row(
            "SELECT payload FROM messages WHERE id=?1",
            [sent["message_id"].as_str().unwrap()],
            |r| r.get(0),
        )
        .unwrap();
    assert!(message.contains("Report the latest checkpoint."));
    let update = |v| AgentOp::DashboardUpdate {
        expected_revision: 1,
        values: BTreeMap::from([("trend".into(), v)]),
    };
    assert!(pair.agent(1, update(json!(["bad"]))).is_err());
    assert_eq!(pair.agent(1, update(json!([0.25]))).unwrap()["revision"], 2);
    assert!(pair.agent(1, define).is_err());
    pair.pump();
    pair.reopen(0);
    assert_eq!(
        pair.owner(0, OwnerOp::Dashboards { after: None }).unwrap()["rows"][0]["board"]["widgets"]
            [0]["value"],
        json!([0.25])
    );
    pair.agent(
        1,
        AgentOp::DashboardDelete {
            expected_revision: 2,
        },
    )
    .unwrap();
    pair.pump();
    assert_eq!(
        pair.owner(0, OwnerOp::Dashboards { after: None }).unwrap()["rows"],
        json!([])
    );
}

#[tokio::test]
async fn dashboard_link_survives_legacy_storage_downgrade_and_idle_reopen() -> Result<()> {
    use crate::messages::wire::{DASHBOARD_VERSION, NODE_RENAME_VERSION};
    let mut pair = Pair::new().await;
    directory_push_tests::negotiate(&mut pair);
    let native = json!({"title":"Run","widgets":[
        {"id":"guide","kind":"link","label":"Guide","value":"https://example.org/docs?q=1#intro","min":2.0},
        {"id":"action","kind":"button","label":"Check","value":"Check the run."},
        {"id":"plain","kind":"text","label":"Plain","value":"https://example.org/"},
        {"id":"other","kind":"text","label":"Other","value":"https://example.org/","unit":"url"},
        {"id":"note","kind":"text","label":"Note","value":"Reference pending","unit":"URL"}
    ]});
    let mut legacy = native.clone();
    legacy["widgets"][0]["kind"] = json!("text");
    legacy["widgets"][0]["unit"] = json!("↗ web link");
    let define = |value: &Value| -> Result<AgentOp> {
        Ok(AgentOp::DashboardDefine {
            expected_revision: 0,
            board: serde_json::from_value(value.clone())?,
        })
    };
    pair.agent(0, define(&native)?)?;
    assert_eq!(pair.agent(0, define(&legacy)?)?["revision"], 1);
    let bytes: Vec<u8> = pair.stores[0].db.query_row(
        "SELECT e.body FROM network_events e JOIN dashboard_sent s ON e.id=s.event",
        [],
        |r| r.get(0),
    )?;
    let envelope: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(envelope["version"], DASHBOARD_VERSION);
    assert_eq!(envelope["event"]["board"], legacy);
    for version in [DASHBOARD_VERSION, NODE_RENAME_VERSION] {
        let mut malformed = envelope.clone();
        malformed["version"] = json!(version);
        malformed["event"]["board"] = native.clone();
        assert!(serde_json::from_value::<Record>(malformed).is_err());
    }

    // This queued snapshot predates the downgrade. Subsequent ordinary
    // traffic must drain on the very same ordered stream.
    for store in &pair.stores {
        store
            .db
            .execute("UPDATE wire_peers SET version=?1", [DASHBOARD_VERSION])?;
    }
    pair.pump();
    let publisher = &pair.agents[0];
    let receiver = &pair.stores[1];
    let raw: String = receiver.db.query_row(
        "SELECT body FROM dashboards WHERE agent=?1",
        [publisher],
        |r| r.get(0),
    )?;
    assert_eq!(serde_json::from_str::<Value>(&raw)?, legacy);
    // An old receiver normalizes and persists a typed Board. All information
    // needed after upgrade must survive that write, with no additional rows.
    let stored: gent_protocol::dashboard::Board = serde_json::from_str(&raw)?;
    stored.validate().unwrap();
    receiver.db.execute(
        "UPDATE dashboards SET body=?2 WHERE agent=?1",
        params![publisher, serde_json::to_string(&stored)?],
    )?;
    pair.send(vec![])?;
    pair.pump();
    assert_eq!(pair.agent(1, AgentOp::Inbox)?.as_array().unwrap().len(), 1);
    pair.reopen(0);
    pair.reopen(1);
    let rows = pair.owner(1, OwnerOp::Dashboards { after: None })?;
    assert_eq!(rows["rows"][0]["board"], native);
    assert_eq!(rows["rows"][0]["revision"], 1);
    assert_eq!(pair.agent(0, AgentOp::DashboardGet)?["board"], native);

    let recipient = pair.stores[1].identity.node.id();
    let sender = &pair.stores[0];
    for version in [DASHBOARD_VERSION, NODE_RENAME_VERSION] {
        let tx = sender.db.unchecked_transaction()?;
        let session = sender.network_session(&tx, sender.identity.state(&tx)?);
        for _ in 0..3 {
            session.confirm_wire_version(recipient, version)?;
        }
        assert!(!tx.prepare("SELECT 1 FROM network_events")?.exists([])?);
        assert!(!tx.prepare("SELECT 1 FROM presence_requests")?.exists([])?);
        // An ordinary legacy heartbeat gets its normal replies and never
        // schedules a reciprocal dashboard preference probe.
        session.presence_receive(recipient, Uuid::new_v4(), false)?;
        assert!(!tx.prepare("SELECT 1 FROM presence_requests")?.exists([])?);
        tx.rollback()?;
    }
    for store in &mut pair.stores {
        store
            .db
            .execute("UPDATE node_presence SET next_probe_at=?1", [now() - 1])?;
        assert!(!store.presence_tick()?);
    }

    assert!(
        pair.agent(
            0,
            AgentOp::DashboardUpdate {
                expected_revision: 1,
                values: BTreeMap::from([("guide".into(), json!("just text"))]),
            }
        )
        .is_err()
    );
    assert_eq!(pair.agent(0, AgentOp::DashboardGet)?["revision"], 1);
    for (expected_revision, status) in [(1, "https://example.org/status"), (2, "pending")] {
        pair.agent(
            0,
            AgentOp::DashboardUpdate {
                expected_revision,
                values: BTreeMap::from([("note".into(), json!(status))]),
            },
        )?;
        let board = pair.agent(0, AgentOp::DashboardGet)?;
        assert_eq!(board["board"]["widgets"][4]["kind"], "text");
        assert_eq!(board["board"]["widgets"][4]["unit"], "URL");
        assert_eq!(board["board"]["widgets"][4]["value"], status);
    }
    Ok(())
}

#[tokio::test]
async fn advanced_dashboard_survives_legacy_replication_edits_retries_and_deletion() -> Result<()> {
    let mut pair = Pair::new().await;
    directory_push_tests::negotiate(&mut pair);
    let categories: Vec<_> = (0..16)
        .map(|i| json!({"label": format!("{}{i}", "界".repeat(41)), "value":i}))
        .collect();
    let mut native = json!({"title":"Mixed","widgets":[
        {"id":"m","kind":"metric","label":"Total","value":-12.5,"unit":"kg","min":-20.0},
        {"id":"b","kind":"bar","label":"Sales","value":categories},
        {"id":"p","kind":"pie","label":"Shares","value":categories},
        {"id":"r","kind":"radar","label":"Bands","value":categories},
        {"id":"s","kind":"scatter","label":"Position","value":[[-1,2.5],[4,0]],"x_unit":"s","unit":"m","max":20.0},
        {"id":"i","kind":"image","label":"Result","value":"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAEUlEQVR4nGP4z/AfK2IYWhIA0ad/gXfwoGMAAAAASUVORK5CYII="},
        {"id":"g","kind":"graph","label":"Trend","value":[0,1]},
        {"id":"l","kind":"link","label":"Guide","value":"https://example.org/"},
        {"id":"old","kind":"events","label":"Notes","unit":"Gent widget v1","value":["work in progress"]},
        {"id":"invalid","kind":"events","label":"Notes","unit":"Gent widget v1","value":["{\"kind\":\"scatter\"}","[1,2]"]}
    ]});
    let define = |board| -> Result<AgentOp> {
        Ok(AgentOp::DashboardDefine {
            expected_revision: 0,
            board: serde_json::from_value(board)?,
        })
    };
    pair.agent(0, define(native.clone())?)?;
    let bytes: Vec<u8> = pair.stores[0].db.query_row(
        "SELECT body FROM network_events e JOIN dashboard_sent s ON s.event=e.id",
        [],
        |r| r.get(0),
    )?;
    let wire: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(wire["version"], 9);
    let legacy = &wire["event"]["board"];
    for widget in &legacy["widgets"].as_array().unwrap()[..6] {
        assert_eq!(widget["kind"], "events");
        assert_eq!(widget["unit"], "Gent widget v1");
        assert!(widget.get("x_unit").is_none());
        assert!(
            widget["value"]
                .as_array()
                .unwrap()
                .iter()
                .all(|s| s.as_str().unwrap().len() <= 2048)
        );
    }
    assert!(legacy["widgets"][1]["value"].as_array().unwrap().len() >= 3);
    assert_eq!(pair.agent(0, define(legacy.clone())?)?["revision"], 1);
    let mut malformed = wire.clone();
    malformed["event"]["board"] = native.clone();
    assert!(serde_json::from_value::<Record>(malformed).is_err());
    pair.pump();
    pair.reopen(1);
    let list = |pair: &mut Pair| pair.owner(1, OwnerOp::Dashboards { after: None });
    assert_eq!(list(&mut pair)?["rows"][0]["board"], native);
    // A V9/V10 rewrite stores precisely the board which entered its stream.
    let body: String = pair.stores[1].db.query_row(
        "SELECT body FROM dashboards WHERE agent=?1",
        [&pair.agents[0]],
        |r| r.get(0),
    )?;
    assert_eq!(serde_json::from_str::<Value>(&body)?, *legacy);

    let update = |expected_revision, data| AgentOp::DashboardUpdate {
        expected_revision,
        values: BTreeMap::from([("s".into(), data)]),
    };
    assert!(pair.agent(0, update(1, json!([1, 2]))).is_err());
    let points = json!([[1, 3], [2, -4]]);
    for _ in 0..2 {
        assert_eq!(pair.agent(0, update(1, points.clone()))?["revision"], 2);
    }
    let portable_points = json!([legacy["widgets"][4]["value"][0], "[[1,3],[2,-4]]"]);
    assert_eq!(pair.agent(0, update(1, portable_points))?["revision"], 2);
    let changed_unit = json!([
        "{\"kind\":\"scatter\",\"unit\":\"other\",\"x_unit\":\"s\"}",
        "[[1,3]]"
    ]);
    assert!(pair.agent(0, update(2, changed_unit)).is_err());
    native["widgets"][4]["value"] = points;
    pair.pump();
    assert_eq!(list(&mut pair)?["rows"][0]["board"], native);
    let portable_empty = json!([legacy["widgets"][4]["value"][0], "[]"]);
    assert_eq!(pair.agent(0, update(2, portable_empty))?["revision"], 3);
    pair.reopen(0);
    assert_eq!(pair.agent(0, update(2, json!([])))?["revision"], 3);
    native["widgets"][4]["value"] = json!([]);
    pair.pump();
    assert_eq!(list(&mut pair)?["rows"][0]["board"], native);
    pair.agent(
        0,
        AgentOp::DashboardDelete {
            expected_revision: 3,
        },
    )?;
    pair.pump();
    assert_eq!(list(&mut pair)?["rows"], json!([]));
    Ok(())
}

#[tokio::test]
async fn idle_pre_dashboard_receiver_discovers_existing_boards_on_upgrade() -> Result<()> {
    for saved_codec in [true, false] {
        discover_after_dashboard_upgrade(saved_codec).await?;
    }
    Ok(())
}

async fn discover_after_dashboard_upgrade(saved_codec: bool) -> Result<()> {
    let mut pair = Pair::new().await;
    directory_push_tests::negotiate(&mut pair);
    for store in &pair.stores {
        store.db.execute("UPDATE wire_peers SET version=8", [])?;
        store
            .db
            .execute("UPDATE node_presence SET next_probe_at=?1", [now() - 1])?;
    }
    pair.agent(
        0,
        AgentOp::DashboardDefine {
            expected_revision: 0,
            board: serde_json::from_value(json!({"title":"Run","widgets":[
            {"id":"link","kind":"link","label":"Guide","value":"https://example.org/"}]}))?,
        },
    )?;
    assert!(
        !pair.stores[0]
            .db
            .prepare("SELECT 1 FROM dashboard_sent")?
            .exists([])?
    );
    pair.stores[1].db.execute_batch(
        "DROP TABLE dashboards; DROP TABLE dashboard_sent;
        DROP TABLE hosted_dashboard_gates;",
    )?;
    if !saved_codec {
        pair.stores[1].db.execute("DELETE FROM wire_peers", [])?;
    }
    pair.reopen(1);
    assert!(pair.stores[1].presence_tick()?);
    pair.pump();
    pair.stores[1]
        .db
        .execute("UPDATE node_presence SET next_probe_at=?1", [now() - 1])?;
    pair.stores[1].presence_tick()?;
    pair.pump();
    let rows = pair.owner(1, OwnerOp::Dashboards { after: None })?;
    assert_eq!(rows["rows"][0]["revision"], 1);
    assert_eq!(rows["rows"][0]["board"]["widgets"][0]["kind"], "link");
    // Publication itself may request one ordinary reachability check.
    for store in &mut pair.stores {
        store
            .db
            .execute("UPDATE node_presence SET next_probe_at=?1", [now() - 1])?;
        store.presence_tick()?;
    }
    pair.pump();
    for store in &mut pair.stores {
        store
            .db
            .execute("UPDATE node_presence SET next_probe_at=?1", [now() - 1])?;
        assert!(!store.presence_tick()?);
    }
    Ok(())
}

#[tokio::test]
async fn babysitter_deduplicates_resume_across_restart_and_queues_one_account_event() {
    use gent_protocol::notifications::{Failure, Scope};
    let mut pair = Pair::new().await;
    let clock = now();
    let goal = "a".repeat(64);
    let claim = |turn| AgentOp::BabysitterClaim {
        goal: goal.clone(),
        turn,
        failed_at: clock,
        reason: Failure::Capacity,
    };
    let first = claim(Uuid::new_v4());
    let attempt: Uuid =
        serde_json::from_value(pair.agent(0, first.clone()).unwrap()["claim"].clone()).unwrap();
    pair.reopen(0);
    assert!(pair.agent(0, first.clone()).unwrap()["claim"].is_null());
    assert_eq!(
        pair.agent(0, AgentOp::BabysitterCheck { attempt }).unwrap()["eligible"],
        true
    );
    let finish = AgentOp::BabysitterSubmitted {
        attempt,
        scope: Some(Scope {
            account: "a".into(),
            origin: "https://example.test".into(),
        }),
    };
    assert!(pair.agent(1, finish.clone()).is_err());
    for _ in 0..2 {
        pair.agent(0, finish.clone()).unwrap();
    }
    let pending = |account: &str| OwnerOp::NotificationPending {
        scope: Scope {
            account: account.into(),
            origin: "https://example.test/".into(),
        },
    };
    assert_eq!(pair.owner(0, pending("other")).unwrap(), json!([]));
    let out = pair.owner(0, pending("a")).unwrap();
    assert_eq!(out.as_array().unwrap().len(), 1);
    assert_eq!(out[0]["event"]["chat"], pair.agents[0]);
    let second = claim(Uuid::new_v4());
    assert!(pair.agent(0, second.clone()).unwrap()["claim"].is_null());
    let wait: i64 = pair.stores[0]
        .db
        .query_row("SELECT delay FROM babysitter_attempts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(wait, 15);
    pair.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(false),
        },
    )
    .unwrap();
    assert!(pair.agent(0, claim(Uuid::new_v4())).unwrap()["claim"].is_null());
    pair.agent(
        0,
        AgentOp::Babysit {
            enabled: Some(true),
        },
    )
    .unwrap();
    assert!(pair.agent(0, second).unwrap()["claim"].is_null());
}

#[tokio::test]
async fn babysitter_recovers_fifteen_failures_in_one_goal_across_a_day() {
    use gent_protocol::notifications::{Failure, Scope};

    let mut pair = Pair::new().await;
    let start = now() + 60;
    let scope = Scope {
        account: "training".into(),
        origin: "https://example.test/".into(),
    };
    let advance = |pair: &mut Pair, time: i64| {
        pair.stores[0]
            .db
            .execute("UPDATE request_clock SET floor=?1", [time])
            .unwrap();
    };
    for incident in 0..5 {
        let mut failed_at = start + incident * 4 * 3600;
        for (reason, delay) in [
            (Failure::Capacity, 0),
            (Failure::Connection, 15),
            (Failure::ToolSchema, 30),
        ] {
            let claim = AgentOp::BabysitterClaim {
                goal: "b".repeat(64),
                turn: Uuid::new_v4(),
                failed_at,
                reason,
            };
            advance(&mut pair, failed_at);
            if delay > 0 {
                assert!(pair.agent(0, claim.clone()).unwrap()["claim"].is_null());
                // A daemon restart during backoff must preserve the deadline.
                pair.reopen(0);
                advance(&mut pair, failed_at + delay - 1);
                assert!(pair.agent(0, claim.clone()).unwrap()["claim"].is_null());
                advance(&mut pair, failed_at + delay);
            }
            let result = pair.agent(0, claim.clone()).unwrap();
            let attempt = serde_json::from_value(result["claim"].clone()).unwrap();
            pair.agent(
                0,
                AgentOp::BabysitterSubmitted {
                    attempt,
                    scope: Some(scope.clone()),
                },
            )
            .unwrap();
            assert!(pair.agent(0, claim).unwrap()["claim"].is_null());
            failed_at += delay + 5;
        }
    }
    let events = pair
        .owner(0, OwnerOp::NotificationPending { scope })
        .unwrap();
    assert_eq!(events.as_array().unwrap().len(), 15);
}
