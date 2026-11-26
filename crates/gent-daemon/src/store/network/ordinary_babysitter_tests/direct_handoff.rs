use super::*;
use gent_protocol::babysitter::{ForegroundInput, ForegroundInputs};

struct Fixture {
    pair: Pair,
    failed: i64,
    item: Uuid,
    proof: ForegroundInputs,
    messages: Vec<String>,
}

impl Fixture {
    async fn new(count: usize) -> Result<Self> {
        let mut pair = Pair::new().await;
        let failed = now();
        let turn = Uuid::now_v7();
        let thread = Uuid::now_v7();
        let mut inputs = Vec::new();
        let mut messages = Vec::new();
        for i in 0..count {
            let message = pair.send(vec![])?["message_id"]
                .as_str()
                .unwrap()
                .to_owned();
            pair.pump();
            let received = failed - 100 + 10 * i as i64;
            let input = ForegroundInput {
                client: Uuid::new_v4(),
                sha256: format!("{i:064x}"),
                received_at_ms: received * 1000,
            };
            let record = json!({"message_id":message,"agent":pair.agents[1],"attempt_id":input.client,
                "target":{"host":"codex","thread_id":thread},"state":"submitted","submission_id":turn,
                "claimed_at":received-1,"updated_at":received+1,"inbox_seen_at":received+1,
                "direct":{"finished":true,"input_hash":input.sha256,"turn_id":turn,"reply_request_id":Uuid::new_v4()}});
            pair.stores[1].db.execute(
                "INSERT INTO wake_dispatches(message_id,agent,attempt_id,claimed_at,payload)
                VALUES(?1,?2,?3,?4,?5)",
                params![
                    message,
                    pair.agents[1],
                    input.client.to_string(),
                    received - 1,
                    record.to_string()
                ],
            )?;
            inputs.push(input);
            messages.push(message);
        }
        Ok(Self {
            pair,
            failed,
            item: Uuid::now_v7(),
            proof: ForegroundInputs {
                thread,
                turn,
                started_at: failed - 110,
                inputs,
            },
            messages,
        })
    }

    fn enable(&self) -> Result<()> {
        config::set_ordinary_babysitter_enabled(self.pair.homes[1].path(), true)
    }

    fn request(&self) -> AgentOp {
        claim(
            self.proof.turn,
            self.failed,
            ChatOrigin::DirectHandoff {
                item: self.item,
                proof: self.proof.clone(),
            },
        )
    }

    fn claim(&mut self) -> Result<Value> {
        self.pair.agent(1, self.request())
    }
}

#[tokio::test]
async fn direct_handoff_matches_every_documented_input_and_only_one_retry() -> Result<()> {
    for count in [1, 3] {
        let mut f = Fixture::new(count).await?;
        assert!(f.claim()?["claim"].is_null());
        f.enable()?;
        let probe = AgentOp::BabysitterChatProbe {
            turn: f.proof.turn,
            operator: f.proof.turn,
            failed_at: f.failed,
        };
        assert_eq!(f.pair.agent(1, probe.clone())?["direct_handoff"], true);
        let original = f.proof.clone();
        for i in 0..count {
            f.proof.inputs[i].sha256 = "f".repeat(64);
            assert!(f.claim()?["claim"].is_null());
            f.proof = original.clone();
            f.proof.inputs.remove(i);
            assert!(f.claim()?["claim"].is_null());
            f.proof = original.clone();
        }
        if count > 1 {
            f.proof.inputs.swap(0, 1);
            assert!(f.claim()?["claim"].is_null());
            f.proof = original.clone();
            f.proof.inputs[1] = f.proof.inputs[0].clone();
            assert!(f.claim()?["claim"].is_null());
            f.proof = original.clone();
        }
        let message = &f.messages[0];
        let db = &f.pair.stores[1].db;
        let saved: String = db.query_row(
            "SELECT payload FROM wake_dispatches WHERE message_id=?1",
            [message],
            |r| r.get(0),
        )?;
        let row: Value = serde_json::from_str(&saved)?;
        for (path, val) in [
            ("/target/thread_id", json!(Uuid::new_v4())),
            ("/submission_id", json!(Uuid::new_v4())),
            ("/direct/turn_id", json!(Uuid::new_v4())),
            ("/direct/finished", json!(false)),
            ("/inbox_seen_at", Value::Null),
            ("/updated_at", json!(f.failed + 1)),
            ("/direct/response_hash", json!("a".repeat(64))),
            ("/direct/response_message_id", json!(Uuid::new_v4())),
            ("/state", json!("uncertain")),
        ] {
            let mut changed = row.clone();
            if path == "/state" {
                changed["submission_id"] = Value::Null;
            }
            let (parent, key) = path.rsplit_once('/').unwrap();
            changed.pointer_mut(parent).unwrap()[key] = val;
            f.pair.stores[1].db.execute(
                "UPDATE wake_dispatches SET payload=?2 WHERE message_id=?1",
                params![f.messages[0], changed.to_string()],
            )?;
            assert!(f.claim()?["claim"].is_null(), "{path}");
        }
        f.pair.stores[1].db.execute(
            "UPDATE wake_dispatches SET payload=?2 WHERE message_id=?1",
            params![f.messages[0], saved],
        )?;
        for kind in ["request", "progress", "complete", "cancel", "cancelled"] {
            f.pair.stores[1].db.execute(
                "UPDATE messages SET payload=json_set(payload,'$.relay.kind',?2) WHERE id=?1",
                params![f.messages[0], kind],
            )?;
            assert!(f.claim()?["claim"].is_null(), "{kind}");
        }
        f.pair.stores[1].db.execute(
            "UPDATE messages SET payload=json_remove(payload,'$.relay') WHERE id=?1",
            [&f.messages[0]],
        )?;
        // Removing the last matching journal before probing must still require the machine proof.
        f.pair.stores[1].db.execute(
            "DELETE FROM wake_dispatches WHERE message_id=?1",
            [&f.messages[0]],
        )?;
        assert_eq!(f.pair.agent(1, probe)?["direct_handoff"], true);
        assert!(f.claim()?["claim"].is_null());
        f.pair.stores[1].db.execute("INSERT INTO wake_dispatches(message_id,agent,attempt_id,claimed_at,payload) VALUES(?1,?2,?3,?4,?5)",
            params![f.messages[0],f.pair.agents[1],f.proof.inputs[0].client.to_string(),row["claimed_at"].as_i64(),saved])?;
        let attempt: Uuid = serde_json::from_value(f.claim()?["claim"].clone())?;
        f.pair.reopen(1);
        assert!(f.claim()?["claim"].is_null());
        let check = AgentOp::BabysitterChatCheck { attempt };
        assert_eq!(
            f.pair.agent(1, check.clone())?,
            json!({"eligible":true,"direct_handoff":true})
        );
        assert_eq!(f.pair.agent(1, check)?["eligible"], false);
        f.pair.stores[1]
            .db
            .execute("UPDATE request_clock SET floor=?1", [f.failed + 61])?;
        assert!(
            f.pair.agent(
                1,
                claim(
                    Uuid::now_v7(),
                    f.failed,
                    ChatOrigin::Continuation { attempt }
                )
            )?["claim"]
                .is_null()
        );
    }
    Ok(())
}

#[tokio::test]
async fn direct_handoff_rechecks_explicit_reply_retirement_and_opt_out() -> Result<()> {
    for change in [
        "prior_reply",
        "new_reply",
        "retired",
        "extra_dispatch",
        "chat_off",
        "node_off",
    ] {
        let mut f = Fixture::new(1).await?;
        f.enable()?;
        let reply = AgentOp::Reply {
            message_id: f.messages[0].clone(),
            request_id: Uuid::now_v7().to_string(),
            text: "handled".into(),
            files: vec![],
            file_ids: vec![],
        };
        if change == "prior_reply" {
            f.pair.agent(1, reply)?;
            assert!(f.claim()?["claim"].is_null());
            continue;
        }
        let attempt = serde_json::from_value(f.claim()?["claim"].clone())?;
        match change {
            "new_reply" => {
                f.pair.agent(1, reply)?;
            }
            "retired" => {
                f.pair.stores[1]
                    .db
                    .execute("DELETE FROM messages WHERE id=?1", [&f.messages[0]])?;
            }
            "extra_dispatch" => {
                f.pair.stores[1].db.execute(
                "INSERT INTO wake_dispatches SELECT ?2,agent,?3,claimed_at,json_set(payload,'$.message_id',?2,'$.attempt_id',?3) FROM wake_dispatches WHERE message_id=?1",
                params![f.messages[0],Uuid::new_v4().to_string(),Uuid::new_v4().to_string()])?;
            }
            "chat_off" => {
                for enabled in [false, true] {
                    f.pair.agent(
                        1,
                        AgentOp::Babysit {
                            enabled: Some(enabled),
                        },
                    )?;
                }
            }
            "node_off" => {
                config::set_ordinary_babysitter_enabled(f.pair.homes[1].path(), false)?;
            }
            _ => unreachable!(),
        }
        assert_eq!(
            f.pair.agent(1, AgentOp::BabysitterChatCheck { attempt })?["eligible"],
            false,
            "{change}"
        );
    }
    Ok(())
}
