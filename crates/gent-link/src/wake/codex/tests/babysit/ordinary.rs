use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn late_command_requires_a_scoped_native_completion() {
    use crate::wake::codex::babysit::rollout::completed_command;
    let thread = Uuid::now_v7().to_string();
    let turn = Uuid::now_v7();
    let receipt = json!({"type":"event_msg","payload":{"type":"item_completed",
        "thread_id":thread,"turn_id":turn,"started_at_ms":1000,"completed_at_ms":1200,
        "item":{"type":"CommandExecution","id":"call","status":"completed"}}});
    let accepts = |row: &Value| completed_command(&serde_json::to_vec(row).unwrap(), &thread, turn);
    assert!(accepts(&receipt));
    for (field, replacement) in [
        ("/type", json!("response_item")),
        ("/payload/type", json!("item_started")),
        ("/payload/thread_id", json!(Uuid::now_v7())),
        ("/payload/turn_id", json!(Uuid::now_v7())),
        ("/payload/item/type", json!("UserMessage")),
        ("/payload/item/id", json!("")),
        ("/payload/item/status", json!("in_progress")),
    ] {
        let mut other = receipt.clone();
        *other.pointer_mut(field).unwrap() = replacement;
        assert!(!accepts(&other), "{field}");
    }
    let mut other = receipt.clone();
    other["payload"]["item"]["internal_chat_message_metadata_passthrough"] =
        json!({"turn_id":turn});
    assert!(!accepts(&other));
    let mut unknown = receipt;
    unknown["payload"]["future_field"] = json!(1);
    assert!(!accepts(&unknown));
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Change {
    LostReply,
    PausedGoal,
    CompletedGoal,
    ChangedCompletedGoal,
    CompletedDuringRoot,
    MissingGoal,
    StaleTurn,
    Interrupted,
    NewUserTurn,
    Queue,
    Active,
    WrongThread,
    Detached,
    Unbound,
    SpoofedError,
    GoalTrigger,
    LaterInputInRollout,
    SecondInputInTurn,
    LongOperator,
    SupersededRollout,
    ComposerCommandDuringCheck,
    ComposerCarryOnDuringCheck,
    ComposerAgent,
    ComposerDuplicateItem,
    ComposerUnidentifiedSteer,
}

#[tokio::test]
async fn ordinary_sweeps_refuse_changed_or_unproven_input_and_burn_ambiguous_claims() -> Result<()>
{
    use Change::*;
    let mut node = Node::start().await?;
    config::write_private(&node.home.join("babysitter-disabled"), b"")?;
    config::set_ordinary_babysitter_enabled(&node.home, true)?;
    for change in [
        PausedGoal,
        CompletedGoal,
        ChangedCompletedGoal,
        CompletedDuringRoot,
        MissingGoal,
        StaleTurn,
        Interrupted,
        NewUserTurn,
        Queue,
        Active,
        WrongThread,
        Detached,
        Unbound,
        SpoofedError,
        GoalTrigger,
        LaterInputInRollout,
        SecondInputInTurn,
        LongOperator,
        SupersededRollout,
        ComposerCommandDuringCheck,
        ComposerCarryOnDuringCheck,
        ComposerAgent,
        ComposerDuplicateItem,
        ComposerUnidentifiedSteer,
        LostReply,
    ] {
        let thread = Uuid::now_v7();
        let turn = Uuid::now_v7();
        let now = gent_daemon::store::now();
        let ended = if change == StaleTurn { now - 601 } else { now };
        let started = if change == LongOperator {
            now - 7200
        } else {
            ended - 2
        };
        let path = node.home.join(format!("rollout-fixture-{thread}.jsonl"));
        let envelope = |p: Value| json!({"type":"event_msg","payload":p});
        let composer = matches!(
            change,
            ComposerCommandDuringCheck
                | ComposerCarryOnDuringCheck
                | ComposerAgent
                | ComposerDuplicateItem
                | ComposerUnidentifiedSteer
        );
        let input = envelope(
            json!({"type":"item_completed","thread_id":thread,"turn_id":turn,"item":{"type":"UserMessage","id":"one","client_id":"first"}}),
        );
        let mut rows = vec![
            json!({"type":"session_meta","payload":{"id":thread}}),
            envelope(
                json!({"type":"task_started","turn_id":turn,"started_at":started,
                "turn_attribution":{"turn_id":turn,"root_turn_id":turn,"turn_trigger":if composer {"composer"} else if change==GoalTrigger {"goal"} else {"user"}}}),
            ),
            input.clone(),
        ];
        if change == SecondInputInTurn {
            rows.push(input.clone());
        }
        if composer {
            let mut steer = input.clone();
            steer["payload"]["item"] =
                json!({"type":"UserMessage","id":"two","client_id":"second"});
            match change {
                ComposerDuplicateItem => steer["payload"]["item"]["id"] = json!("one"),
                ComposerUnidentifiedSteer => steer["payload"]["item"]["client_id"] = Value::Null,
                ComposerAgent => {
                    rows[1]["payload"]["turn_attribution"]["initiating_agent_path"] = json!("agent")
                }
                _ => {}
            }
            rows.push(steer);
        }
        rows.push(envelope(json!({"type":"task_complete","turn_id":turn,"started_at":started,"completed_at":ended,"error":{"message":"Model at capacity"}})));
        if change == LaterInputInRollout {
            rows.push(input);
        }
        let contents = rows
            .iter()
            .map(|r| r.to_string() + "\n")
            .collect::<String>();
        config::write_private(&path, contents.as_bytes())?;
        let reads = AtomicUsize::new(0);
        let host = Fixture::respond(move |r| {
            let reread = reads.load(Ordering::Relaxed) > 1;
            match r["method"].as_str().unwrap() {
                "thread/loaded/list" => Some(json!({"data":[thread],"nextCursor":null})),
                "thread/read" => {
                    let racing = reads.fetch_add(1, Ordering::Relaxed) > 0;
                    Some(
                        json!({"thread":{"id":if racing && change==WrongThread {Uuid::now_v7()} else {thread},
                        "path":path,"status":{"type":if racing && change==Active {"active"} else {"idle"}},
                        "canAcceptDirectInput":!(racing && change==Detached)}}),
                    )
                }
                "thread/goal/get" => Some(match (reread, change) {
                    (true, PausedGoal) => json!({"goal":{"status":"paused"}}),
                    (true, CompletedGoal)
                    | (_, ChangedCompletedGoal | CompletedDuringRoot | GoalTrigger) => {
                        json!({"goal":{"status":"complete","threadId":thread,"objective":
                            if reread && change==ChangedCompletedGoal { "different" } else { "finished fixture" },
                            "createdAt":started-60,"updatedAt":if change==CompletedDuringRoot {started} else {started-5},
                            "tokensUsed":0,"timeUsedSeconds":0,"tokenBudget":null}})
                    }
                    (_, MissingGoal) => json!({}),
                    _ => json!({"goal":null}),
                }),
                "thread/turns/list" => Some(json!({"data":[{
                    "id":if reread && change==NewUserTurn {Uuid::now_v7()} else {turn},
                    "rootTurnId":turn,"startedAt":started,"completedAt":ended,"itemsView":"notLoaded",
                    "status":if reread && change==Interrupted {"interrupted"} else {"failed"},
                    "error":if change==SpoofedError {json!({"message":"unknown","codexErrorInfo":"other"})}
                        else {json!({"message":"Model at capacity","codexErrorInfo":"serverOverloaded"})},
                    "items":[{"type":"userMessage","content":[{"type":"text","text":"model at capacity"}]}]
                }]})),
                "thread/queue/list" => {
                    if reread && change == SupersededRollout {
                        config::write_private(&path, b"changed\n").unwrap();
                    }
                    if reads.load(Ordering::Relaxed) == 2 && composer {
                        use std::io::Write;
                        let mut file = std::fs::OpenOptions::new()
                            .append(true)
                            .open(&path)
                            .unwrap();
                        writeln!(
                            file,
                            "{}",
                            json!({"type":"event_msg","payload":{
                            "type":"item_completed","thread_id":thread,"turn_id":turn,
                            "item":{"type":"CommandExecution","id":"late","status":"completed"}}})
                        )
                        .unwrap();
                        if change == ComposerCarryOnDuringCheck {
                            writeln!(
                                file,
                                "{}",
                                json!({"type":"event_msg","payload":{
                                "type":"thread_settings_applied","thread_id":thread}})
                            )
                            .unwrap();
                        }
                    }
                    Some(
                        json!({"data":if reread && change==Queue {json!([{"id":"pending"}])} else {json!([])},"nextCursor":null}),
                    )
                }
                "turn/start" => {
                    assert!(matches!(
                        change,
                        LongOperator | LostReply | ComposerCommandDuringCheck
                    ));
                    assert_eq!(
                        r["params"]["input"],
                        json!([{"type":"text","text":"please continue"}])
                    );
                    assert_eq!(r["params"]["parentTurnId"], turn.to_string());
                    matches!(change, LongOperator | ComposerCommandDuringCheck)
                        .then(|| json!({"turn":{"id":Uuid::now_v7(),"rootTurnId":turn}}))
                }
                other => panic!("unexpected host operation {other}"),
            }
        });
        let bound = if change == Unbound {
            Uuid::now_v7()
        } else {
            thread
        };
        let (_, registry, registered) = node.register(&host.path, &bound.to_string()).await?;
        let first = sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await;
        if change == LostReply {
            assert!(first.is_err());
            node.stop.cancel();
            (&mut node.daemon).await??;
            node.stop = tokio_util::sync::CancellationToken::new();
            node.daemon = tokio::spawn(gent_daemon::run_locked_until(
                gent_daemon::DaemonLock::acquire(&node.home)?,
                node.stop.clone().cancelled_owned(),
            ));
            tokio::time::timeout(Duration::from_secs(5), async {
                while !node.home.join("daemon.sock").exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await?;
            sweep(&node.home, &registry, &mut None, Sweep::GoalsOnly).await?;
        } else {
            first?;
        }
        let starts = host
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "turn/start")
            .count();
        assert_eq!(
            starts,
            usize::from(matches!(
                change,
                LongOperator | LostReply | ComposerCommandDuringCheck
            )),
            "{change:?}"
        );
        assert_eq!(node.notices(&registered).await?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn ordinary_opt_in_keeps_an_active_goal_on_its_native_recovery_path() -> Result<()> {
    let node = Node::start().await?;
    config::set_ordinary_babysitter_enabled(&node.home, true)?;
    let thread = Uuid::now_v7().to_string();
    let mut state = Read::new(&thread);
    state.meta["path"] = json!(node.home.join(format!("rollout-fixture-{thread}.jsonl")));
    let observed = exercise(&node, state.clone(), state, false, 2).await?;
    assert_eq!(observed.resumes, 1);
    assert_eq!(observed.notices, 1);
    Ok(())
}
