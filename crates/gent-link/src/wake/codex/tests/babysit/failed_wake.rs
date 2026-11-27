//! The normal coordinator and upgraded daemon use the same per-message claim.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn failed_wake_races_preserve_the_pending_message_and_uncertain_submissions() -> Result<()> {
    for case in [
        "only recipient",
        "two senders",
        "lost reply",
        "new head",
        "queue arrived",
        "already seen",
        "opted out",
        "permission revoked",
    ] {
        let node = Node::start().await?;
        let thread = Uuid::now_v7().to_string();
        let target = thread.clone();
        let failed = Uuid::now_v7();
        let starts = Arc::new(AtomicUsize::new(0));
        let started = starts.clone();
        let reads = AtomicUsize::new(0);
        let fixture = Fixture::respond(move |request| {
            if request["method"] != "thread/loaded/list" {
                assert!(
                    request["params"]["threadId"] == target,
                    "inspected an unrelated thread"
                );
            } else {
                assert_eq!(case, "two senders", "catch-up enumerated loaded threads");
            }
            let r = reads.load(Ordering::SeqCst);
            Some(match request["method"].as_str().unwrap() {
                "thread/loaded/list" => json!({"data":[target],"nextCursor":null}),
                "thread/read" => {
                    reads.fetch_add(1, Ordering::SeqCst);
                    json!({"thread":{"id":target,"status":{"type":"systemError"},"canAcceptDirectInput":true}})
                }
                "thread/turns/list" => {
                    if request["params"]["itemsView"] == "full" {
                        return Some(json!({"data":[],"nextCursor":null}));
                    }
                    json!({"data":[{"id":if case=="new head" && r>1 {Uuid::now_v7()}else{failed},
                        "status":"failed","startedAt":100,"completedAt":101,"error":{"message":"capacity","codexErrorInfo":"serverOverloaded"}}]})
                }
                "thread/queue/list" => {
                    if case == "queue arrived" && r > 1 {
                        json!({"data":[{}]})
                    } else {
                        json!({"data":[]})
                    }
                }
                "turn/start" => {
                    started.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request["params"]["input"].as_array().unwrap().len(), 1);
                    assert!(
                        request["params"]["input"][0]["text"]
                            .as_str()
                            .unwrap()
                            .ends_with("\n\nActual fixture notification.")
                    );
                    if case == "lost reply" {
                        return None;
                    }
                    json!({"turn":{"id":Uuid::now_v7()}})
                }
                other => panic!("unexpected {other}"),
            })
        });
        if case != "opted out" {
            scheduler::install(&node, &node.root.path().join("installed"), &fixture.path)?;
        }
        let (_bindings, registry, recipient) = node.register(&fixture.path, &thread).await?;
        let _owner = registry.coordinator()?.unwrap();
        let unrelated = Fixture::respond(|_| panic!("unrelated managed host was contacted"));
        let _other_owner = if case == "only recipient" {
            // Another bound thread shares this endpoint and a separate managed
            // endpoint also has a live wake lease. Neither has pending work.
            node.register(&fixture.path, &Uuid::now_v7().to_string())
                .await?;
            scheduler::install(&node, &node.root.path().join("other"), &unrelated.path)?;
            let (_, registry, _) = node
                .register(&unrelated.path, &Uuid::now_v7().to_string())
                .await?;
            registry.coordinator()?
        } else {
            None
        };
        let mut pending = crate::integration::pending::Pending::default();
        let sender = config::secret();
        agent(
            &node.home,
            &sender,
            AgentOp::Register {
                name: "sender".into(),
                provider: "test".into(),
            },
        )
        .await?;
        let msg = agent(
            &node.home,
            &sender,
            AgentOp::Send {
                recipient,
                request_id: Uuid::now_v7().to_string(),
                text: "Actual fixture notification.".into(),
                files: vec![],
                file_ids: vec![],
            },
        )
        .await?["message_id"]
            .clone();
        let key = registry.credential(&thread)?.unwrap();
        if case == "already seen" {
            agent(
                &node.home,
                &key,
                AgentOp::Ack {
                    message_id: msg.as_str().unwrap().into(),
                },
            )
            .await?;
        }
        if case == "permission revoked" {
            use gent_protocol::{Effect, Permission, Policy, Rule, Selector};
            crate::owner(
                &node.home,
                gent_protocol::OwnerOp::SetPolicy {
                    policy: Policy {
                        rules: vec![Rule {
                            actor: Selector::All,
                            peer: Selector::All,
                            permission: Permission::Send,
                            effect: Effect::Deny,
                        }],
                        ..Default::default()
                    },
                },
            )
            .await?;
        }
        if case == "two senders" {
            let mut a = None;
            tokio::try_join!(
                sweep(&node.home, &registry, &mut a, Sweep::WakeOnly),
                pending.tick(&node.home)
            )?;
        } else {
            let pass = pending.tick(&node.home).await;
            assert_eq!(pass.is_err(), case == "lost reply");
        }
        pending.tick(&node.home).await?;
        let expected = usize::from(matches!(
            case,
            "only recipient" | "two senders" | "lost reply"
        ));
        assert_eq!(starts.load(Ordering::SeqCst), expected, "{case}");
        assert!(unrelated.requests.lock().unwrap().is_empty());
        let db = rusqlite::Connection::open_with_flags(
            node.home.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let journal: Vec<String> = db
            .prepare(
                "SELECT json_extract(payload,'$.state') FROM wake_dispatches WHERE message_id=?1",
            )?
            .query_map([msg.as_str().unwrap()], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        match case {
            "already seen" | "opted out" | "permission revoked" => assert!(journal.is_empty()),
            "only recipient" | "two senders" => assert_eq!(journal, ["submitted"]),
            _ => assert_eq!(journal, ["uncertain"]),
        }
    }
    Ok(())
}

#[tokio::test]
async fn idle_sockets_and_unrelated_recipients_do_not_trigger_host_probes() -> Result<()> {
    use gent_protocol::{OwnerOp, Response};
    use std::collections::BTreeMap;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut node = Node::start().await?;
    let host = Fixture::respond(|_| panic!("catch-up contacted an unowned endpoint"));
    let other = Fixture::respond(|_| panic!("catch-up contacted an unrelated endpoint"));
    scheduler::install(&node, &node.root.path().join("first"), &host.path)?;
    scheduler::install(&node, &node.root.path().join("second"), &other.path)?;
    let mut tags = BTreeMap::new();
    // Nine eligible recipients exceed one tick's work budget.
    for _ in 0..9 {
        let thread = Uuid::now_v7().to_string();
        let (_binding, reg, id) = node.register(&host.path, &thread).await?;
        let key = reg.credential(&thread)?.unwrap();
        use sha2::{Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(key));
        tags.insert(id, gent_daemon::store::wake_binding_tag(&hash));
    }
    node.register(&other.path, &Uuid::now_v7().to_string())
        .await?;
    // Stand in for the *local owner socket*, checking every request and cursor.
    node.stop.cancel();
    (&mut node.daemon).await??;
    let listener = UnixListener::bind(node.home.join("daemon.sock"))?;
    let page_end = Uuid::from_u128(128).to_string();
    let ids: Vec<_> = tags.keys().cloned().collect();
    let pages = vec![
        (None, json!({"agents":[],"next":null})),
        (None, json!({"agents":[],"next":null})),
        (
            None,
            json!({"agents":(1..=128).map(|n| Uuid::from_u128(n).to_string()).collect::<Vec<_>>(),
                     "next":page_end,"binding_tags":{}}),
        ),
        (
            Some(page_end),
            json!({"agents":ids,"next":null,"binding_tags":tags}),
        ),
        (
            Some(ids[7].clone()),
            json!({"agents":[ids[8]],"next":null,"binding_tags":tags}),
        ),
        (None, json!({"agents":[],"next":null})),
    ];
    let replies = tokio::spawn(async move {
        for (expected, page) in pages {
            let (socket, _) = listener.accept().await?;
            let mut socket = BufReader::new(socket);
            let mut line = Vec::new();
            socket.read_until(b'\n', &mut line).await?;
            let Request::Owner {
                action: OwnerOp::WakePendingAgents { after },
                ..
            } = serde_json::from_slice(&line)?
            else {
                anyhow::bail!("unrelated owner or agent operation")
            };
            ensure!(after == expected, "incorrect pending-recipient cursor");
            let mut reply = serde_json::to_vec(&Response::Ok(page))?;
            reply.push(b'\n');
            socket.get_mut().write_all(&reply).await?;
        }
        Ok::<_, anyhow::Error>(())
    });
    let count_leases = || -> Result<usize> {
        let mut count = 0;
        for scope in std::fs::read_dir(node.home.join("host-bindings"))? {
            for file in std::fs::read_dir(scope?.path())? {
                count += usize::from(file?.file_name().as_encoded_bytes().starts_with(b"wake-"));
            }
        }
        Ok(count)
    };
    let mut pending = crate::integration::pending::Pending::default();
    for expected_leases in [0, 0, 0, 1, 1, 1] {
        pending.tick(&node.home).await?;
        assert_eq!(count_leases()?, expected_leases);
    }
    replies.await??;
    assert!(host.requests.lock().unwrap().is_empty());
    assert!(other.requests.lock().unwrap().is_empty());
    Ok(())
}
