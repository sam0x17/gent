//! Owner-enabled cold recovery, separate from the loaded-thread queue adapter.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Readiness {
    Loaded,
    IdleHistory,
    NeedsOwner,
}

async fn readiness(host: &mut Host, thread: &str) -> Result<Readiness> {
    let value = host
        .rpc(
            "thread/read",
            json!({"threadId":thread,"includeTurns":false}),
        )
        .await?;
    let metadata = &value["thread"];
    ensure!(metadata["id"] == thread, "Codex returned another thread");
    match metadata["status"]["type"].as_str() {
        Some("idle" | "active") if metadata["canAcceptDirectInput"] == true => {
            return Ok(Readiness::Loaded);
        }
        Some("notLoaded") => {}
        _ => return Ok(Readiness::NeedsOwner),
    }
    let turns = host
        .rpc(
            "thread/turns/list",
            json!({"threadId":thread,
        "sortDirection":"desc","limit":1,"itemsView":"summary"}),
        )
        .await?;
    let turns = turns["data"]
        .as_array()
        .context("invalid Codex turn history")?;
    ensure!(
        turns.len() <= 1,
        "Codex exceeded the requested history limit"
    );
    if turns.len() != 1 || turns[0]["status"] != "completed" || turns[0]["error"] != Value::Null {
        return Ok(Readiness::NeedsOwner);
    }
    let queued = host
        .rpc("thread/queue/list", json!({"threadId":thread}))
        .await?;
    let queued = queued["data"].as_array().context("invalid Codex queue")?;
    Ok(if queued.is_empty() {
        Readiness::IdleHistory
    } else {
        Readiness::NeedsOwner
    })
}

pub(crate) async fn inspect(socket: &Path, thread: &str) -> Result<Readiness> {
    ensure!(
        crate::integration::wake::valid_thread(thread),
        "invalid Codex thread ID"
    );
    readiness(&mut Host::connect(socket).await?, thread).await
}

pub(crate) async fn restore(socket: &Path, thread: &str) -> Result<&'static str> {
    ensure!(
        crate::integration::wake::valid_thread(thread),
        "invalid Codex thread ID"
    );
    let mut host = Host::connect(socket).await?;
    match readiness(&mut host, thread).await? {
        Readiness::Loaded => return Ok("already_loaded"),
        Readiness::NeedsOwner => return Ok("needs_owner"),
        Readiness::IdleHistory => {}
    }
    // Native resume preserves saved settings. Never supply overrides, input,
    // queue-start, interruption or a replacement history/path.
    let value = host
        .rpc(
            "thread/resume",
            json!({"threadId":thread,"excludeTurns":true}),
        )
        .await?;
    ensure!(
        value["thread"]["id"] == thread
            && value["thread"]["canAcceptDirectInput"] == true
            && matches!(
                value["thread"]["status"]["type"].as_str(),
                Some("idle" | "active")
            ),
        "Codex did not restore the selected conversation"
    );
    Ok("resumed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[tokio::test]
    async fn only_completed_unloaded_empty_queue_conversations_resume_without_overrides() {
        for case in [
            "eligible",
            "loaded",
            "interrupted",
            "inProgress",
            "queued",
            "foreign",
            "bad_queue",
            "bad_resume",
        ] {
            let root = tempfile::tempdir_in("/tmp").unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let socket = root.path().join("host.sock");
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            let thread = uuid::Uuid::new_v4().to_string();
            let expected = thread.clone();
            let task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = tokio_tungstenite::accept_async(stream).await.unwrap();
                let mut calls = Vec::new();
                while let Some(Ok(Message::Text(text))) = stream.next().await {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    let method = value["method"].as_str().unwrap();
                    if method == "initialized" {
                        continue;
                    }
                    let result = match method {
                        "initialize" => json!({}),
                        "thread/read" => {
                            json!({"thread":{"id":if case == "foreign" {"foreign"} else {&expected},
                            "status":{"type":if case == "loaded" {"active"} else {"notLoaded"}},
                            "canAcceptDirectInput":case == "loaded"}})
                        }
                        "thread/turns/list" => {
                            assert_eq!(
                                value["params"],
                                json!({"threadId":expected,"limit":1,"sortDirection":"desc","itemsView":"summary"})
                            );
                            json!({"data":[{"status":if matches!(case,"interrupted"|"inProgress") {case} else {"completed"},"error":null}]})
                        }
                        "thread/queue/list" => match case {
                            "bad_queue" => json!({"data":"invalid"}),
                            "queued" => json!({"data":[{}]}),
                            _ => json!({"data":[]}),
                        },
                        "thread/resume" => {
                            assert_eq!(
                                value["params"],
                                json!({"threadId":expected,"excludeTurns":true})
                            );
                            json!({"thread":{"id":if case=="bad_resume" {"foreign"} else {&expected},
                                "status":{"type":"idle"},"canAcceptDirectInput":true}})
                        }
                        _ => panic!("unexpected method {method}"),
                    };
                    calls.push(method.to_string());
                    stream
                        .send(Message::Text(
                            json!({"id":value["id"],"result":result}).to_string().into(),
                        ))
                        .await
                        .unwrap();
                }
                calls
            });
            let result = restore(&socket, &thread).await;
            match case {
                "eligible" => assert_eq!(result.unwrap(), "resumed"),
                "loaded" => assert_eq!(result.unwrap(), "already_loaded"),
                "interrupted" | "inProgress" | "queued" => {
                    assert_eq!(result.unwrap(), "needs_owner")
                }
                _ => assert!(result.is_err()),
            }
            let calls = task.await.unwrap();
            assert_eq!(
                calls.iter().filter(|m| *m == "thread/resume").count(),
                usize::from(matches!(case, "eligible" | "bad_resume"))
            );
        }
    }
}
