use super::*;
use gent_protocol::{
    ReleaseChannel::{Beta, Stable},
    Response,
};
use std::sync::{Arc, Mutex};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};

struct Daemon {
    current: ReleaseChannel,
    can_set: bool,
    edits: Vec<(String, ReleaseChannel)>,
    receipt: Option<&'static str>,
}

impl Daemon {
    fn respond(&mut self, action: OwnerOp) -> Option<Response> {
        let status = |id: &str, channel: ReleaseChannel, state: &str| {
            json!({
                "state":state, "applied":state=="applied", "request_id":id, "channel":channel,
                "revision":12, "reason":"Fixture permission withdrawn",
            })
        };
        let value = match action {
            OwnerOp::Status => {
                json!({"release_channel": self.current, "can_set_release_channel":self.can_set,
                "authority":{"revision": if self.current == Stable { 11 } else { 12 }}})
            }
            OwnerOp::Configure {
                request_id,
                edit: ConfigurationEdit::SetReleaseChannel { channel },
            } => {
                self.edits.push((request_id.clone(), channel));
                // Drop the first submission response. The second attempt has a durable receipt.
                if self.edits.len() == 1 {
                    return None;
                }
                status(&request_id, channel, self.receipt.unwrap_or("queued"))
            }
            OwnerOp::ConfigurationRequests {
                request_id: Some(id),
            } => {
                let (request, channel) = self.edits.last().unwrap();
                assert_eq!(&id, request);
                let Some(state) = self.receipt else {
                    return Some(Response::Error("unknown configuration request".into()));
                };
                status(&id, *channel, state)
            }
            _ => panic!("unexpected channel RPC"),
        };
        Some(Response::Ok(value))
    }
}

#[tokio::test]
async fn desktop_recovers_a_lost_reply_reuses_the_intent_and_waits_for_signed_state() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    let cfg = gent_daemon::config::initialize(&home, "fixture").unwrap();
    let listener = UnixListener::bind(home.join("daemon.sock")).unwrap();
    let state = Arc::new(Mutex::new(Daemon {
        current: Stable,
        can_set: false,
        edits: Vec::new(),
        receipt: None,
    }));
    let daemon = state.clone();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let gent_protocol::Request::Owner { action, .. } = serde_json::from_str(&line).unwrap()
            else {
                panic!("expected owner operation");
            };
            let response = daemon.lock().unwrap().respond(action);
            if let Some(response) = response {
                let bytes = format!("{}\n", serde_json::to_string(&response).unwrap());
                reader.get_mut().write_all(bytes.as_bytes()).await.unwrap();
            }
        }
    });
    let read = || Request::Read.respond(&home);
    let choose_beta = || Request::Set { channel: Beta }.respond(&home);
    let member = choose_beta().await;
    assert_eq!(member["current"], "stable");
    assert_eq!(member["can_set"], false);
    assert!(state.lock().unwrap().edits.is_empty());
    state.lock().unwrap().can_set = true;

    let lost = choose_beta().await;
    assert_eq!(lost["current"], "stable");
    assert_eq!(lost["retry"], true);
    let record = home.join(format!(
        "desktop-channel-{}-{}.json",
        cfg.cluster.id, cfg.node.id
    ));
    let saved: Intent = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(saved.request_id.get_version_num(), 4);
    assert_eq!(saved.channel, Beta);
    assert_eq!(choose_beta().await["can_set"], false);
    assert_eq!(read().await["retry"], true);
    assert_eq!(state.lock().unwrap().edits.len(), 1);

    let retried = Request::Retry.respond(&home).await;
    assert_eq!(retried["pending"], true);
    assert_eq!(retried["current"], "stable");
    assert!(retried["notice"].as_str().unwrap().contains("queued"));
    let edits = state.lock().unwrap().edits.clone();
    assert_eq!(edits.len(), 2);
    assert_eq!(edits[0], edits[1]);
    assert_eq!(edits[0].0, saved.request_id.to_string());
    state.lock().unwrap().receipt = Some("queued");
    assert_eq!(Request::Retry.respond(&home).await["retry"], false);
    state.lock().unwrap().receipt = Some("applied");
    let lag = read().await;
    assert_eq!(lag["current"], "stable");
    assert_eq!(lag["pending"], true);
    assert!(record.exists());
    state.lock().unwrap().current = Beta;
    let accepted = read().await;
    assert_eq!(accepted["current"], "beta");
    assert_eq!(accepted["pending"], false);
    assert_eq!(accepted["can_set"], true);
    assert!(!record.exists());
    assert_eq!(state.lock().unwrap().edits.len(), 2);

    state.lock().unwrap().receipt = Some("rejected");
    let rejected = Request::Set { channel: Stable }.respond(&home).await;
    assert_eq!(rejected["current"], "beta");
    assert_eq!(rejected["pending"], false);
    assert!(
        rejected["notice"]
            .as_str()
            .unwrap()
            .contains("Fixture permission withdrawn")
    );
    assert!(!record.exists());
    assert_ne!(state.lock().unwrap().edits[2].0, edits[0].0);
    assert_eq!(
        gent_daemon::config::load(&home)
            .unwrap()
            .updates()
            .unwrap()
            .enabled,
        cfg.updates().unwrap().enabled
    );
    server.abort();
}

#[tokio::test]
async fn fresh_settings_do_not_invent_a_cluster_channel_or_submit_an_edit() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("new");
    let view = Request::Set { channel: Beta }.respond(&home).await;
    assert!(view["current"].is_null());
    assert!(!home.exists());
    assert!(
        serde_json::from_str::<Request>(r#"{"op":"set_release_channel","channel":"nightly"}"#)
            .is_err()
    );
}

#[tokio::test]
async fn offline_settings_show_signed_beta_and_disable_changes() {
    use gent_daemon::{config, store::Store};
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    config::initialize(&home, "offline").unwrap();
    assert!(Request::Read.respond(&home).await["current"].is_null());
    let result = Store::open(&home)
        .unwrap()
        .handle(gent_protocol::Request::Owner {
            credential: config::read_private(&home.join("owner.key")).unwrap(),
            action: OwnerOp::Configure {
                request_id: Uuid::new_v4().to_string(),
                edit: ConfigurationEdit::SetReleaseChannel { channel: Beta },
            },
        });
    assert!(matches!(result, Response::Ok(ref v) if v["state"] == "applied"));
    let view = Request::Set { channel: Stable }.respond(&home).await;
    assert_eq!(view["current"], "beta");
    assert_eq!(view["can_set"], false);
    assert_eq!(view["pending"], false);
    assert!(view["notice"].as_str().unwrap().contains("Last verified"));
}
