//! The selector shows this node's accepted cluster policy. A request receipt
//! describes the edit independently of policy propagation or binary activation.
use crate::{
    configure,
    managed_file::{self, Snapshot},
    node_home, owner,
};
use anyhow::{Context, Result, ensure};
use gent_protocol::{ConfigurationEdit, OwnerOp, ReleaseChannel};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub(super) enum Request {
    #[serde(rename = "release_channel")]
    Read,
    #[serde(rename = "set_release_channel")]
    Set { channel: ReleaseChannel },
    #[serde(rename = "retry_release_channel")]
    Retry,
}

#[derive(Serialize, Deserialize)]
struct Intent {
    request_id: Uuid,
    channel: ReleaseChannel,
}

impl Intent {
    async fn lookup(&self, home: &Path) -> Result<Value> {
        owner(
            home,
            OwnerOp::ConfigurationRequests {
                request_id: Some(self.request_id.to_string()),
            },
        )
        .await
    }
}

#[derive(Default, Serialize)]
struct View {
    current: Option<ReleaseChannel>,
    can_set: bool,
    pending: bool,
    retry: bool,
    notice: String,
    #[serde(skip)]
    revision: Option<u64>,
    #[serde(skip)]
    online: bool,
}

impl View {
    async fn read(home: &Path) -> Self {
        let Ok(status) = owner(home, OwnerOp::Status).await else {
            // A new home has no accepted authority, even if the installer's default is stable.
            let current = home
                .join("state.sqlite3")
                .is_file()
                .then(|| gent_daemon::release_channel::current(home).ok())
                .flatten();
            return Self {
                current,
                notice: if current.is_some() {
                    "Last verified channel on this node. Reconnect to the daemon to change it."
                } else {
                    "Cluster channel unavailable. Connect this node to the cluster daemon."
                }
                .into(),
                ..Self::default()
            };
        };
        let current = status["release_channel"]
            .as_str()
            .and_then(|s| s.parse().ok());
        let can_set = current.is_some() && status["can_set_release_channel"] == true;
        let notice = if current.is_none() {
            "The daemon did not report a release channel."
        } else if !can_set {
            "This node can view the cluster channel. Changing it requires configuration permission."
        } else {
            "Showing the last verified cluster selection."
        };
        Self {
            current,
            can_set,
            notice: notice.into(),
            revision: status["authority"]["revision"].as_u64(),
            online: true,
            ..Self::default()
        }
    }

    fn receipt(&mut self, intent: &Intent, result: Option<Value>) -> bool {
        let id = intent.request_id.to_string();
        let channel = intent.channel;
        let status = result.filter(|s| s["request_id"] == id && s["channel"] == channel.as_str());
        let state = status.as_ref().and_then(|s| s["state"].as_str());
        match state {
            Some("queued") => {
                self.notice =
                    format!("Requested {channel} · queued. Waiting for a cluster decision.");
            }
            Some("applied") => {
                self.notice =
                    format!("Cluster accepted {channel}. Each node applies the switch when ready.");
                if self.current == Some(channel)
                    || self
                        .revision
                        .zip(status.as_ref().and_then(|s| s["revision"].as_u64()))
                        .is_some_and(|(local, accepted)| local >= accepted)
                {
                    return true;
                }
                self.notice
                    .push_str(" Waiting for the signed policy on this node.");
            }
            Some("rejected") => {
                let reason = status
                    .as_ref()
                    .and_then(|s| s["reason"].as_str())
                    .unwrap_or("No reason supplied");
                self.notice = format!("Request for {channel} rejected · {reason}");
                return true;
            }
            _ => {
                self.retry = self.can_set;
                self.notice = format!(
                    "Outcome of the {channel} request is unconfirmed. Check gent config request {id}."
                );
            }
        }
        self.pending = true;
        self.can_set = false;
        false
    }
}

impl Request {
    async fn run(self, home: &Path) -> Result<View> {
        let cfg = node_home::inspect(home)
            .context("Open Settings on an enrolled node to select a cluster channel.")?;
        let path = home.join(format!(
            "desktop-channel-{}-{}.json",
            cfg.cluster.id, cfg.node.id
        ));
        let record = Snapshot::read(&path)?;
        record.private()?;
        let saved: Option<Intent> = record
            .text
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("Cannot read the saved Desktop channel request.")?;
        let mut view = View::read(home).await;
        if let Some(intent) = &saved {
            let result = if view.online {
                intent.lookup(home).await.ok()
            } else {
                None
            };
            if view.receipt(intent, result) {
                let _lock = managed_file::lock(&path.with_extension("lock"))?;
                record.remove()?;
            }
        }
        let intent = match self {
            Self::Set { channel } if view.can_set && view.current != Some(channel) => {
                let intent = Intent {
                    request_id: Uuid::new_v4(),
                    channel,
                };
                // Persist before submission so a restart or lost reply preserves retry identity.
                let _lock = managed_file::lock(&path.with_extension("lock"))?;
                let record = Snapshot::read(&path)?;
                ensure!(
                    record.text.is_none(),
                    "Another channel request is in progress."
                );
                record.write(&serde_json::to_string(&intent)?)?;
                intent
            }
            Self::Retry if view.retry => saved.context("Missing channel request.")?,
            _ => return Ok(view),
        };

        let record = Snapshot::read(&path)?;
        ensure!(
            record.text.as_deref() == Some(&serde_json::to_string(&intent)?),
            "The saved channel request changed."
        );
        let result = configure(
            home,
            &intent.request_id.to_string(),
            ConfigurationEdit::SetReleaseChannel {
                channel: intent.channel,
            },
        )
        .await;
        view = View::read(home).await;
        // configure converts a durable rejection into an error. Recover the
        // receipt by the same ID, including after a lost submission response.
        let receipt = match result.as_ref() {
            Ok(status) => Some(status.clone()),
            Err(_) if view.online => intent.lookup(home).await.ok(),
            Err(_) => None,
        };
        let missing = receipt.is_none();
        if view.receipt(&intent, receipt) {
            let _lock = managed_file::lock(&path.with_extension("lock"))?;
            record.remove()?;
        } else if missing && let Err(error) = result {
            view.notice = format!("{error}. {}", view.notice);
        }
        Ok(view)
    }

    pub(super) async fn respond(self, home: &Path) -> Value {
        let mut reply = match self.run(home).await {
            Ok(view) => json!(view),
            Err(error) => json!({"notice":error.to_string()}),
        };
        reply["page"] = json!("release_channel");
        reply
    }
}

#[cfg(test)]
mod tests;
