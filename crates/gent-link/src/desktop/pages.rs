//! Requests from the two native frontends travel only on the supervisor's private pipes.
mod dashboard;

use super::login;
use crate::{config_editor, integration::discovery, managed_file::Snapshot, owner, update};
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, Direct};
use gent_protocol::{OwnerOp, directory::Entry};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;

#[derive(Deserialize)]
#[serde(untagged)]
enum PageRequest {
    Dashboard(dashboard::Request),
    Other(Request),
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    About,
    Cluster,
    Permissions,
    Chats,
    Settings,
    Set { key: Preference, enabled: bool },
    Edit,
    Discard,
    Save { text: String, publish: bool },
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Preference {
    Babysitter,
    Login,
    Updates,
    Discovery,
    Direct,
    Udp,
    Helper,
}

fn settings(home: &Path) -> Result<Value> {
    let cfg = crate::node_home::inspect(home)?;
    let transport = cfg.transport()?;
    Ok(json!({
        "paid": gent_daemon::entitlements::paid(home, &cfg),
        "babysitter": !home.join("babysitter-disabled").try_exists()?,
        "login": login::autostarts(home)?,
        "updates": cfg.updates()?.enabled,
        "discovery": cfg.discovery()?.enabled,
        "direct": matches!(transport.direct, Direct::Auto),
        "udp": transport.udp,
        "helper": matches!(transport.helper, Direct::Auto),
    }))
}

async fn set(home: &Path, key: Preference, enabled: bool) -> Result<()> {
    match key {
        Preference::Login => login::set_autostart(home, enabled),
        Preference::Updates => {
            let op = if enabled {
                update::Command::Enable
            } else {
                update::Command::Disable
            };
            update::execute(home, op).await?;
            Ok(())
        }
        Preference::Babysitter => {
            let cfg = crate::node_home::inspect(home)?;
            ensure!(
                gent_daemon::entitlements::paid(home, &cfg),
                "Babysitter requires Gent Pro. See https://gent.link/pricing"
            );
            let marker = Snapshot::read(&home.join("babysitter-disabled"))?;
            if enabled {
                marker.remove()
            } else {
                marker.write("disabled\n")
            }
        }
        Preference::Discovery => discovery::configure(home, enabled),
        Preference::Direct | Preference::Udp | Preference::Helper => {
            config::edit_local(home, |cfg| {
                let mut transport = cfg.transport()?;
                let mode = if enabled { Direct::Auto } else { Direct::Off };
                match key {
                    Preference::Direct => transport.direct = mode,
                    Preference::Udp => transport.udp = enabled,
                    Preference::Helper => transport.helper = mode,
                    _ => unreachable!(),
                }
                cfg.extra
                    .insert("transport".into(), toml::Value::try_from(transport)?);
                Ok(())
            })
        }
    }
}

fn chats(value: Value) -> Result<Value> {
    let mut entries: Vec<Entry> = serde_json::from_value(value)?;
    entries.sort_by_cached_key(|entry| {
        let dates = entry.message_dates;
        (
            !dates.has_gent_messages,
            std::cmp::Reverse(if dates.has_gent_messages {
                dates.last_gent_message_at
            } else {
                dates.last_native_message_at
            }),
            entry.agent.name.to_lowercase(),
            entry.agent.id.clone(),
        )
    });
    let rows: Vec<_> = entries
        .into_iter()
        .map(|entry| {
            let chat = entry.agent;
            let state = if chat.revoked {
                "Revoked"
            } else if entry.retired {
                "Retired"
            } else {
                "Registered"
            };
            json!({
                "name": chat.name,
                "node": entry.node_name.unwrap_or(chat.node_id),
                "provider": chat.provider,
                "state": state,
                "id": chat.id,
            })
        })
        .collect();
    Ok(json!(rows))
}

#[derive(Default)]
pub(super) struct Pages {
    // A private, in-memory edit session. The snapshot detects concurrent CLI or daemon writes.
    draft: Option<(Snapshot, uuid::Uuid)>,
    dashboard: dashboard::Page,
}

impl Pages {
    pub(super) async fn respond(&mut self, home: &Path, line: &str) -> Value {
        let request = match serde_json::from_str::<PageRequest>(line) {
            Ok(PageRequest::Dashboard(request)) => {
                let mut reply = self.dashboard.respond(home, request).await;
                reply["page"] = json!("dashboard");
                return reply;
            }
            Ok(PageRequest::Other(request)) => request,
            Err(_) => return json!({"page":"settings","error":"Invalid desktop request"}),
        };
        let page = match request {
            Request::About => "about",
            Request::Cluster => "cluster",
            Request::Permissions => "permissions",
            Request::Chats => "chats",
            _ => "settings",
        };
        match self.handle(home, request).await {
            Ok(mut response) => {
                response["page"] = json!(page);
                response
            }
            Err(error) => json!({"page":page,"error":error.to_string()}),
        }
    }

    async fn handle(&mut self, home: &Path, request: Request) -> Result<Value> {
        match request {
            Request::About => Ok(super::admin::about()),
            Request::Cluster => super::admin::cluster(home),
            Request::Permissions => super::admin::permissions(home).await,
            Request::Chats => Ok(
                json!({"rows":chats(owner(home, OwnerOp::Agents).await?)?, "actions":super::admin::directory_actions(true)}),
            ),
            Request::Settings => Ok(json!({"values":settings(home)?})),
            Request::Set { key, enabled } => {
                set(home, key, enabled).await?;
                Ok(json!({"values":settings(home)?}))
            }
            Request::Edit => {
                let file = config_editor::open(home)?;
                let response = json!({"document":file.text});
                self.draft = Some((file, uuid::Uuid::new_v4()));
                Ok(response)
            }
            Request::Discard => {
                self.draft = None;
                Ok(json!({}))
            }
            Request::Save { text, publish } => {
                let (file, id) = self
                    .draft
                    .as_mut()
                    .context("Reopen the configuration editor")?;
                let saved = config_editor::save_text(home, file, &text, || Ok(()))?;
                let changed = saved.is_some();
                if let Some(saved) = saved {
                    *file = saved;
                    *id = uuid::Uuid::new_v4();
                }
                let notice = if publish {
                    file.verify()
                        .context("Configuration changed. Reopen the editor before publishing.")?;
                    ensure!(
                        file.text.as_deref() == Some(&text),
                        "Configuration changed before publication"
                    );
                    let proposed = config_editor::parse(&text)?;
                    let result = crate::publish_config(home, &id.to_string(), proposed).await.with_context(|| {
                        format!("Saved locally. Check gent config request {id} for the publication result.")
                    })?;
                    format!(
                        "Configuration request {} · {}",
                        id,
                        result["state"].as_str().unwrap_or("submitted")
                    )
                } else if changed {
                    "Saved locally".to_owned()
                } else {
                    "No changes to save".to_owned()
                };
                self.draft = None;
                Ok(json!({"saved":true, "notice":notice, "values":settings(home)?}))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn editor_saves_rejects_conflicts_and_retains_invalid_drafts() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "original").unwrap();
        let mut pages = Pages::default();
        let reply = pages.handle(&home, Request::Edit).await.unwrap();
        let original = reply["document"].as_str().unwrap();
        let changed = original.replace("original", "edited");
        assert!(
            pages
                .handle(
                    &home,
                    Request::Save {
                        text: "private-invalid{".into(),
                        publish: false
                    }
                )
                .await
                .is_err()
        );
        assert!(pages.draft.is_some());
        pages
            .handle(
                &home,
                Request::Set {
                    key: Preference::Updates,
                    enabled: false,
                },
            )
            .await
            .unwrap();
        assert!(
            pages
                .handle(
                    &home,
                    Request::Save {
                        text: changed,
                        publish: false
                    }
                )
                .await
                .is_err()
        );
        assert_eq!(config::load(&home).unwrap().cluster.name, "original");
        let reply = pages.handle(&home, Request::Edit).await.unwrap();
        let edited = reply["document"]
            .as_str()
            .unwrap()
            .replace("original", "edited");
        let saved = pages
            .handle(
                &home,
                Request::Save {
                    text: edited,
                    publish: false,
                },
            )
            .await
            .unwrap();
        assert_eq!(saved["saved"], true);
        assert_eq!(config::load(&home).unwrap().cluster.name, "edited");
        assert_eq!(saved["values"]["updates"], false);
    }

    #[test]
    fn chat_order_uses_the_date_for_each_group_and_keeps_unknowns_last() {
        let row = |id, name, gent: Option<i64>, native: Option<i64>| {
            json!({"id":id,"name":name,"node_id":"node","provider":"test","revoked":false,
                "last_seen":9999,"last_activity_at":9999,
                "has_gent_messages":gent.is_some(),"last_gent_message_at":gent,"last_native_message_at":native})
        };
        let mut undated_gent = row("5", "Old Gent", None, Some(900));
        undated_gent["has_gent_messages"] = true.into();
        let rows = chats(json!([
            undated_gent,
            row("9", "Unknown", None, None),
            row("4", "A", None, Some(400)),
            row("3", "Z", Some(30), Some(999)),
            row("2", "beta", Some(35), None),
            row("8", "Recent", None, Some(800)),
            row("1", "Beta", Some(35), Some(100)),
        ]))
        .unwrap();
        let ids: Vec<_> = rows
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["1", "2", "3", "5", "8", "4", "9"]);
    }

    #[test]
    fn chat_inventory_includes_retired_chats() {
        let old = json!({"id":"c","name":"Old","node_id":"remote","provider":"codex","last_seen":1,"revoked":false,"retired":true});
        let chat = &chats(json!([old])).unwrap()[0];
        assert_eq!(chat["state"], "Retired");
        assert_eq!(chat["node"], "remote");
    }
}
