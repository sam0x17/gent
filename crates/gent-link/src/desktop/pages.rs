//! Requests from the two native frontends travel only on the supervisor's private pipes.
use super::{charts, login};
use crate::{config_editor, integration::discovery, managed_file::Snapshot, owner, update};
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, Direct};
use gent_protocol::{OwnerOp, directory::Entry};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Dashboard(DashboardLayout),
    DashboardLayout(DashboardLayout),
    DashboardClick {
        agent: String,
        revision: u64,
        widget: String,
    },
    About,
    Cluster,
    Permissions,
    Chats,
    Settings,
    Set {
        key: Preference,
        enabled: bool,
    },
    Edit,
    Discard,
    Save {
        text: String,
        publish: bool,
    },
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct DashboardLayout {
    palette: charts::Palette,
    // Index k-1 is the usable width of one chart when k cards share a row.
    chart_widths: Vec<u16>,
}

impl Default for DashboardLayout {
    fn default() -> Self {
        Self {
            palette: charts::Palette::default(),
            chart_widths: vec![260],
        }
    }
}

impl DashboardLayout {
    fn render(&self, rows: &[Value]) -> Result<Value> {
        ensure!(
            (1..=4).contains(&self.chart_widths.len())
                && self.chart_widths.iter().all(|w| (160..=16384).contains(w)),
            "invalid dashboard chart widths"
        );
        let mut display = rows.to_vec();
        for line in display.chunks_mut(self.chart_widths.len()) {
            let width = usize::from(self.chart_widths[line.len() - 1]);
            for row in line {
                for widget in row["board"]["widgets"]
                    .as_array_mut()
                    .context("invalid dashboard widgets")?
                {
                    charts::decorate(widget, &self.palette, width);
                }
            }
        }
        Ok(json!({"rows":display}))
    }
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
    // The same frontend keeps its last rendered dashboard until its pipe closes.
    dashboard_snapshot: Option<(DashboardLayout, Vec<Value>)>,
}

impl Pages {
    fn dashboard(&mut self, mut rows: Vec<Value>, layout: DashboardLayout) -> Result<Value> {
        rows.sort_by_cached_key(|r| r["chat"].as_str().unwrap_or_default().to_lowercase());
        if self
            .dashboard_snapshot
            .as_ref()
            .is_some_and(|(_, previous_rows)| previous_rows == &rows)
        {
            return self.layout_dashboard(layout);
        }
        let reply = layout.render(&rows)?;
        self.dashboard_snapshot = Some((layout, rows));
        Ok(reply)
    }

    fn layout_dashboard(&mut self, layout: DashboardLayout) -> Result<Value> {
        let Some((previous, rows)) = &mut self.dashboard_snapshot else {
            return Ok(json!({"unchanged":true}));
        };
        if *previous == layout {
            return Ok(json!({"unchanged":true}));
        }
        let reply = layout.render(rows)?;
        *previous = layout;
        Ok(reply)
    }

    pub(super) async fn respond(&mut self, home: &Path, line: &str) -> Value {
        let Ok(request) = serde_json::from_str::<Request>(line) else {
            return json!({"page":"settings","error":"Invalid desktop request"});
        };
        let page = match request {
            Request::Dashboard(_)
            | Request::DashboardLayout(_)
            | Request::DashboardClick { .. } => "dashboard",
            Request::About => "about",
            Request::Cluster => "cluster",
            Request::Permissions => "permissions",
            Request::Chats => "chats",
            _ => "settings",
        };
        let dashboard_locked = || {
            page == "dashboard"
                && !crate::node_home::inspect(home)
                    .is_ok_and(|cfg| gent_daemon::entitlements::paid(home, &cfg))
        };
        if dashboard_locked() {
            return self.lock_dashboard();
        }
        let waits_for_daemon = matches!(
            request,
            Request::Dashboard(_) | Request::DashboardClick { .. }
        );
        let result = self.handle(home, request).await;
        if waits_for_daemon && dashboard_locked() {
            return self.lock_dashboard();
        }
        match result {
            Ok(mut response) => {
                response["page"] = json!(page);
                response
            }
            Err(error) => json!({"page":page,"error":error.to_string()}),
        }
    }

    fn lock_dashboard(&mut self) -> Value {
        self.dashboard_snapshot = None;
        json!({"page":"dashboard","pro_required":true,"rows":[]})
    }

    async fn handle(&mut self, home: &Path, request: Request) -> Result<Value> {
        match request {
            Request::Dashboard(layout) => {
                let mut after = None;
                let mut rows = Vec::new();
                loop {
                    let mut page = owner(
                        home,
                        OwnerOp::Dashboards {
                            after: after.clone(),
                        },
                    )
                    .await?;
                    rows.append(
                        page["rows"]
                            .as_array_mut()
                            .context("invalid dashboard page")?,
                    );
                    let Some(cursor) = page["next"].as_str() else {
                        break;
                    };
                    ensure!(
                        after.as_deref().is_none_or(|a| a < cursor),
                        "invalid dashboard cursor"
                    );
                    after = Some(cursor.to_owned());
                }
                self.dashboard(rows, layout)
            }
            Request::DashboardLayout(layout) => {
                let mut reply = self.layout_dashboard(layout)?;
                reply["layout_only"] = true.into();
                Ok(reply)
            }
            Request::DashboardClick {
                agent,
                revision,
                widget,
            } => {
                owner(
                    home,
                    OwnerOp::DashboardClick {
                        agent,
                        revision,
                        widget,
                        request_id: uuid::Uuid::now_v7().to_string(),
                    },
                )
                .await?;
                Ok(json!({"notice":"Action sent to chat."}))
            }
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

    #[test]
    fn dashboard_refresh_only_sends_charts_when_the_snapshot_changes() {
        let mut pages = Pages::default();
        let read_layout = |request| match serde_json::from_value::<Request>(request).unwrap() {
            Request::Dashboard(layout) => layout,
            _ => unreachable!(),
        };
        let light = read_layout(json!({"op":"dashboard"}));
        let dark = read_layout(json!({"op":"dashboard","palette":{
            "surface":[32,33,37],"text":[240,241,242],"secondary":[159,160,161],"accent":[180,155,255]
        }}));
        let mut rows = vec![json!({"agent":"chat","chat":"Trainer","revision":1,
            "board":{"title":"Training","widgets":[{"id":"loss","kind":"graph",
                "label":"Loss","unit":"%","value":[4,2,3]}]}})];
        let first = pages.dashboard(rows.clone(), light.clone()).unwrap();
        assert!(first["rows"][0]["board"]["widgets"][0]["chart_svg"].is_string());
        assert_eq!(
            pages.dashboard(rows.clone(), light).unwrap(),
            json!({"unchanged":true})
        );
        let recolored = pages.layout_dashboard(dark.clone()).unwrap();
        assert_ne!(
            first["rows"][0]["board"]["widgets"][0]["chart_svg"],
            recolored["rows"][0]["board"]["widgets"][0]["chart_svg"]
        );
        assert_eq!(
            pages.dashboard(rows.clone(), dark.clone()).unwrap(),
            json!({"unchanged":true})
        );
        rows[0]["chat"] = json!("Renamed");
        assert_eq!(
            pages.dashboard(rows, dark.clone()).unwrap()["rows"][0]["chat"],
            "Renamed"
        );
        assert_eq!(
            pages.dashboard(vec![], dark.clone()).unwrap(),
            json!({"rows":[]})
        );
        assert_eq!(
            pages.dashboard(vec![], dark).unwrap(),
            json!({"unchanged":true})
        );
    }

    #[tokio::test]
    async fn dashboard_resize_renders_each_row_at_its_width_from_cached_data() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("node");
        let cfg = config::initialize(&home, "cached-resize").unwrap();
        gent_daemon::entitlements::grant_test(&home, &cfg);
        let mut pages = Pages::default();
        let resize = r#"{"op":"dashboard_layout","chart_widths":[704,332]}"#;
        assert_eq!(pages.respond(&home, resize).await["unchanged"], true);
        let boards = ["C", "A", "B"].map(|chat| {
            json!({
                "chat":chat, "board":{"widgets":[{"kind":"graph","label":"Loss","value":[3,2]}]}
            })
        });
        pages
            .dashboard(boards.to_vec(), DashboardLayout::default())
            .unwrap();
        let reply = pages.respond(&home, resize).await;
        assert_eq!(reply["layout_only"], true);
        for (i, (chat, width)) in [("A", 332), ("B", 332), ("C", 704)].into_iter().enumerate() {
            let row = &reply["rows"][i];
            assert_eq!(row["chat"], chat);
            let svg = row["board"]["widgets"][0]["chart_svg"].as_str().unwrap();
            assert!(svg.contains(&format!(r#"viewBox="0 0 {width} "#)));
        }
        for invalid in ["[]", "[0]", "[65535]", "[240,240,240,240,240]"] {
            let request = format!(r#"{{"op":"dashboard_layout","chart_widths":{invalid}}}"#);
            assert!(pages.respond(&home, &request).await["error"].is_string());
        }
        assert_eq!(pages.respond(&home, resize).await["unchanged"], true);
    }

    #[tokio::test]
    async fn free_desktop_clears_cached_boards_and_refuses_old_clicks() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("node");
        config::initialize(&home, "free").unwrap();
        let mut pages = Pages::default();
        for op in [
            r#"{"op":"dashboard_layout"}"#,
            r#"{"op":"dashboard_click","agent":"old","revision":1,"widget":"run"}"#,
            r#"{"op":"dashboard"}"#,
        ] {
            pages.dashboard_snapshot =
                Some((DashboardLayout::default(), vec![json!({"chat":"former"})]));
            assert_eq!(
                pages.respond(&home, op).await,
                json!({"page":"dashboard","pro_required":true,"rows":[]})
            );
            assert!(pages.dashboard_snapshot.is_none());
        }
        assert!(!settings(&home).unwrap()["paid"].as_bool().unwrap());
        assert!(set(&home, Preference::Babysitter, false).await.is_err());
        assert!(!home.join("babysitter-disabled").exists());
    }

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
