//! The desktop owns visibility. The daemon owns the boards and their revisions.
use super::super::charts;
use crate::owner;
use anyhow::{Context, Result, ensure};
use gent_protocol::OwnerOp;
use preferences::{Hidden, Label};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use uuid::Uuid;

mod preferences;
#[cfg(test)]
mod tests;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Dashboard(Layout),
    DashboardLayout(Layout),
    DashboardHide {
        agent: String,
    },
    DashboardRestore {
        agent: String,
    },
    DashboardClick {
        agent: String,
        revision: u64,
        widget: String,
    },
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Layout {
    palette: charts::Palette,
    // Index k-1 is the usable width of one chart when k cards share a row.
    chart_widths: Vec<u16>,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            palette: charts::Palette::default(),
            chart_widths: vec![260],
        }
    }
}

impl Layout {
    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=4).contains(&self.chart_widths.len())
                && self.chart_widths.iter().all(|w| (160..=16384).contains(w)),
            "invalid dashboard chart widths"
        );
        Ok(())
    }
}

// During rolling upgrades the daemon may supply fields or widget kinds the desktop
// does not recognize. Preserve them for the native renderer.
#[derive(Clone, Deserialize, Serialize, PartialEq)]
struct Board {
    title: String,
    widgets: Vec<Value>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq)]
struct Row {
    agent: Uuid,
    chat: String,
    revision: u64,
    board: Board,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

struct View {
    file: PathBuf,
    layout: Layout,
    // Only the last complete set of daemon pages lives in memory.
    rows: Vec<Row>,
    hidden: Hidden,
}

impl View {
    fn new(file: &Path, layout: Layout, mut rows: Vec<Row>) -> Result<Self> {
        layout.validate()?;
        rows.sort_by_cached_key(|r| r.chat.to_lowercase());
        let hidden = preferences::for_rows(file, &rows)?;
        Ok(Self {
            file: file.into(),
            layout,
            rows,
            hidden,
        })
    }

    fn visible(&self) -> impl Iterator<Item = &Row> {
        self.rows
            .iter()
            .filter(|row| !self.hidden.contains_key(&row.agent))
    }

    fn render(&self) -> Value {
        let mut rows: Vec<_> = self.visible().cloned().collect();
        for line in rows.chunks_mut(self.layout.chart_widths.len()) {
            let width = usize::from(self.layout.chart_widths[line.len() - 1]);
            for row in line {
                for widget in &mut row.board.widgets {
                    charts::decorate(widget, &self.layout.palette, width);
                }
            }
        }
        json!({"rows":rows,"hidden":self.labels()})
    }

    fn labels(&self) -> Vec<Value> {
        let mut labels: Vec<_> = self.hidden.iter().collect();
        labels.sort_by_cached_key(|(_, label)| label.chat.to_lowercase());
        labels
            .into_iter()
            .map(|(agent, label)| json!({"agent":agent, "chat":label.chat, "title":label.title}))
            .collect()
    }

    fn hide(&mut self, agent: Uuid) -> Result<Value> {
        let row = self
            .rows
            .iter()
            .find(|row| row.agent == agent)
            .context("Dashboard is no longer available. Refresh the dashboard.")?;
        self.hidden = preferences::edit(&self.file, |hidden| {
            hidden.entry(agent).or_insert_with(|| Label::from(row));
        })?;
        Ok(self.render())
    }

    fn restore(&mut self, agent: Uuid) -> Result<Value> {
        ensure!(
            self.hidden.contains_key(&agent),
            "Dashboard is no longer hidden. Refresh the dashboard."
        );
        self.hidden = preferences::edit(&self.file, |hidden| {
            hidden.remove(&agent);
        })?;
        Ok(self.render())
    }
}

#[derive(Default)]
pub(super) struct Page {
    view: Option<View>,
    // A failed refresh preserves the display but invalidates its button actions.
    fresh: bool,
}

fn active_file(home: &Path) -> Option<PathBuf> {
    let cfg = crate::node_home::inspect(home).ok()?;
    gent_daemon::entitlements::paid(home, &cfg).then(|| preferences::path(home, &cfg))
}

impl Page {
    pub(super) async fn respond(&mut self, home: &Path, request: Request) -> Value {
        let Some(file) = active_file(home) else {
            return self.clear(true);
        };
        let switched = self.view.as_ref().is_some_and(|v| v.file != file);
        if switched {
            *self = Self::default();
        }

        let result = match request {
            Request::Dashboard(layout) => {
                let rows = fetch(home).await;
                if let Some(reply) = self.check_after_rpc(home, &file) {
                    return reply;
                }
                match rows {
                    Ok(rows) => self
                        .refresh(&file, layout, rows)
                        .inspect_err(|_| self.fresh = false),
                    Err(error) => self.refresh_failed(&file, layout, error),
                }
            }
            Request::DashboardLayout(layout) => self.resize(layout),
            Request::DashboardHide { agent } => {
                self.view_mut().and_then(|v| v.hide(publisher(&agent)?))
            }
            Request::DashboardRestore { agent } => {
                self.view_mut().and_then(|v| v.restore(publisher(&agent)?))
            }
            Request::DashboardClick {
                agent,
                revision,
                widget,
            } => {
                let sent = self.click(home, &agent, revision, widget).await;
                if let Some(reply) = self.check_after_rpc(home, &file) {
                    return reply;
                }
                sent
            }
        };
        let mut reply = result.unwrap_or_else(|error| json!({"error":error.to_string()}));
        if switched && reply.get("rows").is_none() {
            reply.as_object_mut().unwrap().remove("unchanged");
            reply["rows"] = json!([]);
            if reply.get("hidden").is_none() {
                reply["hidden"] = json!([]);
            }
        }
        reply
    }

    fn clear(&mut self, locked: bool) -> Value {
        *self = Self::default();
        if locked {
            json!({"pro_required":true,"rows":[],"hidden":[]})
        } else {
            json!({"rows":[],"hidden":[],"error":"Active cluster changed. Refresh the dashboard."})
        }
    }

    fn check_after_rpc(&mut self, home: &Path, file: &Path) -> Option<Value> {
        let current = active_file(home);
        (current.as_deref() != Some(file)).then(|| self.clear(current.is_none()))
    }

    fn view_mut(&mut self) -> Result<&mut View> {
        self.view.as_mut().context("Refresh the dashboard first.")
    }

    fn refresh(&mut self, file: &Path, layout: Layout, rows: Vec<Row>) -> Result<Value> {
        let next = View::new(file, layout, rows)?;
        let unchanged = self.fresh
            && self.view.as_ref().is_some_and(|v| {
                v.layout == next.layout && v.hidden == next.hidden && v.visible().eq(next.visible())
            });
        let reply = if unchanged {
            json!({"unchanged":true})
        } else {
            next.render()
        };
        self.view = Some(next);
        self.fresh = true;
        Ok(reply)
    }

    fn refresh_failed(
        &mut self,
        file: &Path,
        layout: Layout,
        error: anyhow::Error,
    ) -> Result<Value> {
        self.fresh = false;
        if self.view.is_some() {
            return Err(error);
        }
        // On first open the daemon can be offline. The user can still restore
        // retained labels, and the next complete refresh supplies the live rows.
        let view = View::new(file, layout, Vec::new())?;
        let reply = json!({"hidden":view.labels(),"error":error.to_string()});
        self.view = Some(view);
        Ok(reply)
    }

    fn resize(&mut self, layout: Layout) -> Result<Value> {
        layout.validate()?;
        let Some(view) = self.view.as_mut().filter(|v| v.layout != layout) else {
            return Ok(json!({"unchanged":true,"layout_only":true}));
        };
        view.layout = layout;
        let mut reply = view.render();
        reply["layout_only"] = true.into();
        Ok(reply)
    }

    async fn click(
        &self,
        home: &Path,
        agent: &str,
        revision: u64,
        widget: String,
    ) -> Result<Value> {
        let id = publisher(agent)?;
        ensure!(
            self.fresh
                && self
                    .view
                    .as_ref()
                    .is_some_and(|v| v.visible().any(|r| r.agent == id && r.revision == revision)),
            "Dashboard changed. Refresh before clicking."
        );
        owner(
            home,
            OwnerOp::DashboardClick {
                agent: id.to_string(),
                revision,
                widget,
                request_id: Uuid::now_v7().to_string(),
            },
        )
        .await?;
        Ok(json!({"notice":"Action sent to chat."}))
    }
}

fn publisher(agent: &str) -> Result<Uuid> {
    Uuid::parse_str(agent).context("Invalid dashboard publisher")
}

#[derive(Deserialize)]
struct BoardPage {
    rows: Vec<Row>,
    next: Option<String>,
}

async fn fetch(home: &Path) -> Result<Vec<Row>> {
    let mut after = None;
    let mut rows = Vec::new();
    loop {
        let page: BoardPage = serde_json::from_value(
            owner(
                home,
                OwnerOp::Dashboards {
                    after: after.clone(),
                },
            )
            .await?,
        )
        .context("invalid dashboard page")?;
        rows.extend(page.rows);
        let Some(cursor) = page.next else {
            return Ok(rows);
        };
        ensure!(
            after.as_ref().is_none_or(|a| a < &cursor),
            "invalid dashboard cursor"
        );
        after = Some(cursor);
    }
}
