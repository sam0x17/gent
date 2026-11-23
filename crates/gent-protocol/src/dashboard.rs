//! Declarative, chat-owned dashboards. Values contain no executable markup.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Board {
    pub title: String,
    pub widgets: Vec<Widget>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Text,
    Events,
    Graph,
    Gauge,
    Progress,
    Button,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Widget {
    pub id: String,
    pub label: String,
    pub kind: Kind,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
}

fn label(s: &str, limit: usize) -> bool {
    !s.trim().is_empty() && s.len() <= limit && !s.chars().any(char::is_control)
}
fn text(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() <= 2048
            && !s
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    })
}

impl Board {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !label(&self.title, 128) || !(1..=32).contains(&self.widgets.len()) {
            return Err("use a title and 1–32 widgets");
        }
        let mut keys = BTreeSet::new();
        for w in &self.widgets {
            if w.id.is_empty()
                || w.id.len() > 64
                || !w
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                || !keys.insert(&w.id)
                || !label(&w.label, 128)
                || w.unit.as_ref().is_some_and(|u| !label(u, 32))
            {
                return Err("invalid or duplicate widget key, label or unit");
            }
            let min = w.min.unwrap_or(0.);
            let max = w.max.unwrap_or(100.);
            let valid = match w.kind {
                Kind::Text => text(&w.value),
                Kind::Button => {
                    text(&w.value) && w.value.as_str().is_some_and(|v| !v.trim().is_empty())
                }
                Kind::Events => w
                    .value
                    .as_array()
                    .is_some_and(|a| a.len() <= 64 && a.iter().all(text)),
                Kind::Graph => w.value.as_array().is_some_and(|a| {
                    a.len() <= 256
                        && a.iter()
                            .all(|v| v.as_f64().is_some_and(|x| x.abs() <= 1e100))
                }),
                Kind::Progress | Kind::Gauge => {
                    min.abs() <= 1e100
                        && max.abs() <= 1e100
                        && min < max
                        && w.value.as_f64().is_some_and(|v| (min..=max).contains(&v))
                }
            };
            if !valid {
                return Err("invalid value for dashboard widget type");
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| "invalid dashboard")?
            .len()
            > 32 * 1024
        {
            return Err("dashboard exceeds 32 KiB");
        }
        Ok(())
    }
}
