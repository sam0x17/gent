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
    Link,
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

/// Whether a dashboard destination can be opened by the system web browser.
pub fn web_url(value: &str) -> bool {
    let Some((scheme, authority_and_path)) = value.split_once("://") else {
        return false;
    };
    // URL parsers can repair missing hosts, extra slashes and backslashes.
    // Keep the same explicit web destination across the native browser handlers.
    value.len() <= 2048
        && (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("http"))
        && !authority_and_path.starts_with(['/', '?', '#'])
        && !value.contains(|c: char| c.is_whitespace() || c.is_control() || c == '\\')
        && url::Url::parse(value).is_ok_and(|url| url.has_host())
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
                Kind::Link => {
                    if !w.value.as_str().is_some_and(web_url) {
                        return Err("use an absolute HTTP or HTTPS URL for a dashboard link");
                    }
                    if w.unit.is_some() {
                        return Err("omit the unit on a dashboard link");
                    }
                    true
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_widgets_reject_display_units() {
        let board: Board = serde_json::from_value(serde_json::json!({
            "title":"Results", "widgets":[{
                "id":"report", "label":"Open report", "kind":"link",
                "value":"https://example.org/report", "unit":"ms"
            }]
        }))
        .unwrap();
        assert_eq!(board.validate(), Err("omit the unit on a dashboard link"));
    }

    #[test]
    fn links_accept_only_explicit_web_destinations() {
        for value in [
            "https://example.org/runs/42?q=a%20b&tag=last#chart",
            "HTTP://localhost:8000/",
            "https://[::1]/",
            "https://例え.jp/結果",
        ] {
            assert!(web_url(value), "{value}");
        }
        for value in [
            "javascript:alert(1)",
            "file:///tmp/status",
            "data:text/html,page",
            "gent://some-action",
            "//example.org",
            "/report",
            "https:example.org",
            "https:///example.org",
            "https://",
            "http://[::1",
            "https://host:65536/",
            "https://example.org/a b",
            "https://example.org/\n",
            "https://example.org\\other",
            "https://example.org/\u{0}",
        ] {
            assert!(!web_url(value), "{value:?}");
        }
    }
}
