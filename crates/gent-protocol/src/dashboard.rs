//! Declarative, chat-owned dashboards. Values contain no executable markup.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

mod image;

pub const MAX_BOARD_BYTES: usize = 32 * 1024;

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
    Metric,
    Bar,
    Pie,
    Radar,
    Scatter,
    Image,
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
    pub x_unit: Option<String>,
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

fn number(v: &Value) -> bool {
    v.as_f64().is_some_and(|n| n.abs() <= 1e100)
}

fn categories(kind: Kind, value: &Value) -> bool {
    let Some(entries) = value.as_array() else {
        return false;
    };
    if entries.len() > 16 || (kind == Kind::Radar && entries.len() < 3) {
        return false;
    }
    let mut positive = false;
    for entry in entries {
        let Some(obj) = entry.as_object() else {
            return false;
        };
        if obj.len() != 2 || !entry["label"].as_str().is_some_and(|s| label(s, 128)) {
            return false;
        }
        let Some(n) = entry["value"].as_f64() else {
            return false;
        };
        if n.abs() > 1e100 || (kind != Kind::Bar && n < 0.) {
            return false;
        }
        positive |= n > 0.;
    }
    kind != Kind::Pie || positive
}

impl Widget {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
            || !label(&self.label, 128)
            || self.unit.as_ref().is_some_and(|u| !label(u, 32))
        {
            return Err("invalid widget key, label or unit");
        }
        if self
            .x_unit
            .as_ref()
            .is_some_and(|u| self.kind != Kind::Scatter || !label(u, 32))
        {
            return Err("x_unit requires a scatter widget and a label of 1–32 bytes");
        }
        let valid = match self.kind {
            Kind::Text => text(&self.value),
            Kind::Link => {
                if !self.value.as_str().is_some_and(web_url) {
                    return Err("use an absolute HTTP or HTTPS URL for a dashboard link");
                }
                if self.unit.is_some() {
                    return Err("omit the unit on a dashboard link");
                }
                true
            }
            Kind::Button => {
                text(&self.value) && self.value.as_str().is_some_and(|v| !v.trim().is_empty())
            }
            Kind::Events => self
                .value
                .as_array()
                .is_some_and(|a| a.len() <= 64 && a.iter().all(text)),
            Kind::Graph => self
                .value
                .as_array()
                .is_some_and(|a| a.len() <= 256 && a.iter().all(number)),
            Kind::Progress | Kind::Gauge => {
                let min = self.min.unwrap_or(0.);
                let max = self.max.unwrap_or(100.);
                min.abs() <= 1e100
                    && max.abs() <= 1e100
                    && min < max
                    && self
                        .value
                        .as_f64()
                        .is_some_and(|v| (min..=max).contains(&v))
            }
            Kind::Metric => number(&self.value),
            Kind::Bar | Kind::Pie | Kind::Radar => categories(self.kind, &self.value),
            Kind::Scatter => self.value.as_array().is_some_and(|a| {
                a.len() <= 256
                    && a.iter().all(|p| {
                        p.as_array()
                            .is_some_and(|xy| xy.len() == 2 && xy.iter().all(number))
                    })
            }),
            Kind::Image => self.value.as_str().is_some_and(image::valid),
        };
        if !valid {
            return Err("invalid value for dashboard widget type");
        }
        Ok(())
    }
}

impl Board {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !label(&self.title, 128) || !(1..=32).contains(&self.widgets.len()) {
            return Err("use a title and 1–32 widgets");
        }
        if serde_json::to_vec(self)
            .map_err(|_| "invalid dashboard")?
            .len()
            > MAX_BOARD_BYTES
        {
            return Err("dashboard exceeds 32 KiB");
        }
        let mut keys = BTreeSet::new();
        for widget in &self.widgets {
            if !keys.insert(&widget.id) {
                return Err("duplicate widget key");
            }
            widget.validate()?;
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

#[cfg(test)]
mod chart_tests {
    use super::*;
    use serde_json::json;

    fn widget(kind: Kind, value: Value) -> Widget {
        serde_json::from_value(json!({"id":"chart","kind":kind,"label":"Chart","value":value}))
            .unwrap()
    }

    #[test]
    fn category_charts_check_shape_bounds_and_totals() {
        let item = |n| json!({"label":"North","value":n});
        for (kind, values, ok) in [
            (Kind::Bar, vec![], true),
            (Kind::Bar, vec![item(-4); 16], true),
            (Kind::Bar, vec![item(1); 17], false),
            (Kind::Pie, vec![], false),
            (Kind::Pie, vec![item(0); 2], false),
            (Kind::Pie, vec![item(0), item(1)], true),
            (Kind::Pie, vec![item(2), item(-1)], false),
            (Kind::Radar, vec![item(4); 2], false),
            (Kind::Radar, vec![item(0); 3], true),
            (Kind::Radar, vec![item(4), item(1), item(-1)], false),
        ] {
            assert_eq!(
                widget(kind, json!(values)).validate().is_ok(),
                ok,
                "{kind:?}"
            );
        }
        for invalid in [
            json!([1]),
            json!([{"label":"  ","value":1}]),
            json!([{"label":"x","value":"1"}]),
            json!([{"label":"x","value":1e101}]),
            json!([{"label":"x","value":1,"extra":true}]),
        ] {
            assert!(widget(Kind::Bar, invalid).validate().is_err());
        }
    }

    #[test]
    fn scatter_has_pairs_and_units_while_graph_keeps_numeric_samples() {
        let mut scatter = widget(Kind::Scatter, json!(vec![[-1.0, 2.5]; 256]));
        scatter.x_unit = Some("s".into());
        scatter.unit = Some("m".into());
        assert!(scatter.validate().is_ok());
        assert!(widget(Kind::Scatter, json!([])).validate().is_ok());
        for bad in [
            json!(vec![[0, 1]; 257]),
            json!([1, 2]),
            json!([[1, 2, 3]]),
            json!([[1, "2"]]),
            json!([[0, 1e101]]),
        ] {
            assert!(widget(Kind::Scatter, bad).validate().is_err());
        }
        scatter.kind = Kind::Graph;
        scatter.value = json!([1, 2]);
        assert!(scatter.validate().is_err());
        scatter.x_unit = None;
        assert!(scatter.validate().is_ok());
        assert!(widget(Kind::Graph, json!([[1, 2]])).validate().is_err());
        assert!(widget(Kind::Metric, json!(-1e100)).validate().is_ok());
        assert!(widget(Kind::Metric, json!("1")).validate().is_err());
        assert!(widget(Kind::Metric, json!(1e101)).validate().is_err());
    }
}
