//! Optional native presentation of ordinary events widgets. Older presenters read
//! the original widget array, including every lane and all of the feed strings.
use serde::Serialize;
use serde_json::{Value, json};

const LANE: &str = "gent:lane:v1";
const FEED: &str = "gent:feed-pair:v1";

fn marked(widget: &Value, marker: &str) -> bool {
    widget["kind"] == "events" && widget["unit"] == marker
}

#[derive(Serialize)]
struct Lane<'a> {
    id: &'a str,
    label: &'a str,
    tone: &'a str,
    state: &'a str,
    details: Vec<&'a str>,
}

fn single_line(text: &str) -> bool {
    !text.trim().is_empty() && !text.chars().any(char::is_control)
}

fn lane<'a>(widget: &'a Value, entries: &'a [Value]) -> Option<Lane<'a>> {
    let (first, lines) = entries.split_first()?;
    let (tone, state) = first.as_str()?.split_once(": ")?;
    if !matches!(
        tone,
        "neutral" | "info" | "success" | "warning" | "critical"
    ) || !single_line(state)
        || lines.len() > 3
    {
        return None;
    }
    let details = lines
        .iter()
        .map(|line| line.as_str().filter(|text| single_line(text)))
        .collect::<Option<_>>()?;
    Some(Lane {
        id: widget["id"].as_str()?,
        label: widget["label"].as_str()?,
        tone,
        state,
        details,
    })
}

pub(super) fn sections(widgets: &[Value]) -> Option<Value> {
    if !widgets.iter().any(|w| marked(w, LANE) || marked(w, FEED)) {
        return None;
    }
    let mut sections = Vec::new();
    let mut lanes = Vec::new();
    let mut widgets = widgets.iter().enumerate().peekable();
    while let Some((index, widget)) = widgets.next() {
        if marked(widget, LANE)
            && let Some(entries) = widget["value"].as_array()
        {
            if entries.is_empty() {
                continue;
            }
            if let Some(card) = lane(widget, entries) {
                lanes.push(card);
                continue;
            }
        }
        if !lanes.is_empty() {
            sections.push(json!({"lanes": lanes}));
            lanes.clear();
        }
        if marked(widget, FEED)
            && let Some((next, _)) = widgets.next_if(|(_, w)| marked(w, FEED))
        {
            sections.push(json!({"feeds": [index, next]}));
        } else {
            sections.push(json!(index));
        }
    }
    if !lanes.is_empty() {
        sections.push(json!({"lanes": lanes}));
    }
    Some(Value::Array(sections))
}
