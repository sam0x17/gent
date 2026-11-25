use crate::display::visible;
use serde_json::Value;
use std::fmt::Write;

fn label(key: &str) -> String {
    if key == "invitation" {
        return "Invitation ID".into();
    }
    let text = key
        .split('_')
        .map(|word| match word {
            "agent" => "chat",
            "agents" => "chats",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(" ");
    let mut chars = text.chars();
    chars
        .next()
        .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
        .unwrap_or_default()
}
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(visible(text)),
        Value::Bool(value) => Some(if *value { "yes" } else { "no" }.into()),
        Value::Number(value) => Some(value.to_string()),
        Value::Null => Some("none".into()),
        _ => None,
    }
}
fn fields(out: &mut String, value: &Value, depth: usize) {
    let indent = "  ".repeat(depth);
    match value {
        Value::Object(values) => {
            let width = values
                .keys()
                .map(|key| label(key).chars().count())
                .max()
                .unwrap_or(0)
                .min(28);
            for (key, value) in values {
                if matches!(key.as_str(), "agent" | "agents" | "agent_id")
                    && values.contains_key(match key.as_str() {
                        "agent" => "chat",
                        "agents" => "chats",
                        _ => "chat_id",
                    })
                {
                    continue;
                }
                if value.is_null() {
                    continue;
                }
                let key = visible(&label(key));
                if let Some(value) = scalar(value) {
                    let _ = writeln!(
                        out,
                        "{indent}{}  {value}",
                        super::paint(&format!("{key:width$}"), "2")
                    );
                } else if value.as_array().is_some_and(Vec::is_empty)
                    || value.as_object().is_some_and(serde_json::Map::is_empty)
                {
                    let _ = writeln!(
                        out,
                        "{indent}{}  none",
                        super::paint(&format!("{key:width$}"), "2")
                    );
                } else {
                    let _ = writeln!(out, "{indent}{}", super::paint(&key, "1"));
                    fields(out, value, depth + 1);
                }
            }
        }
        Value::Array(values) => {
            if values.is_empty() {
                let _ = writeln!(out, "{indent}None.");
            }
            for (index, value) in values.iter().enumerate() {
                if let Some(value) = scalar(value) {
                    let _ = writeln!(out, "{indent}{value}");
                } else {
                    if index > 0 {
                        out.push('\n');
                    }
                    fields(out, value, depth);
                }
            }
        }
        other => {
            let _ = writeln!(out, "{indent}{}", scalar(other).unwrap_or_default());
        }
    }
}

pub(super) fn response(title: &str, value: &Value) -> String {
    let mut out = format!(
        "{}  {}\n",
        super::paint("gent", "1;36"),
        super::paint(title, "1")
    );
    if value["joined"] == true {
        let _ = writeln!(
            out,
            "  Joined {} as {}.",
            visible(value["cluster"]["name"].as_str().unwrap_or("cluster")),
            visible(value["node"]["name"].as_str().unwrap_or("node"))
        );
        let _ = writeln!(
            out,
            "  Daemon  {}",
            if value["daemon"]["running"] == true {
                super::state("running")
            } else {
                super::state("stopped")
            }
        );
        if let Some(error) = value["daemon"]["error"].as_str() {
            let _ = writeln!(out, "  {}", visible(error));
        }
        if let Some(next) = value["next"].as_str() {
            let _ = writeln!(out, "\n  {}", visible(next));
        }
    } else if title == "Updates" {
        updates(&mut out, value);
    } else {
        fields(&mut out, value, 1);
    }
    out
}

fn updates(out: &mut String, value: &Value) {
    let mut rows = Vec::new();
    if let Some(channel) = value["channel"].as_str() {
        rows.push(("Channel", visible(channel)));
    }
    if let Some(applied) = value["applied_channel"].as_str()
        && value["channel"] != applied
    {
        rows.push(("Applied channel", visible(applied)));
    }
    if let Some(enabled) = value["enabled"].as_bool() {
        rows.push((
            "Automatic",
            if enabled {
                "enabled, every 5 minutes"
            } else {
                "disabled"
            }
            .into(),
        ));
    }
    for (label, key) in [("Installed", "installed"), ("Running", "running")] {
        if let Some(commit) = value[key]["commit"].as_str() {
            rows.push((
                label,
                format!(
                    "{}{}",
                    visible(commit),
                    if value[key]["dirty"] == true {
                        " (modified source)"
                    } else {
                        ""
                    }
                ),
            ));
        }
    }
    if let Some(commit) = value["blessed_commit"].as_str() {
        rows.push(("Release revision", visible(commit)));
    } else if let Some(commit) = value["update"]["blessed_commit"].as_str() {
        rows.push(("Last resolved", visible(commit)));
    }
    if value.get("state").is_some() || value.get("update").is_some() {
        let state = value["state"]
            .as_str()
            .or_else(|| value["update"]["phase"].as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("waiting for first check");
        rows.push(("Status", visible(&state.replace('_', " "))));
    }
    if let Some(available) = value["update_available"].as_bool() {
        rows.push((
            "Update available",
            if available { "yes" } else { "no" }.into(),
        ));
    }
    if let Some(active) = value["update_in_progress"].as_bool() {
        rows.push(("Updater", if active { "running" } else { "idle" }.into()));
    }
    if let Some(commit) = value["commit"].as_str() {
        rows.push(("Revision", visible(commit)));
    }
    if let Some(state) = value["integrations"]["state"].as_str() {
        rows.push(("Integrations", visible(&state.replace('_', " "))));
    }
    if let Some(log) = value["build_log"].as_str() {
        rows.push(("Build log", visible(log)));
    }
    if value.get("daemon").is_some() {
        let revision = value["running"]["commit"].as_str().unwrap_or_else(|| {
            if value["daemon"]["reachable"] == true {
                "unknown (older daemon)"
            } else {
                "not responding"
            }
        });
        rows.push(("Daemon revision", visible(revision)));
    }
    for (label, value) in rows {
        let _ = writeln!(
            out,
            "  {}  {value}",
            super::paint(&format!("{label:<18}"), "2")
        );
    }
    for key in [
        "error",
        "channel_error",
        "applied_channel_error",
        "next",
        "activation",
    ] {
        if let Some(text) = value[key]
            .as_str()
            .or_else(|| value["update"][key].as_str())
        {
            let _ = writeln!(out, "\n  {}", visible(text));
        }
    }
    if value["activation_pending"] == true {
        let _ = writeln!(
            out,
            "\n  Waiting for the daemon to finish accepted requests and restart."
        );
    }
}
