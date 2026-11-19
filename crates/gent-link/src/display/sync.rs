use super::*;

fn state(value: &Value) -> &str {
    match value["state"].as_str() {
        Some("syncing") => "catching up",
        Some("retrying") => "retrying after an error",
        Some("connecting") => "establishing peer connections",
        Some("idle") => "idle (no known backlog)",
        Some("disabled") => "local only",
        Some("waiting_for_authority") => "waiting for current cluster authority",
        _ => "starting",
    }
}

pub(super) fn summary(output: &mut String, value: &Value) -> std::fmt::Result {
    if value.is_null() {
        return Ok(());
    }
    writeln!(
        output,
        "  Sync: {}; {} records waiting to send; {} packets received this session.",
        state(value),
        value["records_waiting_to_send"].as_u64().unwrap_or(0),
        value["packets_received"].as_u64().unwrap_or(0)
    )?;
    if !matches!(value["state"].as_str(), Some("idle" | "disabled")) {
        writeln!(
            output,
            "  Chat listings may still be incomplete. Use gent sync for progress."
        )?;
    }
    Ok(())
}

pub(super) fn render(output: &mut String, value: &Value) -> std::fmt::Result {
    header(output, "Sync")?;
    row(output, "Status", state(value))?;
    for (label, field) in [
        ("Records to send", "records_waiting_to_send"),
        ("Transferring streams", "transferring_streams"),
        ("Retrying streams", "retrying_streams"),
        ("Packets sent", "packets_sent"),
        ("Packets received", "packets_received"),
    ] {
        row(
            output,
            label,
            &value[field].as_u64().unwrap_or(0).to_string(),
        )?;
    }
    if let Some(peers) = value["directory"]["peers"]
        .as_array()
        .filter(|p| !p.is_empty())
    {
        writeln!(output, "\n  Chat directories (checked every minute)")?;
        for peer in peers {
            let state = match peer["state"].as_str() {
                Some("checking") => "comparing roots",
                Some("repairing") => "repairing differences",
                Some("matched") => "matched at last check",
                Some("changed") => "changed during check; retry scheduled",
                Some("different") => "differences remain; retry scheduled",
                _ if peer["supported"] != true => "waiting for peer capability",
                _ => "awaiting first check",
            };
            row(
                output,
                peer["node_name"].as_str().unwrap_or("unknown"),
                state,
            )?;
            if let Some(timestamp) = peer["verified_at"].as_u64() {
                writeln!(
                    output,
                    "    Last match: {} ({} chats)",
                    date(timestamp),
                    peer["verified_chats"].as_u64().unwrap_or(0)
                )?;
            }
        }
    }
    for (label, field) in [
        ("Last progress", "last_progress_at"),
        ("Last relay contact", "last_success_at"),
    ] {
        row(
            output,
            label,
            &value[field]
                .as_u64()
                .map(date)
                .unwrap_or_else(|| "not observed".into()),
        )?;
    }
    writeln!(
        output,
        "\n  Packet counts reset when the daemon starts. Idle means no known transport backlog; offline nodes and host discovery can still leave the directory incomplete."
    )
}
