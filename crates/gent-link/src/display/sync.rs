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
