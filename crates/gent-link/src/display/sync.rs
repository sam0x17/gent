use super::*;

pub(super) fn transport(event: &Value) -> String {
    let Some(path) = event["path"].as_str() else {
        return "unobserved".into();
    };
    let route = match path {
        "direct_quic" => "direct QUIC".into(),
        "cluster_helper" => format!(
            "QUIC via helper {}",
            event["helper_id"].as_str().unwrap_or("?")
        ),
        "configured_relay" => "QUIC via configured relay".into(),
        "quic_unknown" => "QUIC (path unknown)".into(),
        "quic_mixed" => "QUIC (mixed paths)".into(),
        "relay_wss" => "relay WSS".into(),
        "mailbox" => "mailbox".into(),
        _ => "unknown transport".into(),
    };
    match event["evidence"].as_str() {
        Some("received_packet") => format!("{route} received packet"),
        Some("signed_receipt") => format!("{route} signed receipt"),
        Some("mailbox_upload") => format!("{route} upload"),
        _ => route,
    }
}

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
        writeln!(
            output,
            "\n  Chat directories (compared on traffic; periodic fallback)"
        )?;
        if let Some(sequence) = value["directory"]["sequence"].as_u64() {
            row(output, "Local tree sequence", &sequence.to_string())?;
        }
        for peer in peers {
            let state = match peer["state"].as_str() {
                Some("checking") => "comparing roots",
                Some("repairing") => "repairing differences",
                Some("awaiting_peer") => "differences sent; awaiting peer view",
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
            if let Some(error) = peer["error"].as_str() {
                row(output, "Repair deferred", error)?;
            }
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
    if let Some(peers) = value["peer_transports"]
        .as_array()
        .filter(|p| !p.is_empty())
    {
        writeln!(output, "\n  Last observed peer transfers")?;
        for peer in peers {
            let event = &peer["last"];
            let name = peer["carrier_name"]
                .as_str()
                .or_else(|| peer["carrier_id"].as_str())
                .unwrap_or("unknown");
            let timestamp = event["observed_at"]
                .as_u64()
                .map(date)
                .unwrap_or_else(|| "time unknown".into());
            row(
                output,
                &visible(name),
                &format!("{} ({timestamp})", transport(event)),
            )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use serde_json::json;

    #[test]
    fn nodes_and_sync_parse_compact_and_verbose_modes() {
        for command in ["nodes", "sync"] {
            for (args, verbose) in [
                (vec!["gent", command], false),
                (vec!["gent", command, "--verbose"], true),
                (vec!["gent", "-v", command], true),
            ] {
                let cli = crate::Cli::try_parse_from(args).unwrap();
                let output = crate::ui::Output::for_cli(&cli);
                assert_eq!(output.raw(), verbose);
                assert_eq!(output.verbose, verbose);
                assert!(!output.json);
                assert!(matches!(
                    (command, cli.command),
                    ("nodes", Some(crate::Command::Nodes))
                        | ("sync", Some(crate::Command::Sync { .. }))
                ));
            }
        }
    }

    #[test]
    fn node_and_sync_views_show_actual_evidence_and_accept_older_daemons() {
        let mut nodes = json!([
            {"name":"carrier","id":"node-a","status":"connected","data_link":true,"can_configure":false},
            {"name":"web","id":"node-b","status":"connected","data_link":true,"can_configure":false}
        ]);
        assert!(
            super::super::render(View::Nodes, &nodes)
                .unwrap()
                .contains("unobserved")
        );
        let transfer = json!({"carrier_id":"node-a","carrier_name":"carrier","last":{
            "path":"cluster_helper","helper_id":"helper-id","evidence":"signed_receipt",
            "sequence":7,"observed_at":20
        }});
        nodes[1]["transport"] = transfer.clone();
        let list = super::super::render(View::Nodes, &nodes).unwrap();
        assert!(list.contains("QUIC via helper helper-id signed receipt (via carrier)"));
        let mut text = String::new();
        render(&mut text, &json!({"peer_transports":[transfer]})).unwrap();
        assert!(text.contains("QUIC via helper helper-id signed receipt"));
        assert_eq!(
            transport(&json!({"path":"mailbox","evidence":"mailbox_upload"})),
            "mailbox upload"
        );
    }
}
