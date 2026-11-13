use serde_json::Value;

pub fn print_transport(value: &Value) {
    if let Some(dry_run) = value["dry_run"].as_bool() {
        println!(
            "{} {} duplicate ciphertext copies ({} bytes), {} accepted digests, and {} wire receipts.",
            if dry_run {
                "Would compact"
            } else {
                "Compacted"
            },
            value["duplicate_copies_compacted"],
            value["duplicate_bytes_removed"],
            value["accepted_digests_removed"],
            value["wire_receipts_removed"]
        );
        println!(
            "Confirmed packet bodies retired: {} ({} bytes). Full configuration records compacted: {} ({} bytes).",
            value["retained_packets_removed"],
            value["retained_packet_bytes_removed"],
            value["authority_records_compacted"],
            value["authority_bytes_removed"]
        );
        println!(
            "Confirmed transport retry records removed: {}.",
            value["transport_requests_removed"]
        );
        println!(
            "Repeat cleanup while a batch reaches its limit; pending sends and joins keep required history."
        );
    } else {
        for purpose in ["data", "configuration"] {
            let usage = &value["outgoing"][purpose];
            println!(
                "{purpose} retry records: {} / {} ({} daemon allocations).",
                usage["retry_records"],
                usage["max_retry_records"],
                usage["allocated_retry_records"]
            );
            println!(
                "{purpose}: {} / {} packets; {} / {} packet bytes.",
                usage["packets"],
                usage["max_packets"],
                usage["packet_bytes"],
                usage["max_packet_bytes"]
            );
        }
        println!(
            "Duplicate ciphertext: {} copies ({} bytes). Replay evidence due: {} digests, {} receipts.",
            value["duplicate_copies"],
            value["duplicate_bytes"],
            value["accepted_digests_due"],
            value["wire_receipts_due"]
        );
        println!(
            "Recent replay evidence: {} positions per stream plus its origin.",
            value["recent_packets_per_stream"]
        );
        println!(
            "Receiver checkpoints: {}; retired packet tombstones: {}.",
            value["confirmed_streams"], value["retired_packet_tombstones"]
        );
        let authority = &value["authority_history"];
        println!(
            "Signed configurations: {} / {} full records; {} / {} bytes. Accepted digests: {}.",
            authority["full_records"],
            authority["max_records"],
            authority["full_record_bytes"],
            authority["max_record_bytes"],
            authority["accepted_digests"]
        );
        println!(
            "Configuration records due for compaction: {}; pending join pins: {}.",
            authority["full_records_due"], authority["pending_join_pins"]
        );
        println!(
            "Unconfirmed packets remain for offline peers. Verified checkpoints release confirmed packet capacity."
        );
        println!(
            "Legacy retries count against admission limits. Accepted authority digests, event deduplication, raw groups, plaintext, and total database size have separate retention needs."
        );
    }
}

pub fn print_history(value: &Value) {
    if let Some(dry_run) = value["dry_run"].as_bool() {
        println!(
            "{} {} exchanges, {} messages ({} payload bytes), {} import retries, and {} relay attachments.",
            if dry_run { "Would retire" } else { "Retired" },
            value["exchanges_removed"],
            value["messages_removed"],
            value["payload_bytes_removed"],
            value["import_retries_removed"],
            value["relay_attachments_removed"]
        );
        println!(
            "Outbound events retained for cancellation: {}; migration-deferred exchanges: {}; more due: {}.",
            value["outbound_events_cancelled"],
            value["legacy_exchanges_deferred"],
            value["more_exchanges_due"]
        );
        println!(
            "Sent node-event retry records removed: {}.",
            value["sent_event_retries_removed"]
        );
    } else {
        println!(
            "Gent messages: {} / {}; payload bytes: {} / {}.",
            value["messages"],
            value["limits"]["messages"],
            value["message_payload_bytes"],
            value["limits"]["message_payload_bytes"]
        );
        println!(
            "Exchanges: {}; expired exchanges due: {}. Import retries: {} / {}; relay attachments: {}.",
            value["exchanges"],
            value["expired_exchanges_due"],
            value["import_retry_records"],
            value["limits"]["import_retry_records"],
            value["relay_attachments"]
        );
        println!(
            "Queued events: {} ({} bytes), including {} cancellations.",
            value["queued_events"], value["queued_event_bytes"], value["queued_cancellations"]
        );
        let network = &value["network"];
        for class in ["data", "control"] {
            let usage = &network["traffic"][class];
            println!(
                "{class} node queue: {} / {} events; {} / {} bytes; {} / {} retry slots.",
                usage["queued_events"],
                usage["max_queued_events"],
                usage["queued_bytes"],
                usage["max_queued_bytes"],
                usage["retry_slots"],
                usage["max_retry_slots"]
            );
        }
        println!(
            "Sent event retries: {} ({} legacy, {} due). Registration generation records: {} / {}.",
            network["sent_retries"],
            network["legacy_sent_retries"],
            network["sent_retries_due"],
            network["announcement_watermarks"],
            network["max_announcement_watermarks"]
        );
        println!(
            "Message history: seven days after expiry. New request IDs: UUIDv7, first use within 24 hours."
        );
        println!(
            "Encrypted stream, configuration, and provider histories are separate. Preview: gent history clean --dry-run"
        );
    }
}

pub fn print_report(value: &Value) {
    if let Some(dry_run) = value["dry_run"].as_bool() {
        println!(
            "{} {} expired encrypted objects and {} handoff copies ({} plaintext bytes).",
            if dry_run { "Would remove" } else { "Removed" },
            value["expired_objects"],
            value["handoffs_removed"],
            value["plaintext_bytes_removed"]
        );
        println!(
            "Missing copies: {}; changed copies preserved: {}; blocked: {}.",
            value["handoffs_missing"], value["handoffs_preserved"], value["handoffs_blocked"]
        );
        println!(
            "More copies due: {}. Run gent files status for details.",
            value["more_due"]
        );
    } else {
        let objects = &value["objects"];
        let handoffs = &value["handoffs"];
        println!(
            "Encrypted objects: {} / {}; reserved bytes: {} / {}.",
            objects["count"],
            objects["max_count"],
            objects["reserved_bytes"],
            objects["max_reserved_bytes"]
        );
        println!(
            "Stored ciphertext: {} bytes; complete objects: {}; expired: {}.",
            value["ciphertext_chunks"]["stored_bytes"], objects["complete"], objects["expired"]
        );
        println!(
            "Tracked handoff copies: {} ({} bytes when recorded); expired: {}.",
            handoffs["tracked_copies"], handoffs["recorded_bytes"], handoffs["expired"]
        );
        println!(
            "Changed copies preserved: {}; cleanup blocked: {}.",
            handoffs["preserved"], handoffs["blocked"]
        );
        if let Some(attention) = value["attention"].as_array() {
            for item in attention {
                // JSON quoting escapes control characters in a user-selected home path.
                println!(
                    "  {}: {}; recovery path if present: {}",
                    item["outcome"], item["path"], item["recovery_path"]
                );
                if !item["reason"].is_null() {
                    println!("    {}", item["reason"]);
                }
            }
        }
        println!(
            "Endpoint database: {} logical bytes, {} reusable; excludes WAL and other files.",
            value["database"]["logical_bytes"], value["database"]["reusable_bytes"]
        );
        println!(
            "Retained messages: {}; import retry records: {}.",
            value["retained_messages"], value["retained_import_retries"]
        );
        println!(
            "Untracked files and host edits are not measured. Preview cleanup: gent files clean --dry-run"
        );
    }
}
