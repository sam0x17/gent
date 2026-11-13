use serde_json::Value;

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
