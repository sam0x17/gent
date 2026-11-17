use crate::{display::visible, ui};
use serde_json::Value;

pub fn print(value: &Value) {
    if let Some(lines) = value["lines"].as_array() {
        for line in lines {
            println!("{}", visible(line.as_str().unwrap_or_default()));
        }
        return;
    }
    let kind = value["service"]["kind"].as_str().unwrap_or("daemon");
    let daemon = &value[kind];
    let service = &value["service"];
    ui::heading(if kind == "gateway" {
        "Gateway"
    } else {
        "Daemon"
    });
    ui::field(
        "Status",
        if daemon["running"] == true {
            "running"
        } else {
            "stopped or unavailable"
        },
    );
    if let Some(pid) = daemon["pid"].as_u64() {
        ui::field("Process", &pid.to_string());
    }
    ui::field(
        "Service",
        &format!(
            "{} ({})",
            if service["installed"] == true {
                "installed"
            } else {
                "not installed"
            },
            service["backend"].as_str().unwrap_or("unknown")
        ),
    );
    let startup = &service["startup"];
    ui::field(
        "Startup",
        match startup["trigger"].as_str() {
            Some("boot") => "at boot, including before login",
            Some("login") => "with your login session",
            Some("disabled") => "disabled",
            _ => "unknown",
        },
    );
    ui::field("State", service["home"].as_str().unwrap_or_default());
    ui::field("Service file", service["file"].as_str().unwrap_or_default());
    if startup["trigger"] == "login" && service["backend"] == "systemd" {
        println!("\n  For startup before login: gent daemon install --linger");
    }
    for error in [
        &startup["error"],
        &service["error"],
        &service["file_error"],
        &daemon["error"],
    ]
    .into_iter()
    .filter_map(Value::as_str)
    {
        println!("\n  {}", visible(error));
    }
}
