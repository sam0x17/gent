use serde_json::Value;

pub fn print(value: &Value) {
    if let Some(lines) = value["lines"].as_array() {
        for line in lines {
            println!("{}", line.as_str().unwrap_or_default());
        }
        return;
    }
    let kind = value["service"]["kind"].as_str().unwrap_or("daemon");
    let daemon = &value[kind];
    let service = &value["service"];
    println!(
        "{}: {}",
        if kind == "gateway" {
            "Gateway"
        } else {
            "Daemon"
        },
        if daemon["running"] == true {
            if daemon["managed"] == true {
                "running (managed service)"
            } else {
                "running (outside service)"
            }
        } else {
            "stopped or unavailable"
        }
    );
    println!(
        "Service: {} ({}, {})",
        if service["installed"] == true {
            "installed"
        } else {
            "not installed"
        },
        service["backend"].as_str().unwrap_or("unknown"),
        if service["enabled"] == true {
            "startup enabled"
        } else {
            "startup disabled"
        }
    );
    println!(
        "State directory: {}",
        service["home"].as_str().unwrap_or_default()
    );
    let startup = &service["startup"];
    println!(
        "Startup: {}",
        match startup["trigger"].as_str() {
            Some("boot") => "at boot, including before login",
            Some("login") => "with the user's login session",
            Some("disabled") => "disabled",
            _ => "unknown",
        }
    );
    if startup["trigger"] == "login" && service["backend"] == "systemd" {
        println!("For startup before login and after logout: gent daemon install --linger");
    }
    if let Some(error) = startup["error"].as_str() {
        println!("Startup inspection: {error}");
    }
    println!(
        "Service file: {}",
        service["file"].as_str().unwrap_or_default()
    );
    for key in ["error", "file_error"] {
        if let Some(error) = service[key].as_str() {
            println!("{error}");
        }
    }
    if daemon["running"] != true
        && let Some(error) = daemon["error"].as_str()
    {
        println!("{error}");
    }
}
