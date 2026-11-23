use serde_json::{Value, json};
use std::collections::HashMap;

fn route(path: &str) -> &str {
    match path {
        "direct_quic" => "Direct QUIC",
        "cluster_helper" => "Cluster helper",
        "relay_wss" => "Relay WebSocket",
        "mailbox" => "Mailbox",
        "configured_relay" => "Configured relay",
        "quic_mixed" => "Mixed QUIC",
        "quic_unknown" => "QUIC",
        _ => path,
    }
}

fn presence_detail(reason: &str) -> &str {
    match reason {
        "local_daemon" => "This machine runs the local daemon.",
        "local_hosting_daemon" => "This machine hosts the connector.",
        "not_paired" => "No paired data link to this node’s carrier.",
        "stale_authority" => "Cluster authority is out of date.",
        "local_node_not_enrolled" => "The local node lacks current cluster authorization.",
        "relay_not_configured" => "The local node has no relay configured.",
        "recent_encrypted_round_trip" => {
            "Recent encrypted round trip with the node or its carrier."
        }
        "probe_timed_out" => "A recent presence check timed out.",
        "no_recent_encrypted_round_trip" => {
            "No recent encrypted round trip with the node or its carrier."
        }
        "awaiting_fresh_round_trip" => "Waiting for a fresh encrypted round trip.",
        "awaiting_first_round_trip" => "Waiting for the first encrypted round trip.",
        _ => reason,
    }
}

/// Membership determines which rows may be managed. Sync observations only
/// describe native peers and may outlive a removal or a hosted carrier change.
fn node_rows(members: &[Value], sync: &Value) -> Vec<Value> {
    let names: HashMap<_, _> = members
        .iter()
        .filter_map(|m| Some((m["id"].as_str()?, m["name"].as_str()?)))
        .collect();
    let directory: HashMap<_, _> = sync["directory"]["peers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| Some((p["node_id"].as_str()?, p["state"].as_str()?)))
        .collect();
    let mut rows: Vec<_> = members
        .iter()
        .map(|node| {
            let host = node["hosted_by"]
                .as_str()
                .map(|id| names.get(id).copied().unwrap_or(id));
            let peer = node["id"]
                .as_str()
                .filter(|_| host.is_none() && node["status"] != "local");
            let transport = &node["transport"];
            let path = peer
                .filter(|id| transport["carrier_id"] == *id)
                .and_then(|_| transport["last"]["path"].as_str())
                .map(route);
            let role = if node["is_owner"] == true {
                "Owner"
            } else if node["can_configure"] == true {
                "Admin"
            } else {
                "Member"
            };
            let mut row = json!({
                "id": node["id"], "name": node["name"], "state": node["status"],
                "role": role, "host": host,
                "directory": peer.and_then(|id| directory.get(id)),
                "route": path,
            });
            if let Some(reason) = node["presence"]["reason"].as_str() {
                row["status_detail"] = presence_detail(reason).into();
            }
            row
        })
        .collect();
    rows.sort_by_cached_key(|n| {
        (
            n["state"] != "local",
            n["name"].as_str().unwrap_or_default().to_lowercase(),
            n["id"].to_string(),
        )
    });
    rows
}

pub(super) fn snapshot(status: &Value) -> Value {
    let daemon = &status["daemon"];
    let service = &status["service"];
    let sync = &status["sync"];
    let running = daemon["running"] == true;
    let manager_running = service["running"] == true;
    let available = service["available"] == true && service["installed"] == true;
    let state = if running {
        "Running"
    } else if manager_running {
        "Unresponsive"
    } else if available {
        "Stopped"
    } else {
        "Unavailable"
    };
    let mut connection = Vec::new();
    if let Some(online) = sync["notifications_connected"].as_bool() {
        connection.push(format!(
            "Notifications {}",
            if online { "connected" } else { "disconnected" }
        ));
    }
    if let Some(retries) = sync["retrying_streams"].as_u64() {
        connection.push(format!("Retrying streams: {retries}"));
    }
    if sync["local_error"] == true {
        connection.push("Local sync error".into());
    }
    if sync["control_error"] == true {
        connection.push("Sync control error".into());
    }
    let nodes = match status["members"].as_array() {
        Some(members) => {
            json!({"rows":node_rows(members, sync), "actions":super::admin::directory_actions(false)})
        }
        None => {
            let mut nodes = json!({"rows":[], "actions":[]});
            if running {
                nodes["error"] = "Node directory unavailable. Refresh to try again.".into();
            }
            nodes
        }
    };
    json!({
        "enrolled": status["enrolled"],
        "connection":connection.join(" · "),
        "running": running,
        "state": state,
        "node": status["node"]["name"],
        "cluster": status["cluster"]["name"],
        "can_start": available && !running && !manager_running,
        "can_stop": available && (daemon["managed"] == true || (!running && manager_running)),
        "queue": sync["records_waiting_to_send"],
        "chats": sync["directory"]["known_chats"],
        "sync": sync["state"],
        "nodes": nodes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_follow_local_service_ownership_and_health() {
        for (available, running, managed, manager_running, state, start, stop) in [
            (true, true, false, false, "Running", false, false),
            (true, true, true, true, "Running", false, true),
            (true, false, false, true, "Unresponsive", false, true),
            (true, false, false, false, "Stopped", true, false),
            (false, false, false, false, "Unavailable", false, false),
        ] {
            let gui = snapshot(&json!({
                "daemon": {"running": running, "managed": managed},
                "service": {"installed": true, "available": available, "running": manager_running},
            }));
            assert_eq!(gui["state"], state);
            assert_eq!(gui["can_start"], start);
            assert_eq!(gui["can_stop"], stop);
            assert_eq!(gui["nodes"]["rows"], json!([]));
            assert!(gui["queue"].is_null());
        }
    }

    #[test]
    fn member_rows_join_presence_directory_and_transport_by_id() {
        let mut status = json!({
            "daemon":{"running":true},
            "members":[
                {"id":"local","name":"Laptop","is_owner":true,"status":"local"},
                {"id":"web","name":"Claude","status":"hosted","hosted_by":"local",
                 "transport":{"carrier_id":"local","last":{"path":"direct_quic"}}},
                {"id":"peer","name":"Studio","can_configure":true,"status":"connected",
                 "transport":{"carrier_id":"peer","last":{"path":"relay_wss"}}},
                {"id":"other","name":"Studio","status":"disconnected"}
            ],
            "sync":{
                "records_waiting_to_send":0, "directory":{"known_chats":3,"peers":[
                    {"node_id":"peer","node_name":"old name","state":"matched"},
                    {"node_id":"web","state":"checking"},{"node_id":"removed","state":"matched"}]}
            }
        });
        let gui = snapshot(&status);
        assert_eq!(gui["queue"], 0);
        assert_eq!(gui["chats"], 3);
        assert_eq!(
            gui["nodes"]["rows"],
            json!([
                {"id":"local","name":"Laptop","state":"local","role":"Owner","host":null,"directory":null,"route":null},
                {"id":"web","name":"Claude","state":"hosted","role":"Member","host":"Laptop","directory":null,"route":null},
                {"id":"other","name":"Studio","state":"disconnected","role":"Member","host":null,"directory":null,"route":null},
                {"id":"peer","name":"Studio","state":"connected","role":"Admin","host":null,"directory":"matched","route":"Relay WebSocket"}
            ])
        );
        status["members"][1]["presence"]["reason"] = "awaiting_fresh_round_trip".into();
        assert_eq!(
            snapshot(&status)["nodes"]["rows"][1]["status_detail"],
            "Waiting for a fresh encrypted round trip."
        );
        status["members"][1]["hosted_by"] = "peer".into();
        assert_eq!(snapshot(&status)["nodes"]["rows"][1]["host"], "Studio");
    }

    #[test]
    fn directory_failure_preserves_health_and_offers_no_member_actions() {
        let status = snapshot(&json!({"daemon":{"running":true}, "sync":{"state":"idle"}}));
        assert_eq!(status["state"], "Running");
        assert_eq!(status["sync"], "idle");
        assert!(status["nodes"]["error"].is_string());
        assert_eq!(status["nodes"]["actions"], json!([]));
    }
}
