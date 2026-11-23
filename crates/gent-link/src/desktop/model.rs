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
    let routes: HashMap<_, _> = sync["peer_transports"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|peer| {
            Some((
                peer["carrier_id"].as_str()?,
                route(peer["last"]["path"].as_str()?),
            ))
        })
        .collect();
    let members: HashMap<_, _> = status["members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|m| Some((m["id"].as_str()?, m)))
        .collect();
    let mut peers: Vec<_> = sync["directory"]["peers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|peer| {
            peer["node_id"]
                .as_str()
                .and_then(|id| members.get(id))
                .is_none_or(|m| m["hosted_by"].is_null())
        })
        .map(|peer| {
            json!({
                "name": peer["node_name"],
                "state": peer["state"],
                "route": peer["node_id"].as_str().and_then(|id| routes.get(id)),
            })
        })
        .collect();
    for member in status["members"].as_array().into_iter().flatten() {
        if let Some(host) = member["hosted_by"].as_str() {
            let carrier = members
                .get(host)
                .and_then(|m| m["name"].as_str())
                .unwrap_or(host);
            peers.push(json!({"name":member["name"],"state":member["status"],"route":format!("Hosted by {carrier}")}));
        }
    }
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
    json!({
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
        "peers": peers,
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
            assert_eq!(gui["peers"], json!([]));
            assert!(gui["queue"].is_null());
        }
    }

    #[test]
    fn status_includes_hosted_members_without_native_streams() {
        let value = snapshot(
            &json!({"members":[{"id":"n","name":"Studio"},{"name":"claude-web","status":"connected","hosted_by":"n"}]}),
        );
        assert_eq!(
            value["peers"],
            json!([{"name":"claude-web","state":"connected","route":"Hosted by Studio"}])
        );
    }

    #[test]
    fn status_uses_current_carrier_when_a_cached_peer_entry_exists() {
        let mut status = json!({
            "members":[{"id":"a","name":"Laptop"},{"id":"b","name":"Studio"},
                       {"id":"w","name":"claude-web","status":"unknown","hosted_by":"a"}],
            "sync":{"directory":{"peers":[{"node_id":"w","node_name":"claude-web","state":"matched"}]}}
        });
        assert_eq!(
            snapshot(&status)["peers"],
            json!([{"name":"claude-web","state":"unknown","route":"Hosted by Laptop"}])
        );
        status["members"][2]["hosted_by"] = json!("b");
        assert_eq!(snapshot(&status)["peers"][0]["route"], "Hosted by Studio");
    }

    #[test]
    fn only_attributes_transport_to_its_observed_peer() {
        let gui = snapshot(&json!({"sync": {
            "directory": {"known_chats": 3, "peers": [
                {"node_id": "a", "node_name": "A", "state": "matched"},
                {"node_id": "b", "node_name": "B", "state": "checking"}
            ]},
            "peer_transports": [{"carrier_id": "b", "last": {"path": "relay_wss"}}],
            "records_waiting_to_send": 0
        }}));
        assert!(gui["peers"][0]["route"].is_null());
        assert_eq!(gui["peers"][1]["route"], "Relay WebSocket");
        assert_eq!(gui["queue"], 0);
        assert_eq!(gui["chats"], 3);
    }
}
