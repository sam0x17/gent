use super::*;
use gent_protocol::wake::{DirectWake, WakeState};
use sha2::{Digest, Sha256};

fn fixture() -> (WakeRecord, Value) {
    let attempt = uuid::Uuid::new_v4().to_string();
    let record = WakeRecord {
        message_id: uuid::Uuid::now_v7().to_string(),
        agent: uuid::Uuid::new_v4().to_string(),
        attempt_id: attempt.clone(),
        target: WakeTarget::Codex {
            thread_id: uuid::Uuid::now_v7().to_string(),
        },
        state: WakeState::Uncertain,
        submission_id: None,
        inbox_seen_at: None,
        claimed_at: 1,
        updated_at: 1,
        direct: Some(DirectWake {
            reply_request_id: uuid::Uuid::now_v7().to_string(),
            input_hash: format!("{:x}", Sha256::digest(b"exact input")),
            turn_id: None,
            finished: false,
            response_hash: None,
            response_message_id: None,
        }),
    };
    let turn = json!({"id":uuid::Uuid::now_v7().to_string(),"status":"completed","items":[
        {"type":"userMessage","clientId":attempt,"content":[{"type":"text","text":"exact input"}]},
        {"type":"agentMessage","phase":"commentary","text":"preamble"},
        {"type":"agentMessage","phase":"final_answer","text":"final response"}
    ]});
    (record, turn)
}

#[test]
fn direct_capture_requires_exact_input_identity_even_with_steered_turns() {
    let (record, turn) = fixture();
    assert!(matched(&turn, &record).unwrap());
    for field in ["text", "client", "mixed", "file"] {
        let mut turn = turn.clone();
        match field {
            "text" => turn["items"][0]["content"][0]["text"] = json!("different input"),
            "client" => turn["items"][0]["clientId"] = json!(uuid::Uuid::new_v4().to_string()),
            "mixed" => {
                let other = turn["items"][0].clone();
                turn["items"].as_array_mut().unwrap().push(other);
            }
            _ => turn["items"][0]["content"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type":"image"})),
        }
        assert!(!matched(&turn, &record).unwrap(), "{field}");
    }
}

#[test]
fn final_capture_excludes_preambles_partial_output_and_unsupported_host_results() {
    let (_, mut turn) = fixture();
    assert_eq!(answer(&turn).unwrap().as_deref(), Some("final response"));
    let mut empty = turn.clone();
    empty["items"][2]["text"] = json!("");
    assert!(
        answer(&empty)
            .unwrap()
            .unwrap()
            .contains("without a text response")
    );
    turn["status"] = json!("inProgress");
    assert!(answer(&turn).unwrap().is_none());
    for status in ["failed", "interrupted"] {
        turn["status"] = json!(status);
        assert!(answer(&turn).unwrap().unwrap().contains("not repeated"));
    }
    turn["status"] = json!("completed");
    for (key, value) in [
        ("delivery", json!({"kind":"async"})),
        ("moderation", json!({"moderated":true})),
        ("questions", json!([])),
    ] {
        let mut changed = turn.clone();
        changed["items"][2][key] = value;
        assert!(answer(&changed).is_err());
    }
    turn["items"][2]["phase"] = Value::Null;
    assert_eq!(answer(&turn).unwrap().as_deref(), Some("final response"));
    turn["items"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"mcpToolCall"}));
    assert!(
        answer(&turn)
            .unwrap()
            .unwrap()
            .contains("without a text response")
    );
}

#[test]
fn steered_input_is_observed_but_mixed_work_is_not_automatically_forwarded() {
    let (record, mut turn) = fixture();
    assert!(isolated(&turn));
    turn["items"].as_array_mut().unwrap().insert(
        0,
        json!({
            "type":"userMessage", "clientId":uuid::Uuid::new_v4().to_string(),
            "content":[{"type":"text","text":"Unrelated private work"}]
        }),
    );
    assert!(matched(&turn, &record).unwrap());
    assert!(!isolated(&turn));
    turn["items"][1]["clientId"] = json!(uuid::Uuid::new_v4().to_string());
    assert!(!matched(&turn, &record).unwrap());
}
