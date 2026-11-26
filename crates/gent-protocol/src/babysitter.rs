//! Host attribution for ordinary conversation recovery.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CHAT_FAILURE_MAX_AGE: i64 = 10 * 60;
pub const CHAT_CHAIN_MAX_AGE: i64 = 30 * 60;
/// Maximum number of client IDs on one chat claim, including the original.
pub const MAX_CHAT_INPUTS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChatOrigin {
    Operator {
        turn: Uuid,
        started_at: i64,
        client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        additional_client_ids: Vec<String>,
    },
    /// Ordered, source-paired admissions on a native user-started root.
    ForegroundInputs(ForegroundInputs),
    /// A named host handoff whose every user input was a journaled notification.
    DirectHandoff {
        item: Uuid,
        proof: ForegroundInputs,
    },
    ThreadHandoff {
        item: Uuid,
        started_at: i64,
    },
    Continuation {
        attempt: Uuid,
    },
    // Keep old single-input continuations wire compatible. Older daemons must
    // reject this proof in full instead of dropping its additional input IDs.
    SteeredContinuation {
        attempt: Uuid,
        root: Uuid,
        parent: Uuid,
        parent_failed_at: i64,
        started_at: i64,
        additional_client_ids: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForegroundInputs {
    pub thread: Uuid,
    pub turn: Uuid,
    pub started_at: i64,
    pub inputs: Vec<ForegroundInput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForegroundInput {
    pub client: Uuid,
    pub sha256: String,
    pub received_at_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_operator_origins_keep_the_single_input_wire_format() {
        let turn = Uuid::new_v4();
        let mut wire = json!({"kind":"operator","turn":turn,"started_at":42});
        for client_id in [None, Some("first")] {
            if let Some(id) = client_id {
                wire["client_id"] = json!(id);
            }
            let origin: ChatOrigin = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(
                origin,
                ChatOrigin::Operator {
                    turn,
                    started_at: 42,
                    client_id: client_id.map(String::from),
                    additional_client_ids: vec![],
                }
            );
            let mut expected = wire.clone();
            expected["client_id"] = json!(client_id);
            assert_eq!(serde_json::to_value(origin).unwrap(), expected);
        }
    }

    #[test]
    fn multi_input_operator_origin_preserves_all_client_ids_in_order() {
        let wire = json!({"kind":"operator","turn":Uuid::new_v4(),"started_at":42,
                          "client_id":"first","additional_client_ids":["second","third"]});
        let origin: ChatOrigin = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(origin).unwrap(), wire);
    }
}
