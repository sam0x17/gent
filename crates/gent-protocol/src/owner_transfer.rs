//! Local-owner RPC only. Agents cannot issue signing-owner transfers.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerTransferOp {
    Prepare { request_id: String, node_id: String },
    Status { request_id: Option<String> },
    Commit { request_id: String },
    Resume { request_id: String },
}
