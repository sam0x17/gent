//! Read models for the owner-facing Gent statistics command and Desktop tab.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Traffic {
    pub messages: u64,
    pub bytes: u64,
    pub text_bytes: u64,
    pub attachment_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Sender {
    pub chat_id: String,
    pub name: String,
    #[serde(flatten)]
    pub traffic: Traffic,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Babysitter {
    pub ordinary_submitted: u64,
    pub goal_submitted: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tracking {
    pub tracking_started_at: i64,
    pub backfill: String,
    pub older_daemon_activity: String,
}

/// A physical node's contribution before ranking or merging chat IDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeContribution {
    pub node: Node,
    pub outbound: Traffic,
    pub senders: Vec<Sender>,
    pub babysitter: Babysitter,
    pub coverage: Tracking,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStats {
    pub node: Node,
    pub status: String,
    pub as_of: Option<i64>,
    pub outbound: Option<Traffic>,
    pub babysitter: Option<Babysitter>,
    pub coverage: Option<Tracking>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    pub expected_nodes: usize,
    pub reporting_nodes: usize,
    pub fresh_nodes: usize,
    pub complete: bool,
}

/// Counts from a bounded refresh, including the local node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refresh {
    pub confirmed_nodes: usize,
    pub expected_nodes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stats {
    pub scope: String,
    pub outbound: Traffic,
    pub babysitter: Babysitter,
    pub top_senders: Vec<Sender>,
    pub nodes: Vec<NodeStats>,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<Refresh>,
}
