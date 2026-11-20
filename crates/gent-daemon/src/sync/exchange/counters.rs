use super::{Reply, binary};
use gent_protocol::transport_batch::{Batch, HEADER_BYTES};
use serde::Serialize;
use std::collections::BTreeMap;

/// Keep the label set fixed. Paths contain opaque mailbox names.
pub(super) fn classify(op: &binary::Operation) -> &'static str {
    let get = op.method == "GET";
    match (op.path.split('/').nth(4), get) {
        (None, _) => "position",
        (Some("state"), _) => "state",
        (Some("batch"), true) => "batch_read",
        (Some("batch"), false) => "batch_write",
        (Some("retire"), _) => "retire",
        (Some("checkpoint"), true) => "checkpoint_read",
        (Some("checkpoint"), false) => "checkpoint_write",
        (_, true) => "packet_read",
        (_, false) => "packet_write",
    }
}

#[derive(Default, Serialize)]
pub(super) struct Operations {
    completed: BTreeMap<&'static str, u64>,
    empty_batch_reads: u64,
    unchanged_checkpoint_writes: u64,
    failed: u64,
}

impl Operations {
    pub(super) fn observe(&mut self, kind: &'static str, reply: Option<&Reply>) {
        *self.completed.entry(kind).or_default() += 1;
        let Some(reply) = reply.filter(|r| r.status.is_success()) else {
            self.failed += 1;
            return;
        };
        if kind == "batch_read"
            && reply.body.len() == HEADER_BYTES
            && Batch::decode(&reply.body).is_ok_and(|batch| batch.packets().is_empty())
        {
            self.empty_batch_reads += 1;
        }
        if kind == "checkpoint_write" && reply.status.as_u16() == 204 {
            self.unchanged_checkpoint_writes += 1;
        }
    }
}
