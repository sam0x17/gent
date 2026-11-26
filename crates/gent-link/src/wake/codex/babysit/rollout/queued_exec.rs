//! Named exec outputs can arrive after the primary result, even in the next
//! queued turn. Walk backwards to the original scoped call and primary result.
use std::collections::HashSet;

#[derive(Default)]
pub(super) struct Queue {
    pub(super) clients: HashSet<String>,
    pending: HashSet<String>,
    calls: HashSet<String>,
    items: HashSet<String>,
}

impl Queue {
    pub(super) fn bound(&self) -> bool {
        self.pending.is_empty()
    }

    pub(super) fn admit(&mut self, client: String, turn: Turn) -> bool {
        if self.clients.contains(&client)
            || !self.pending.is_subset(&turn.pairs)
            || !self.calls.is_disjoint(&turn.calls)
            || !self.items.is_disjoint(&turn.items)
            || !turn.pending.is_disjoint(&self.calls)
        {
            return false;
        }
        self.clients.insert(client);
        self.pending = turn.pending;
        self.calls.extend(turn.calls);
        self.items.extend(turn.items);
        true
    }
}

#[derive(Default)]
pub(super) struct Turn {
    pending: HashSet<String>,
    pairs: HashSet<String>,
    calls: HashSet<String>,
    items: HashSet<String>,
}

impl Turn {
    pub(super) fn output_id(&mut self, id: &str, call: &str) -> bool {
        !id.is_empty() && id != call && self.items.insert(id.into())
    }

    pub(super) fn supplement(&mut self, call: String) -> bool {
        if self.calls.contains(&call) {
            return false;
        }
        self.pending.insert(call);
        true
    }

    pub(super) fn call(&mut self, call: &str, paired_exec: bool) -> bool {
        if !self.calls.insert(call.into()) {
            return false;
        }
        if paired_exec {
            self.pending.remove(call);
            self.pairs.insert(call.into());
        }
        !self.pending.contains(call)
    }
}
