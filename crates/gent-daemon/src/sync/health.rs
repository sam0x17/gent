//! Process-local observations only. They do not authorize delivery or prove a
//! peer has read a message, and restart discards previous observations.
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub(crate) struct Health {
    pub(crate) connected: Arc<AtomicBool>,
    pass: Mutex<Pass>,
    exchange: Mutex<Option<Arc<super::exchange::Exchange>>>,
    direct: Mutex<Option<Arc<super::direct::Metrics>>>,
}
#[derive(Default, Serialize)]
struct Pass {
    observed_at: Option<i64>,
    last_success_at: Option<i64>,
    last_failure_at: Option<i64>,
    retrying_streams: usize,
    local_error: bool,
    control_error: bool,
    connecting: bool,
    packets_sent: u64,
    packets_received: u64,
    last_progress_at: Option<i64>,
    cycle_duration_ms: Option<u64>,
    watch_reconnects: u64,
    watch_last_error: Option<String>,
    watch_last_connection_ms: Option<u64>,
    #[serde(skip)]
    transferring: BTreeSet<Vec<u8>>,
}
impl Health {
    pub(super) fn set_direct(&self, metrics: Arc<super::direct::Metrics>) {
        *self.direct.lock().expect("direct metrics poisoned") = Some(metrics);
    }
    pub(super) fn set_exchange(&self, exchange: Option<Arc<super::exchange::Exchange>>) {
        *self.exchange.lock().expect("sync metrics poisoned") = exchange;
    }
    pub(super) fn watch_ended(&self, reason: Option<&str>, elapsed: std::time::Duration) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.watch_reconnects = pass.watch_reconnects.saturating_add(1);
        pass.watch_last_error = reason.map(str::to_owned);
        pass.watch_last_connection_ms = Some(elapsed.as_millis().try_into().unwrap_or(u64::MAX));
    }
    pub(super) fn cycle_completed(&self, elapsed: std::time::Duration) {
        self.pass
            .lock()
            .expect("sync health lock poisoned")
            .cycle_duration_ms = Some(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX));
    }

    pub(super) fn retain(&self, streams: &[super::Stream], connecting: bool) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.transferring
            .retain(|group| streams.iter().any(|stream| &stream.group == group));
        pass.connecting = connecting;
    }

    pub(super) fn progress(&self, group: &[u8], outgoing: bool, now: i64) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.last_progress_at = Some(now);
        pass.transferring.insert(group.to_vec());
        if outgoing {
            pass.packets_sent = pass.packets_sent.saturating_add(1);
        } else {
            pass.packets_received = pass.packets_received.saturating_add(1);
        }
    }

    pub(super) fn idle(&self, group: &[u8]) {
        self.pass
            .lock()
            .expect("sync health lock poisoned")
            .transferring
            .remove(group);
    }

    pub(super) fn observe(
        &self,
        now: i64,
        successes: usize,
        failures: usize,
        retrying: usize,
        local_error: bool,
        control_error: bool,
    ) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.observed_at = Some(now);
        if successes > 0 {
            pass.last_success_at = Some(now);
        }
        if failures > 0 || local_error || control_error {
            pass.last_failure_at = Some(now);
        }
        pass.retrying_streams = retrying;
        pass.local_error = local_error;
        pass.control_error = control_error;
    }
    pub(crate) fn snapshot(&self) -> Value {
        let pass = self.pass.lock().expect("sync health lock poisoned");
        let mut value = json!(*pass);
        value["transferring_streams"] = json!(pass.transferring.len());
        value["notifications_connected"] = json!(self.connected.load(Ordering::SeqCst));
        if let Some(direct) = self
            .direct
            .lock()
            .expect("direct metrics poisoned")
            .as_ref()
        {
            value["direct_traffic"] = direct.snapshot();
        }
        if let Some(exchange) = self
            .exchange
            .lock()
            .expect("sync metrics poisoned")
            .as_ref()
        {
            value["relay_traffic"] = exchange.snapshot();
        }
        value
    }

    pub(crate) fn status(&self, configured: bool, fresh: bool, queued: u64) -> Value {
        let mut value = self.snapshot();
        let state = if !configured {
            "disabled"
        } else if !fresh {
            "waiting_for_authority"
        } else if value["control_error"] == true
            || value["local_error"] == true
            || value["retrying_streams"].as_u64().unwrap_or(0) > 0
        {
            "retrying"
        } else if queued > 0 || value["transferring_streams"].as_u64().unwrap_or(0) > 0 {
            "syncing"
        } else if value["connecting"] == true {
            "connecting"
        } else if value["observed_at"].is_null() {
            "starting"
        } else {
            "idle"
        };
        value["state"] = json!(state);
        value["records_waiting_to_send"] = json!(queued);
        value["scope"] = json!(
            "Local transport observations; idle means no known backlog, not a complete cluster directory. Packet counters reset when the daemon starts."
        );
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_passes_do_not_claim_contact_and_failures_remain_visible_until_recovery() {
        let health = Health::default();
        health.observe(10, 0, 0, 0, false, false);
        assert_eq!(health.snapshot()["last_success_at"], Value::Null);
        health.observe(11, 1, 1, 1, false, false);
        assert_eq!(health.snapshot()["retrying_streams"], 1);
        health.observe(12, 0, 0, 1, false, false);
        assert_eq!(health.snapshot()["last_failure_at"], 11);
        health.observe(13, 1, 0, 0, false, false);
        assert_eq!(health.snapshot()["last_success_at"], 13);
        assert_eq!(health.snapshot()["retrying_streams"], 0);
    }
    #[test]
    fn sync_status_reports_backlog_failures_authority_and_process_local_progress() {
        let health = Health::default();
        assert_eq!(health.status(false, true, 0)["state"], "disabled");
        assert_eq!(health.status(true, true, 0)["state"], "starting");
        health.observe(1, 1, 0, 0, false, false);
        assert_eq!(health.status(true, true, 0)["state"], "idle");
        assert_eq!(health.status(true, true, 2)["state"], "syncing");
        health.progress(b"stream", false, 2);
        assert_eq!(health.status(true, true, 0)["state"], "syncing");
        assert_eq!(health.status(true, true, 0)["packets_received"], 1);
        health.retain(&[], true);
        assert_eq!(health.status(true, true, 0)["state"], "connecting");
        health.observe(3, 1, 0, 0, false, true);
        assert_eq!(health.status(true, true, 0)["state"], "retrying");
        assert_eq!(
            health.status(true, false, 0)["state"],
            "waiting_for_authority"
        );
        health.observe(4, 1, 0, 0, false, false);
        health.retain(&[], false);
        assert_eq!(health.status(true, true, 0)["state"], "idle");
        assert_eq!(Health::default().snapshot()["packets_received"], 0);
    }
}
