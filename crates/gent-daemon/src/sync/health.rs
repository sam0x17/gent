//! Process-local observations only. They do not authorize delivery or prove a
//! peer has read a message, and restart discards previous observations.
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "path", rename_all = "snake_case")]
pub(crate) enum TransportPath {
    DirectQuic,
    ClusterHelper { helper_id: String },
    ConfiguredRelay,
    QuicUnknown,
    QuicMixed,
    RelayWss,
    Mailbox,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransportEvidence {
    ReceivedPacket,
    SignedReceipt,
    MailboxUpload,
}

#[derive(Serialize)]
struct Observation {
    #[serde(flatten)]
    path: TransportPath,
    evidence: TransportEvidence,
    sequence: u64,
    observed_at: i64,
    #[serde(skip)]
    order: u64,
}

#[derive(Default)]
pub(crate) struct Health {
    pub(crate) connected: Arc<AtomicBool>,
    pub(crate) verify_watch: tokio::sync::Notify,
    pass: Mutex<Pass>,
    wss: Mutex<Option<Arc<super::notifications::wss::Metrics>>>,
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
    sweep_http_requests: u64,
    sweep_request_body_bytes: u64,
    sweep_response_body_bytes: u64,
    sweep_current_streams: u64,
    watch_reconnects: u64,
    watch_last_error: Option<String>,
    watch_last_connection_ms: Option<u64>,
    #[serde(skip)]
    transferring: BTreeSet<Vec<u8>>,
    #[serde(skip)]
    transport: BTreeMap<Vec<u8>, BTreeMap<TransportEvidence, Observation>>,
    #[serde(skip)]
    observation_order: u64,
}
impl Health {
    /// Call only after packet acceptance, a verified receipt, or acknowledged mailbox storage.
    pub(crate) fn record_transport(
        &self,
        group: &[u8],
        path: TransportPath,
        evidence: TransportEvidence,
        sequence: u64,
    ) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.observation_order += 1;
        let observation = Observation {
            path,
            evidence,
            sequence,
            observed_at: crate::store::now(),
            order: pass.observation_order,
        };
        pass.transport
            .entry(group.to_vec())
            .or_default()
            .insert(evidence, observation);
    }

    /// Resolve observations only through the carrier's currently pinned data-link groups.
    pub(crate) fn peer_transport(&self, carrier: &str, groups: Option<(&[u8], &[u8])>) -> Value {
        use TransportEvidence::*;
        let pass = self.pass.lock().expect("sync health lock poisoned");
        let incoming = groups.and_then(|(rx, _)| pass.transport.get(rx));
        let outgoing = groups.and_then(|(_, tx)| pass.transport.get(tx));
        let received = incoming.and_then(|events| events.get(&ReceivedPacket));
        let receipt = outgoing.and_then(|events| events.get(&SignedReceipt));
        let upload = outgoing.and_then(|events| events.get(&MailboxUpload));
        let last = [received, receipt, upload]
            .into_iter()
            .flatten()
            .max_by_key(|event| event.order);
        json!({"carrier_id":carrier,"last":last,"last_received_packet":received,
               "last_signed_receipt":receipt,"last_mailbox_upload":upload})
    }
    pub(super) fn sweep_request(&self, bytes: usize) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.sweep_http_requests += 1;
        pass.sweep_request_body_bytes += bytes as u64;
    }
    pub(super) fn sweep_reply(&self, bytes: usize, current: u32) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.sweep_response_body_bytes += bytes as u64;
        pass.sweep_current_streams += u64::from(current);
    }
    pub(super) fn set_wss(&self, metrics: Arc<super::notifications::wss::Metrics>) {
        *self.wss.lock().expect("peer watch metrics poisoned") = Some(metrics);
    }
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
        if !pass.transport.is_empty() {
            let groups: BTreeSet<&[u8]> = streams
                .iter()
                .filter(|s| !s.configuration)
                .map(|s| s.group.as_slice())
                .collect();
            pass.transport
                .retain(|group, _| groups.contains(group.as_slice()));
        }
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
        if let Some(wss) = self
            .wss
            .lock()
            .expect("peer watch metrics poisoned")
            .as_ref()
        {
            value["wss_traffic"] = wss.snapshot();
        }
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
    fn transport_evidence_follows_pinned_streams_and_orders_same_second_observations() {
        use TransportEvidence::*;
        use TransportPath::*;
        let health = Health::default();
        let inspect = || health.peer_transport("carrier", Some((b"rx", b"tx")));
        health.record_transport(b"tx", DirectQuic, SignedReceipt, 17);
        health.record_transport(b"rx", QuicMixed, ReceivedPacket, 3);
        health.record_transport(b"tx", Mailbox, MailboxUpload, 18);
        let observed = inspect();
        assert_eq!(observed["last"]["evidence"], "mailbox_upload");
        assert_eq!(observed["last_signed_receipt"]["path"], "direct_quic");
        assert_eq!(observed["last_received_packet"]["path"], "quic_mixed");
        assert!(health.peer_transport("new carrier", None)["last"].is_null());
        assert!(health.peer_transport("carrier", Some((b"new rx", b"new tx")))["last"].is_null());
        health.retain(&[], false);
        assert!(inspect()["last"].is_null());
    }
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
