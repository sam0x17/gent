//! Process-local observations only. They do not authorize delivery or prove a
//! peer has read a message, and restart discards previous observations.
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

#[derive(Default)]
pub(crate) struct Health {
    pub(crate) connected: Arc<AtomicBool>,
    pass: Mutex<Pass>,
}
#[derive(Default, Serialize)]
struct Pass {
    observed_at: Option<i64>,
    last_success_at: Option<i64>,
    last_failure_at: Option<i64>,
    retrying_streams: usize,
    local_error: bool,
}
impl Health {
    pub(super) fn observe(
        &self,
        now: i64,
        successes: usize,
        failures: usize,
        retrying: usize,
        local_error: bool,
    ) {
        let mut pass = self.pass.lock().expect("sync health lock poisoned");
        pass.observed_at = Some(now);
        if successes > 0 {
            pass.last_success_at = Some(now);
        }
        if failures > 0 || local_error {
            pass.last_failure_at = Some(now);
        }
        pass.retrying_streams = retrying;
        pass.local_error = local_error;
    }
    pub(crate) fn snapshot(&self) -> Value {
        let pass = self.pass.lock().expect("sync health lock poisoned");
        let mut value = json!(*pass);
        value["notifications_connected"] = json!(self.connected.load(Ordering::SeqCst));
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_passes_do_not_claim_contact_and_failures_remain_visible_until_recovery() {
        let health = Health::default();
        health.observe(10, 0, 0, 0, false);
        assert_eq!(health.snapshot()["last_success_at"], Value::Null);
        health.observe(11, 1, 1, 1, false);
        assert_eq!(health.snapshot()["retrying_streams"], 1);
        health.observe(12, 0, 0, 1, false);
        assert_eq!(health.snapshot()["last_failure_at"], 11);
        health.observe(13, 1, 0, 0, false);
        assert_eq!(health.snapshot()["last_success_at"], 13);
        assert_eq!(health.snapshot()["retrying_streams"], 0);
    }
}
