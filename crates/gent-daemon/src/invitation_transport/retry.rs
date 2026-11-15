//! Relay delays are availability hints, never authority or delivery evidence.
use anyhow::{Result, anyhow};
use reqwest::{StatusCode, header};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use tokio::time::Instant;

pub(super) const MAX_DELAY: Duration = Duration::from_secs(120);
const DEFAULT_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub(super) enum Lane {
    Data = 0,
    Control = 1,
}

#[derive(Debug)]
struct Deferred {
    until: Instant,
}
impl std::fmt::Display for Deferred {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let delay = self.until.saturating_duration_since(Instant::now());
        let seconds = delay.as_secs() + u64::from(delay.subsec_nanos() != 0);
        write!(
            f,
            "invitation relay temporarily unavailable; retry in {seconds} seconds"
        )
    }
}
impl std::error::Error for Deferred {}

pub(super) fn until(error: &anyhow::Error) -> Option<Instant> {
    error.downcast_ref::<Deferred>().map(|error| error.until)
}

fn delay(headers: &header::HeaderMap, now: SystemTime) -> Duration {
    let mut values = headers.get_all(header::RETRY_AFTER).iter();
    let first = values.next();
    if values.next().is_some() {
        return DEFAULT_DELAY;
    }
    let parsed = first.and_then(|value| {
        let value = value.to_str().ok()?;
        if value.is_empty() || value.len() > 128 {
            return None;
        }
        if value.bytes().all(|byte| byte.is_ascii_digit()) {
            // Arbitrarily long decimal values are bounded without overflowing.
            let seconds = value.bytes().fold(0u64, |seconds, byte| {
                seconds
                    .saturating_mul(10)
                    .saturating_add(u64::from(byte - b'0'))
            });
            Some(Duration::from_secs(seconds))
        } else {
            Some(
                httpdate::parse_http_date(value)
                    .ok()?
                    .duration_since(now)
                    .unwrap_or_default(),
            )
        }
    });
    parsed
        .unwrap_or(DEFAULT_DELAY)
        .clamp(Duration::from_secs(1), MAX_DELAY)
}

#[derive(Clone, Default)]
pub(super) struct Backoff {
    deadlines: Arc<Mutex<[Option<Instant>; 2]>>,
}
impl Backoff {
    pub(super) fn check(&self, lane: Lane) -> Result<()> {
        let deadlines = self
            .deadlines
            .lock()
            .map_err(|_| anyhow!("invitation retry state unavailable"))?;
        if let Some(until) = deadlines[lane as usize].filter(|until| *until > Instant::now()) {
            return Err(Deferred { until }.into());
        }
        Ok(())
    }

    pub(super) fn observe(&self, lane: Lane, response: &reqwest::Response) -> Result<()> {
        if response.status() != StatusCode::TOO_MANY_REQUESTS
            && !(response.status() == StatusCode::SERVICE_UNAVAILABLE
                && response.headers().contains_key(header::RETRY_AFTER))
        {
            return Ok(());
        }
        let until = Instant::now() + delay(response.headers(), SystemTime::now());
        let mut deadlines = self
            .deadlines
            .lock()
            .map_err(|_| anyhow!("invitation retry state unavailable"))?;
        let until = deadlines[lane as usize].map_or(until, |previous| previous.max(until));
        deadlines[lane as usize] = Some(until);
        Err(Deferred { until }.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delays_are_bounded_and_never_reflect_untrusted_headers() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let mut headers = header::HeaderMap::new();
        assert_eq!(delay(&headers, now), DEFAULT_DELAY);
        for (value, seconds) in [
            ("0", 1),
            ("60", 60),
            ("999999999999999999999", 120),
            ("-1", 5),
            ("private reflected value", 5),
        ] {
            headers.insert(header::RETRY_AFTER, value.parse().unwrap());
            assert_eq!(delay(&headers, now), Duration::from_secs(seconds));
        }
        headers.insert(
            header::RETRY_AFTER,
            httpdate::fmt_http_date(now + Duration::from_secs(70))
                .parse()
                .unwrap(),
        );
        assert_eq!(delay(&headers, now), Duration::from_secs(70));
        headers.insert(
            header::RETRY_AFTER,
            httpdate::fmt_http_date(now - Duration::from_secs(70))
                .parse()
                .unwrap(),
        );
        assert_eq!(delay(&headers, now), Duration::from_secs(1));
        headers.append(header::RETRY_AFTER, "120".parse().unwrap());
        assert_eq!(delay(&headers, now), DEFAULT_DELAY);
    }

    #[test]
    fn clones_share_cooldowns_without_blocking_other_traffic_or_shortening_a_delay() {
        let backoff = Backoff::default();
        let until = Instant::now() + Duration::from_secs(60);
        backoff.deadlines.lock().unwrap()[Lane::Data as usize] = Some(until);
        let copy = backoff.clone();
        let response = reqwest::Response::from(
            tokio_tungstenite::tungstenite::http::Response::builder()
                .status(429)
                .header("Retry-After", "1")
                .body("")
                .unwrap(),
        );
        assert_eq!(
            super::until(&copy.observe(Lane::Data, &response).unwrap_err()),
            Some(until)
        );
        assert_eq!(
            super::until(&copy.check(Lane::Data).unwrap_err()),
            Some(until)
        );
        assert!(copy.check(Lane::Control).is_ok());
        assert!(Backoff::default().check(Lane::Data).is_ok());
        backoff.deadlines.lock().unwrap()[Lane::Data as usize] =
            Some(Instant::now() - Duration::from_secs(1));
        assert!(copy.check(Lane::Data).is_ok());
    }

    #[test]
    fn throttling_is_temporary_but_permission_and_sequence_refusals_remain_fatal() {
        use crate::invitation_transport::{Refusal, fatal};
        for code in [429, 500, 503] {
            assert!(!fatal(&Refusal(StatusCode::from_u16(code).unwrap()).into()));
        }
        for code in [400, 401, 403, 409, 410] {
            assert!(fatal(&Refusal(StatusCode::from_u16(code).unwrap()).into()));
        }
    }
}
