//! A measured home belongs to one TLS session. Native renewal can extend
//! its use after idle MLS locator expiry, without publishing another locator.
use super::super::helper_service::lease::{self, Grant};
use super::*;

#[derive(Clone)]
pub(super) struct Authority {
    pub(super) offer: Arc<HelperOffer>,
    pub(super) operator: (EndpointId, [u8; 32]),
    pub(super) locator: watch::Receiver<i64>,
}

pub(super) use lease::deadline;

struct Authorization {
    deadline: watch::Sender<Option<Instant>>,
    grant: Option<Grant>,
    retry: Instant,
}

/// One immutable helper, TLS certificate and alias per auxiliary. Iroh's
/// closed counter changes even when a latest-value watcher coalesces a close
/// and a reconnect to that same alias.
pub(super) struct Home {
    session: Option<u64>,
    rtt_ms: Option<u32>,
    initial: bool,
    authorization: Option<Authorization>,
    retired: bool,
}

impl Default for Home {
    fn default() -> Self {
        Self {
            session: None,
            rtt_ms: None,
            initial: true,
            authorization: None,
            retired: false,
        }
    }
}

impl Home {
    fn measured(&self, session: u64) -> Option<u32> {
        self.rtt_ms.filter(|_| self.session == Some(session))
    }

    pub(super) fn observe(
        &mut self,
        session: Option<u64>,
        rtt: Option<u32>,
        new_report: bool,
    ) -> bool {
        let previous = self.rtt_ms;
        let same = session == self.session;
        if !same {
            self.retired = false;
            self.rtt_ms = None;
            self.authorization = None;
        }
        if let Some(closed) = session {
            // The initial probe can precede registration. After any close,
            // discard the reconnect-time snapshot and wait for a new report.
            if ((self.initial && closed == 0) || (same && new_report))
                && let Some(ms) = rtt
                && self
                    .rtt_ms
                    .is_none_or(|old| old.abs_diff(ms) > (old / 5).max(2))
            {
                self.rtt_ms = Some(ms);
            }
            self.initial = false;
        }
        self.session = session;
        previous != self.rtt_ms
    }
}

impl Home {
    fn active_deadline(&self) -> Option<Instant> {
        (*self.authorization.as_ref()?.deadline.borrow()).filter(|t| *t > Instant::now())
    }

    fn authorize(&mut self, expiry: i64) {
        if self
            .authorization
            .as_ref()
            .and_then(|a| a.grant.as_ref())
            .is_some_and(|g| g.until <= Instant::now())
        {
            self.retired = true;
        }
        if self.rtt_ms.is_none() || self.retired {
            self.authorization = None;
            return;
        }
        // A deadline channel is never reopened after expiry or a socket change.
        if self.active_deadline().is_none() {
            self.authorization = None;
        }
        let from_locator = deadline(expiry);
        let from_grant = self
            .authorization
            .as_ref()
            .and_then(|a| a.grant.as_ref())
            .map(|g| g.until);
        let Some(until) = from_grant.or(from_locator).filter(|d| *d > Instant::now()) else {
            return;
        };
        let auth = self.authorization.get_or_insert_with(|| Authorization {
            deadline: watch::channel(None).0,
            grant: None,
            retry: Instant::now() + Duration::from_secs(6),
        });
        auth.deadline.send_if_modified(|old| {
            // Wall-clock conversion can differ by nanoseconds for the same
            // signed deadline. Renewal needs no wakeup outside this channel.
            if old.is_some_and(|value| {
                value.max(until).duration_since(value.min(until)) < Duration::from_millis(1)
            }) {
                return false;
            }
            *old = Some(until);
            true
        });
    }
}

impl Auxiliary {
    fn home_session(&self) -> Option<u64> {
        let closed = self.endpoint.metrics().socket.relay_conns_closed.get();
        self.endpoint
            .home_relay_status()
            .get()
            .iter()
            .any(|s| s.url() == &self.relay_config.url && s.is_connected())
            .then_some(closed)
    }

    pub(super) fn registration(&self) -> Option<HelperRegistration> {
        if !*self.active.borrow() {
            return None;
        }
        let home = self.home.lock().expect("helper registration poisoned");
        let session = self.home_session()?;
        let rtt_ms = home.measured(session)?;
        home.active_deadline()?;
        Some(HelperRegistration {
            helper_node: self.offer.helper_node.clone(),
            generation: self.offer.generation,
            url: self.relay_config.url.clone(),
            rtt_ms,
        })
    }

    pub(super) fn update_registration(
        &self,
        report: Option<&iroh::unstable_net_report::NetReport>,
        new_report: bool,
    ) -> bool {
        let mut home = self.home.lock().expect("helper registration poisoned");
        if !*self.active.borrow() {
            return false;
        }
        let rtt = report
            .and_then(|r| {
                r.relay_latency
                    .iter()
                    .filter(|(_, url, _)| *url == &self.relay_config.url)
                    .map(|(_, _, rtt)| rtt)
                    .min()
            })
            .map(|rtt| rtt.as_millis().min(60_000) as u32);
        let old = home.authorization.is_some();
        let changed = home.observe(self.home_session(), rtt, new_report);
        home.authorize(*self.authority.locator.borrow());
        let change = (changed && old) || old != home.authorization.is_some();
        if change {
            self.home_changed.notify_one();
        }
        change
    }

    pub(super) fn withdraw_registration(&self) -> bool {
        let mut home = self.home.lock().expect("helper registration poisoned");
        let had_registration = home.authorization.is_some();
        self.home_changed.notify_one();
        *home = Home {
            initial: false,
            ..Home::default()
        };
        had_registration
    }

    pub(super) fn live_until(&self) -> Option<Instant> {
        let home = self.home.lock().expect("helper registration poisoned");
        home.measured(self.home_session()?)?;
        home.active_deadline()
    }

    pub(super) fn retained(&self) -> bool {
        let home = self.home.lock().expect("helper registration poisoned");
        home.session.is_some()
            && home.session == self.home_session()
            && home
                .authorization
                .as_ref()
                .and_then(|a| a.grant.as_ref())
                .is_some_and(|g| g.until > Instant::now())
    }

    pub(super) fn channel(&self, peer: EndpointId) -> Option<HelperChannel> {
        if !*self.active.borrow() {
            return None;
        }
        let home = self.home.lock().expect("helper registration poisoned");
        home.measured(self.home_session()?)?;
        home.active_deadline()?;
        Some(HelperChannel {
            local: self.endpoint.id(),
            peer,
            offer: self.offer.clone(),
            operator: self.authority.operator,
            lease: home.authorization.as_ref()?.deadline.subscribe(),
        })
    }

    pub(super) async fn renew_home(&self) {
        loop {
            let changed = self.home_changed.notified();
            let plan = {
                let home = self.home.lock().expect("helper registration poisoned");
                home.authorization.as_ref().and_then(|auth| {
                    let until = auth
                        .grant
                        .as_ref()
                        .map(|g| g.until)
                        .or_else(|| deadline(*self.authority.locator.borrow()))?;
                    Some((
                        home.session?,
                        auth.deadline.subscribe(),
                        auth.grant.clone(),
                        auth.retry,
                        until,
                    ))
                })
            };
            let Some((session, scope, previous, retry, until)) = plan else {
                changed.await;
                continue;
            };
            if until <= Instant::now() {
                changed.await;
                continue;
            }
            tokio::select! {
                _ = changed => continue,
                _ = tokio::time::sleep_until(retry.min(until)) => {}
            }
            if Instant::now() >= until {
                continue;
            }
            if !*self.active.borrow() || self.home_session() != Some(session) {
                self.home_changed.notified().await;
                continue;
            }
            let authorize = async {
                let offered = self.offer.clone();
                let operator = self.authority.operator;
                let current = local(self.store.clone(), move |s| s.helper_authority(&offered))
                    .await
                    .ok()??;
                if (current.0, current.1) != operator
                    || previous.is_none() && deadline(current.2).is_none()
                {
                    return None;
                }
                lease::renew(
                    self.endpoint.secret_key(),
                    &self.offer,
                    &self.relay_config.url,
                    previous.as_ref(),
                )
                .await
                .ok()
            };
            let renewed = tokio::time::timeout_at(
                until.min(Instant::now() + Duration::from_secs(3)),
                authorize,
            )
            .await
            .ok()
            .flatten();
            let mut home = self.home.lock().expect("helper registration poisoned");
            if self.home_session() != Some(session) || home.session != Some(session) {
                continue;
            }
            let Some(auth) = &mut home.authorization else {
                continue;
            };
            if !auth.deadline.subscribe().same_channel(&scope) {
                continue;
            }
            if let Some(mut grant) =
                renewed.filter(|g| g.until > Instant::now() && Instant::now() < until)
            {
                if previous.is_none() {
                    grant.until = grant.until.min(until);
                }
                let now = Instant::now();
                auth.retry = now
                    + (grant.until.saturating_duration_since(now) / 2).max(Duration::from_secs(1));
                auth.grant = Some(grant);
                self.reschedule.notify_one();
                home.authorize(*self.authority.locator.borrow());
            } else {
                auth.retry = Instant::now() + Duration::from_secs(12);
            }
        }
    }
}
