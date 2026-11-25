//! A manual poll shares one fresh challenge per eligible physical peer. All
//! waiters observe the same completion and deadline without holding the Store.
use super::*;
use std::time::Duration;
use tokio::{sync::watch, time::Instant};

const COLLECT: Duration = Duration::from_secs(8);
const REUSE: Duration = Duration::from_secs(5);

pub(in crate::store) struct Poll {
    pub(super) id: Uuid,
    deadline: Instant,
    completed: watch::Sender<Option<Instant>>,
}

impl Poll {
    fn active(&self) -> bool {
        self.completed.borrow().is_none() && Instant::now() < self.deadline
    }

    fn reusable(&self) -> bool {
        Instant::now() < self.completed.borrow().unwrap_or(self.deadline) + REUSE
    }
}

pub(crate) struct StatsWait {
    id: Uuid,
    deadline: Instant,
    completed: watch::Receiver<Option<Instant>>,
    routes: watch::Receiver<usize>,
}

impl StatsWait {
    pub(crate) async fn wait(mut self, until: Instant) -> Uuid {
        tokio::select! {
            _ = self.completed.wait_for(Option::is_some) => {},
            _ = self.routes.wait_for(|n| *n == 0) => {},
            _ = tokio::time::sleep_until(until.min(self.deadline)) => {},
        }
        self.id
    }
}

impl Store {
    pub(crate) fn begin_stats_refresh(&mut self, credential: &str) -> Result<StatsWait> {
        self.require_owner_credential(credential)?;
        let routes = self.sync_health.stats.routes.subscribe();
        if self.stats_poll.as_ref().is_none_or(|p| !p.reusable()) {
            let connected = *routes.borrow() > 0
                && matches!(self.direct_settings()?.direct, config::Direct::Auto);
            let tx = self.db.transaction()?;
            tx.execute("DELETE FROM stats_poll", [])?;
            let state = self.identity.state(&tx)?;
            let at = now();
            let id = Uuid::new_v4();
            let round = id.to_string();
            if connected
                && state
                    .authorize_node(
                        self.identity.node.id(),
                        &self.identity.node.public_key(),
                        at as u64,
                    )
                    .is_ok()
            {
                let mut insert = tx.prepare(
                    "INSERT INTO stats_poll(peer,poll,key,probe,failed) SELECT l.peer,?6,l.peer_key,1,0 FROM network_links l
                     LEFT JOIN stats_peers s ON l.peer=s.peer AND l.peer_key=s.key
                     LEFT JOIN wire_peers w ON l.peer=w.peer AND l.peer_key=w.peer_key
                     WHERE l.peer=?1 AND l.peer_key=?2 AND
                       ((s.supported=1 AND (s.failed_at IS NULL OR s.failed_at<=?3))
                         OR (w.version>=?4 AND COALESCE(s.attempt_at,0)<=?5))",
                )?;
                for (id, member) in &state.state().nodes {
                    if member.hosted_by.is_none() && id != self.identity.node.id() {
                        insert.execute(params![
                            id,
                            member.signing_key.as_slice(),
                            at - COALESCE,
                            crate::messages::wire::MESSAGE_DATES_VERSION,
                            at,
                            round
                        ])?;
                    }
                }
            }
            tx.commit()?;
            self.stats_poll = Some(Poll {
                id,
                deadline: Instant::now() + COLLECT,
                completed: watch::Sender::default(),
            });
            self.check_stats_poll()?;
            if self.active_stats_poll().is_some() {
                self.sync_health.stats.tick.notify_one();
            }
        }
        let poll = self.stats_poll.as_ref().expect("initialized poll");
        Ok(StatsWait {
            id: poll.id,
            deadline: poll.deadline,
            completed: poll.completed.subscribe(),
            routes,
        })
    }

    pub(super) fn active_stats_poll(&self) -> Option<Uuid> {
        self.stats_poll
            .as_ref()
            .filter(|p| p.active())
            .map(|p| p.id)
    }

    pub(super) fn record_stats_confirmation(&self, tx: &Connection, peer: &str) -> Result<()> {
        if self.active_stats_poll().is_some() {
            tx.execute(
                "UPDATE stats_poll AS p SET confirmed=EXISTS(
                    SELECT 1 FROM stats_peers s WHERE s.peer=p.peer AND s.key=p.key
                    AND s.head=p.head AND s.round IS NULL)
                 WHERE peer=?1 AND failed=0",
                [peer],
            )?;
        }
        Ok(())
    }

    pub(super) fn check_stats_poll(&self) -> Result<()> {
        if let Some(poll) = self.stats_poll.as_ref().filter(|p| p.active()) {
            let pending = self.db.prepare(
                "SELECT 1 FROM stats_poll p JOIN network_links l ON l.peer=p.peer AND l.peer_key=p.key
                 WHERE p.failed=0 AND p.confirmed=0"
            )?.exists([])?;
            if !pending {
                poll.completed.send_replace(Some(Instant::now()));
            }
        }
        Ok(())
    }
}
