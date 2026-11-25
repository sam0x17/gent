use super::*;
use gent_protocol::stats::{
    Babysitter, Coverage, Node, NodeStats, Refresh, Sender, Stats, Tracking, Traffic,
};

// Store owns one bounded result, keyed by the included contributions. Status,
// timestamps and names can change independently and are read in the transaction.
#[derive(PartialEq)]
struct Revisions {
    local: Option<Mark>,
    remote: Vec<(String, gent_crypto::PublicKey, String)>,
}

pub(in crate::store) struct Ranking {
    revisions: Revisions,
    local: Option<(Traffic, Babysitter, Tracking)>,
    top: Vec<Sender>,
}

fn add(target: &mut u64, n: u64) -> Result<()> {
    *target = target
        .checked_add(n)
        .context("statistics exceed supported range")?;
    Ok(())
}

fn accumulate(total: &mut Traffic, part: &Traffic) -> Result<()> {
    add(&mut total.messages, part.messages)?;
    add(&mut total.text_bytes, part.text_bytes)?;
    add(&mut total.attachment_bytes, part.attachment_bytes)?;
    add(&mut total.bytes, part.bytes)
}

impl StoreSession<'_> {
    fn rank_stats(&self, revisions: Revisions) -> Result<Ranking> {
        let mut senders = BTreeMap::<String, Traffic>::new();
        let local = if revisions.local.is_some() {
            let contribution = self.usage_stats_export()?;
            for sender in contribution.senders {
                senders.insert(sender.chat_id, sender.traffic);
            }
            Some((
                contribution.outbound,
                contribution.babysitter,
                contribution.coverage,
            ))
        } else {
            None
        };
        let mut query = self
            .db
            .prepare("SELECT chat,m,t,a FROM stats_remote WHERE peer=?1")?;
        for (peer, _, _) in &revisions.remote {
            let mut rows = query.query([peer])?;
            while let Some(r) = rows.next()? {
                let text_bytes: u64 = r.get(2)?;
                let attachment_bytes: u64 = r.get(3)?;
                let part = Traffic {
                    messages: r.get(1)?,
                    bytes: text_bytes + attachment_bytes,
                    text_bytes,
                    attachment_bytes,
                };
                accumulate(senders.entry(r.get(0)?).or_default(), &part)?;
            }
        }
        let mut top: Vec<_> = senders
            .into_iter()
            .map(|(chat_id, traffic)| Sender {
                chat_id,
                traffic,
                name: String::new(),
            })
            .collect();
        let rank = |a: &Sender, b: &Sender| {
            b.traffic
                .messages
                .cmp(&a.traffic.messages)
                .then_with(|| a.chat_id.cmp(&b.chat_id))
        };
        if top.len() > 10 {
            top.select_nth_unstable_by(10, rank);
            top.truncate(10);
        }
        top.sort_by(rank);
        Ok(Ranking {
            revisions,
            local,
            top,
        })
    }

    fn cluster_usage_stats(
        &self,
        cache: &mut Option<Ranking>,
        poll: Option<Uuid>,
    ) -> Result<Value> {
        let mut nodes = Vec::new();
        let round = poll.map(|id| id.to_string());
        let mut confirmed_nodes = 0;
        let mut revisions = Revisions {
            local: None,
            remote: Vec::new(),
        };
        let authority_fresh = self.state.require_fresh(self.timestamp as u64).is_ok();
        let mut cache_row=self.db.prepare(
            "SELECT s.head,s.as_of,s.started,s.ordinary,s.goals,s.m,s.t,s.a,s.round IS NOT NULL OR s.failed_at IS NOT NULL,
                    p.confirmed=1 AND p.head=s.head AND p.failed=0 AND s.round IS NULL
             FROM stats_peers s JOIN network_links l ON l.peer=s.peer AND l.peer_key=s.key
             LEFT JOIN stats_poll p ON p.peer=s.peer AND p.key=s.key AND p.poll=?3
             WHERE s.peer=?1 AND s.key=?2 AND s.head IS NOT NULL")?;
        for (id, member) in &self.state.state().nodes {
            if member.hosted_by.is_some() {
                continue;
            }
            let mut detail = NodeStats {
                node: Node {
                    id: id.clone(),
                    name: member.name.clone(),
                },
                status: "missing".into(),
                as_of: None,
                outbound: None,
                babysitter: None,
                coverage: None,
            };
            if id == self.identity.node.id()
                && member.signing_key == self.identity.node.public_key()
            {
                confirmed_nodes += 1;
                revisions.local = Some(self.stats_head()?);
                detail.status = "local".into();
                detail.as_of = Some(self.timestamp);
            } else if let Some(row) = cache_row
                .query(params![id, member.signing_key.as_slice(), round])?
                .next()?
            {
                if row.get::<_, Option<bool>>(9)? == Some(true) {
                    confirmed_nodes += 1;
                }
                let at: i64 = row.get(1)?;
                let fresh = authority_fresh
                    && !row.get::<_, bool>(8)?
                    && (self.timestamp - FRESH..=self.timestamp).contains(&at);
                detail.status = if fresh { "fresh" } else { "stale" }.into();
                detail.as_of = Some(at);
                detail.coverage = Some(Tracking {
                    tracking_started_at: row.get(2)?,
                    backfill: "retained_native_messages_and_ordinary_submissions".into(),
                    older_daemon_activity: "excluded".into(),
                });
                detail.babysitter = Some(Babysitter {
                    ordinary_submitted: row.get(3)?,
                    goal_submitted: row.get(4)?,
                });
                let text_bytes: u64 = row.get(6)?;
                let attachment_bytes: u64 = row.get(7)?;
                detail.outbound = Some(Traffic {
                    messages: row.get(5)?,
                    bytes: text_bytes + attachment_bytes,
                    text_bytes,
                    attachment_bytes,
                });
                revisions
                    .remote
                    .push((id.clone(), member.signing_key, row.get(0)?));
            }
            nodes.push(detail);
        }
        if cache
            .as_ref()
            .is_none_or(|saved| saved.revisions != revisions)
        {
            *cache = Some(self.rank_stats(revisions)?);
        }
        let ranking = cache.as_ref().expect("ranking initialized");
        let mut outbound = Traffic::default();
        let mut babysitter = Babysitter::default();
        let mut reporting_nodes = 0;
        let mut fresh_nodes = 0;
        for detail in &mut nodes {
            if detail.status == "local"
                && let Some((out, b, tracking)) = &ranking.local
            {
                detail.outbound = Some(out.clone());
                detail.babysitter = Some(b.clone());
                detail.coverage = Some(tracking.clone());
            }
            if let (Some(out), Some(b)) = (&detail.outbound, &detail.babysitter) {
                reporting_nodes += 1;
                fresh_nodes += usize::from(matches!(detail.status.as_str(), "local" | "fresh"));
                accumulate(&mut outbound, out)?;
                add(&mut babysitter.ordinary_submitted, b.ordinary_submitted)?;
                add(&mut babysitter.goal_submitted, b.goal_submitted)?;
            }
        }
        let mut top_senders = ranking.top.clone();
        let mut name = self.db.prepare(
            "SELECT COALESCE((SELECT name FROM agents WHERE id=?1),
            (SELECT name FROM usage_senders WHERE chat_id=?1),?1)",
        )?;
        for sender in &mut top_senders {
            sender.name = name.query_row([&sender.chat_id], |r| r.get(0))?;
        }
        let coverage = Coverage {
            expected_nodes: nodes.len(),
            reporting_nodes,
            fresh_nodes,
            complete: authority_fresh && fresh_nodes == nodes.len(),
        };
        Ok(serde_json::to_value(Stats {
            scope: "cluster".into(),
            outbound,
            top_senders,
            babysitter,
            nodes,
            refresh: poll.is_some().then_some(Refresh {
                confirmed_nodes,
                expected_nodes: coverage.expected_nodes,
            }),
            coverage,
        })?)
    }
}

impl Store {
    pub(crate) fn stats_snapshot(&mut self, poll: Option<Uuid>) -> Result<Value> {
        let tx = self.db.transaction()?;
        let session = StoreSession {
            home: &self.home,
            config: self.config.clone(),
            identity: &self.identity,
            state: self.identity.state(&tx)?,
            timestamp: requests::diagnostic_clock(&tx, now())?,
            db: &tx,
        };
        let result = session.cluster_usage_stats(&mut self.stats_cache, poll)?;
        tx.commit()?;
        Ok(result)
    }
}
