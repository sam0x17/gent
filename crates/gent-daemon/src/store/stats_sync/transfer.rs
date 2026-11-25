use super::*;

impl StoreSession<'_> {
    pub(in crate::store) fn receive_stats(&self, peer: &str, exchange: Exchange) -> Result<()> {
        self.stats_peer(peer)?;
        match exchange {
            Exchange::Hello => Ok(()),
            Exchange::Read { round, base } => {
                if round.is_nil() {
                    return Ok(());
                }
                self.stats_savepoint(|| self.send_stats_pages(peer, round, base))
            }
            Exchange::Page {
                round,
                page,
                full,
                rows,
                finish,
            } => self.apply_stats_page(peer, round, page, full, &rows, finish),
        }
    }

    fn send_stats_pages(&self, peer: &str, round: Uuid, base: Option<Mark>) -> Result<()> {
        let busy = self
            .db
            .prepare(
                "SELECT 1 FROM stats_peers s WHERE s.peer=?1 AND
          (s.last_read>?2 OR EXISTS(SELECT 1 FROM stats_pending WHERE id=s.last_event))",
            )?
            .exists(params![peer, self.timestamp - 5])?;
        let reserved: bool = self.db.query_row(
            "SELECT COALESCE(SUM(length(body)),0)>?1 FROM stats_pending",
            [32 * 1024 * 1024],
            |r| r.get(0),
        )?;
        if busy || reserved {
            return Ok(());
        }
        // Keep the last sent and acknowledged bases per physical peer. Thousands
        // of sends to one chat still require only that one row after an idle gap.
        let marker = base.as_ref().map(serde_json::to_string).transpose()?;
        let anchored = self
            .db
            .prepare("SELECT 1 FROM stats_peers WHERE peer=?1 AND ?2 IN (sent_head,base_head)")?
            .exists(params![peer, marker])?;
        let base = base.filter(|_| anchored).map(|mark| mark.0);
        let head = self.stats_head()?;
        let sent_head = serde_json::to_string(&head)?;
        let finish=self.db.query_row("SELECT started_at,ordinary_submitted,goal_submitted FROM usage_tracking WHERE singleton=1",[],|r|Ok(Finish {
            head, as_of:self.timestamp, started:r.get(0)?,ordinary:r.get(1)?,goals:r.get(2)?,
        }))?;
        let sql = if base.is_some() {
            "SELECT s.chat_id,s.messages,s.text_bytes,s.attachment_bytes FROM stats_changed c
             JOIN usage_senders s USING(chat_id) WHERE c.rev>?1 ORDER BY c.rev"
        } else {
            "SELECT chat_id,messages,text_bytes,attachment_bytes FROM usage_senders WHERE ?1 IS NULL ORDER BY chat_id"
        };
        let mut query = self.db.prepare(sql)?;
        let mut records = query.query([base])?;
        let mut batch = Vec::with_capacity(PAGE_ROWS);
        let mut page = 0;
        let mut count = 0;
        while let Some(r) = records.next()? {
            if count == MAX_ROWS {
                // Roll back queued pages and keep the last completed remote snapshot.
                return Err(TooManySenders.into());
            }
            if batch.len() == PAGE_ROWS {
                self.queue_stats(
                    peer,
                    Exchange::Page {
                        round,
                        page,
                        full: base.is_none(),
                        rows: batch,
                        finish: None,
                    },
                )?;
                page += 1;
                batch = Vec::with_capacity(PAGE_ROWS);
            }
            batch.push(Counts(
                Uuid::parse_str(r.get_ref(0)?.as_str()?)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
            ));
            count += 1;
        }
        let last = self.queue_stats(
            peer,
            Exchange::Page {
                round,
                page,
                full: base.is_none(),
                rows: batch,
                finish: Some(finish),
            },
        )?;
        self.db.execute(
            "UPDATE stats_peers SET last_read=?2,last_event=?3,sent_head=?4,base_head=?5 WHERE peer=?1",
            params![peer, self.timestamp, last.to_string(),sent_head,marker.filter(|_|anchored)],
        )?;
        Ok(())
    }

    fn apply_stats_page(
        &self,
        peer: &str,
        round: Uuid,
        page: usize,
        full: bool,
        rows: &[Counts],
        finish: Option<Finish>,
    ) -> Result<()> {
        let valid = self
            .db
            .prepare(
                "SELECT 1 FROM stats_peers WHERE peer=?1 AND round=?2 AND page=?3
            AND (full IS NULL OR full=?4) AND (head IS NOT NULL OR ?4)",
            )?
            .exists(params![peer, round.to_string(), page as i64, full])?;
        if !valid
            || page >= MAX_ROWS / PAGE_ROWS
            || rows.len() > PAGE_ROWS
            || (finish.is_none() && rows.len() != PAGE_ROWS)
            || rows.iter().any(|r| {
                r.0.is_nil() || r.1 == 0 || [r.1, r.2, r.3].iter().any(|n| *n > i64::MAX as u64)
            })
        {
            return Ok(());
        }
        {
            let mut insert = self
                .db
                .prepare("INSERT OR IGNORE INTO stats_stage VALUES(?1,?2,?3,?4,?5)")?;
            for Counts(id, m, t, a) in rows {
                if insert.execute(params![peer, id.to_string(), m, t, a])? == 0 {
                    self.db.execute(
                        "UPDATE stats_peers SET round=NULL,request_at=NULL WHERE peer=?1",
                        [peer],
                    )?;
                    self.db
                        .execute("DELETE FROM stats_stage WHERE peer=?1", [peer])?;
                    return Ok(());
                }
            }
        }
        if let Some(end) = finish {
            if end.head.0 < 1
                || end.head.1.len() != 32
                || !end.head.1.bytes().all(|c| c.is_ascii_hexdigit())
                || end.started <= 0
                || end.started > end.as_of
                || end.as_of > self.timestamp + 60
                || end.ordinary > u64::MAX / 1024
                || end.goals > u64::MAX / 1024
            {
                return Ok(());
            }
            let Some(totals) = self.stats_merged_totals(peer, full)? else {
                self.db
                    .execute("DELETE FROM stats_stage WHERE peer=?1", [peer])?;
                return Ok(());
            };
            if full {
                self.db
                    .execute("DELETE FROM stats_remote WHERE peer=?1", [peer])?;
            }
            self.db.execute(
                "INSERT OR REPLACE INTO stats_remote SELECT * FROM stats_stage WHERE peer=?1",
                [peer],
            )?;
            self.db
                .execute("DELETE FROM stats_stage WHERE peer=?1", [peer])?;
            self.db.execute(
                "UPDATE stats_peers SET round=NULL,request_at=NULL,page=0,full=NULL,
              head=?2,as_of=?3,started=?4,ordinary=?5,goals=?6,n=?7,m=?8,t=?9,a=?10 WHERE peer=?1",
                params![
                    peer,
                    serde_json::to_string(&end.head)?,
                    end.as_of.min(self.timestamp),
                    end.started,
                    end.ordinary,
                    end.goals,
                    totals[0],
                    totals[1],
                    totals[2],
                    totals[3]
                ],
            )?;
        } else {
            self.db.execute(
                "UPDATE stats_peers SET page=page+1,full=?2,request_at=?3 WHERE peer=?1",
                params![peer, full, self.timestamp],
            )?;
        }
        Ok(())
    }
    // Validate before publishing. Only the replaced rows of an existing
    // snapshot are read when applying a sparse update.
    fn stats_merged_totals(&self, peer: &str, full: bool) -> Result<Option<[i64; 4]>> {
        let mut totals = [0i128; 4];
        if !full {
            let old = self.db.query_row(
                "SELECT n,m,t,a FROM stats_peers WHERE peer=?1",
                [peer],
                |r| Ok([r.get::<_, i64>(0)?, r.get(1)?, r.get(2)?, r.get(3)?]),
            )?;
            totals = old.map(i128::from);
        }
        let mut query = self.db.prepare(
            "SELECT r.chat IS NULL,s.m,s.t,s.a,
          COALESCE(r.m,0),COALESCE(r.t,0),COALESCE(r.a,0) FROM stats_stage s
          LEFT JOIN stats_remote r ON ?2=0 AND r.peer=s.peer AND r.chat=s.chat WHERE s.peer=?1",
        )?;
        let mut rows = query.query(params![peer, full])?;
        while let Some(row) = rows.next()? {
            totals[0] += i128::from(row.get::<_, i64>(0)?);
            for (i, total) in totals.iter_mut().enumerate().skip(1) {
                *total += i128::from(row.get::<_, i64>(i)?) - i128::from(row.get::<_, i64>(i + 3)?);
            }
        }
        // Signed membership admits at most 1024 nodes. Reserve space for
        // every reporting node when combining untrusted numeric input.
        let limit = i128::from(u64::MAX) / 1024;
        if totals[0] > MAX_ROWS as i128 || totals[1] > limit || totals[2] + totals[3] > limit {
            return Ok(None);
        }
        Ok(Some(totals.map(|v| v as i64)))
    }
}

#[derive(Debug)]
pub(super) struct TooManySenders;
impl std::fmt::Display for TooManySenders {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("statistics sender limit exceeded")
    }
}
impl std::error::Error for TooManySenders {}
