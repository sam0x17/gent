//! Authenticated durable receiver checkpoints for immutable two-node streams.
//! Relay storage acknowledgments never supply this authority.
use super::*;
use gent_crypto::stream::Receipt;

pub(crate) fn next(db: &Connection, group: &[u8]) -> Result<u64> {
    Ok(db
        .query_row(
            "SELECT sequence+1 FROM stream_confirmed WHERE group_id=?1",
            [group],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0))
}

fn mode(db: &Connection, group: &[u8]) -> Result<Purpose> {
    Ok(
        match stream(db, group)?
            .context("unknown stream")?
            .purpose
            .as_str()
        {
            "data" => Purpose::Data,
            "configuration" => Purpose::Configuration,
            _ => bail!("unknown stream purpose"),
        },
    )
}

impl OrderedEndpoint<'_> {
    /// Sign only a committed stream head, including durably buffered plaintext
    /// or configuration fragments. This does not acknowledge chat execution.
    pub fn receipt(&mut self, group: &[u8], now: u64) -> Result<Receipt> {
        let purpose = mode(&self.inner.db, group)?;
        self.inner
            .transact_mode(now, purpose == Purpose::Configuration, |session| {
                let saved = checked_stream(session, group, purpose)?;
                ensure!(
                    saved.writer != session.signer.id(),
                    "writer cannot acknowledge its own stream"
                );
                ensure!(
                    saved.roster == roster_hash(&[session.signer.id(), &saved.writer])?,
                    "receipt requires an immutable two-node stream"
                );
                session
                    .signer
                    .sign_stream_receipt(group, saved.head, saved.digest)
            })
    }

    /// `reader` comes from the caller's independently pinned link or owner grant.
    pub fn confirm(&mut self, receipt: &Receipt, reader: &str, now: u64) -> Result<()> {
        let purpose = mode(&self.inner.db, receipt.group())?;
        self.inner.transact_mode(now, purpose == Purpose::Configuration, |session| {
            let saved = checked_stream(session, receipt.group(), purpose)?;
            ensure!(saved.writer == session.signer.id() && reader != session.signer.id(),
                "invalid stream receipt roles");
            ensure!(saved.roster == roster_hash(&[session.signer.id(), reader])?,
                "receipt reader does not match two-node roster");
            let key = session.state.state().nodes.get(reader)
                .context("unknown receipt reader")?.signing_key;
            if purpose == Purpose::Configuration {
                let grant = configuration::progress(session.db, receipt.group())?.grant;
                ensure!(grant.grant.reader == reader && grant.grant.reader_key == key,
                    "configuration receipt reader mismatch");
            } else {
                session.state.authorize_node(reader, &key, now)?;
            }
            receipt.verify(&key)?;
            ensure!(receipt.sequence() <= saved.head, "receipt is ahead of local stream");
            let previous: Option<(String, PublicKey, u64, Digest)> = session.db.query_row(
                "SELECT reader,reader_key,sequence,digest FROM stream_confirmed WHERE group_id=?1",
                [receipt.group()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ).optional()?;
            if let Some((peer, pin, sequence, digest)) = previous {
                ensure!(peer == reader && pin == key, "receipt reader pin changed");
                if receipt.sequence() <= sequence {
                    ensure!(receipt.sequence() < sequence || receipt.digest() == digest,
                        "conflicting receiver checkpoint");
                    retire(session.db, false)?;
                    return Ok(());
                }
            }
            let wire: Vec<u8> = session.db.query_row(
                "SELECT packet FROM stream_outbox WHERE group_id=?1 AND sequence=?2",
                params![receipt.group(), receipt.sequence()], |r| r.get(0),
            )?;
            let packet = Packet::decode(&wire)?;
            packet.verify(&saved.key)?;
            ensure!(packet.group() == receipt.group() && packet.sequence() == receipt.sequence()
                && packet.digest()? == receipt.digest(), "receipt does not match committed stream");
            session.db.execute("INSERT INTO stream_confirmed VALUES(?1,?2,?3,?4,?5,?6)
                ON CONFLICT(group_id) DO UPDATE SET sequence=excluded.sequence,digest=excluded.digest,receipt=excluded.receipt",
                params![receipt.group(), reader, key.as_slice(), receipt.sequence(),
                    receipt.digest().as_slice(), receipt.encode()?])?;
            retire(session.db, false)?;
            Ok(())
        })
    }
    pub fn confirmed_next(&self, group: &[u8]) -> Result<u64> {
        next(&self.inner.db, group)
    }

    /// Return only a previously verified checkpoint, rechecking current peer
    /// authority before transport can use it to restore a relay's missing floor.
    pub fn confirmed_receipt(&mut self, group: &[u8], now: u64) -> Result<Option<Receipt>> {
        let wire: Option<(Vec<u8>, String)> = self
            .inner
            .db
            .query_row(
                "SELECT receipt,reader FROM stream_confirmed WHERE group_id=?1",
                [group],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((wire, reader)) = wire else {
            return Ok(None);
        };
        let receipt = Receipt::decode(&wire)?;
        self.confirm(&receipt, &reader, now)?;
        Ok(Some(receipt))
    }

    pub(crate) fn configuration_reader(&self, group: &[u8]) -> Result<String> {
        Ok(configuration::progress(&self.inner.db, group)?
            .grant
            .grant
            .reader)
    }
}

/// Keep any packet whose daemon fragment cursor may not have committed yet.
/// Only the oldest event for a peer can have been encrypted. Both part/cancel
/// IDs are protected across revocation or history cleanup changing that event.
fn protected(db: &Connection) -> Result<String> {
    let runtime: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_events')",
        [],
        |r| r.get(0),
    )?;
    let mut ids = vec![];
    if runtime {
        let mut query=db.prepare("SELECT e.id,e.offset FROM network_events e JOIN
            (SELECT peer,MIN(rowid) AS first FROM network_events GROUP BY peer) h ON e.rowid=h.first")?;
        for row in query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, usize>(1)?)))? {
            let (id, offset) = row?;
            for cancel in [false, true] {
                ids.push(
                    crate::messages::packet_id(Uuid::parse_str(&id)?, offset, cancel).to_string(),
                );
            }
        }
        let mut query = db.prepare("SELECT r.id FROM transport_requests r JOIN network_events e
            ON r.event=e.id AND r.offset=e.offset JOIN
            (SELECT peer,MIN(rowid) AS first FROM network_events GROUP BY peer) h ON e.rowid=h.first")?;
        for row in query.query_map([], |r| r.get::<_, String>(0))? {
            ids.push(row?);
        }
    }
    Ok(serde_json::to_string(&ids)?)
}

/// Preserve origins and legacy tombstones. Allocated IDs can be forgotten because
/// an unknown UUIDv7 cannot start another operation through any MLS request API.
pub(crate) fn retire(db: &Connection, dry_run: bool) -> Result<(usize, u64, usize)> {
    let protected = protected(db)?;
    let rows = db
        .prepare(
            "SELECT o.id,length(o.packet)+COALESCE(length(r.bytes),0),t.id IS NOT NULL FROM stream_outbox o
        JOIN stream_confirmed c USING(group_id) LEFT JOIN outbox r ON r.id=o.id
        LEFT JOIN transport_requests t ON t.id=o.id
        WHERE o.sequence>0 AND o.sequence<=c.sequence AND (length(o.packet)>0 OR t.id IS NOT NULL)
          AND o.id NOT IN (SELECT value FROM json_each(?1)) ORDER BY o.rowid LIMIT 256",
        )?
        .query_map([protected], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?, r.get::<_, bool>(2)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut bytes = 0;
    let mut requests = 0;
    for (id, size, managed) in &rows {
        bytes += size;
        requests += usize::from(*managed);
        if !dry_run {
            if *managed {
                db.execute("DELETE FROM configuration_requests WHERE id=?1", [id])?;
                db.execute("DELETE FROM stream_outbox WHERE id=?1", [id])?;
                db.execute("DELETE FROM outbox WHERE id=?1", [id])?;
                db.execute("DELETE FROM transport_requests WHERE id=?1", [id])?;
            } else {
                db.execute("UPDATE stream_outbox SET packet=X'' WHERE id=?1", [id])?;
                db.execute("UPDATE outbox SET bytes=X'' WHERE id=?1", [id])?;
            }
        }
    }
    Ok((rows.len(), bytes, requests))
}
