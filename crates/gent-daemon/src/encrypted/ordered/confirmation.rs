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
    match stream(db, group)?
        .context("unknown stream")?
        .purpose
        .as_str()
    {
        "data" => Ok(Purpose::Data),
        "configuration" => Ok(Purpose::Configuration),
        _ => bail!("unknown stream purpose"),
    }
}

struct SavedReceipt {
    reader: String,
    key: PublicKey,
    sequence: u64,
    digest: Digest,
    wire: Vec<u8>,
}

impl SavedReceipt {
    fn load(db: &Connection, group: &[u8]) -> Result<Option<Self>> {
        Ok(db.query_row(
            "SELECT reader,reader_key,sequence,digest,receipt FROM stream_confirmed WHERE group_id=?1",
            [group], |r| Ok(Self {
                reader: r.get(0)?, key: r.get(1)?, sequence: r.get(2)?, digest: r.get(3)?, wire: r.get(4)?,
            }),
        ).optional()?)
    }

    fn verified(&self, group: &[u8], key: &PublicKey, head: u64) -> Result<Receipt> {
        let receipt = Receipt::decode(&self.wire)?;
        ensure!(
            receipt.group() == group
                && receipt.sequence() == self.sequence
                && receipt.digest() == self.digest
                && self.sequence <= head
                && self.key == *key,
            "saved receipt does not match the confirmed stream"
        );
        receipt.verify(key)?;
        Ok(receipt)
    }
}

fn authorized_reader(
    session: &Session<'_>,
    group: &[u8],
    purpose: Purpose,
    reader: &str,
) -> Result<(Stream, PublicKey)> {
    let saved = checked_stream(session, group, purpose)?;
    ensure!(
        saved.writer == session.signer.id() && reader != session.signer.id(),
        "invalid stream receipt roles"
    );
    ensure!(
        saved.roster == roster_hash(&[session.signer.id(), reader])?,
        "receipt reader does not match two-node roster"
    );
    let key = session
        .state
        .state()
        .nodes
        .get(reader)
        .context("unknown receipt reader")?
        .signing_key;
    if purpose == Purpose::Configuration {
        let grant = configuration::progress(session.db, group)?.grant;
        ensure!(
            grant.grant.reader == reader && grant.grant.reader_key == key,
            "configuration receipt reader mismatch"
        );
    } else {
        session.state.authorize_node(reader, &key, session.now)?;
    }
    Ok((saved, key))
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
        self.confirm_and_get(receipt, reader, now).map(|_| ())
    }

    /// Return the newest authenticated checkpoint in the same transaction that
    /// accepts an ACK. A stale ACK may arrive after another route advanced it.
    pub(crate) fn confirm_and_get(
        &mut self,
        receipt: &Receipt,
        reader: &str,
        now: u64,
    ) -> Result<(Receipt, bool)> {
        let purpose = mode(&self.inner.db, receipt.group())?;
        self.inner.transact_mode(now, purpose == Purpose::Configuration, |session| {
            let (saved, key) = authorized_reader(session, receipt.group(), purpose, reader)?;
            receipt.verify(&key)?;
            ensure!(receipt.sequence() <= saved.head, "receipt is ahead of local stream");
            if let Some(previous) = SavedReceipt::load(session.db, receipt.group())? {
                ensure!(previous.reader == reader && previous.key == key, "receipt reader pin changed");
                if receipt.sequence() < previous.sequence {
                    return Ok((previous.verified(receipt.group(), &key, saved.head)?, false));
                }
                if receipt.sequence() == previous.sequence {
                    ensure!(receipt.digest() == previous.digest && receipt.encode()? == previous.wire, "conflicting receiver checkpoint");
                    return Ok((receipt.clone(), false));
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
            Ok((receipt.clone(), true))
        })
    }
    pub fn confirmed_next(&self, group: &[u8]) -> Result<u64> {
        next(&self.inner.db, group)
    }

    /// Return only a previously verified checkpoint, rechecking current peer
    /// authority before transport can use it to restore a relay's missing floor.
    pub fn confirmed_receipt(&mut self, group: &[u8], now: u64) -> Result<Option<Receipt>> {
        let tx = self
            .inner
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let Some(previous) = SavedReceipt::load(&tx, group)? else {
            return Ok(None);
        };
        let purpose = mode(&tx, group)?;
        let session = Session::load(
            &tx,
            self.inner.identity,
            now,
            purpose == Purpose::Configuration,
        )?;
        let (saved, key) = authorized_reader(&session, group, purpose, &previous.reader)?;
        let receipt = previous.verified(group, &key, saved.head)?;
        tx.commit()?;
        Ok(Some(receipt))
    }

    pub(crate) fn configuration_reader(&self, group: &[u8]) -> Result<String> {
        Ok(configuration::progress(&self.inner.db, group)?
            .grant
            .grant
            .reader)
    }
}

// Legacy requests have no event association. Derive their deterministic IDs
// only if the retirement pass encounters a confirmed legacy packet.
fn legacy_fragments(db: &Connection) -> Result<BTreeSet<String>> {
    let mut query = db.prepare("SELECT id,offset FROM network_events")?;
    let mut rows = query.query([])?;
    let mut ids = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let event = Uuid::parse_str(&row.get::<_, String>(0)?)?;
        let offset = row.get(1)?;
        for cancelled in [false, true] {
            ids.insert(crate::messages::packet_id(event, offset, cancelled).to_string());
        }
    }
    Ok(ids)
}

fn retire_request(db: &Connection, id: &str, managed: bool) -> Result<()> {
    if managed {
        db.execute("DELETE FROM configuration_requests WHERE id=?1", [id])?;
        db.execute("DELETE FROM stream_outbox WHERE id=?1", [id])?;
        db.execute("DELETE FROM outbox WHERE id=?1", [id])?;
        db.execute("DELETE FROM transport_requests WHERE id=?1", [id])?;
    } else {
        db.execute("UPDATE stream_outbox SET packet=X'' WHERE id=?1", [id])?;
        db.execute("UPDATE outbox SET bytes=X'' WHERE id=?1", [id])?;
    }
    Ok(())
}

/// The caller has advanced or deleted this exact cursor in the same transaction.
/// A cancellation can release both a part and a cancel at the same offset.
pub(crate) fn retire_released_fragment(
    db: &Connection,
    group: &[u8],
    event: Uuid,
    offset: usize,
) -> Result<()> {
    let legacy =
        [false, true].map(|cancel| crate::messages::packet_id(event, offset, cancel).to_string());
    let mut query = db.prepare(
        "WITH ids(id) AS (
            SELECT id FROM transport_requests WHERE group_id=?1 AND event=?2 AND offset=?3
            UNION ALL SELECT ?4 UNION ALL SELECT ?5)
         SELECT o.id,t.id IS NOT NULL FROM ids CROSS JOIN stream_outbox o ON o.id=ids.id
         JOIN stream_confirmed c ON c.group_id=o.group_id LEFT JOIN transport_requests t ON t.id=o.id
         WHERE o.group_id=?1 AND o.sequence>0 AND o.sequence<=c.sequence"
    )?;
    let released = query
        .query_map(
            params![group, event.to_string(), offset, legacy[0], legacy[1]],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (id, managed) in released {
        retire_request(db, &id, managed)?;
    }
    Ok(())
}

/// Preserve origins and legacy tombstones. Allocated IDs can be forgotten because
/// an unknown UUIDv7 cannot start another operation through any MLS request API.
pub(crate) fn retire(db: &Connection, dry_run: bool) -> Result<(usize, u64, usize)> {
    let runtime: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_events')",
        [],
        |row| row.get(0),
    )?;
    // The scheduler can prioritize any queued event. Check each allocated
    // fragment's own cursor, independent of which event is currently first.
    let unprotected = if runtime {
        "AND NOT EXISTS(SELECT 1 FROM network_events e WHERE e.id=t.event AND e.offset=t.offset)"
    } else {
        ""
    };
    let mut query = db.prepare(&format!(
        "SELECT o.id,length(o.packet)+COALESCE(length(r.bytes),0),t.id IS NOT NULL FROM stream_outbox o
         JOIN stream_confirmed c USING(group_id) LEFT JOIN outbox r ON r.id=o.id
         LEFT JOIN transport_requests t ON t.id=o.id
         WHERE o.sequence>0 AND o.sequence<=c.sequence AND (length(o.packet)>0 OR t.id IS NOT NULL)
         {unprotected} ORDER BY o.rowid"
    ))?;
    let mut candidates = query.query([])?;
    let mut legacy = None;
    let mut rows = Vec::new();
    let mut bytes = 0;
    let mut requests = 0;
    while rows.len() < 256
        && let Some(row) = candidates.next()?
    {
        let id: String = row.get(0)?;
        let managed: bool = row.get(2)?;
        if runtime && !managed {
            let ids = match &legacy {
                Some(ids) => ids,
                None => legacy.insert(legacy_fragments(db)?),
            };
            if ids.contains(&id) {
                continue;
            }
        }
        bytes += row.get::<_, u64>(1)?;
        requests += usize::from(managed);
        rows.push((id, managed));
    }
    drop(candidates);
    if !dry_run {
        for (id, managed) in &rows {
            retire_request(db, id, *managed)?;
        }
    }
    Ok((rows.len(), bytes, requests))
}
