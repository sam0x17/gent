//! Durable, compare-and-swap storage for an enrolled cluster's verified authority.
//! This is not yet used by the local-only RPC store or connected to a relay.
use anyhow::{Context, Result, ensure};
use gent_crypto::{
    Checkpoint, MAX_CHAIN_BYTES, MAX_CHAIN_LENGTH, SignedState, TrustAnchor, VerifiedState,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    fs,
    io::ErrorKind,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub struct Replica {
    db: Connection,
}

impl Replica {
    /// One replica per cluster directory, beneath a private endpoint state directory.
    pub fn open(home: &Path) -> Result<Self> {
        crate::config::private_dir(home)?;
        let path = home.join("authority.sqlite3");
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o077 == 0,
            "authority database must be a private regular file"
        );
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        ensure!(
            matches!(version, 0..=2),
            "unsupported authority database version"
        );
        crate::storage::configure(&db)?;
        db.execute_batch(
            "
          CREATE TABLE IF NOT EXISTS cluster_state (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            anchor BLOB NOT NULL, checkpoint BLOB NOT NULL, state BLOB NOT NULL
          );
          CREATE TABLE IF NOT EXISTS cluster_history (
            revision INTEGER PRIMARY KEY, state BLOB NOT NULL
          );
          PRAGMA user_version=2;",
        )?;
        Ok(Self { db })
    }

    /// Install the genesis already verified against an independently pinned anchor.
    pub fn initialize(&mut self, state: &VerifiedState) -> Result<()> {
        ensure!(
            state.checkpoint().revision == 0,
            "initialize with pinned genesis, then apply its history"
        );
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO cluster_state VALUES (1,?1,?2,?3)",
            params![
                serde_json::to_vec(state.anchor())?,
                serde_json::to_vec(state.checkpoint())?,
                state.signed().encode()?
            ],
        )
        .context("replica already initialized or storage unavailable")?;
        tx.execute(
            "INSERT INTO cluster_history VALUES (0,?1)",
            [state.signed().encode()?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn load(&self) -> Result<VerifiedState> {
        load(&self.db)
    }

    /// Signature validation, history insertion, and checkpoint advancement commit together.
    /// Return the new authority only after durable commit. Stale writers must reload.
    pub fn apply(
        &mut self,
        expected: &Checkpoint,
        updates: &[SignedState],
        now: u64,
    ) -> Result<VerifiedState> {
        self.advance(expected, updates, Some(now))
    }

    /// Persist a verified history batch even if still stale. This must not enable
    /// delivery until the returned state's freshness check passes.
    pub fn apply_history(
        &mut self,
        expected: &Checkpoint,
        updates: &[SignedState],
    ) -> Result<VerifiedState> {
        self.advance(expected, updates, None)
    }

    fn advance(
        &mut self,
        expected: &Checkpoint,
        updates: &[SignedState],
        now: Option<u64>,
    ) -> Result<VerifiedState> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut current = load(&tx)?;
        ensure!(
            current.checkpoint() == expected,
            "configuration changed; reload before applying this revision"
        );
        match now {
            Some(now) => current.apply_chain(updates, now)?,
            None => current.advance_history(updates)?,
        }
        for state in updates {
            tx.execute(
                "INSERT INTO cluster_history VALUES (?1,?2)",
                params![i64::try_from(state.state.revision)?, state.encode()?],
            )?;
        }
        tx.execute(
            "UPDATE cluster_state SET checkpoint=?1,state=?2 WHERE singleton=1",
            params![
                serde_json::to_vec(current.checkpoint())?,
                current.signed().encode()?
            ],
        )?;
        tx.commit()?;
        Ok(current)
    }

    /// Bounded history for endpoint synchronization. Callers must encrypt it before relay upload.
    pub fn history(&self, after_revision: u64, limit: usize) -> Result<Vec<SignedState>> {
        ensure!(
            limit > 0 && limit <= MAX_CHAIN_LENGTH,
            "invalid history limit"
        );
        let mut statement = self.db.prepare(
            "SELECT state FROM cluster_history WHERE revision>?1 ORDER BY revision LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![i64::try_from(after_revision)?, i64::try_from(limit)?],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut history = Vec::new();
        let mut total_bytes = 0;
        for row in rows {
            let bytes = row?;
            if total_bytes + bytes.len() > MAX_CHAIN_BYTES {
                break;
            }
            total_bytes += bytes.len();
            history.push(SignedState::decode(&bytes)?);
        }
        Ok(history)
    }
}

fn load(db: &Connection) -> Result<VerifiedState> {
    let (anchor, checkpoint, state): (Vec<u8>, Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT anchor,checkpoint,state FROM cluster_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .context("authority replica is not initialized")?;
    VerifiedState::restore(
        serde_json::from_slice::<TrustAnchor>(&anchor)?,
        serde_json::from_slice::<Checkpoint>(&checkpoint)?,
        SignedState::decode(&state)?,
    )
}
