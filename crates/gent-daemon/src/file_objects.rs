//! Trusted endpoint storage for immutable encrypted files. Agent bindings and
//! permission checks live in store::files; the dispatcher moves only ciphertext.
//!
//! The caller must authenticate agents and check current message/file permissions
//! before every operation. Grants here live in the protected endpoint database;
//! only ciphertext goes to object storage. Mutations share the caller's immediate
//! transaction so a message and its files commit or roll back together.
use anyhow::{Context, Result, ensure};
use gent_crypto::files::{FileGrant, SealedFile};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const MAX_OBJECTS: u64 = 128;
pub const MAX_RESERVED_BYTES: u64 = 256 * 1024 * 1024;
pub const INCOMPLETE_TTL_SECONDS: u64 = 60 * 60;
pub const MAX_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Initialize within the same protected database used for endpoint state.
pub fn initialize(db: &mut Connection) -> Result<()> {
    ensure!(
        db.pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))?,
        "file storage requires foreign keys"
    );
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS file_object_schema (
            id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL);
         INSERT OR IGNORE INTO file_object_schema VALUES(1,1);",
    )?;
    check_version(&tx)?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS file_objects (
            id TEXT PRIMARY KEY,
            grant BLOB NOT NULL,
            reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=16),
            expires_at INTEGER NOT NULL,
            incomplete_until INTEGER NOT NULL,
            complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)));
         CREATE TABLE IF NOT EXISTS file_chunks (
            object_id TEXT NOT NULL REFERENCES file_objects(id) ON DELETE CASCADE,
            position INTEGER NOT NULL CHECK(position>=0 AND position<128),
            ciphertext BLOB NOT NULL CHECK(length(ciphertext)>=16 AND length(ciphertext)<=262160),
            uploaded INTEGER NOT NULL DEFAULT 0 CHECK(uploaded IN (0,1)),
            PRIMARY KEY(object_id,position));",
    )?;
    tx.commit()?;
    Ok(())
}

fn check_version(db: &Connection) -> Result<()> {
    let version: u64 = db.query_row(
        "SELECT version FROM file_object_schema WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(version == 1, "unsupported file storage version");
    Ok(())
}

pub struct Objects<'a> {
    db: &'a Connection,
    now: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub complete: bool,
    pub chunks_present: u32,
    pub chunks_uploaded: u32,
    pub expires_at: u64,
    pub incomplete_until: u64,
}

impl<'a> Objects<'a> {
    /// Use an immediate transaction and propagate errors before committing.
    /// This constructor deliberately cannot take an autocommit Connection.
    pub fn new(tx: &'a Transaction<'_>, now: u64) -> Result<Self> {
        Self::in_transaction(tx, now)
    }

    pub(crate) fn in_transaction(tx: &'a Connection, now: u64) -> Result<Self> {
        ensure!(!tx.is_autocommit(), "file storage requires a transaction");
        ensure!(
            now <= i64::MAX as u64 - MAX_RETENTION_SECONDS,
            "invalid file storage clock"
        );
        check_version(tx)?;
        ensure!(
            tx.pragma_query_value(None, "foreign_keys", |r| r.get::<_, bool>(0))?,
            "file storage requires foreign keys"
        );
        Ok(Self { db: tx, now })
    }

    /// Reserve the entire object before accepting any chunks. Exact retries do
    /// not consume more quota, replace a grant, or extend its local lifetime.
    pub fn expect(&self, grant: &FileGrant, expires_at: u64) -> Result<()> {
        ensure!(
            expires_at > self.now && expires_at <= self.now + MAX_RETENTION_SECONDS,
            "invalid file retention deadline"
        );
        let id = &grant.descriptor().id;
        let encoded = grant.encode_private()?;
        let previous: Option<(Vec<u8>, u64)> = self
            .db
            .query_row(
                "SELECT grant,expires_at FROM file_objects WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((previous, expiry)) = previous {
            let previous = Zeroizing::new(previous);
            ensure!(
                *previous == *encoded && expiry == expires_at,
                "conflicting file object"
            );
            self.status(id)?;
            return Ok(());
        }
        self.reap()?;
        let (count, reserved): (u64, u64) = self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(reserved_bytes),0) FROM file_objects",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            count < MAX_OBJECTS && reserved + grant.ciphertext_bytes() <= MAX_RESERVED_BYTES,
            "file storage quota exhausted"
        );
        self.db.execute(
            "INSERT INTO file_objects(id,grant,reserved_bytes,expires_at,incomplete_until)
             VALUES(?1,?2,?3,?4,?5)",
            params![
                id,
                encoded.as_slice(),
                grant.ciphertext_bytes(),
                expires_at,
                expires_at.min(self.now + INCOMPLETE_TTL_SECONDS)
            ],
        )?;
        Ok(())
    }

    /// Persist the complete encrypted representation in the message transaction.
    pub fn stage(&self, sealed: &SealedFile, expires_at: u64) -> Result<()> {
        self.expect(sealed.grant(), expires_at)?;
        let id = &sealed.grant().descriptor().id;
        // SealedFile can only be constructed by the crypto module. It is immutable
        // and already binds its complete plaintext digest and every chunk.
        for (index, bytes) in sealed.chunks().iter().enumerate() {
            self.insert_chunk(id, index as u32, bytes)?;
        }
        self.db
            .execute("UPDATE file_objects SET complete=1 WHERE id=?1", [id])?;
        Ok(())
    }

    fn insert_chunk(&self, id: &str, index: u32, bytes: &[u8]) -> Result<()> {
        let previous: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT ciphertext FROM file_chunks WHERE object_id=?1 AND position=?2",
                params![id, index],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            ensure!(previous == bytes, "conflicting file chunk");
        } else {
            self.db.execute(
                "INSERT INTO file_chunks(object_id,position,ciphertext) VALUES(?1,?2,?3)",
                params![id, index, bytes],
            )?;
        }
        Ok(())
    }

    pub fn status(&self, id: &str) -> Result<Status> {
        let status = self
            .db
            .query_row(
                "SELECT complete,expires_at,incomplete_until,
                    (SELECT COUNT(*) FROM file_chunks WHERE object_id=?1),
                    (SELECT COALESCE(SUM(uploaded),0) FROM file_chunks WHERE object_id=?1)
                 FROM file_objects WHERE id=?1",
                [id],
                |r| {
                    Ok(Status {
                        complete: r.get(0)?,
                        expires_at: r.get(1)?,
                        incomplete_until: r.get(2)?,
                        chunks_present: r.get(3)?,
                        chunks_uploaded: r.get(4)?,
                    })
                },
            )
            .optional()?
            .context("file object unavailable")?;
        ensure!(
            status.expires_at > self.now && (status.complete || status.incomplete_until > self.now),
            "file object unavailable"
        );
        Ok(status)
    }

    /// Private grant for an already authorized message or local operation.
    pub fn grant(&self, id: &str) -> Result<FileGrant> {
        self.status(id)?;
        let encoded = Zeroizing::new(self.db.query_row(
            "SELECT grant FROM file_objects WHERE id=?1",
            [id],
            |r| r.get::<_, Vec<u8>>(0),
        )?);
        let grant = FileGrant::decode_private(&encoded)?;
        ensure!(grant.descriptor().id == id, "file object identity mismatch");
        Ok(grant)
    }

    pub fn missing_chunks(&self, id: &str) -> Result<Vec<u32>> {
        let grant = self.grant(id)?;
        let mut query = self.db.prepare(
            "SELECT EXISTS(SELECT 1 FROM file_chunks WHERE object_id=?1 AND position=?2)",
        )?;
        let mut missing = Vec::new();
        for index in 0..grant.chunk_count() {
            if !query.query_row(params![id, index], |r| r.get::<_, bool>(0))? {
                missing.push(index);
            }
        }
        Ok(missing)
    }

    /// Verify before durable storage. Out-of-order arrivals and identical retries
    /// are allowed; completion requires a separate whole-file integrity check.
    pub fn accept_chunk(&self, id: &str, index: u32, bytes: &[u8]) -> Result<()> {
        self.grant(id)?.decrypt_chunk(index, bytes)?;
        self.insert_chunk(id, index, bytes)
    }

    fn open(&self, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let grant = self.grant(id)?;
        let mut query = self.db.prepare(
            "SELECT position,ciphertext FROM file_chunks WHERE object_id=?1 ORDER BY position",
        )?;
        let chunks = query
            .query_map([id], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            chunks
                .iter()
                .enumerate()
                .all(|(index, (saved, _))| index as u32 == *saved),
            "incomplete file object"
        );
        grant.open(
            &chunks
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
        )
    }

    pub fn finish(&self, id: &str) -> Result<()> {
        self.open(id)?;
        self.db
            .execute("UPDATE file_objects SET complete=1 WHERE id=?1", [id])?;
        Ok(())
    }

    fn ready(&self, id: &str) -> Result<FileGrant> {
        let status = self.status(id)?;
        let grant = self.grant(id)?;
        let present: u32 = self.db.query_row(
            "SELECT COUNT(*) FROM file_chunks WHERE object_id=?1 AND position<?2",
            params![id, grant.chunk_count()],
            |r| r.get(0),
        )?;
        ensure!(
            status.complete
                && status.chunks_present == grant.chunk_count()
                && present == grant.chunk_count(),
            "file object incomplete"
        );
        Ok(grant)
    }

    pub fn read(&self, id: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.ready(id)?;
        self.open(id)
    }

    /// Authenticate one plaintext chunk of a completed object. Completion already
    /// checked the whole-file digest; reassemblers should check it again. This
    /// reads only the selected ciphertext, not the entire file on every call.
    pub fn read_chunk(&self, id: &str, index: u32) -> Result<Zeroizing<Vec<u8>>> {
        let grant = self.ready(id)?;
        grant.ciphertext_len(index)?;
        let bytes: Vec<u8> = self.db.query_row(
            "SELECT ciphertext FROM file_chunks WHERE object_id=?1 AND position=?2",
            params![id, index],
            |r| r.get(0),
        )?;
        grant.decrypt_chunk(index, &bytes)
    }

    /// Reconstruct the public storage manifest after restart from saved immutable
    /// chunks and the original deadline. This never exports a private grant.
    pub fn transport_manifest(&self, id: &str) -> Result<gent_protocol::file_objects::Manifest> {
        use gent_protocol::file_objects::{Chunk, Manifest};
        let grant = self.ready(id)?;
        let mut chunks = Vec::with_capacity(grant.chunk_count() as usize);
        for index in 0..grant.chunk_count() {
            let bytes = self.upload_chunk(id, index)?;
            chunks.push(Chunk {
                bytes: bytes.len() as u32,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            });
        }
        let manifest = Manifest {
            version: 1,
            chunks,
            expires_at: self.status(id)?.expires_at,
        };
        manifest.validate().map_err(anyhow::Error::msg)?;
        Ok(manifest)
    }

    /// Uploads expose only fully persisted objects, never partial local imports.
    pub fn upload_chunk(&self, id: &str, index: u32) -> Result<Vec<u8>> {
        let grant = self.ready(id)?;
        let bytes: Vec<u8> = self
            .db
            .query_row(
                "SELECT ciphertext FROM file_chunks WHERE object_id=?1 AND position=?2",
                params![id, index],
                |r| r.get(0),
            )
            .optional()?
            .context("file chunk unavailable")?;
        grant.decrypt_chunk(index, &bytes)?;
        Ok(bytes)
    }

    pub fn pending_uploads(&self, id: &str) -> Result<Vec<u32>> {
        self.ready(id)?;
        let mut query = self.db.prepare(
            "SELECT position FROM file_chunks WHERE object_id=?1 AND uploaded=0 ORDER BY position",
        )?;
        Ok(query
            .query_map([id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?)
    }

    /// Records service storage only; this never means agent delivery or completion.
    pub fn acknowledge_upload(&self, id: &str, index: u32) -> Result<()> {
        self.ready(id)?.ciphertext_len(index)?;
        ensure!(
            self.db.execute(
                "UPDATE file_chunks SET uploaded=1 WHERE object_id=?1 AND position=?2",
                params![id, index],
            )? == 1,
            "file chunk unavailable"
        );
        Ok(())
    }

    /// Recover after relay storage loss using the same persisted ciphertext.
    pub fn retry_upload(&self, id: &str) -> Result<()> {
        self.ready(id)?;
        self.db
            .execute("UPDATE file_chunks SET uploaded=0 WHERE object_id=?1", [id])?;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> Result<bool> {
        Ok(self
            .db
            .execute("DELETE FROM file_objects WHERE id=?1", [id])?
            != 0)
    }

    /// Releases logical quota, including grants and abandoned partial downloads.
    /// SQLite/WAL/backups may retain old pages; this is not forensic erasure.
    pub fn reap(&self) -> Result<usize> {
        Ok(self.db.execute(
            "DELETE FROM file_objects WHERE expires_at<=?1 OR (complete=0 AND incomplete_until<=?1)",
            [self.now],
        )?)
    }
}
