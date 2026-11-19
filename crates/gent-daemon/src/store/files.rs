//! Agent authorization and durable bindings for separately transported files.
use super::*;
use crate::{file_objects::Objects, messages::PrivateAttachment};
use base64::{Engine, engine::general_purpose::STANDARD};
use gent_crypto::files::{FileGrant, seal};
use gent_protocol::file_objects::Manifest;
use zeroize::Zeroizing;
mod exports;
mod host;
mod receive;
mod retention;

#[derive(Clone, Copy)]
pub(super) enum ExportStep {
    Reserve,
    Write,
    Publish,
}

const FILE_UNAVAILABLE: &str = "file unavailable";

pub(super) fn schema(db: &mut Connection) -> Result<()> {
    crate::file_objects::initialize(db)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS agent_files (
            object_id TEXT PRIMARY KEY REFERENCES file_objects(id) ON DELETE CASCADE,
            agent TEXT REFERENCES agents(id),
            message TEXT REFERENCES messages(id),
            manifest TEXT NOT NULL,
            CHECK((agent IS NULL) != (message IS NULL)));
         CREATE TABLE IF NOT EXISTS file_imports (
            agent TEXT NOT NULL REFERENCES agents(id), request_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL, object_id TEXT NOT NULL, PRIMARY KEY(agent,request_id));
         CREATE TABLE IF NOT EXISTS message_file_proofs (
            message TEXT PRIMARY KEY REFERENCES messages(id), digest TEXT NOT NULL);",
    )?;
    retention::schema(db)?;
    let columns = db
        .prepare("PRAGMA table_info(file_imports)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|name| name == "retire_after") {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "ALTER TABLE file_imports ADD COLUMN retire_after INTEGER NOT NULL DEFAULT 0;",
        )?;
        let rows = tx
            .prepare("SELECT agent,request_id FROM file_imports")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (agent, request) in rows {
            let deadline =
                requests::issued(&request).map_or(0, |issued| issued + requests::LIFETIME);
            tx.execute(
                "UPDATE file_imports SET retire_after=?3 WHERE agent=?1 AND request_id=?2",
                params![agent, request, deadline],
            )?;
        }
        tx.commit()?;
    }
    db.execute_batch(
        "CREATE INDEX IF NOT EXISTS file_import_retention ON file_imports(retire_after);",
    )?;
    Ok(())
}

fn proof(files: &[PrivateAttachment]) -> Result<String> {
    let bytes = Zeroizing::new(serde_json::to_vec(files)?);
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

impl StoreSession<'_> {
    pub(super) fn objects(&self) -> Result<Objects<'_>> {
        Objects::in_transaction(self.db, self.timestamp as u64)
    }

    /// Uniform absence/authorization errors for caller-selected opaque IDs.
    fn accessible_file(&self, who: &Agent, id: &str) -> Result<FileGrant> {
        let result = (|| {
            let (agent, message): (Option<String>, Option<String>) = self.db.query_row(
                "SELECT agent,message FROM agent_files WHERE object_id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if let Some(agent) = agent {
                ensure!(agent == who.id, FILE_UNAVAILABLE);
            } else {
                let message = self.message(message.as_deref().context(FILE_UNAVAILABLE)?)?;
                ensure!(
                    (message.sender == who.id || message.recipient == who.id)
                        && self.deliverable(&message)?,
                    FILE_UNAVAILABLE
                );
            }
            self.objects()?.grant(id)
        })();
        result.map_err(|_: anyhow::Error| anyhow::anyhow!(FILE_UNAVAILABLE))
    }

    pub(super) fn file_paths(&self, who: &Agent) -> Result<Value> {
        let paths = host::Folders::open(self.home, &who.id)?;
        Ok(
            json!({"import_directory":paths.import_path,"export_directory":paths.export_path,
            "max_file_bytes":gent_crypto::files::MAX_FILE_BYTES,
            "handoff_retention":"unchanged imported/exported copies are cleaned after file expiry; save lasting files elsewhere"}),
        )
    }

    pub(super) fn file_import(
        &self,
        who: &Agent,
        request: &str,
        name: &str,
        media_type: &str,
    ) -> Result<Value> {
        uuid::Uuid::parse_str(request).context("request_id must be a UUID")?;
        // Validate metadata before any caller-selected filesystem operation.
        host::basename(name)?;
        let paths = host::Folders::open(self.home, &who.id)?;
        let (bytes, stamp) = paths.read(name)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let fingerprint = hash(&serde_json::to_string(&json!([name, media_type, digest]))?);
        let previous: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT fingerprint,object_id FROM file_imports WHERE agent=?1 AND request_id=?2",
                params![who.id, request],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((previous, id)) = previous {
            ensure!(
                previous == fingerprint,
                "request_id already used with different content"
            );
            let grant = self.accessible_file(who, &id)?;
            let expiry = self.objects()?.status(&id)?.expires_at;
            retention::track(self.db, &who.id, "", name, &stamp, &digest, expiry)?;
            return Ok(json!({"file":grant.descriptor(),"duplicate":true,"cleanup_after":expiry}));
        }
        requests::admit(request, self.timestamp)?;
        history::import_capacity(self.db)?;
        let sealed = seal(name, media_type, &bytes)?;
        let expiry = self.timestamp as u64 + crate::file_objects::MAX_RETENTION_SECONDS;
        self.objects()?.stage(&sealed, expiry)?;
        let descriptor = sealed.grant().descriptor();
        self.db.execute(
            "INSERT INTO agent_files VALUES(?1,?2,NULL,?3)",
            params![
                descriptor.id,
                who.id,
                serde_json::to_string(&sealed.transport_manifest(expiry)?)?
            ],
        )?;
        self.db.execute(
            "INSERT INTO file_imports(agent,request_id,fingerprint,object_id,retire_after) VALUES(?1,?2,?3,?4,?5)",
            params![who.id, request, fingerprint, descriptor.id,requests::issued(request).unwrap()+requests::LIFETIME],
        )?;
        retention::track(self.db, &who.id, "", name, &stamp, &digest, expiry)?;
        Ok(json!({"file":descriptor,"duplicate":false,"cleanup_after":expiry}))
    }

    pub(super) fn file_status(&self, who: &Agent, id: &str) -> Result<Value> {
        let grant = self.accessible_file(who, id)?;
        let status = self.objects()?.status(id)?;
        Ok(
            json!({"file":grant.descriptor(),"state":if status.complete {"ready"} else {"pending"},
            "chunks_present":status.chunks_present,"chunks_total":grant.chunk_count(),"expires_at":status.expires_at}),
        )
    }

    pub(super) fn file_read(&self, who: &Agent, id: &str, index: u32) -> Result<Value> {
        let grant = self.accessible_file(who, id)?;
        let bytes = self.objects()?.read_chunk(id, index)?;
        let next = (index + 1 < grant.chunk_count()).then_some(index + 1);
        Ok(json!({"file":grant.descriptor(),"chunk_index":index,
            "offset":u64::from(index) * gent_protocol::file_objects::CHUNK_BYTES as u64,
            "byte_length":bytes.len(),"chunks_total":grant.chunk_count(),
            "next_chunk_index":next,"data_base64":STANDARD.encode(&bytes)}))
    }

    pub(super) fn file_view(&self, who: &Agent, id: &str) -> Result<Value> {
        let grant = self.accessible_file(who, id)?;
        let descriptor = grant.descriptor();
        ensure!(
            matches!(
                descriptor.media_type.as_str(),
                "image/png" | "image/jpeg" | "image/webp" | "image/gif"
            ),
            "file view requires PNG, JPEG, WebP, or GIF; use file_read for other files"
        );
        ensure!(
            descriptor.byte_length <= gent_protocol::file_objects::MAX_IMAGE_VIEW_BYTES as u64,
            "file view exceeds 4 MiB; use file_read or request a smaller image"
        );
        let bytes = self.objects()?.read(id)?;
        Ok(json!({"file":descriptor,"data_base64":STANDARD.encode(&bytes)}))
    }

    pub(super) fn seal_attachments(
        &self,
        who: &Agent,
        ids: &[String],
        expiry: i64,
    ) -> Result<Vec<PrivateAttachment>> {
        let mut result = Vec::with_capacity(ids.len());
        for id in ids {
            let grant = self.accessible_file(who, id)?;
            let bytes = self.objects()?.read(id)?;
            let sealed = seal(
                &grant.descriptor().name,
                &grant.descriptor().media_type,
                &bytes,
            )?;
            self.objects()?.stage(&sealed, expiry as u64)?;
            result.push(PrivateAttachment {
                grant: FileGrant::decode_private(&sealed.grant().encode_private()?)?,
                manifest: sealed.transport_manifest(expiry as u64)?,
            });
        }
        Ok(result)
    }

    pub(super) fn bind_attachments(
        &self,
        message: &Message,
        files: &[PrivateAttachment],
    ) -> Result<()> {
        ensure!(
            files.len() == message.attachments.len() && files.len() <= 4,
            "invalid file grants"
        );
        let mut ids = std::collections::BTreeSet::new();
        for (file, descriptor) in files.iter().zip(&message.attachments) {
            ensure!(
                file.grant.descriptor() == descriptor && ids.insert(&descriptor.id),
                "invalid file grant binding"
            );
            file.manifest.validate().map_err(anyhow::Error::msg)?;
            ensure!(
                file.manifest.expires_at == message.expires_at as u64
                    && file.manifest.chunks.len() == file.grant.chunk_count() as usize,
                "invalid file manifest binding"
            );
            for (i, chunk) in file.manifest.chunks.iter().enumerate() {
                ensure!(
                    chunk.bytes as usize == file.grant.ciphertext_len(i as u32)?,
                    "invalid file chunk binding"
                );
            }
        }
        let digest = proof(files)?;
        let previous: Option<String> = self
            .db
            .query_row(
                "SELECT digest FROM message_file_proofs WHERE message=?1",
                [&message.id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            ensure!(digest == previous, "conflicting remote file grants");
            return Ok(());
        }
        for file in files {
            self.objects()?
                .expect(&file.grant, message.expires_at as u64)?;
            self.db.execute(
                "INSERT INTO agent_files VALUES(?1,NULL,?2,?3)",
                params![
                    file.grant.descriptor().id,
                    message.id,
                    serde_json::to_string(&file.manifest)?
                ],
            )?;
        }
        if !files.is_empty() {
            self.db.execute(
                "INSERT INTO message_file_proofs VALUES(?1,?2)",
                params![message.id, digest],
            )?;
        }
        Ok(())
    }

    pub(super) fn private_attachments(&self, message: &Message) -> Result<Vec<PrivateAttachment>> {
        message
            .attachments
            .iter()
            .map(|descriptor| {
                Ok(PrivateAttachment {
                    grant: self.objects()?.grant(&descriptor.id)?,
                    manifest: self.file_manifest(&descriptor.id)?,
                })
            })
            .collect()
    }

    fn file_manifest(&self, id: &str) -> Result<Manifest> {
        let encoded: String = self.db.query_row(
            "SELECT manifest FROM agent_files WHERE object_id=?1",
            [id],
            |r| r.get(0),
        )?;
        Ok(serde_json::from_str(&encoded)?)
    }
}

pub(crate) struct Transfer {
    pub id: String,
    pub manifest: Manifest,
    pub upload: bool,
    pub missing: Vec<u32>,
}
impl StoreSession<'_> {
    fn transfer(&self, id: &str) -> Result<Option<Transfer>> {
        let subject: String = self.db.query_row(
            "SELECT message FROM agent_files WHERE object_id=?1 AND message IS NOT NULL",
            [id],
            |r| r.get(0),
        )?;
        let message = self.message(&subject)?;
        ensure!(self.deliverable(&message)?, FILE_UNAVAILABLE);
        let sender = self.get_agent(&message.sender)?;
        let recipient = self.get_agent(&message.recipient)?;
        let upload = self.local_node(&sender.node_id);
        if upload && self.local_node(&recipient.node_id) {
            return Ok(None);
        }
        ensure!(
            upload || self.local_node(&recipient.node_id),
            FILE_UNAVAILABLE
        );
        let objects = self.objects()?;
        let status = objects.status(id)?;
        if !upload && status.complete {
            return Ok(None);
        }
        Ok(Some(Transfer {
            id: id.into(),
            manifest: self.file_manifest(id)?,
            upload,
            missing: if upload {
                objects.pending_uploads(id)?
            } else {
                objects.missing_chunks(id)?
            },
        }))
    }
}
impl Store {
    fn file_transaction<T>(
        &mut self,
        operation: impl FnOnce(&StoreSession<'_>) -> Result<T>,
    ) -> Result<T> {
        let tx = rusqlite::Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            now() as u64,
        )?;
        let session = self.network_session(&tx, state);
        let result = operation(&session)?;
        tx.commit()?;
        Ok(result)
    }
    pub(crate) fn file_jobs(&mut self) -> Result<Vec<String>> {
        self.file_transaction(|s| {
            s.objects()?.reap()?;
            let ids: Vec<String> = s.db.prepare("SELECT object_id FROM agent_files WHERE message IS NOT NULL ORDER BY object_id")?.query_map([],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
            Ok(ids.into_iter().filter(|id| matches!(s.transfer(id),Ok(Some(_)))).collect())
        })
    }
    pub(crate) fn file_transfer(&mut self, id: &str) -> Result<Option<Transfer>> {
        self.file_transaction(|s| s.transfer(id))
    }
    pub(crate) fn file_upload(&mut self, id: &str, index: u32) -> Result<Vec<u8>> {
        self.file_transaction(|s| {
            ensure!(s.transfer(id)?.is_some_and(|t| t.upload), FILE_UNAVAILABLE);
            s.objects()?.upload_chunk(id, index)
        })
    }
    pub(crate) fn file_uploaded(&mut self, id: &str, uploaded: &[u32]) -> Result<bool> {
        let (changed, complete) = self.file_transaction(|s| {
            let transfer = s.transfer(id)?.context(FILE_UNAVAILABLE)?;
            ensure!(transfer.upload, FILE_UNAVAILABLE);
            let objects = s.objects()?;
            objects.retry_upload(id)?;
            for index in uploaded {
                objects.acknowledge_upload(id, *index)?;
            }
            let missing = objects.pending_uploads(id)?;
            Ok((transfer.missing != missing, missing.is_empty()))
        })?;
        if changed && complete {
            self.sync_wakeup.notify_one();
        }
        Ok(changed)
    }
    pub(crate) fn file_received(&mut self, id: &str, index: u32, bytes: &[u8]) -> Result<()> {
        self.file_transaction(|s| {
            ensure!(s.transfer(id)?.is_some_and(|t| !t.upload), FILE_UNAVAILABLE);
            let objects = s.objects()?;
            objects.accept_chunk(id, index, bytes)?;
            if objects.missing_chunks(id)?.is_empty() {
                objects.finish(id)?;
            }
            Ok(())
        })
    }
}
