//! Atomic imports from a bounded local binary RPC. No plaintext handoff files.
use super::*;
use gent_protocol::file_objects::IncomingFile;

impl StoreSession<'_> {
    fn received_file(
        &self,
        who: &Agent,
        file: &IncomingFile,
    ) -> Result<Option<(FileGrant, String)>> {
        gent_crypto::files::validate_metadata(&file.name, &file.media_type)?;
        ensure!(
            file.source_id.len() == 64
                && file
                    .source_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid file source identity"
        );
        uuid::Uuid::parse_str(&file.request_id).context("request_id must be a UUID")?;
        let previous: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT fingerprint,object_id FROM file_imports WHERE agent=?1 AND request_id=?2",
                params![who.id, file.request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((fingerprint, id)) = previous {
            let prefix = format!("remote-v1:{}:", file.source_id);
            let digest = fingerprint
                .strip_prefix(&prefix)
                .context("request_id already used with different content")?;
            let grant = self.accessible_file(who, &id)?;
            ensure!(
                grant.descriptor().name == file.name
                    && grant.descriptor().media_type == file.media_type
                    && grant.descriptor().sha256 == digest,
                "request_id already used with different content"
            );
            ensure!(
                self.objects()?.status(&id)?.complete,
                "file object incomplete"
            );
            return Ok(Some((grant, digest.into())));
        }
        requests::admit(&file.request_id, self.timestamp)?;
        history::import_capacity(self.db)?;
        Ok(None)
    }

    pub(in crate::store) fn file_receive_status(
        &self,
        who: &Agent,
        file: &IncomingFile,
    ) -> Result<Value> {
        Ok(match self.received_file(who, file)? {
            Some((grant, _)) => json!({"state":"ready","file":grant.descriptor(),"duplicate":true}),
            None => json!({"state":"upload"}),
        })
    }

    pub(in crate::store) fn file_receive(
        &self,
        who: &Agent,
        file: &IncomingFile,
        bytes: &[u8],
    ) -> Result<Value> {
        ensure!(
            bytes.len() <= gent_crypto::files::MAX_FILE_BYTES,
            "file exceeds 32 MiB"
        );
        let digest = format!("{:x}", Sha256::digest(bytes));
        if let Some((grant, previous)) = self.received_file(who, file)? {
            ensure!(
                previous == digest,
                "request_id already used with different content"
            );
            return Ok(json!({"state":"ready","file":grant.descriptor(),"duplicate":true}));
        }
        let sealed = seal(&file.name, &file.media_type, bytes)?;
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
        self.db.execute("INSERT INTO file_imports(agent,request_id,fingerprint,object_id,retire_after) VALUES(?1,?2,?3,?4,?5)",
            params![who.id,file.request_id,format!("remote-v1:{}:{digest}",file.source_id),descriptor.id,requests::issued(&file.request_id).unwrap()+requests::LIFETIME])?;
        Ok(json!({"state":"ready","file":descriptor,"duplicate":false}))
    }
}
