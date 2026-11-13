//! Persistent target selection. Relay turns are added separately; attaching
//! never sends a message or asserts that a human authored agent-provided text.
use super::*;
use uuid::Uuid;

pub(super) fn schema(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS relay_attachments (
        id TEXT PRIMARY KEY,
        intermediary TEXT NOT NULL REFERENCES agents(id),
        request_id TEXT NOT NULL,
        target TEXT NOT NULL REFERENCES agents(id),
        detached INTEGER NOT NULL DEFAULT 0,
        payload TEXT NOT NULL,
        UNIQUE(intermediary,request_id));
        CREATE UNIQUE INDEX IF NOT EXISTS relay_current
        ON relay_attachments(intermediary) WHERE detached=0;",
    )?;
    Ok(())
}

impl StoreSession<'_> {
    fn relay_attachment(&self, who: &Agent, id: &str) -> Result<RelayAttachment> {
        let (payload, detached): (String, bool) = self
            .db
            .query_row(
                "SELECT payload,detached FROM relay_attachments WHERE id=?1 AND intermediary=?2",
                params![id, who.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .context(UNAVAILABLE)?;
        let mut attachment: RelayAttachment = serde_json::from_str(&payload)?;
        attachment.detached = detached;
        Ok(attachment)
    }

    fn relay_view(&self, who: &Agent, attachment: RelayAttachment) -> Result<Value> {
        let target = self.get_agent(&attachment.target)?;
        if !self.config.policy.visible(who, &target) {
            return Ok(
                json!({"attachment_id":attachment.id,"state":"unavailable","supports_turns":false}),
            );
        }
        let now = self.timestamp as u64;
        let grant = self.config.policy.relay_grants.get(&attachment.grant_id);
        let valid_grant = grant.is_some_and(|grant| {
            grant.intermediary == who.id
                && grant.target == target.id
                && grant.issued_at <= now
                && grant.expires_at > now
        });
        let state = if attachment.detached {
            "detached"
        } else if attachment.expires_at <= now {
            "expired"
        } else if !valid_grant {
            "revoked"
        } else if !self.config.policy.can_open(who, &target) {
            "blocked"
        } else {
            "attached"
        };
        Ok(json!({"attachment":attachment,"target":target,"state":state,"supports_turns":false}))
    }

    pub(super) fn relay_attach(
        &self,
        who: &Agent,
        target: &str,
        request_id: &str,
    ) -> Result<Value> {
        let request = Uuid::parse_str(request_id).context("relay request_id must be a UUID")?;
        ensure!(
            !request.is_nil() && request.to_string() == request_id,
            "invalid relay request_id"
        );
        let previous: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT id,target FROM relay_attachments WHERE intermediary=?1 AND request_id=?2",
                params![who.id, request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, previous_target)) = previous {
            ensure!(
                previous_target == target,
                "request_id already used for another relay target"
            );
            // An old retry must not reactivate an attachment after a switch.
            return self.relay_view(who, self.relay_attachment(who, &id)?);
        }
        let peer = self.get_agent(target)?;
        ensure!(
            who.id != peer.id && self.config.policy.can_open(who, &peer),
            UNAVAILABLE
        );
        let now = self.timestamp as u64;
        let (grant_id, grant) = self
            .config
            .policy
            .relay_grants
            .iter()
            .filter(|(_, grant)| {
                grant.intermediary == who.id
                    && grant.target == peer.id
                    && grant.issued_at <= now
                    && grant.expires_at > now
            })
            .max_by_key(|(id, grant)| (grant.expires_at, grant.issued_at, *id))
            .context("relay target requires an active owner grant")?;
        let count: u32 = self.db.query_row(
            "SELECT COUNT(*) FROM relay_attachments WHERE intermediary=?1",
            [&who.id],
            |r| r.get(0),
        )?;
        ensure!(count < 1024, "relay attachment history limit reached");
        let id = gent_crypto::scoped_id(
            b"gent/relay-attachment/v1\0",
            &[who.id.as_bytes(), request.as_bytes()],
        )
        .to_string();
        let attachment = RelayAttachment {
            id,
            intermediary: who.id.clone(),
            target: peer.id.clone(),
            grant_id: grant_id.clone(),
            security_mode: if who.node_id == peer.node_id {
                RelaySecurityMode::LocalDaemon
            } else {
                RelaySecurityMode::EncryptedDaemonLink
            },
            created_at: now,
            expires_at: grant.expires_at,
            detached: false,
        };
        // The outer RPC transaction makes switching and its retry record atomic.
        self.db.execute(
            "UPDATE relay_attachments SET detached=1 WHERE intermediary=?1 AND detached=0",
            [&who.id],
        )?;
        self.db.execute("INSERT INTO relay_attachments(id,intermediary,request_id,target,payload) VALUES(?1,?2,?3,?4,?5)",
            params![attachment.id,who.id,request_id,peer.id,serde_json::to_string(&attachment)?])?;
        self.relay_view(who, attachment)
    }

    pub(super) fn relay_status(&self, who: &Agent, id: Option<String>) -> Result<Value> {
        let id = match id {
            Some(id) => Some(id),
            None => self
                .db
                .query_row(
                    "SELECT id FROM relay_attachments WHERE intermediary=?1 AND detached=0",
                    [&who.id],
                    |r| r.get(0),
                )
                .optional()?,
        };
        match id {
            Some(id) => self.relay_view(who, self.relay_attachment(who, &id)?),
            None => Ok(Value::Null),
        }
    }

    pub(super) fn relay_detach(&self, who: &Agent, id: &str) -> Result<Value> {
        let mut attachment = self.relay_attachment(who, id)?;
        self.db.execute(
            "UPDATE relay_attachments SET detached=1 WHERE id=?1 AND intermediary=?2",
            params![id, who.id],
        )?;
        attachment.detached = true;
        self.relay_view(who, attachment)
    }

    pub(super) fn relay_attachments(&self) -> Result<Value> {
        let rows = self
            .db
            .prepare(
                "SELECT payload,detached FROM relay_attachments ORDER BY rowid DESC LIMIT 100",
            )?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut attachments = Vec::new();
        for (payload, detached) in rows {
            let mut attachment: RelayAttachment = serde_json::from_str(&payload)?;
            attachment.detached = detached;
            attachments.push(attachment);
        }
        Ok(json!(attachments))
    }
}
