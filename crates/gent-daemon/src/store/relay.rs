//! Persistent selection and ordered relay turns under ordinary message policy.
//! Relay context does not assert human authorship or authorize host execution.
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
        ON relay_attachments(intermediary) WHERE detached=0;
        CREATE TABLE IF NOT EXISTS relay_turns (
        id TEXT PRIMARY KEY REFERENCES messages(id),
        intermediary TEXT NOT NULL,
        target TEXT NOT NULL,
        attachment TEXT NOT NULL,
        final_message TEXT REFERENCES messages(id),
        cancel_message TEXT REFERENCES messages(id),
        closed_reason TEXT);
        CREATE INDEX IF NOT EXISTS relay_target_turns ON relay_turns(target)
          WHERE final_message IS NULL AND closed_reason IS NULL;
        CREATE INDEX IF NOT EXISTS relay_intermediary_turns ON relay_turns(intermediary);
        CREATE INDEX IF NOT EXISTS relay_responses ON messages(json_extract(payload,'$.relay.turn_id'),recipient);",
    )?;
    Ok(())
}

impl StoreSession<'_> {
    pub(super) fn relay_authorized(&self, message: &Message) -> Result<bool> {
        let Some(relay) = &message.relay else {
            return Ok(true);
        };
        let (intermediary, target) = match relay.kind {
            RelayMessageKind::Request | RelayMessageKind::Cancel => {
                (&message.sender, &message.recipient)
            }
            _ => (&message.recipient, &message.sender),
        };
        if let Some(id) = &relay.grant_id {
            let Some(grant) = self.config.policy.relay_grants.get(id) else {
                return Ok(false);
            };
            if grant.intermediary != *intermediary
                || grant.target != *target
                || grant.issued_at > message.created_at as u64
                || grant.issued_at > self.timestamp as u64
                || grant.expires_at <= self.timestamp as u64
                || message.expires_at as u64 > grant.expires_at
            {
                return Ok(false);
            }
        }
        Ok(self
            .config
            .policy
            .can_open(&self.get_agent(intermediary)?, &self.get_agent(target)?))
    }

    fn legacy_relay_revoked(&self, relay: &RelayMessage) -> bool {
        relay
            .grant_id
            .as_ref()
            .is_some_and(|id| !self.config.policy.relay_grants.contains_key(id))
    }

    /// Validate both local and authenticated remote envelopes. Generic replies
    /// cannot strip relay context, and a response must reference the root turn.
    pub(super) fn validate_relay_message(&self, message: &Message) -> Result<()> {
        let Some(relay) = &message.relay else {
            if let Some(parent) = &message.reply_to {
                ensure!(
                    self.message(parent)?.relay.is_none(),
                    "reply omitted relay context"
                );
            }
            return Ok(());
        };
        for id in [&relay.attachment_id, &relay.turn_id]
            .into_iter()
            .chain(relay.grant_id.iter())
        {
            let parsed = Uuid::parse_str(id)?;
            ensure!(
                !parsed.is_nil() && parsed.to_string() == *id,
                "invalid relay identity"
            );
        }
        ensure!(self.relay_authorized(message)?, UNAVAILABLE);
        ensure!(
            message.exchange_id == relay.turn_id,
            "relay exchange mismatch"
        );
        if relay.kind == RelayMessageKind::Request {
            ensure!(
                relay.turn_id == message.id && message.reply_to.is_none(),
                "invalid relay root"
            );
        } else {
            let root = self.relay_root(&relay.turn_id)?;
            let original = root.relay.as_ref().unwrap();
            ensure!(
                message.reply_to.as_deref() == Some(root.id.as_str())
                    && relay.attachment_id == original.attachment_id
                    && relay.grant_id == original.grant_id
                    && message.expires_at == root.expires_at,
                "relay response belongs to another turn or attachment"
            );
            let cancellation = relay.kind == RelayMessageKind::Cancel;
            ensure!(
                if cancellation {
                    message.sender == root.sender && message.recipient == root.recipient
                } else {
                    message.sender == root.recipient && message.recipient == root.sender
                },
                "relay participants changed"
            );
            let (finished, cancelled, closed) = self.relay_turn_flags(&root.id)?;
            // A cancellation may cross a final reply in flight. Persist it
            // without reopening the turn or changing the target's outcome.
            if cancellation {
                ensure!(
                    cancelled.is_none(),
                    "cancellation already requested; retry its original request_id"
                );
            } else {
                ensure!(
                    finished.is_none() && closed.is_none(),
                    "relay turn already finished"
                );
                if relay.kind == RelayMessageKind::Cancelled {
                    ensure!(cancelled.is_some(), "no cancellation was requested");
                }
                let sent: u32 = self.db.query_row(
                    "SELECT COUNT(*) FROM messages WHERE sender=?1 AND json_extract(payload,'$.exchange_id')=?2",
                    params![message.sender,root.id], |r| r.get(0))?;
                // Reserve the final slot even when many progress updates were
                // sent. Use the same per-target budget on local/remote turns.
                let limit =
                    MAX_EXCHANGE_MESSAGES / 2 - u32::from(relay.kind == RelayMessageKind::Progress);
                ensure!(
                    sent < limit,
                    "relay response limit reached; reserve the last slot for a final outcome"
                );
            }
        }
        Ok(())
    }

    pub(super) fn validate_local_relay(&self, message: &Message) -> Result<()> {
        let Some(relay) = &message.relay else {
            return Ok(());
        };
        if relay.kind == RelayMessageKind::Request {
            let who = self.get_agent(&message.sender)?;
            let attachment = self.relay_attachment(&who, &relay.attachment_id)?;
            ensure!(
                !attachment.detached
                    && attachment
                        .expires_at
                        .is_none_or(|expiry| expiry > self.timestamp as u64)
                    && attachment.target == message.recipient
                    && attachment.grant_id == relay.grant_id,
                "relay attachment is no longer active"
            );
        } else if relay.kind == RelayMessageKind::Cancel {
            let (finished, _, closed) = self.relay_turn_flags(&relay.turn_id)?;
            ensure!(
                finished.is_none() && closed.is_none(),
                "relay turn already finished"
            );
        } else {
            ensure!(
                self.relay_head(&message.sender)?
                    .is_some_and(|root| root.id == relay.turn_id),
                "relay turn is not the target's current turn"
            );
        }
        Ok(())
    }

    pub(super) fn record_relay_message(&self, message: &Message) -> Result<()> {
        let Some(relay) = &message.relay else {
            return Ok(());
        };
        match relay.kind {
            RelayMessageKind::Request => {
                self.db.execute(
                "INSERT INTO relay_turns(id,intermediary,target,attachment) VALUES(?1,?2,?3,?4)",
                params![message.id,message.sender,message.recipient,relay.attachment_id])?;
            }
            RelayMessageKind::Complete | RelayMessageKind::Cancelled => {
                ensure!(self.db.execute(
                "UPDATE relay_turns SET final_message=?1 WHERE id=?2 AND final_message IS NULL AND closed_reason IS NULL",
                params![message.id,relay.turn_id])? == 1, "relay turn already finished");
            }
            RelayMessageKind::Cancel => {
                self.db.execute(
                    "UPDATE relay_turns SET cancel_message=COALESCE(cancel_message,?1) WHERE id=?2",
                    params![message.id, relay.turn_id],
                )?;
            }
            RelayMessageKind::Progress => {}
        }
        Ok(())
    }

    fn relay_root(&self, id: &str) -> Result<Message> {
        let root = self.message(id)?;
        ensure!(
            root.relay.as_ref().is_some_and(
                |relay| relay.kind == RelayMessageKind::Request && relay.turn_id == root.id
            ),
            UNAVAILABLE
        );
        Ok(root)
    }

    fn relay_turn_flags(
        &self,
        id: &str,
    ) -> Result<(Option<String>, Option<String>, Option<String>)> {
        Ok(self.db.query_row(
            "SELECT final_message,cancel_message,closed_reason FROM relay_turns WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?)
    }

    fn relay_head(&self, target: &str) -> Result<Option<Message>> {
        loop {
            let id: Option<String> = self.db.query_row("SELECT id FROM relay_turns WHERE target=?1 AND final_message IS NULL AND closed_reason IS NULL ORDER BY rowid LIMIT 1",
                [target], |r| r.get(0)).optional()?;
            let Some(id) = id else {
                return Ok(None);
            };
            let root = self.relay_root(&id)?;
            let relay = root.relay.as_ref().unwrap();
            let closed = if root.expires_at <= self.timestamp {
                Some("expired")
            } else if self.legacy_relay_revoked(relay) {
                Some("revoked")
            } else {
                None
            };
            if let Some(reason) = closed {
                self.db.execute(
                    "UPDATE relay_turns SET closed_reason=?1 WHERE id=?2",
                    params![reason, id],
                )?;
                continue;
            }
            // Temporary permission blocks pause the head; later turns cannot
            // overtake it and then overlap when permissions are restored.
            return Ok(self.deliverable(&root)?.then_some(root));
        }
    }

    pub(super) fn relay_inbox_visible(&self, message: &Message) -> Result<bool> {
        let Some(relay) = &message.relay else {
            return Ok(true);
        };
        Ok(match relay.kind {
            RelayMessageKind::Request | RelayMessageKind::Cancel => self
                .relay_head(&message.recipient)?
                .is_some_and(|root| root.id == relay.turn_id),
            _ => true,
        })
    }

    pub(super) fn relay_send(
        &mut self,
        who: &Agent,
        attachment: &str,
        request: &str,
        content: (String, Vec<FilePart>, Vec<String>),
    ) -> Result<Value> {
        let attachment = self.relay_attachment(who, attachment)?;
        let turn_id = crate::messages::message_id(&who.id, request)?;
        let relay = RelayMessage {
            attachment_id: attachment.id,
            grant_id: attachment.grant_id,
            turn_id: turn_id.clone(),
            kind: RelayMessageKind::Request,
        };
        let mut result = self.send(
            who,
            &attachment.target,
            request,
            content.0,
            content.1,
            SendContext {
                parent: None,
                relay: Some(relay),
                file_ids: content.2,
            },
        )?;
        result["turn_id"] = json!(turn_id);
        Ok(result)
    }

    pub(super) fn relay_respond(
        &mut self,
        who: &Agent,
        turn: &str,
        request: &str,
        content: (String, Vec<FilePart>, Vec<String>),
        outcome: RelayResponseKind,
    ) -> Result<Value> {
        let root = self.relay_root(turn)?;
        ensure!(root.recipient == who.id, UNAVAILABLE);
        let mut relay = root.relay.clone().unwrap();
        relay.kind = match outcome {
            RelayResponseKind::Progress => RelayMessageKind::Progress,
            RelayResponseKind::Complete => RelayMessageKind::Complete,
            RelayResponseKind::Cancelled => RelayMessageKind::Cancelled,
        };
        self.send(
            who,
            &root.sender.clone(),
            request,
            content.0,
            content.1,
            SendContext {
                parent: Some(root),
                relay: Some(relay),
                file_ids: content.2,
            },
        )
    }

    pub(super) fn relay_cancel(&mut self, who: &Agent, turn: &str, request: &str) -> Result<Value> {
        let root = self.relay_root(turn)?;
        ensure!(root.sender == who.id, UNAVAILABLE);
        let mut relay = root.relay.clone().unwrap();
        relay.kind = RelayMessageKind::Cancel;
        self.send(
            who,
            &root.recipient.clone(),
            request,
            "Cancellation requested.".into(),
            vec![],
            SendContext {
                parent: Some(root),
                relay: Some(relay),
                file_ids: vec![],
            },
        )
    }

    pub(super) fn relay_next(&self, who: &Agent) -> Result<Value> {
        let Some(root) = self.relay_head(&who.id)? else {
            return Ok(Value::Null);
        };
        let (_, cancel, _) = self.relay_turn_flags(&root.id)?;
        Ok(json!({"request":root,"cancel_requested":cancel.is_some()}))
    }

    pub(super) fn relay_turn_status(
        &self,
        who: &Agent,
        id: &str,
        after: Option<&str>,
    ) -> Result<Value> {
        let root = self.relay_root(id)?;
        ensure!(root.sender == who.id, UNAVAILABLE);
        let target = self.get_agent(&root.recipient)?;
        if !self.config.policy.visible(who, &target) {
            return Ok(json!({"turn_id":id,"state":"unavailable"}));
        }
        let (finished, cancelled, closed) = self.relay_turn_flags(id)?;
        let rejected: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_rejections WHERE message=?1)",
            [id],
            |r| r.get(0),
        )?;
        let state = if root.expires_at <= self.timestamp {
            "expired"
        } else if closed.is_some() {
            closed.as_deref().unwrap()
        } else if self.legacy_relay_revoked(root.relay.as_ref().unwrap()) || rejected {
            "revoked"
        } else if !self.relay_authorized(&root)? {
            "blocked"
        } else if finished.is_some() {
            "completed"
        } else {
            "pending"
        };
        let mut replies = Vec::new();
        let mut next_after = after.map(str::to_owned);
        let mut has_more = false;
        if ["pending", "completed"].contains(&state) {
            let cursor: i64 = if let Some(after) = after {
                self.db.query_row(
                "SELECT rowid FROM messages WHERE id=?1 AND recipient=?2 AND json_extract(payload,'$.relay.turn_id')=?3",
                params![after,who.id,id], |r| r.get(0)).optional()?.context("invalid relay response cursor")?
            } else {
                0
            };
            let mut bytes = 0;
            let mut query = self.db.prepare("SELECT payload,acknowledged FROM messages WHERE recipient=?1 AND json_extract(payload,'$.relay.turn_id')=?2 AND rowid>?3 ORDER BY rowid")?;
            for row in query.query_map(params![who.id, id, cursor], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
            })? {
                let (payload, acknowledged) = row?;
                if bytes + payload.len() > MAX_FRAME_BYTES / 2 {
                    has_more = true;
                    break;
                }
                let mut message: Message = serde_json::from_str(&payload)?;
                message.acknowledged = acknowledged;
                bytes += payload.len();
                next_after = Some(message.id.clone());
                if self.deliverable(&message)? {
                    replies.push(message);
                }
            }
        }
        Ok(
            json!({"turn_id":id,"relay":root.relay,"target":target,"state":state,
            "expires_at":root.expires_at,"received":root.acknowledged,
            "security_mode":if who.node_id == target.node_id { RelaySecurityMode::LocalDaemon } else { RelaySecurityMode::EncryptedDaemonLink },
            "cancel_requested":cancelled.is_some(),"final_message_id":finished,
            "responses":replies,"next_after":next_after,"has_more":has_more}),
        )
    }

    pub(super) fn relay_turns(&self, who: &Agent, after: Option<&str>) -> Result<Value> {
        let cursor: i64 = if let Some(after) = after {
            self.db
                .query_row(
                    "SELECT rowid FROM relay_turns WHERE id=?1 AND intermediary=?2",
                    params![after, who.id],
                    |r| r.get(0),
                )
                .optional()?
                .context("invalid relay turn cursor")?
        } else {
            0
        };
        let ids = self.db.prepare("SELECT id FROM relay_turns WHERE intermediary=?1 AND rowid>?2 ORDER BY rowid LIMIT 51")?
            .query_map(params![who.id,cursor], |r| r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let has_more = ids.len() > 50;
        let mut turns = Vec::new();
        let mut next_after = after.map(str::to_owned);
        for id in ids.into_iter().take(50) {
            let root = self.relay_root(&id)?;
            let target = self.get_agent(&root.recipient)?;
            if self.config.policy.visible(who, &target) {
                let (finished, cancelled, closed) = self.relay_turn_flags(&id)?;
                turns.push(json!({"turn_id":id,"relay":root.relay,"target":target,
                    "expires_at":root.expires_at,"final_message_id":finished,
                    "cancel_requested":cancelled.is_some(),"closed_reason":closed}));
            } else {
                turns.push(json!({"turn_id":id,"state":"unavailable"}));
            }
            next_after = Some(id);
        }
        Ok(json!({"turns":turns,"next_after":next_after,"has_more":has_more}))
    }

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
                json!({"attachment_id":attachment.id,"state":"unavailable","supports_turns":true}),
            );
        }
        let now = self.timestamp as u64;
        let valid_grant = attachment.grant_id.as_ref().is_none_or(|id| {
            self.config
                .policy
                .relay_grants
                .get(id)
                .is_some_and(|grant| {
                    grant.intermediary == who.id
                        && grant.target == target.id
                        && grant.issued_at <= now
                        && grant.expires_at > now
                })
        });
        let state = if attachment.detached {
            "detached"
        } else if attachment.expires_at.is_some_and(|expiry| expiry <= now) {
            "expired"
        } else if !valid_grant {
            "revoked"
        } else if !self.config.policy.can_open(who, &target) {
            "blocked"
        } else {
            "attached"
        };
        Ok(json!({"attachment":attachment,"target":target,"state":state,"supports_turns":true}))
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
        requests::admit(request_id, self.timestamp)?;
        let peer = self.get_agent(target)?;
        ensure!(
            who.id != peer.id && self.config.policy.can_open(who, &peer),
            UNAVAILABLE
        );
        let now = self.timestamp as u64;
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
            grant_id: None,
            security_mode: if who.node_id == peer.node_id {
                RelaySecurityMode::LocalDaemon
            } else {
                RelaySecurityMode::EncryptedDaemonLink
            },
            created_at: now,
            expires_at: None,
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
