//! Direct native delivery and exactly one recorded response per dispatched turn.
//! Host execution remains outside this journal; recovery only reads host results.
use super::*;
use gent_protocol::wake::{DirectWake, WakeDelivery};

const _: () = assert!(AGENT_HOURLY_LIMIT * (EXCHANGE_TTL_SECONDS as u64 / 3600 + 2) < 512);

impl StoreSession<'_> {
    fn direct_record(
        &self,
        who: &Agent,
        message: &str,
        attempt: &str,
        host: &WakeTarget,
    ) -> Result<WakeRecord> {
        id(attempt)?;
        target(host)?;
        let record = self.wake_record(message)?.context(UNAVAILABLE)?;
        ensure!(
            record.agent == who.id
                && record.attempt_id == attempt
                && &record.target == host
                && record.direct.is_some(),
            UNAVAILABLE
        );
        Ok(record)
    }

    fn direct_delivery(&self, mut message: Message) -> Result<WakeDelivery> {
        let automatic_reply = message
            .relay
            .as_ref()
            .is_some_and(|r| r.kind == RelayMessageKind::Request);
        // File bytes stay in Gent; host wake bodies carry only attachment metadata.
        for file in &mut message.files {
            file.data_base64.clear();
        }
        Ok(WakeDelivery {
            sender: self.get_agent(&message.sender)?,
            message,
            automatic_reply,
        })
    }

    pub(in crate::store) fn wake_direct_claim(
        &self,
        who: &Agent,
        message: &str,
        attempt: &str,
        host: WakeTarget,
    ) -> Result<Value> {
        let source = self.message(message)?;
        if source
            .relay
            .as_ref()
            .is_some_and(|r| r.kind == RelayMessageKind::Request)
        {
            // A manually started/completed action must not be replayed by a late wake.
            ensure!(
                self.work_status(who, message)?["record"].is_null(),
                "message has recorded work; reconcile before native delivery"
            );
        }
        let mut result = self.wake_claim(who, message, attempt, host)?;
        if result["may_submit"] != true {
            return Ok(result);
        }
        let mut record = self.wake_record(message)?.context(UNAVAILABLE)?;
        let request = self.request_ids(1)?["request_ids"][0]
            .as_str()
            .context("missing reply request ID")?
            .to_owned();
        let delivery = self.direct_delivery(source)?;
        record.direct = Some(DirectWake {
            input_hash: hash(&delivery.prompt()),
            reply_request_id: request,
            turn_id: None,
            finished: false,
            response_hash: None,
            response_message_id: None,
        });
        self.wake_write(&record)?;
        result["record"] = json!(record);
        result["delivery"] = json!(delivery);
        Ok(result)
    }

    pub(in crate::store) fn wake_direct_read(
        &self,
        who: &Agent,
        message: &str,
        attempt: &str,
        host: &WakeTarget,
    ) -> Result<Value> {
        self.direct_record(who, message, attempt, host)?;
        let mut result = self.wake_check(who, message, attempt, host)?;
        if result["eligible"] == true {
            let delivery = self.direct_delivery(self.message(message)?)?;
            let record = self.direct_record(who, message, attempt, host)?;
            if record.direct.unwrap().input_hash == hash(&delivery.prompt()) {
                result["delivery"] = json!(delivery);
            } else {
                result["eligible"] = json!(false);
            }
        }
        Ok(result)
    }

    pub(in crate::store) fn wake_direct_pending(
        &self,
        who: &Agent,
        host: &WakeTarget,
    ) -> Result<Value> {
        target(host)?;
        let mut query = self.db.prepare("SELECT w.message_id FROM wake_dispatches w JOIN messages m ON m.id=w.message_id WHERE w.agent=?1 AND json_extract(w.payload,'$.direct.finished')=0 ORDER BY w.claimed_at,w.message_id")?;
        let mut pending = Vec::new();
        for id in query.query_map([&who.id], |r| r.get::<_, String>(0))? {
            let id = id?;
            let record = self.wake_record(&id)?.context(UNAVAILABLE)?;
            let message = self.message(&id)?;
            if &record.target == host && self.deliverable(&message)? {
                let automatic_reply = message
                    .relay
                    .as_ref()
                    .is_some_and(|r| r.kind == RelayMessageKind::Request);
                pending.push(json!({"record":record,"automatic_reply":automatic_reply}));
                // 24-hour expiry and 12 claims/hour bound live records below
                // this metadata-only page. Uncertain old entries cannot starve
                // recovery of a newer answer, and no message bodies are copied.
                ensure!(pending.len() <= 512, "too many live direct dispatches");
            }
        }
        Ok(json!({"pending":pending}))
    }

    pub(in crate::store) fn wake_direct_observe(
        &self,
        who: &Agent,
        message_id: &str,
        attempt: &str,
        host: &WakeTarget,
        turn: &str,
    ) -> Result<Value> {
        id(turn)?;
        let mut record = self.direct_record(who, message_id, attempt, host)?;
        let direct = record.direct.as_mut().unwrap();
        if let Some(previous) = &direct.turn_id {
            ensure!(previous == turn, "native turn changed");
        }
        let message = self.message(message_id)?;
        ensure!(
            message.recipient == who.id && self.deliverable(&message)?,
            UNAVAILABLE
        );
        direct.turn_id = Some(turn.into());
        let acknowledge = message.files.is_empty();
        if !self.direct_delivery(message)?.automatic_reply {
            direct.finished = true;
        }
        if record.submission_id.is_none() {
            record.submission_id = Some(turn.into());
            record.state = WakeState::Submitted;
        }
        record.inbox_seen_at.get_or_insert(self.timestamp);
        record.updated_at = self.timestamp;
        self.wake_write(&record)?;
        if acknowledge {
            self.acknowledge(who, message_id)?;
        }
        Ok(json!({"observed":true}))
    }

    pub(in crate::store) fn wake_direct_complete(
        &mut self,
        who: &Agent,
        message: &str,
        attempt: &str,
        host: &WakeTarget,
        answer: (&str, String),
    ) -> Result<Value> {
        let (turn, text) = answer;
        id(turn)?;
        ensure!(
            text.len() <= MAX_TEXT_BYTES,
            "native response exceeds message limit"
        );
        let hash = hash(&text);
        let mut record = self.direct_record(who, message, attempt, host)?;
        let direct = record.direct.as_mut().unwrap();
        ensure!(
            direct.turn_id.as_deref() == Some(turn),
            "response belongs to another native turn"
        );
        if direct.finished {
            if let Some(saved) = &direct.response_hash {
                ensure!(*saved == hash, "native response changed on retry");
            }
            return Ok(
                json!({"finished":true,"message_id":direct.response_message_id,"duplicate":true}),
            );
        }
        let root = self.relay_root(message)?;
        ensure!(
            root.recipient == who.id && self.deliverable(&root)?,
            UNAVAILABLE
        );
        let (finished, cancelled, closed) = self.relay_turn_flags(message)?;
        if finished.is_none() && closed.is_none() {
            let result = self.relay_respond(
                who,
                message,
                &direct.reply_request_id,
                (text, vec![], vec![]),
                if cancelled.is_some() {
                    RelayResponseKind::Cancelled
                } else {
                    RelayResponseKind::Complete
                },
            )?;
            direct.response_message_id = result["message_id"].as_str().map(str::to_owned);
        }
        self.acknowledge(who, message)?;
        direct.response_hash = Some(hash);
        direct.finished = true;
        record.updated_at = self.timestamp;
        self.wake_write(&record)?;
        Ok(json!({"finished":true,"message_id":record.direct.unwrap().response_message_id}))
    }
}
