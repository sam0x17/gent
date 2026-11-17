use super::*;

/// Only the protected enrollment channel may supply this bootstrap checkpoint.
pub(crate) fn install_checkpoint(
    db: &Connection,
    node: &gent_crypto::NodeIdentity,
    state: &VerifiedState,
    commit: &Commit,
    decisions: &[u8],
) -> Result<()> {
    let receipt = crypto::verify(commit)?;
    let opened = envelope::decrypt(node, commit)?;
    ensure!(
        opened.state.encode()? == state.signed().encode()?
            && receipt.head.sequence == state.checkpoint().revision,
        "pairing configuration checkpoint mismatch"
    );
    schema(db)?;
    let tx = db.unchecked_transaction()?;
    let capability = opened.capability.as_ref().map(WriteCapability::secret);
    let bootstrap = Bootstrap {
        cluster: receipt.cluster.clone(),
        head: commit.header.previous.clone(),
    };
    tx.execute(
        "INSERT INTO peer_configuration VALUES(1,?1,?2,?3,NULL,1)",
        params![
            serde_json::to_vec(&bootstrap)?,
            serde_json::to_vec(&receipt.head)?,
            capability.as_ref().map(|k| k.as_slice())
        ],
    )?;
    tx.execute(
        "INSERT INTO peer_configuration_history VALUES(?1,?2,?3)",
        params![
            receipt.head.sequence,
            serde_json::to_vec(&receipt)?,
            serde_json::to_vec(commit)?
        ],
    )?;
    super::decisions::install(&tx, state, decisions)?;
    tx.commit()?;
    Ok(())
}

impl Store {
    pub(crate) fn configuration_record(&self, sequence: u64) -> Result<Option<Commit>> {
        self.db
            .query_row(
                "SELECT body FROM peer_configuration_history WHERE sequence=?1",
                [sequence],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|wire| serde_json::from_slice(&wire).map_err(Into::into))
            .transpose()
    }
    pub(in crate::store) fn queue_peer_enrollment(
        &self,
        request: &gent_crypto::SignedEnrollment,
        can_configure: bool,
        invitation: Option<&str>,
    ) -> Result<Value> {
        self.identity.require_administrator(&self.db)?;
        let state = self.identity.state(&self.db)?;
        ensure!(
            request.request.anchor == *state.anchor(),
            "wrong pairing authority"
        );
        let node = &request.request.node_id;
        if let Some(member) = state.state().nodes.get(node) {
            ensure!(
                member.signing_key == request.request.member.signing_key
                    && member.name == request.request.member.name,
                "enrollment identity changed"
            );
            return self.pairing_snapshot(&state);
        }
        let id = gent_crypto::scoped_id(
            b"gent/peer-enrollment/v1\0",
            &[
                node.as_bytes(),
                &request.fingerprint()?,
                invitation.unwrap_or("").as_bytes(),
            ],
        )
        .to_string();
        let tx = self.db.unchecked_transaction()?;
        let result = self.network_session(&tx, state).submit_configuration(
            &id,
            ConfigurationEdit::EnrollNode {
                request: STANDARD.encode(request.encode()?),
                can_configure,
                invitation: invitation.map(str::to_owned),
            },
        )?;
        ensure!(
            result["state"] != "rejected",
            "enrollment rejected: {}",
            result["reason"].as_str().unwrap_or("unknown reason")
        );
        tx.commit()?;
        self.sync_wakeup.notify_one();
        Ok(json!({"state":"pending", "request_id":id}))
    }
}
