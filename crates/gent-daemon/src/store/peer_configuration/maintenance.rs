use super::*;

impl Store {
    /// Any remaining administrator can renew authority, including after every
    /// node has been offline long enough for the previous lease to expire.
    pub(crate) fn queue_configuration_renewal(&self) -> Result<u64> {
        let state = self.identity.state(&self.db)?;
        let remaining = state.state().expires_at.saturating_sub(now() as u64);
        if state.state().peer.is_none()
            || remaining > 6 * 60 * 60
            || !state
                .state()
                .nodes
                .get(self.identity.node.id())
                .is_some_and(|n| n.can_configure)
        {
            return Ok(remaining);
        }
        let tx = self.db.unchecked_transaction()?;
        let id = gent_crypto::scoped_id(
            b"gent/configuration-renew/v1\0",
            &[
                state.anchor().cluster_id.as_bytes(),
                &state.checkpoint().revision.to_be_bytes(),
            ],
        );
        self.network_session(&tx, state)
            .submit_configuration(&id.to_string(), ConfigurationEdit::Renew)?;
        tx.commit()?;
        Ok(remaining)
    }

    /// The transport has already checked for a committed retry receipt. Only
    /// deterministic permission/input failures become terminal local results;
    /// storage and publication failures retain the request for another attempt.
    pub(crate) fn validate_configuration_for(&self, queued: &Queued) -> Result<bool> {
        if queued.origin != self.identity.node.id() {
            return Ok(true);
        }
        let id = queued.id.as_str();
        let tx = self.db.unchecked_transaction()?;
        let state = self.identity.state(&tx)?;
        let edit = configuration::pending::load(&tx, self.identity.node.id(), id)?;
        let next = WriteCapability::generate()?;
        let header = header(
            &state,
            self.configuration_log_head()?
                .context("missing configuration checkpoint")?,
            self.identity.node.id(),
            id,
            [1; 32],
            &next,
        );
        let signer = NodeSigner::new(&self.identity.node, header)?;
        let mut session = self.network_session(&tx, state);
        session.timestamp = session
            .timestamp
            .max(session.state.state().issued_at.try_into()?);
        if let Err(error) = session.revision_for_edit_with(self.identity.node.id(), &edit, &signer)
        {
            if error
                .chain()
                .any(|e| e.is::<rusqlite::Error>() || e.is::<std::io::Error>())
            {
                return Err(error);
            }
            let result = crate::messages::EditResult::Rejected {
                reason: configuration::storage::rejection_reason(error.to_string()),
            };
            tx.execute("UPDATE configuration_edits SET result=?1 WHERE origin=?2 AND id=?3 AND result IS NULL", params![serde_json::to_vec(&result)?, self.identity.node.id(), id])?;
            configuration::pending::release(&tx, self.identity.node.id(), id)?;
            tx.execute(
                "UPDATE peer_configuration_requests SET candidate=NULL WHERE origin=?1 AND id=?2",
                params![self.identity.node.id(), id],
            )?;
            tx.commit()?;
            return Ok(false);
        }
        Ok(true)
    }
}
