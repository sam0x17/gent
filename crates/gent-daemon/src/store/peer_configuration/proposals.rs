use super::*;

impl Store {
    /// Reapply a retained edit against the current committed authority. Calling
    /// this again at the same head returns identical ciphertext. A changed head
    /// creates a new candidate with the same operation ID and salted intent.
    /// The transport checks for an existing service receipt before calling this.
    pub fn prepare_configuration_proposal(&self, id: &str) -> Result<Commit> {
        self.prepare_configuration_for(&Queued {
            origin: self.identity.node.id().into(),
            id: id.into(),
            operation: id.into(),
        })
    }

    pub(crate) fn prepare_configuration_for(&self, queued: &Queued) -> Result<Commit> {
        let origin = queued.origin.as_str();
        let id = queued.id.as_str();
        let tx = self.db.unchecked_transaction()?;
        let state = self.identity.state(&tx)?;
        ensure!(
            state.state().peer.is_some(),
            "peer configuration is not active"
        );
        let edit: Vec<u8> = tx.query_row("SELECT p.body FROM configuration_pending p JOIN configuration_edits e ON e.origin=p.origin AND e.id=p.id WHERE p.origin=?1 AND p.id=?2 AND e.result IS NULL", params![origin, id], |r| r.get(0))?;
        let (head, capability): (Vec<u8>, Option<Vec<u8>>) = tx.query_row(
            "SELECT head,capability FROM peer_configuration WHERE singleton=1 AND active=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let head: Head = serde_json::from_slice(&head)?;
        let capability =
            Zeroizing::new(capability.context("this node cannot administer configuration")?);
        let capability = WriteCapability::from_secret(capability.as_slice().try_into()?);
        let saved: Option<SavedProposal> = tx.query_row("SELECT salt,intent,candidate FROM peer_configuration_requests WHERE origin=?1 AND id=?2", params![origin, id], |r| Ok(SavedProposal { salt: Zeroizing::new(r.get(0)?), intent: r.get(1)?, candidate: r.get(2)? })).optional()?;
        let salt = match &saved {
            Some(saved) => Zeroizing::new(saved.salt.as_slice().try_into()?),
            None => Zeroizing::new(random_salt()),
        };
        let intent = crypto::intent(&salt, &edit);
        if let Some(saved) = &saved {
            ensure!(
                saved.intent == intent,
                "pending configuration intent changed"
            );
            if let Some(candidate) = &saved.candidate {
                let candidate: Commit = serde_json::from_slice(candidate)?;
                ensure!(
                    candidate.header.origin == self.identity.node.id()
                        && candidate.header.operation == queued.operation
                        && candidate.header.intent == intent,
                    "saved proposal belongs to another operation"
                );
                if candidate.header.previous == head {
                    let valid = self.configuration_candidate(
                        &tx,
                        &state,
                        candidate.header.clone(),
                        origin,
                        id,
                        &edit,
                    )?;
                    let opened = envelope::open(&self.identity.node, &state, &head, &candidate)?;
                    let same_decision = valid.state.peer.as_ref().and_then(|p| p.request.as_ref())
                        == opened
                            .state
                            .state()
                            .peer
                            .as_ref()
                            .and_then(|p| p.request.as_ref());
                    if same_decision && opened.state.require_fresh(now() as u64).is_ok() {
                        return Ok(candidate);
                    }
                }
            }
        }
        let next = WriteCapability::generate()?;
        let header = header(
            &state,
            head,
            self.identity.node.id(),
            &queued.operation,
            intent,
            &next,
        );
        let candidate =
            self.configuration_candidate(&tx, &state, header.clone(), origin, id, &edit)?;
        let commit = capability.seal(header, &envelope::seal(&candidate, &next)?)?;
        let wire = serde_json::to_vec(&commit)?;
        let bytes: u64 = tx.query_row("SELECT COALESCE(SUM(length(candidate)),0) FROM peer_configuration_requests WHERE origin!=?1 OR id!=?2", params![origin, id], |r| r.get(0))?;
        ensure!(
            bytes.saturating_add(wire.len() as u64) <= 64 * 1024 * 1024,
            "configuration proposal capacity reached"
        );
        tx.execute("INSERT INTO peer_configuration_requests VALUES(?1,?2,?3,?4,?5) ON CONFLICT(origin,id) DO UPDATE SET candidate=excluded.candidate", params![origin, id, salt.as_slice(), intent.as_slice(), wire])?;
        tx.commit()?;
        Ok(commit)
    }
    fn configuration_candidate(
        &self,
        db: &Connection,
        state: &VerifiedState,
        header: Header,
        origin: &str,
        id: &str,
        body: &[u8],
    ) -> Result<gent_crypto::SignedState> {
        let edit = serde_json::from_slice(body)?;
        let mut request = gent_crypto::peer::Request {
            origin: origin.into(),
            id: id.into(),
            fingerprint: configuration::fingerprint(&edit)?,
            rejection: None,
        };
        let signer =
            NodeSigner::new(&self.identity.node, header.clone())?.with_request(request.clone())?;
        let mut session = self.network_session(db, state.clone());
        session.timestamp = session.timestamp.max(state.state().issued_at.try_into()?);
        match session.revision_for_edit_with(origin, &edit, &signer) {
            Ok(candidate) => Ok(candidate),
            Err(error)
                if origin != self.identity.node.id()
                    && !error
                        .chain()
                        .any(|e| e.is::<rusqlite::Error>() || e.is::<std::io::Error>()) =>
            {
                request.rejection =
                    Some(configuration::storage::rejection_reason(error.to_string()));
                let signer = NodeSigner::new(&self.identity.node, header)?.with_request(request)?;
                state.renew(&signer, session.timestamp as u64)
            }
            Err(error) => Err(error),
        }
    }
}
