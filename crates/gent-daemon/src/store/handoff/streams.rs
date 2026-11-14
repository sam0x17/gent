//! Trusted owner operations used to prepare connections before freezing signing.
use super::*;
use crate::encrypted::ordered::{
    OrderedEndpoint,
    configuration::{
        ConfigurationInvitation,
        standby::{self, ConfigurationPreparation},
    },
};
use gent_crypto::{SignedConfigurationGrant, stream::Receipt};

impl Store {
    pub fn prepare_owner_configuration(
        &self,
        credential: &str,
        candidate_id: &str,
        request: Uuid,
        peer: (&str, &[u8]),
    ) -> Result<ConfigurationPreparation> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let _lock = config::state_lock(&self.home, "owner-handoff.lock")?;
        let (_, candidate) = read_key(&candidate_path(&self.home, candidate_id)?)?;
        let wire: Vec<u8> = self.db.query_row(
            "SELECT candidate FROM owner_candidates WHERE id=?1",
            [candidate_id],
            |r| r.get(0),
        )?;
        ensure!(candidate.encode()? == wire, "owner candidate changed");
        OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?
            .prepare_standby_configuration(request, &candidate, peer, now() as u64)
    }

    /// Authorize one exact Welcome durably. Once a handoff is issued only
    /// already committed authorizations may be returned; no new grant is signed.
    pub fn authorize_owner_configuration(
        &mut self,
        credential: &str,
        preparation: &ConfigurationPreparation,
    ) -> Result<SignedConfigurationGrant> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = self.identity.state(&tx)?;
        let candidate = &preparation.candidate;
        ensure!(
            candidate.candidate.node.id != self.identity.node.id(),
            "owner handoff requires another node"
        );
        for (id, key) in [
            (
                &candidate.candidate.node.id,
                &candidate.candidate.node.signing_key,
            ),
            (&preparation.reader, &preparation.reader_key),
        ] {
            ensure!(
                state
                    .state()
                    .nodes
                    .get(id)
                    .is_some_and(|n| &n.signing_key == key),
                "standby endpoint is no longer enrolled"
            );
        }
        let previous: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT candidate,grant FROM owner_configuration_grants WHERE group_id=?1",
                [preparation.packet.group()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((pinned, wire)) = previous {
            ensure!(
                pinned == candidate.encode()?,
                "standby owner candidate changed"
            );
            let grant = SignedConfigurationGrant::decode(&wire)?;
            preparation.verify_grant(&grant)?;
            ensure!(
                &grant.grant.anchor == state.anchor()
                    && state
                        .state()
                        .owner_transitions
                        .starts_with(&grant.grant.owner_transitions),
                "standby grant authority changed"
            );
            return Ok(grant);
        }
        let owner = self.identity.signing_owner(&tx)?;
        let timestamp = requests::clock(&tx, now())? as u64;
        let grant = owner.authorize_standby_configuration_stream(
            &state,
            candidate,
            preparation.packet.group(),
            preparation.packet.digest()?,
            &preparation.reader,
            timestamp,
        )?;
        preparation.verify_grant(&grant)?;
        let candidate = candidate.encode()?;
        let wire = grant.encode()?;
        standby::capacity(
            &tx,
            candidate.len() + wire.len() + preparation.packet.group().len(),
        )?;
        tx.execute(
            "INSERT INTO owner_configuration_grants VALUES(?1,?2,?3)",
            params![preparation.packet.group(), candidate, wire],
        )?;
        tx.commit()?;
        Ok(grant)
    }

    pub fn install_owner_configuration(
        &self,
        credential: &str,
        request: Uuid,
        grant: &SignedConfigurationGrant,
    ) -> Result<ConfigurationInvitation> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let _lock = config::state_lock(&self.home, "owner-handoff.lock")?;
        let wire: Vec<u8> = self.db.query_row(
            "SELECT candidate FROM configuration_preparations WHERE id=?1",
            [request.to_string()],
            |r| r.get(0),
        )?;
        let candidate = SignedOwnerCandidate::decode(&wire)?;
        let (_, pinned) = read_key(&candidate_path(&self.home, &candidate.candidate.id)?)?;
        ensure!(candidate == pinned, "owner candidate changed");
        OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?
            .install_standby_configuration(request, grant, now() as u64)
    }

    /// The receipt proves this reader installed the exact origin durably. It
    /// proves transport readiness only, never acceptance of an owner handoff.
    pub fn receive_owner_configuration(
        &self,
        credential: &str,
        invitation: &ConfigurationInvitation,
    ) -> Result<Receipt> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        ensure!(
            invitation.grant.grant.owner_candidate.is_some(),
            "expected a standby configuration grant"
        );
        let mut endpoint = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
        endpoint.join_configuration(invitation, now() as u64)?;
        endpoint.receipt(invitation.packet.group(), now() as u64)
    }

    pub fn confirm_owner_configuration(&self, credential: &str, receipt: &Receipt) -> Result<()> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        let wire: Vec<u8> = self.db.query_row(
            "SELECT grant FROM configuration_streams WHERE group_id=?1",
            [receipt.group()],
            |r| r.get(0),
        )?;
        let grant = SignedConfigurationGrant::decode(&wire)?;
        ensure!(
            grant.grant.owner_candidate.is_some(),
            "expected a standby configuration grant"
        );
        OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?.confirm(
            receipt,
            &grant.grant.reader,
            now() as u64,
        )
    }
}
