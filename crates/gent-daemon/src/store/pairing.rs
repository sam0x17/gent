use super::*;
use crate::{
    encrypted::ordered::OrderedEndpoint,
    pairing::{Invitation, RelayAccess, ServiceRelay, Snapshot},
};
use gent_crypto::SignedEnrollment;
use gent_protocol::PairingOp;

impl Store {
    /// Only called after verifying the local owner's RPC credential. The caller
    /// must transport requests and responses over an authenticated private channel.
    pub(super) fn pair(&mut self, cluster: &str, action: PairingOp) -> Result<Value> {
        ensure!(cluster == self.config.cluster.id, "wrong pairing cluster");
        self.identity.require_administrator(&self.db)?;
        self.maintain()?;
        self.pair_authorized(action, true, now() as u64)
    }

    /// The SSH owner or invitation dispatcher has already checked authority.
    /// Invitation callers must keep their admission lock through this operation.
    pub(super) fn pair_authorized(
        &mut self,
        action: PairingOp,
        can_configure: bool,
        timestamp: u64,
    ) -> Result<Value> {
        self.pair_with_invitation(action, can_configure, timestamp, None)
    }

    pub(super) fn pair_with_invitation(
        &mut self,
        action: PairingOp,
        can_configure: bool,
        timestamp: u64,
        invitation: Option<&str>,
    ) -> Result<Value> {
        match action {
            PairingOp::Data {
                request_id,
                peer,
                key_package,
                legacy_agents,
            } => {
                ensure!(
                    key_package.len() <= 24 * 1024 && legacy_agents.len() <= 1024,
                    "pairing data request too large"
                );
                let request = uuid::Uuid::parse_str(&request_id)?;
                let mut endpoint = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?;
                let packet = endpoint.create(
                    request,
                    &[(&peer, &STANDARD.decode(key_package)?)],
                    timestamp,
                )?;
                let key_id =
                    gent_crypto::scoped_id(b"gent/pair-return-package/v1\0", &[request.as_bytes()]);
                let package = endpoint.key_package(key_id, timestamp)?;
                drop(endpoint);
                let tx = self.db.unchecked_transaction()?;
                let session = self.network_session(&tx, self.identity.state(&tx)?);
                let legacy = legacy_agents
                    .iter()
                    .map(|agent| session.certify_legacy(agent, &peer))
                    .collect::<Result<Vec<_>>>()?;
                tx.commit()?;
                Ok(
                    json!({"packet":STANDARD.encode(packet.encode()?),"key_package":STANDARD.encode(package),"legacy":legacy}),
                )
            }
            PairingOp::AcceptData {
                peer,
                packet,
                outgoing_group,
            } => {
                ensure!(
                    packet.len() <= 1024 * 1024 && outgoing_group.len() <= 512,
                    "pairing data response too large"
                );
                let packet = gent_crypto::stream::Packet::decode(&STANDARD.decode(packet)?)?;
                OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?.join(
                    &packet,
                    &peer,
                    &[self.identity.node.id(), &peer],
                    timestamp,
                )?;
                self.install_data_link(
                    &peer,
                    &STANDARD.decode(outgoing_group)?,
                    packet.group(),
                    &[],
                )?;
                Ok(json!({"connected":true}))
            }
            PairingOp::Snapshot => {
                let state = self.identity.state(&self.db)?;
                self.pairing_snapshot(&state)
            }
            PairingOp::Enroll { request } => {
                ensure!(request.len() <= 8192, "enrollment request too large");
                let request = SignedEnrollment::decode(&STANDARD.decode(request)?)?;
                let state = self.identity.state(&self.db)?;
                if state.state().peer.is_some() {
                    return self.queue_peer_enrollment(&request, can_configure, invitation);
                }
                // The owner-authenticated caller or restricted invitation
                // dispatcher approves this exact identity. A fingerprint supplied
                // by the relay is never sufficient authority.
                let fingerprint = request.fingerprint()?;
                let tx = self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let mut state = self.identity.state(&tx)?;
                ensure!(
                    request.request.anchor == *state.anchor(),
                    "wrong pairing authority"
                );
                if request.request.replaces.is_some() {
                    let mut session = StoreSession {
                        db: &tx,
                        home: &self.home,
                        config: self.config.clone(),
                        identity: &self.identity,
                        state,
                        timestamp: timestamp.try_into()?,
                    };
                    session.replace_enrollment(&request, fingerprint, can_configure)?;
                    state = session.state;
                } else if state.state().nodes.contains_key(&request.request.node_id) {
                    // A lost reply may leave a successfully enrolled node. Reusing
                    // that exact node/key is safe; it does not issue another revision.
                    state.authorize_node(
                        &request.request.node_id,
                        &request.request.member.signing_key,
                        timestamp,
                    )?;
                } else {
                    let owner = &*self.identity.signing_owner(&tx)?;
                    let update = if can_configure {
                        state.enroll_configurator(owner, &request, fingerprint, timestamp)?
                    } else {
                        state.enroll(owner, &request, fingerprint, timestamp)?
                    };
                    state = self.identity.apply(&tx, update)?;
                }
                encrypted::history::pin_join(
                    &tx,
                    &request.request.node_id,
                    &request.request.member.signing_key,
                    state.checkpoint().revision,
                )?;
                tx.commit()?;
                self.sync_wakeup.notify_one();
                let _ = self.project_config();
                self.pairing_snapshot(&state)
            }
            PairingOp::Configuration {
                request_id,
                peer,
                key_package,
            } => {
                ensure!(key_package.len() <= 24 * 1024, "key package too large");
                let package = STANDARD.decode(key_package)?;
                let invitation = OrderedEndpoint::open_runtime(&self.home, &self.identity.node)?
                    .create_configuration(
                        &*self.identity.signing_owner(&self.db)?,
                        uuid::Uuid::parse_str(&request_id)?,
                        (&peer, &package),
                        timestamp,
                    )?;
                self.sync_wakeup.notify_one();
                Ok(serde_json::to_value(Invitation::encode(&invitation)?)?)
            }
            PairingOp::History { revision, digest } => {
                let state = self.identity.state(&self.db)?;
                ensure!(
                    revision <= state.checkpoint().revision,
                    "pairing checkpoint is ahead of owner"
                );
                ensure!(
                    encrypted::history::checkpoint(&self.db, revision, state.anchor())?.state_hash
                        == digest,
                    "pairing history fork"
                );
                if state.state().peer.is_some() {
                    let commit = self.configuration_record(revision + 1)?;
                    ensure!(
                        commit.is_some() || revision == state.checkpoint().revision,
                        "pairing configuration history gap"
                    );
                    return Ok(json!({"record":null, "commit":commit}));
                }
                let next: Option<Vec<u8>> = self
                    .db
                    .query_row(
                        "SELECT state FROM authority_history WHERE revision=?1",
                        [revision + 1],
                        |r| r.get(0),
                    )
                    .optional()?;
                ensure!(
                    next.is_some() || revision == state.checkpoint().revision,
                    "pairing history gap"
                );
                Ok(json!({"record":next.map(|wire| STANDARD.encode(wire))}))
            }
        }
    }

    pub(super) fn pairing_snapshot(&self, state: &VerifiedState) -> Result<Value> {
        state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            now() as u64,
        )?;
        let service = self
            .config
            .service
            .as_ref()
            .map(|account| -> Result<_> {
                Ok(ServiceRelay {
                    account: account.clone(),
                    relay_endpoint: self
                        .config
                        .relay
                        .as_ref()
                        .context("missing service relay")?
                        .endpoint
                        .clone(),
                })
            })
            .transpose()?;
        ensure!(
            self.config.cluster.local_only || service.is_some(),
            "service metadata is missing; stop the daemon and run gent cluster connect"
        );
        let relay = if service.is_some() {
            None
        } else {
            self.config
                .relay
                .as_ref()
                .map(|relay| -> Result<RelayAccess> {
                    Ok(RelayAccess {
                        endpoint: relay.endpoint.clone(),
                        credential: config::read_private(&self.home.join(&relay.credential_file))?,
                    })
                })
                .transpose()?
        };
        Ok(serde_json::to_value(Snapshot {
            anchor: state.anchor().clone(),
            checkpoint: state.checkpoint().clone(),
            state: STANDARD.encode(state.signed().encode()?),
            writer: self.identity.node.id().into(),
            relay,
            service,
            configuration_decisions: if state.state().peer.is_some() {
                Some(STANDARD.encode(self.configuration_decisions()?))
            } else {
                None
            },
            configuration: if state.state().peer.is_some() {
                Some(
                    self.configuration_record(state.checkpoint().revision)?
                        .context("missing committed configuration")?,
                )
            } else {
                None
            },
        })?)
    }
}
