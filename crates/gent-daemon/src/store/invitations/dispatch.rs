use super::*;
use gent_crypto::{SignedConfigurationGrant, SignedEnrollment, scoped_id, stream::Packet};

pub(super) fn kind(action: &Action) -> &'static str {
    match action {
        Action::Finish => "finish",
        Action::Pair { action } => match action {
            PairingOp::Snapshot => "snapshot",
            PairingOp::Enroll { .. } => "enroll",
            PairingOp::Configuration { .. } => "configuration",
            PairingOp::History { .. } => "history",
            PairingOp::Data { .. } => "data",
            PairingOp::AcceptData { .. } => "accept",
        },
    }
}

impl Store {
    pub(super) fn dispatch_invitation(
        &mut self,
        channel: &Channel,
        request: Invocation,
        wall: u64,
    ) -> Result<Value> {
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, wall)?;
        let id = &channel.offer().offer.id;
        let row = record(&self.db, id)?;
        let state = self.invitation_authority(&row, timestamp)?;
        ensure!(
            row.offer == *channel.offer() && row.claim.as_ref() == Some(channel.node()),
            "invitation session binding changed"
        );
        ensure!(
            row.phase == "claimed"
                || (row.phase == "complete" && matches!(request.action, Action::Finish)),
            "invitation is not active for this operation"
        );
        self.validate_invitation_action(&row, &state, &request.action, timestamp)?;
        let operation = kind(&request.action);
        let fingerprint: [u8; 32] = Sha256::digest(request.encode()?.as_slice()).into();
        self.reserve_invitation_operation(&row, &request.id, operation, &fingerprint)?;
        let result = match &request.action {
            Action::Finish => {
                self.invitation_ready(&row, &state)?;
                json!({"finished":true,"invitation":id,"node":channel.node().id})
            }
            Action::Pair { action } => {
                let mut action = action.clone();
                // A peer cannot select another node's stored cryptographic
                // request ID. Keeping the node/key namespace across offers also
                // lets an explicit continuation recover the original operation.
                if let PairingOp::Configuration { request_id, .. }
                | PairingOp::Data { request_id, .. } = &mut action
                {
                    let external = canonical_v4(request_id)?;
                    *request_id = scoped_id(
                        b"gent/invitation-pair-request/v1\0",
                        &[
                            row.offer.offer.anchor.cluster_id.as_bytes(),
                            channel.node().id.as_bytes(),
                            &channel.node().key,
                            operation.as_bytes(),
                            external.as_bytes(),
                        ],
                    )
                    .to_string();
                }
                self.pair_authorized(action, row.offer.offer.can_configure, timestamp)?
            }
        };
        // The privileged operation may have committed on a separate connection.
        // A failure below leaves its reserved input digest for an exact retry.
        let timestamp = observe(&self.db, (now() as u64).max(timestamp))?;
        let current = record(&self.db, id)?;
        self.invitation_authority(&current, timestamp)?;
        ensure!(
            current.offer == row.offer && current.claim == row.claim && current.phase == row.phase,
            "invitation changed during operation"
        );
        let group = match operation {
            "configuration" | "data" => {
                let packet = Packet::decode(
                    &STANDARD.decode(
                        result["packet"]
                            .as_str()
                            .context("missing pairing packet")?,
                    )?,
                )?;
                packet.verify(&self.identity.node.public_key())?;
                ensure!(packet.sequence() == 0, "pairing requires a Welcome packet");
                Some(packet.group().to_vec())
            }
            "accept" => {
                let Action::Pair {
                    action: PairingOp::AcceptData { packet, .. },
                } = &request.action
                else {
                    unreachable!()
                };
                Some(Packet::decode(&STANDARD.decode(packet)?)?.group().to_vec())
            }
            _ => None,
        };
        let tx = self.db.unchecked_transaction()?;
        let saved: Option<Vec<u8>> = tx.query_row(
            "SELECT group_id FROM invitation_operations WHERE invitation=?1 AND id=?2",
            params![id, request.id],
            |r| r.get(0),
        )?;
        ensure!(
            saved.is_none() || saved == group,
            "pairing retry changed its group"
        );
        tx.execute(
            "UPDATE invitation_operations SET done=1,group_id=?3 WHERE invitation=?1 AND id=?2",
            params![id, request.id, group],
        )?;
        if operation == "enroll" {
            let revision = result["checkpoint"]["revision"]
                .as_u64()
                .context("missing enrollment checkpoint")?;
            tx.execute("UPDATE invitations SET history_floor=MIN(COALESCE(history_floor,?2),?2) WHERE id=?1", params![id,revision])?;
        }
        if operation == "finish" {
            tx.execute("UPDATE invitations SET phase='complete' WHERE id=?1", [id])?;
        }
        tx.commit()?;
        Ok(result)
    }

    fn reserve_invitation_operation(
        &self,
        row: &Record,
        id: &str,
        kind: &str,
        fingerprint: &[u8; 32],
    ) -> Result<()> {
        canonical_v4(id)?;
        let tx = self.db.unchecked_transaction()?;
        let previous: Option<(Vec<u8>, String, bool)> = tx
            .query_row(
                "SELECT fingerprint,kind,done FROM invitation_operations WHERE invitation=?1 AND id=?2",
                params![row.offer.offer.id, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        if let Some((saved, saved_kind, done)) = previous {
            ensure!(
                saved == fingerprint && saved_kind == kind,
                "invitation operation ID already used with another input"
            );
            ensure!(
                row.phase != "complete" || (kind == "finish" && done),
                "invitation complete; retry the original finish operation"
            );
            return Ok(());
        }
        ensure!(
            row.phase != "complete",
            "invitation complete; retry the original finish operation"
        );
        ensure!(
            tx.query_row("SELECT COUNT(*) FROM invitation_operations", [], |r| r
                .get::<_, u64>(0))?
                < MAX_OPERATIONS,
            "invitation operation capacity reached"
        );
        let count: u64 = tx.query_row(
            "SELECT COUNT(*) FROM invitation_operations WHERE invitation=?1",
            [&row.offer.offer.id],
            |r| r.get(0),
        )?;
        ensure!(
            count < MAX_INVITATION_OPERATIONS,
            "invitation operation budget exhausted"
        );
        if matches!(kind, "configuration" | "data" | "accept") {
            let count: u64 = tx.query_row(
                "SELECT COUNT(*) FROM invitation_operations WHERE invitation=?1 AND kind=?2",
                params![row.offer.offer.id, kind],
                |r| r.get(0),
            )?;
            ensure!(count < MAX_GRANTS, "invitation stream budget exhausted");
        }
        tx.execute(
            "INSERT INTO invitation_operations(invitation,id,fingerprint,kind) VALUES(?1,?2,?3,?4)",
            params![row.offer.offer.id, id, fingerprint.as_slice(), kind],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn validate_invitation_action(
        &self,
        row: &Record,
        state: &VerifiedState,
        action: &Action,
        timestamp: u64,
    ) -> Result<()> {
        let node = row.claim.as_ref().context("invitation has no node claim")?;
        match action {
            Action::Finish => {}
            Action::Pair { action } => match action {
                PairingOp::Snapshot => {}
                PairingOp::Enroll { request } => {
                    ensure!(request.len() <= 8192, "enrollment request too large");
                    let signed = SignedEnrollment::decode(&STANDARD.decode(request)?)?;
                    signed.fingerprint()?;
                    let request = signed.request;
                    ensure!(
                        request.anchor == row.offer.offer.anchor
                            && request.node_id == node.id
                            && request.member.signing_key == node.key
                            && request.member.name == node.name
                            && request.issued_at <= timestamp
                            && timestamp < request.expires_at,
                        "enrollment request does not match the invitation claim"
                    );
                }
                PairingOp::Configuration {
                    peer,
                    key_package,
                    request_id,
                }
                | PairingOp::Data {
                    peer,
                    key_package,
                    request_id,
                    ..
                } => {
                    ensure!(
                        peer == &node.id && key_package.len() <= 24 * 1024,
                        "pairing peer or package outside invitation scope"
                    );
                    canonical_v4(request_id)?;
                    state.authorize_node(&node.id, &node.key, timestamp)?;
                    ensure!(
                        row.history_floor.is_some(),
                        "complete invitation enrollment before creating streams"
                    );
                    if let PairingOp::Data { legacy_agents, .. } = action {
                        ensure!(
                            legacy_agents.is_empty(),
                            "invitations cannot migrate legacy agents"
                        );
                    }
                }
                PairingOp::History { revision, .. } => {
                    state.authorize_node(&node.id, &node.key, timestamp)?;
                    ensure!(
                        row.history_floor.is_some_and(|floor| *revision >= floor),
                        "history precedes this invitation's bootstrap"
                    );
                }
                PairingOp::AcceptData {
                    peer,
                    packet,
                    outgoing_group,
                } => {
                    ensure!(
                        peer == &node.id
                            && packet.len() <= 1024 * 1024
                            && outgoing_group.len() <= 512,
                        "data acceptance outside invitation scope"
                    );
                    state.authorize_node(&node.id, &node.key, timestamp)?;
                    let packet = Packet::decode(&STANDARD.decode(packet)?)?;
                    packet.verify(&node.key)?;
                    ensure!(
                        packet.sequence() == 0,
                        "invitation requires a Welcome packet"
                    );
                    let outgoing = STANDARD.decode(outgoing_group)?;
                    let approved: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM invitation_operations WHERE invitation=?1 AND kind='data' AND done=1 AND group_id=?2)", params![row.offer.offer.id,outgoing], |r| r.get(0))?;
                    ensure!(
                        approved,
                        "outgoing data group was not created by this invitation"
                    );
                }
            },
        }
        Ok(())
    }

    fn invitation_ready(&self, row: &Record, state: &VerifiedState) -> Result<()> {
        let node = row.claim.as_ref().context("invitation has no node claim")?;
        ensure!(
            row.history_floor.is_some(),
            "invitation enrollment is incomplete"
        );
        let linked: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM network_links WHERE peer=?1 AND peer_key=?2)",
            params![node.id, node.key.as_slice()],
            |r| r.get(0),
        )?;
        ensure!(linked, "invitation data links are incomplete");
        let mut query = self.db.prepare(
            "SELECT grant FROM configuration_streams WHERE json_extract(grant,'$.grant.reader')=?1",
        )?;
        for grant in query.query_map([&node.id], |r| r.get::<_, Vec<u8>>(0))? {
            let grant = SignedConfigurationGrant::decode(&grant?)?;
            grant.verify(state.anchor())?;
            if grant.grant.reader_key == node.key
                && grant.grant.writer == self.identity.node.id()
                && grant.grant.writer_key == self.identity.node.public_key()
            {
                return Ok(());
            }
        }
        anyhow::bail!("invitation configuration stream is incomplete")
    }
}
