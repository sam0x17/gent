//! Owner-local admission journal. Service approval never substitutes for this
//! state. The only peer-facing entry points accept authenticated Noise traffic.
use super::*;
use gent_crypto::invitation::{
    ClaimedNode, Options, OwnerInvitation, Purpose, ServiceBinding, SignedOffer,
    channel::{Channel, Hello, PendingClaim},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;
mod dispatch;
mod replacement;
#[cfg(test)]
mod tests;

const MAX_INVITATIONS: u64 = 128;
const MAX_ATTEMPTS: u64 = 64;
const MAX_OPERATIONS: u64 = 32_768;
const MAX_INVITATION_OPERATIONS: u64 = 8192;
const MAX_GRANTS: u64 = 4;

pub(crate) fn schema(db: &Connection, previous: i64) -> Result<()> {
    if previous >= 14 {
        for table in ["invitations", "invitation_operations", "invitation_clock"] {
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
                [table],
                |r| r.get(0),
            )?;
            ensure!(
                exists,
                "invitation journal is missing; restore this node's state"
            );
        }
        ensure!(
            db.query_row(
                "SELECT COUNT(*) FROM invitation_clock WHERE singleton=1",
                [],
                |r| r.get::<_, u64>(0)
            )? == 1,
            "invitation clock is missing; restore this node's state"
        );
    } else {
        db.execute_batch("CREATE TABLE IF NOT EXISTS invitation_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),floor INTEGER NOT NULL);
        INSERT OR IGNORE INTO invitation_clock VALUES(1,0);
        CREATE TABLE IF NOT EXISTS invitations(
          id TEXT PRIMARY KEY,create_request TEXT UNIQUE NOT NULL,intent BLOB NOT NULL CHECK(length(intent)=32),
          offer BLOB NOT NULL CHECK(length(offer)<=8192),secret BLOB CHECK(length(secret)<=16384),
          phase TEXT NOT NULL CHECK(phase IN ('draft','issued','claimed','complete','revoked')),
          expires INTEGER NOT NULL,claim BLOB CHECK(length(claim)<=1024),history_floor INTEGER,
          attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 64));
        CREATE INDEX IF NOT EXISTS invitations_expiry ON invitations(expires);
        CREATE TABLE IF NOT EXISTS invitation_operations(
          invitation TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,id TEXT NOT NULL,
          fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),kind TEXT NOT NULL,
          done INTEGER NOT NULL DEFAULT 0 CHECK(done IN (0,1)),group_id BLOB CHECK(length(group_id)<=256),
          PRIMARY KEY(invitation,id));
        CREATE INDEX IF NOT EXISTS invitation_operation_kind ON invitation_operations(invitation,kind);")?;
    }
    if previous >= 15 {
        ensure!(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='invitation_attempts')",
            [], |r| r.get::<_, bool>(0)
        )?, "invitation attempt journal is missing; restore this node's state");
    } else {
        // Version 14 did not retain attempt IDs. It cannot safely distinguish
        // old handshakes after an upgrade. Keep membership/keys, but close used
        // offers; partial joins can use an explicit continuation invitation.
        db.execute_batch("DELETE FROM invitation_operations WHERE invitation IN (SELECT id FROM invitations WHERE attempts>0);
            UPDATE invitations SET phase='revoked',secret=NULL WHERE attempts>0;
            CREATE TABLE IF NOT EXISTS invitation_attempts(
              invitation TEXT NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
              id TEXT NOT NULL CHECK(length(id)=36),PRIMARY KEY(invitation,id));")?;
    }
    Ok(())
}

struct Record {
    offer: SignedOffer,
    secret: Option<Zeroizing<Vec<u8>>>,
    phase: String,
    claim: Option<ClaimedNode>,
    history_floor: Option<u64>,
    attempts: u64,
}
type RecordRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    String,
    Option<Vec<u8>>,
    Option<u64>,
    u64,
    u64,
);
fn record(db: &Connection, id: &str) -> Result<Record> {
    let (offer, secret, phase, claim, history_floor, attempts, expires): RecordRow = db.query_row("SELECT offer,secret,phase,claim,history_floor,attempts,expires FROM invitations WHERE id=?1", [id], |r| {
        Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))
    }).optional()?.context("invitation unavailable")?;
    let secret = secret.map(Zeroizing::new);
    let offer = SignedOffer::decode(&offer)?;
    ensure!(
        offer.offer.id == id && expires == offer.offer.expires_at && attempts <= MAX_ATTEMPTS,
        "invalid invitation journal binding"
    );
    let claim = claim
        .map(|bytes| -> Result<ClaimedNode> {
            ensure!(bytes.len() <= 1024, "invalid saved invitation claim");
            serde_json::from_slice(&bytes).context("invalid saved invitation claim")
        })
        .transpose()?;
    ensure!(
        match phase.as_str() {
            "draft" | "issued" => claim.is_none() && history_floor.is_none(),
            "claimed" => claim.is_some(),
            "complete" => claim.is_some() && history_floor.is_some(),
            "revoked" => secret.is_none(),
            _ => false,
        },
        "invalid invitation journal phase"
    );
    Ok(Record {
        offer,
        secret,
        phase,
        claim,
        history_floor,
        attempts,
    })
}

/// Clock advancement commits independently of a rejected operation. Observing
/// expiry and then rolling the clock back must not reactivate its credential.
fn observe(db: &Connection, wall: u64) -> Result<u64> {
    ensure!(wall > 0 && wall < (1 << 53), "invalid invitation clock");
    db.execute(
        "UPDATE invitation_clock SET floor=MAX(floor,?1) WHERE singleton=1",
        [wall],
    )?;
    let floor: u64 = db.query_row(
        "SELECT floor FROM invitation_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    // Explicit child deletion also works when an OrderedEndpoint connection has
    // SQLite foreign-key enforcement disabled. Both deletions commit together.
    let tx = db.unchecked_transaction()?;
    tx.execute("DELETE FROM invitation_operations WHERE invitation IN (SELECT id FROM invitations WHERE expires<=?1)", [floor])?;
    tx.execute("DELETE FROM invitation_attempts WHERE invitation IN (SELECT id FROM invitations WHERE expires<=?1)", [floor])?;
    tx.execute("DELETE FROM invitations WHERE expires<=?1", [floor])?;
    tx.commit()?;
    Ok(floor)
}

pub struct PendingSession {
    pending: PendingClaim,
}
pub struct Session {
    channel: Channel,
}

/// A bounded encrypted request, distinct from owner RPC. UUIDv4 operation IDs
/// are scoped to this invitation; retries must preserve their complete input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub id: String,
    pub action: Action,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Pair { action: PairingOp },
    Finish,
}
impl Invocation {
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(serde_jcs::to_vec(self)?);
        ensure!(
            bytes.len() <= MAX_FRAME_BYTES,
            "invitation request too large"
        );
        Ok(bytes)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_FRAME_BYTES,
            "invitation request too large"
        );
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid invitation request"))?;
        ensure!(
            *value.encode()? == bytes,
            "invitation request must use canonical JSON"
        );
        canonical_v4(&value.id)?;
        Ok(value)
    }
}
fn canonical_v4(value: &str) -> Result<Uuid> {
    let id = Uuid::parse_str(value).context("invalid invitation operation ID")?;
    ensure!(
        id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
            && id.to_string() == value,
        "invitation operation ID must be UUIDv4"
    );
    Ok(id)
}

impl Store {
    pub(super) fn manage_invitation(
        &mut self,
        credential: &str,
        action: InvitationOp,
    ) -> Result<Value> {
        self.invitation_owner(credential)?;
        match action {
            InvitationOp::Create {
                request_id,
                can_configure,
                continuation,
                replace_node,
            } => {
                let bytes = self.create_invitation_with_replacement(
                    credential,
                    &request_id,
                    can_configure,
                    continuation.as_deref(),
                    replace_node.as_deref(),
                )?;
                Ok(json!({"private_invitation": STANDARD.encode(bytes.as_slice())}))
            }
            InvitationOp::Activate { id } => {
                self.activate_invitation(credential, &id)?;
                Ok(json!({"id":id,"active":true}))
            }
            InvitationOp::Revoke { id } => {
                self.revoke_invitation(credential, &id)?;
                Ok(json!({"id":id,"revoked":true}))
            }
            InvitationOp::List => {
                let _lock = config::state_lock(&self.home, "invitation.lock")?;
                observe(&self.db, now() as u64)?;
                let mut query = self
                    .db
                    .prepare("SELECT id FROM invitations ORDER BY id LIMIT 129")?;
                let ids = query
                    .query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                ensure!(
                    ids.len() <= MAX_INVITATIONS as usize,
                    "invalid invitation journal size"
                );
                let records = ids.iter().map(|id| {
                    let row = record(&self.db, id)?;
                    let mut value = json!({"id":id,"phase":row.phase,"expires_at":row.offer.offer.expires_at,
                        "can_configure":row.offer.offer.can_configure,"node":row.claim});
                    if let Some(target) = &row.offer.offer.replaces {
                        value["replaces"] = json!(target);
                    }
                    Ok(value)
                }).collect::<Result<Vec<_>>>()?;
                Ok(json!({"invitations":records}))
            }
        }
    }

    /// Local scheduling metadata only. No private offer material leaves Store.
    /// This rechecks current native authority even when service access survives.
    pub(crate) fn invitation_jobs(&mut self) -> Result<Vec<SignedOffer>> {
        if self.config.service.is_none()
            || !self
                .identity
                .is_current_owner(&self.identity.state(&self.db)?)
        {
            return Ok(Vec::new());
        }
        if !self
            .db
            .query_row("SELECT EXISTS(SELECT 1 FROM invitations)", [], |r| {
                r.get::<_, bool>(0)
            })?
        {
            return Ok(Vec::new());
        }
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, now() as u64)?;
        let ids = self.db.prepare(
            "SELECT id FROM invitations WHERE phase IN ('issued','claimed','complete') ORDER BY id LIMIT 129"
        )?.query_map([], |r| r.get::<_, String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            ids.len() <= MAX_INVITATIONS as usize,
            "invalid invitation journal size"
        );
        let mut offers = Vec::new();
        for id in ids {
            let row = record(&self.db, &id)?;
            if self.invitation_authority(&row, timestamp).is_ok() {
                offers.push(row.offer);
            }
        }
        Ok(offers)
    }

    pub(crate) fn invitation_bearer(&self) -> Result<Zeroizing<String>> {
        let settings = self
            .config
            .relay
            .as_ref()
            .context("invitation relay unavailable")?;
        Ok(Zeroizing::new(config::read_relay_credential(
            &self.home.join(&settings.credential_file),
        )?))
    }

    /// Recheck before sending a cached response, including a completed Finish.
    /// Revocation cannot retract bytes already released to a network request.
    pub(crate) fn invitation_live(&mut self, offer: &SignedOffer) -> Result<()> {
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, now() as u64)?;
        let row = record(&self.db, &offer.offer.id)?;
        self.invitation_authority(&row, timestamp)?;
        ensure!(
            row.offer == *offer && matches!(row.phase.as_str(), "issued" | "claimed" | "complete"),
            "invitation unavailable"
        );
        Ok(())
    }

    pub(crate) fn invitation_claim_receipt(
        &mut self,
        session: &mut Session,
    ) -> Result<Vec<Vec<u8>>> {
        self.invitation_live(session.channel.offer())?;
        session
            .channel
            .seal(crate::invitation_transport::CLAIM_RECEIPT, now() as u64)
    }

    fn invitation_owner(&self, credential: &str) -> Result<()> {
        ensure!(hash(credential) == self.owner_hash, "unauthorized");
        self.identity.signing_owner(&self.db)?;
        Ok(())
    }
    fn invitation_service(&self) -> Result<ServiceBinding> {
        let account = self
            .config
            .service
            .as_ref()
            .context("invitation enrollment requires service setup")?;
        ensure!(
            !self.config.cluster.local_only,
            "invitation enrollment requires a service cluster"
        );
        let relay = self
            .config
            .relay
            .as_ref()
            .context("invitation enrollment requires a service relay")?;
        // Config origins historically include a trailing slash. Sign the
        // canonical origins, then compare the same representation on every use.
        let service = ServiceBinding {
            account_id: account.account_id.clone(),
            account_origin: account.origin.trim_end_matches('/').into(),
            relay_origin: relay.endpoint.trim_end_matches('/').into(),
        };
        service.validate()?;
        Ok(service)
    }
    fn invitation_authority(&self, record: &Record, timestamp: u64) -> Result<VerifiedState> {
        self.identity.signing_owner(&self.db)?;
        let state = self.identity.state(&self.db)?;
        record.offer.verify_current(&state, timestamp)?;
        ensure!(
            record.offer.offer.issuer_id == self.identity.node.id()
                && record.offer.offer.issuer_key == self.identity.node.public_key()
                && record.offer.offer.service == self.invitation_service()?,
            "invitation owner or service changed"
        );
        state.authorize_node(
            self.identity.node.id(),
            &self.identity.node.public_key(),
            timestamp,
        )?;
        ensure!(record.phase != "revoked", "invitation revoked");
        self.invitation_replacement(record, &state, timestamp)?;
        if let Some(node) = &record.claim {
            ensure!(
                !state.state().retired_nodes.contains(&node.id)
                    && !state.state().retired_keys.contains(&node.key),
                "invitation node was retired"
            );
            if let Some(member) = state.state().nodes.get(&node.id) {
                ensure!(
                    member.signing_key == node.key
                        && member.name == node.name
                        && member.can_configure == record.offer.offer.can_configure,
                    "invitation node identity or privileges changed"
                );
            } else {
                ensure!(
                    record.history_floor.is_none()
                        && matches!(record.offer.offer.purpose, Purpose::NewNode),
                    "invitation node is no longer enrolled"
                );
            }
        }
        Ok(state)
    }

    /// Owner-only local API. The returned bytes are for protected transfer,
    /// never an MCP response or a public account-service request.
    pub fn create_invitation(
        &mut self,
        credential: &str,
        request: &str,
        can_configure: bool,
        continuation: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.create_invitation_with_replacement(
            credential,
            request,
            can_configure,
            continuation,
            None,
        )
    }

    pub fn create_invitation_with_replacement(
        &mut self,
        credential: &str,
        request: &str,
        can_configure: bool,
        continuation: Option<&str>,
        replace_node: Option<&str>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.invitation_owner(credential)?;
        self.maintain()?;
        self.create_invitation_at(
            request,
            can_configure,
            continuation,
            replace_node,
            now() as u64,
        )
    }
    fn create_invitation_at(
        &mut self,
        request: &str,
        can_configure: bool,
        continuation: Option<&str>,
        replace_node: Option<&str>,
        wall: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, wall)?;
        let service = self.invitation_service()?;
        ensure!(
            continuation.is_none() || replace_node.is_none(),
            "choose replacement or continuation, not both"
        );
        // Preserve the original ordinary-invitation retry fingerprint.
        let intent: [u8; 32] = Sha256::digest(match replace_node {
            None => serde_jcs::to_vec(&(can_configure, continuation, &service))?,
            Some(target) => serde_jcs::to_vec(&(can_configure, continuation, &service, target))?,
        })
        .into();
        let previous: Option<(String, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT id,intent FROM invitations WHERE create_request=?1",
                [request],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((id, saved)) = previous {
            ensure!(
                saved == intent,
                "invitation creation request already used with different options"
            );
            let row = record(&self.db, &id)?;
            self.invitation_authority(&row, timestamp)?;
            let private = row.secret.context("invitation secret unavailable")?;
            return OwnerInvitation::decode(&private)?.invitation().encode();
        }
        let issued =
            requests::issued(request).context("invitation creation request must be UUIDv7")? as u64;
        ensure!(
            issued <= timestamp && timestamp - issued < gent_crypto::invitation::OFFER_LIFETIME,
            "invitation creation request expired or is from the future"
        );
        let state = self.identity.state(&self.db)?;
        let purpose = match continuation {
            None => Purpose::NewNode,
            Some(id) => {
                let member = state
                    .state()
                    .nodes
                    .get(id)
                    .context("continuation node unavailable")?;
                Purpose::Continue {
                    node: ClaimedNode {
                        id: id.into(),
                        key: member.signing_key,
                        name: member.name.clone(),
                    },
                }
            }
        };
        let (replaces, can_configure) = match (&purpose, replace_node) {
            (Purpose::NewNode, Some(id)) => {
                ensure!(
                    id != self.identity.node.id(),
                    "cannot replace the signing owner through an invitation"
                );
                let member = state
                    .state()
                    .nodes
                    .get(id)
                    .context("replacement target is unavailable")?;
                (
                    Some(gent_crypto::ReplacedNode {
                        id: id.into(),
                        signing_key: member.signing_key,
                    }),
                    can_configure && member.can_configure,
                )
            }
            (Purpose::Continue { node }, None) => (
                removals::replacement_target(&self.db, &state, &node.id, &node.key)?,
                can_configure,
            ),
            (Purpose::NewNode, None) => (None, can_configure),
            _ => unreachable!("exclusive replacement and continuation checked"),
        };
        let tx = self.db.unchecked_transaction()?;
        ensure!(
            tx.query_row("SELECT COUNT(*) FROM invitations", [], |r| r
                .get::<_, u64>(0))?
                < MAX_INVITATIONS,
            "invitation capacity reached; wait for existing offers to expire"
        );
        let owner = OwnerInvitation::issue(
            self.identity.signing_owner(&self.db)?,
            &state,
            &self.identity.node,
            Options {
                service,
                purpose,
                can_configure,
                replaces,
            },
            timestamp,
        )?;
        let offer = owner.invitation().offer();
        let private = owner.encode()?;
        tx.execute("INSERT INTO invitations(id,create_request,intent,offer,secret,phase,expires) VALUES(?1,?2,?3,?4,?5,'draft',?6)", params![offer.offer.id,request,intent.as_slice(),offer.encode()?,private.as_slice(),offer.offer.expires_at])?;
        tx.commit()?;
        owner.invitation().encode()
    }

    /// Called after the account service confirms the exact persisted draft.
    /// The activation itself does not make an account or cryptographic member.
    pub fn activate_invitation(&mut self, credential: &str, id: &str) -> Result<()> {
        self.invitation_owner(credential)?;
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, now() as u64)?;
        let row = record(&self.db, id)?;
        self.invitation_authority(&row, timestamp)?;
        self.db.execute(
            "UPDATE invitations SET phase='issued' WHERE id=?1 AND phase='draft'",
            [id],
        )?;
        Ok(())
    }
    pub fn revoke_invitation(&mut self, credential: &str, id: &str) -> Result<()> {
        self.invitation_owner(credential)?;
        let issued =
            gent_protocol::service::invitations::issued_at(id).context("invalid invitation ID")?;
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, now() as u64)?;
        let tx = self.db.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE invitations SET phase='revoked',secret=NULL WHERE id=?1",
            [id],
        )?;
        ensure!(
            changed == 1 || timestamp >= issued + gent_crypto::invitation::OFFER_LIFETIME,
            "invitation unavailable"
        );
        tx.execute(
            "DELETE FROM invitation_operations WHERE invitation=?1",
            [id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn begin_invitation(
        &mut self,
        id: &str,
        hello: &Hello,
    ) -> Result<(PendingSession, Vec<u8>)> {
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, now() as u64)?;
        let row = record(&self.db, id)?;
        self.invitation_authority(&row, timestamp)?;
        canonical_v4(&hello.attempt)?;
        ensure!(
            !self.invitation_attempt_seen(id, &hello.attempt)?,
            "invitation attempt already admitted; use a fresh handshake"
        );
        ensure!(
            row.phase != "draft" && row.attempts < MAX_ATTEMPTS,
            "invitation unavailable or attempt budget exhausted"
        );
        let private = row.secret.context("invitation secret unavailable")?;
        let owner = OwnerInvitation::decode(&private)?;
        ensure!(
            owner.invitation().offer() == &row.offer,
            "invitation private record changed"
        );
        let (pending, reply) = owner.respond(hello, timestamp)?;
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO invitation_attempts(invitation,id) VALUES(?1,?2)",
            params![id, hello.attempt],
        )?;
        tx.execute(
            "UPDATE invitations SET attempts=attempts+1 WHERE id=?1",
            [id],
        )?;
        tx.commit()?;
        Ok((PendingSession { pending }, reply))
    }

    /// Scheduling hint only. Admission rechecks under the invitation lock and
    /// commits the ID before releasing a handshake response. A lost in-memory
    /// session must never be reconstructed from an already admitted Hello.
    pub fn invitation_attempt_seen(&self, id: &str, attempt: &str) -> Result<bool> {
        canonical_v4(attempt)?;
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM invitation_attempts WHERE invitation=?1 AND id=?2)",
            params![id, attempt],
            |r| r.get(0),
        )?)
    }
    pub fn accept_invitation(
        &mut self,
        pending: PendingSession,
        frames: &[Vec<u8>],
    ) -> Result<Session> {
        let _lock = config::state_lock(&self.home, "invitation.lock")?;
        let timestamp = observe(&self.db, now() as u64)?;
        let channel = pending.pending.accept(frames, timestamp, |offer, node| {
            self.claim_invitation(offer, node, timestamp)
        })?;
        Ok(Session { channel })
    }
    fn claim_invitation(
        &mut self,
        offer: &SignedOffer,
        node: &ClaimedNode,
        timestamp: u64,
    ) -> Result<()> {
        let row = record(&self.db, &offer.offer.id)?;
        let state = self.invitation_authority(&row, timestamp)?;
        ensure!(
            &row.offer == offer && row.phase != "draft",
            "invitation claim changed"
        );
        if let Some(saved) = &row.claim {
            ensure!(saved == node, "invitation already claimed by another node");
            return Ok(());
        }
        ensure!(row.phase == "issued", "invitation is not claimable");
        let floor = match &offer.offer.purpose {
            Purpose::NewNode => {
                ensure!(
                    !state.state().nodes.contains_key(&node.id)
                        && !state.state().retired_nodes.contains(&node.id)
                        && !state.state().retired_keys.contains(&node.key)
                        && !state
                            .state()
                            .nodes
                            .values()
                            .any(|n| n.signing_key == node.key),
                    "node already enrolled or retired; use an explicit continuation"
                );
                None
            }
            Purpose::Continue { node: expected } => {
                ensure!(node == expected, "continuation identity changed");
                state.authorize_node(&node.id, &node.key, timestamp)?;
                let member = &state.state().nodes[&node.id];
                ensure!(
                    member.name == node.name && member.can_configure == offer.offer.can_configure,
                    "continuation privileges changed"
                );
                Some(
                    self.db
                        .query_row("SELECT MIN(revision) FROM authority_history", [], |r| {
                            r.get::<_, u64>(0)
                        })?,
                )
            }
        };
        let tx = self.db.unchecked_transaction()?;
        let changed = tx.execute("UPDATE invitations SET phase='claimed',claim=?2,history_floor=?3 WHERE id=?1 AND phase='issued' AND claim IS NULL", params![offer.offer.id,serde_jcs::to_vec(node)?,floor])?;
        ensure!(changed == 1, "invitation claim raced another writer");
        tx.commit()?;
        Ok(())
    }

    pub fn invitation_call(
        &mut self,
        session: &mut Session,
        frames: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>> {
        let timestamp = now() as u64;
        let bytes = session.channel.open(frames, timestamp)?;
        let response = match Invocation::decode(&bytes)
            .and_then(|request| self.dispatch_invitation(&session.channel, request, timestamp))
        {
            Ok(value) => Response::Ok(value),
            Err(error) => Response::Error(error.to_string().chars().take(1024).collect()),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&response)?);
        session.channel.seal(&bytes, now() as u64)
    }

    /// Startup/periodic maintenance also retires expired secrets and retry rows.
    pub(super) fn clean_invitations(&mut self) -> Result<()> {
        let any: bool = self
            .db
            .query_row("SELECT EXISTS(SELECT 1 FROM invitations)", [], |r| r.get(0))?;
        if any {
            let _lock = config::state_lock(&self.home, "invitation.lock")?;
            observe(&self.db, now() as u64)?;
        }
        Ok(())
    }
}
