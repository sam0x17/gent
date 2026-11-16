//! Protected invitation files and an owner-authenticated bootstrap channel.
//!
//! Files must arrive through an independently trusted channel. Their embedded
//! signature does not authenticate an anchor downloaded from Gent's service.
//! This module has no storage or membership side effects. The owner must durably
//! claim an invitation and restrict pairing operations before releasing state.
use super::*;
use uuid::Uuid;
use zeroize::Zeroize;

pub mod channel;

pub const OFFER_LIFETIME: u64 = gent_protocol::service::invitations::LIFETIME_SECONDS;
pub const MAX_INVITATION_BYTES: usize = MAX_OWNER_CHAIN_BYTES + 16 * 1024;
const OFFER_DOMAIN: &[u8] = b"gent/invitation-offer/v1\0";
const CLAIM_DOMAIN: &[u8] = b"gent/invitation-claim/v1\0";
const MAX_OFFER_BYTES: usize = MAX_OWNER_CHAIN_BYTES + 8192;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBinding {
    pub account_id: String,
    pub account_origin: String,
    pub relay_origin: String,
}

impl ServiceBinding {
    pub fn validate(&self) -> Result<()> {
        id(&self.account_id)?;
        fn origin(value: &str) -> Result<url::Url> {
            ensure!(value.len() <= 2048, "invitation origin too long");
            let url = url::Url::parse(value).context("invalid invitation origin")?;
            ensure!(
                url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.path() == "/"
                    && url.origin().ascii_serialization() == value
                    && (url.scheme() == "https"
                        || (url.scheme() == "http"
                            && matches!(url.host_str(), Some("127.0.0.1" | "[::1]")))),
                "invitation requires a canonical HTTPS origin or explicit loopback"
            );
            Ok(url)
        }
        let account = origin(&self.account_origin)?;
        let relay = origin(&self.relay_origin)?;
        ensure!(
            account.scheme() != "https" || relay.scheme() == "https",
            "HTTPS account service cannot select an insecure relay"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimedNode {
    pub id: String,
    pub key: PublicKey,
    pub name: String,
}
impl ClaimedNode {
    fn validate(&self, offer: &Offer) -> Result<()> {
        id(&self.id)?;
        public_key(&self.key)?;
        label(&self.name)?;
        if let Purpose::NamedNode { name, .. } = &offer.purpose {
            ensure!(
                &self.name == name,
                "invitation requires its assigned node name"
            );
        }
        ensure!(
            self.id != offer.issuer_id
                && self.key != offer.issuer_key
                && self.key != offer.anchor.owner_key,
            "invitation requires a separate joining identity"
        );
        ensure!(
            offer
                .owner_transitions
                .iter()
                .all(|t| t.transition.owner_key != self.key),
            "joining node cannot reuse an owner signing key"
        );
        if let Some(target) = &offer.replaces {
            ensure!(
                self.id != target.id && self.key != target.signing_key,
                "replacement invitation requires a fresh identity and key"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Purpose {
    NewNode,
    NamedNode {
        name: String,
        inviter: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continuation: Option<ClaimedNode>,
    },
    Continue {
        node: ClaimedNode,
    },
}

impl Purpose {
    pub fn continuation(&self) -> Option<&ClaimedNode> {
        match self {
            Self::Continue { node } => Some(node),
            Self::NamedNode { continuation, .. } => continuation.as_ref(),
            Self::NewNode => None,
        }
    }
}

pub struct Options {
    pub service: ServiceBinding,
    pub purpose: Purpose,
    pub can_configure: bool,
    pub replaces: Option<ReplacedNode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub version: u8,
    pub id: String,
    pub anchor: TrustAnchor,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_transitions: Vec<SignedOwnerTransition>,
    pub issuer_id: String,
    pub issuer_key: PublicKey,
    pub service: ServiceBinding,
    pub responder_key: [u8; 32],
    pub routing_digest: Digest,
    pub purpose: Purpose,
    pub can_configure: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces: Option<ReplacedNode>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedOffer {
    pub offer: Offer,
    pub signature: Vec<u8>,
}
impl SignedOffer {
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode(self, MAX_OFFER_BYTES)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode(bytes, MAX_OFFER_BYTES)
    }
    pub fn fingerprint(&self) -> Result<Digest> {
        self.verify_signature()?;
        digest(OFFER_DOMAIN, self, MAX_OFFER_BYTES)
    }
    fn verify_signature(&self) -> Result<()> {
        let offer = &self.offer;
        ensure!(offer.version == 1, "unsupported invitation version");
        id(&offer.id)?;
        ensure!(
            gent_protocol::service::invitations::issued_at(&offer.id) == Some(offer.issued_at),
            "invitation ID does not match issue time"
        );
        id(&offer.anchor.cluster_id)?;
        id(&offer.issuer_id)?;
        public_key(&offer.anchor.owner_key)?;
        public_key(&offer.issuer_key)?;
        let owner = verify_lineage(&offer.anchor, &offer.owner_transitions)?;
        ensure!(
            offer
                .owner_transitions
                .last()
                .is_none_or(|t| t.transition.issued_at <= offer.issued_at),
            "invitation precedes owner activation"
        );
        ensure!(
            offer.issuer_key != offer.anchor.owner_key
                && !succession::owner_keys(&offer.owner_transitions, owner)
                    .contains(&offer.issuer_key)
                && offer.anchor.genesis_hash != [0; 32]
                && offer.routing_digest != [0; 32]
                && offer.issued_at > 0,
            "invalid invitation authority or binding"
        );
        channel::validate_public_key(&offer.responder_key)?;
        offer.service.validate()?;
        if let Some(target) = &offer.replaces {
            id(&target.id)?;
            public_key(&target.signing_key)?;
            ensure!(
                target.id != offer.issuer_id
                    && target.signing_key != offer.issuer_key
                    && target.signing_key != offer.anchor.owner_key,
                "invitation cannot replace the signing owner"
            );
        }
        if let Some(node) = offer.purpose.continuation() {
            node.validate(offer)?;
        }
        if let Purpose::NamedNode { name, inviter, .. } = &offer.purpose {
            label(name)?;
            id(inviter)?;
            ensure!(
                offer.replaces.is_none(),
                "named invitation cannot replace a node"
            );
        }
        lifetime(offer.issued_at, offer.expires_at, OFFER_LIFETIME)?;
        verify(
            &owner,
            OFFER_DOMAIN,
            offer,
            &self.signature,
            MAX_OFFER_BYTES,
        )
    }
    /// Authenticate the offer and its deadline. Admission must also compare the
    /// current owner epoch through verify_current and check service revocation.
    pub fn verify(&self, anchor: &TrustAnchor, now: u64) -> Result<()> {
        ensure!(&self.offer.anchor == anchor, "invitation authority changed");
        self.verify_signature()?;
        fresh(self.offer.issued_at, self.offer.expires_at, now)
    }

    pub fn verify_current(&self, state: &VerifiedState, now: u64) -> Result<()> {
        self.verify(state.anchor(), now)?;
        ensure!(
            self.offer.owner_transitions == state.state().owner_transitions,
            "invitation is from another owner epoch"
        );
        state.authorize_node(&self.offer.issuer_id, &self.offer.issuer_key, now)?;
        if let Purpose::NamedNode { inviter, .. } = &self.offer.purpose {
            let node = state
                .state()
                .nodes
                .get(inviter)
                .context("inviting node is no longer enrolled")?;
            state.authorize_node(inviter, &node.signing_key, now)?;
            ensure!(
                inviter == &self.offer.issuer_id || node.can_configure,
                "inviting node no longer has configuration authority"
            );
        }
        Ok(())
    }
}

/// Deliberately no Debug, Clone, or Serialize. Export only to a protected file.
pub struct Invitation {
    offer: SignedOffer,
    psk: Zeroizing<[u8; 32]>,
    routing: Zeroizing<[u8; 32]>,
}
impl Invitation {
    pub fn offer(&self) -> &SignedOffer {
        &self.offer
    }
    pub fn expose_routing_secret(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.routing)
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        secret_encode(&self.wire())
    }
    /// Checks the signed offer and routing binding. Protected delivery supplies
    /// provenance; the handshake separately checks the PSK and current expiry.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let wire: WireInvitation = secret_decode(bytes)?;
        Self::from_wire(&wire)
    }
    fn from_wire(wire: &WireInvitation) -> Result<Self> {
        wire.offer.verify_signature()?;
        ensure!(
            <[u8; 32]>::from(Sha256::digest(wire.routing)) == wire.offer.offer.routing_digest,
            "invitation routing secret does not match offer"
        );
        Ok(Self {
            offer: wire.offer.clone(),
            psk: Zeroizing::new(wire.psk),
            routing: Zeroizing::new(wire.routing),
        })
    }
    fn wire(&self) -> WireInvitation {
        WireInvitation {
            offer: self.offer.clone(),
            psk: *self.psk,
            routing: *self.routing,
        }
    }
}

/// Persist locally before publishing the offer. Never export this owner record
/// as the joining file; only `invitation().encode()` belongs on the new machine.
pub struct OwnerInvitation {
    invitation: Invitation,
    private: Zeroizing<[u8; 32]>,
}
impl OwnerInvitation {
    pub fn issue(
        owner: &OwnerKey,
        state: &VerifiedState,
        issuer: &NodeIdentity,
        options: Options,
        now: u64,
    ) -> Result<Self> {
        ensure!(
            owner.public_key() == state.state().owner_key,
            "wrong invitation owner"
        );
        state.authorize_node(issuer.id(), &issuer.public_key(), now)?;
        if let Some(node) = options.purpose.continuation() {
            state.authorize_node(&node.id, &node.key, now)?;
            let member = &state.state().nodes[&node.id];
            ensure!(
                node.name == member.name && options.can_configure == member.can_configure,
                "continuation must preserve the existing node and privileges"
            );
        }
        if let Some(target) = &options.replaces {
            match options.purpose.continuation() {
                None => {
                    let member = state
                        .state()
                        .nodes
                        .get(&target.id)
                        .context("replacement target is unavailable")?;
                    ensure!(
                        member.signing_key == target.signing_key
                            && (!options.can_configure || member.can_configure),
                        "replacement target key or configuration privileges changed"
                    );
                }
                Some(_) => ensure!(
                    !state.state().nodes.contains_key(&target.id)
                        && state.state().retired_nodes.contains(&target.id)
                        && state.state().retired_keys.contains(&target.signing_key),
                    "replacement continuation requires signed retirement"
                ),
            }
        }
        let private = random_secret()?;
        let routing = random_secret()?;
        let psk = random_secret()?;
        let offer = Offer {
            version: 1,
            id: Uuid::new_v7(uuid::Timestamp::from_unix(uuid::NoContext, now, 0)).to_string(),
            anchor: state.anchor().clone(),
            owner_transitions: state.state().owner_transitions.clone(),
            issuer_id: issuer.id().into(),
            issuer_key: issuer.public_key(),
            service: options.service,
            responder_key: channel::public_key(&private),
            routing_digest: Sha256::digest(routing.as_ref()).into(),
            purpose: options.purpose,
            can_configure: options.can_configure,
            replaces: options.replaces,
            issued_at: now,
            expires_at: now
                .checked_add(OFFER_LIFETIME)
                .context("invitation timestamp overflow")?,
        };
        let signature = owner
            .0
            .sign(&signing_input(OFFER_DOMAIN, &offer, MAX_OFFER_BYTES)?)
            .to_bytes()
            .to_vec();
        let signed = SignedOffer { offer, signature };
        signed.verify(state.anchor(), now)?;
        Ok(Self {
            invitation: Invitation {
                offer: signed,
                psk,
                routing,
            },
            private,
        })
    }
    pub fn invitation(&self) -> &Invitation {
        &self.invitation
    }
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        secret_encode(&WireOwner {
            invitation: self.invitation.wire(),
            private: *self.private,
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let wire: WireOwner = secret_decode(bytes)?;
        let invitation = Invitation::from_wire(&wire.invitation)?;
        ensure!(
            channel::public_key(&wire.private) == invitation.offer.offer.responder_key,
            "owner invitation key does not match offer"
        );
        Ok(Self {
            invitation,
            private: Zeroizing::new(wire.private),
        })
    }
}

fn random_secret() -> Result<Zeroizing<[u8; 32]>> {
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut())?;
    Ok(secret)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInvitation {
    offer: SignedOffer,
    psk: [u8; 32],
    routing: [u8; 32],
}
impl Drop for WireInvitation {
    fn drop(&mut self) {
        self.psk.zeroize();
        self.routing.zeroize();
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOwner {
    invitation: WireInvitation,
    private: [u8; 32],
}
impl Drop for WireOwner {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}
fn secret_encode(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(serde_jcs::to_vec(value)?);
    ensure!(
        bytes.len() <= MAX_INVITATION_BYTES,
        "invitation file too large"
    );
    Ok(bytes)
}
fn secret_decode<T: Serialize + DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ensure!(
        bytes.len() <= MAX_INVITATION_BYTES,
        "invitation file too large"
    );
    let value: T =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid invitation file"))?;
    ensure!(
        *secret_encode(&value)? == bytes,
        "invitation file must use canonical JSON"
    );
    Ok(value)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    version: u8,
    invitation: String,
    offer: Digest,
    handshake: Digest,
    node: ClaimedNode,
    issued_at: u64,
    expires_at: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedClaim {
    claim: Claim,
    signature: Vec<u8>,
}
impl SignedClaim {
    fn create(
        offer: &SignedOffer,
        handshake: Digest,
        node: &NodeIdentity,
        name: &str,
        now: u64,
    ) -> Result<Self> {
        let claim = Claim {
            version: 1,
            invitation: offer.offer.id.clone(),
            offer: offer.fingerprint()?,
            handshake,
            node: ClaimedNode {
                id: node.id().into(),
                key: node.public_key(),
                name: name.into(),
            },
            issued_at: now,
            expires_at: now
                .checked_add(60)
                .context("claim timestamp overflow")?
                .min(offer.offer.expires_at),
        };
        let signature = node
            .key
            .sign(&signing_input(CLAIM_DOMAIN, &claim, MAX_REQUEST_BYTES)?)
            .to_bytes()
            .to_vec();
        let signed = Self { claim, signature };
        signed.verify(offer, handshake, now)?;
        Ok(signed)
    }
    fn verify(&self, offer: &SignedOffer, handshake: Digest, now: u64) -> Result<()> {
        offer.verify(&offer.offer.anchor, now)?;
        let claim = &self.claim;
        ensure!(
            claim.version == 1
                && claim.invitation == offer.offer.id
                && claim.offer == offer.fingerprint()?
                && claim.handshake == handshake
                && claim.issued_at >= offer.offer.issued_at
                && claim.expires_at <= offer.offer.expires_at,
            "invitation claim binding mismatch"
        );
        claim.node.validate(&offer.offer)?;
        if let Some(node) = offer.offer.purpose.continuation() {
            ensure!(
                &claim.node == node,
                "continuation requires the original node"
            );
        }
        lifetime(claim.issued_at, claim.expires_at, 60)?;
        fresh(claim.issued_at, claim.expires_at, now)?;
        verify(
            &claim.node.key,
            CLAIM_DOMAIN,
            claim,
            &self.signature,
            MAX_REQUEST_BYTES,
        )
    }
}
