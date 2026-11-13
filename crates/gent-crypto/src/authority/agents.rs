use super::*;
use uuid::Uuid;

const LEGACY_DOMAIN: &[u8] = b"gent/legacy-agent-binding/v1\0";

/// Public, node-bound IDs prevent an authenticated node from claiming another
/// node's agent UUID before the receiver has seen its directory announcement.
pub fn agent_id(node: &str, nonce: Uuid) -> Result<String> {
    id(node)?;
    ensure!(!nonce.is_nil(), "nil agent nonce");
    Ok(scoped_id(
        b"gent/agent-id/v1\0",
        &[Uuid::parse_str(node)?.as_bytes(), nonce.as_bytes()],
    )
    .to_string())
}

/// Domain-separated UUIDv8 identifier from length-prefixed public inputs.
pub fn scoped_id(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u64).to_be_bytes());
    hash.update(domain);
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().expect("SHA256 prefix");
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyAgentBinding {
    pub anchor: TrustAnchor,
    pub agent: String,
    pub node: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedLegacyAgentBinding {
    pub binding: LegacyAgentBinding,
    pub signature: Vec<u8>,
}
impl SignedLegacyAgentBinding {
    pub fn verify(&self, anchor: &TrustAnchor, agent: &str, node: &str) -> Result<()> {
        id(agent)?;
        id(node)?;
        ensure!(
            &self.binding.anchor == anchor
                && self.binding.agent == agent
                && self.binding.node == node,
            "legacy agent binding mismatch"
        );
        verify(
            &anchor.owner_key,
            LEGACY_DOMAIN,
            &self.binding,
            &self.signature,
            4096,
        )
    }
}
impl OwnerKey {
    /// Trusted owner migration approval. The runtime must retain unique bindings
    /// and reject an agent UUID already assigned to a different node.
    pub fn bind_legacy_agent(
        &self,
        state: &VerifiedState,
        agent: &str,
        node: &str,
        now: u64,
    ) -> Result<SignedLegacyAgentBinding> {
        id(agent)?;
        id(node)?;
        state.require_fresh(now)?;
        ensure!(
            self.public_key() == state.anchor().owner_key && state.state().nodes.contains_key(node),
            "legacy agent binding requires owner authority and enrolled node"
        );
        let binding = LegacyAgentBinding {
            anchor: state.anchor().clone(),
            agent: agent.into(),
            node: node.into(),
        };
        let signature = self
            .0
            .sign(&signing_input(LEGACY_DOMAIN, &binding, 4096)?)
            .to_bytes()
            .to_vec();
        Ok(SignedLegacyAgentBinding { binding, signature })
    }
}
