use super::*;
use uuid::Uuid;

const LEGACY_DOMAIN: &[u8] = b"gent/legacy-agent-binding/v1\0";
const MAX_LEGACY_BINDING_BYTES: usize = MAX_OWNER_CHAIN_BYTES + 4096;

/// Public, node-bound IDs prevent an authenticated node from claiming another
/// node's chat UUID before the receiver has seen its directory announcement.
pub fn agent_id(node: &str, nonce: Uuid) -> Result<String> {
    id(node)?;
    ensure!(!nonce.is_nil(), "nil chat nonce");
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_transitions: Vec<SignedOwnerTransition>,
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
    /// Verify historical provenance only. Use verify_current for a live registration.
    pub fn verify(&self, anchor: &TrustAnchor, agent: &str, node: &str) -> Result<()> {
        id(agent)?;
        id(node)?;
        ensure!(
            &self.binding.anchor == anchor
                && self.binding.agent == agent
                && self.binding.node == node,
            "legacy chat binding mismatch"
        );
        let owner = verify_lineage(anchor, &self.binding.owner_transitions)?;
        verify(
            &owner,
            LEGACY_DOMAIN,
            &self.binding,
            &self.signature,
            MAX_LEGACY_BINDING_BYTES,
        )
    }

    /// Historical signatures alone cannot authorize a live registration.
    pub fn verify_current(&self, state: &VerifiedState, agent: &str, node: &str) -> Result<()> {
        self.verify(state.anchor(), agent, node)?;
        ensure!(
            self.binding.owner_transitions == state.state().owner_transitions,
            "legacy binding is from another owner epoch"
        );
        ensure!(
            state.state().nodes.contains_key(node),
            "legacy binding node is unavailable"
        );
        Ok(())
    }
}
impl OwnerKey {
    /// Trusted owner migration approval. The runtime must retain unique bindings
    /// and reject a chat UUID already assigned to a different node.
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
            self.public_key() == state.state().owner_key && state.state().nodes.contains_key(node),
            "legacy chat binding requires owner authority and enrolled node"
        );
        let binding = LegacyAgentBinding {
            anchor: state.anchor().clone(),
            owner_transitions: state.state().owner_transitions.clone(),
            agent: agent.into(),
            node: node.into(),
        };
        let signature = self
            .0
            .sign(&signing_input(
                LEGACY_DOMAIN,
                &binding,
                MAX_LEGACY_BINDING_BYTES,
            )?)
            .to_bytes()
            .to_vec();
        Ok(SignedLegacyAgentBinding { binding, signature })
    }
}
