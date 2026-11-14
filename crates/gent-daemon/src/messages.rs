//! Private node-to-node wire records. Only a verified MLS stream authenticates
//! the hosting node; labels and agent IDs supplied by a model never do.
use anyhow::{Result, ensure};
use gent_crypto::{Checkpoint, SignedLegacyAgentBinding, VerifiedState, agent_id, scoped_id};
use gent_protocol::Message;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FRAGMENT_BYTES: usize = 256 * 1024;
pub const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_PENDING_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub id: String,
    pub node: String,
    pub nonce: Option<Uuid>,
    pub legacy: Option<SignedLegacyAgentBinding>,
    pub generation: u64,
    pub name: String,
    pub provider: String,
    pub revoked: bool,
}
impl Registration {
    pub fn verify(&self, state: &VerifiedState, node: &str) -> Result<()> {
        ensure!(
            self.node == node && state.state().nodes.contains_key(node),
            "registration belongs to another node"
        );
        ensure!(
            (1..=(1 << 53) - 1).contains(&self.generation),
            "invalid registration generation"
        );
        crate::config::label(&self.name)?;
        crate::config::label(&self.provider)?;
        match (&self.nonce, &self.legacy) {
            (Some(nonce), None) => ensure!(
                agent_id(node, *nonce)? == self.id,
                "agent ID does not belong to node"
            ),
            (None, Some(binding)) => binding.verify_current(state, &self.id, node)?,
            _ => anyhow::bail!("ambiguous agent binding"),
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Mesh {
        envelope: MeshEnvelope,
    },
    ConfigurationRequest {
        request_id: Uuid,
        edit: Box<gent_protocol::ConfigurationEdit>,
    },
    ConfigurationResult {
        request_id: Uuid,
        fingerprint: String,
        result: EditResult,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        decided_by: Option<String>,
    },
    Registration {
        agent: Registration,
    },
    Message {
        sender: Box<Registration>,
        request_id: String,
        message: Message,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        attachments: Vec<PrivateAttachment>,
    },
    Receipt {
        message_id: String,
        delivered: bool,
    },
}

/// Private MLS payload only. Never use this type in public agent responses.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateAttachment {
    #[serde(with = "private_grant")]
    pub grant: gent_crypto::files::FileGrant,
    pub manifest: gent_protocol::file_objects::Manifest,
}

mod private_grant {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use gent_crypto::files::{FileGrant, MAX_GRANT_BYTES};
    use serde::{Deserialize, Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(grant: &FileGrant, s: S) -> Result<S::Ok, S::Error> {
        let bytes = grant
            .encode_private()
            .map_err(|_| serde::ser::Error::custom("invalid file grant"))?;
        let encoded = Zeroizing::new(STANDARD.encode(bytes.as_slice()));
        s.serialize_str(&encoded)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FileGrant, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(d)?);
        let bad = || serde::de::Error::custom("invalid file grant");
        if encoded.len() > MAX_GRANT_BYTES.div_ceil(3) * 4 {
            return Err(bad());
        }
        let bytes = Zeroizing::new(STANDARD.decode(encoded.as_bytes()).map_err(|_| bad())?);
        FileGrant::decode_private(&bytes).map_err(|_| bad())
    }
}

/// Private bootstrap metadata, routed through established owner links. MLS key
/// packages and Welcome signatures independently authenticate the actual peer.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshEnvelope {
    pub origin: String,
    pub target: String,
    pub origin_key: gent_crypto::PublicKey,
    pub target_key: gent_crypto::PublicKey,
    pub link: Uuid,
    pub signal: MeshSignal,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub enum MeshSignal {
    Offer { key_package: String },
    Welcome { packet: String },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EditResult {
    Applied { checkpoint: Checkpoint },
    Rejected { reason: String },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u8,
    pub authority: Checkpoint,
    pub event: Event,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Frame {
    Part {
        version: u8,
        id: Uuid,
        digest: [u8; 32],
        total: usize,
        offset: usize,
        data: String,
    },
    Cancel {
        version: u8,
        id: Uuid,
    },
}

pub fn message_id(sender: &str, request: &str) -> Result<String> {
    let sender = Uuid::parse_str(sender)?;
    let request = Uuid::parse_str(request)?;
    ensure!(
        !sender.is_nil() && !request.is_nil(),
        "nil message identity"
    );
    Ok(scoped_id(
        b"gent/message-id/v1\0",
        &[sender.as_bytes(), request.as_bytes()],
    )
    .to_string())
}
pub fn packet_id(event: Uuid, offset: usize, cancelled: bool) -> Uuid {
    scoped_id(
        b"gent/event-fragment/v1\0",
        &[
            event.as_bytes(),
            &(offset as u64).to_be_bytes(),
            &[u8::from(cancelled)],
        ],
    )
}
