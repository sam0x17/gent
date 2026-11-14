//! Historical provenance at trusted endpoints. These records grant no live authority.
use crate::{Agent, Message};
use serde::{Deserialize, Serialize};

pub const MAX_LINEAGE: usize = 64;
pub const MAX_METADATA_BYTES: usize = 128 * 1024;
const MAX_INTEGER: u64 = (1 << 53) - 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Archive {
    pub archive_id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub captured_at: u64,
    pub database_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub archive: Archive,
    pub import_id: String,
    pub manifest_sha256: String,
    pub source_agent: String,
    pub target_agent: String,
    pub target_revoked: bool,
    pub imported_at: i64,
    pub revision: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub archive_id: String,
    pub cluster_id: String,
    pub node_id: String,
    pub captured_at: u64,
    pub database_sha256: String,
    pub source_agent: Agent,
    pub target_agent: String,
    pub imported_at: i64,
    pub provenance: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage: Vec<Assignment>,
}

impl Archive {
    pub fn valid(&self) -> bool {
        valid_id(&self.archive_id)
            && valid_id(&self.cluster_id)
            && valid_id(&self.node_id)
            && (1..MAX_INTEGER).contains(&self.captured_at)
            && valid_digest(&self.database_sha256)
    }
}

impl Origin {
    pub fn archive(&self) -> Archive {
        Archive {
            archive_id: self.archive_id.clone(),
            cluster_id: self.cluster_id.clone(),
            node_id: self.node_id.clone(),
            captured_at: self.captured_at,
            database_sha256: self.database_sha256.clone(),
        }
    }

    pub fn valid(&self) -> bool {
        self.archive().valid()
            && valid_id(&self.source_agent.id)
            && valid_id(&self.source_agent.node_id)
            && valid_id(&self.target_agent)
            && (0..MAX_INTEGER as i64).contains(&self.imported_at)
            && self.provenance.len() <= 1024
            && valid_lineage(&self.lineage, &self.source_agent.id)
    }
}

pub fn valid_lineage(lineage: &[Assignment], source: &str) -> bool {
    lineage.len() <= MAX_LINEAGE
        && lineage.iter().all(|hop| {
            hop.archive.valid()
                && valid_id(&hop.import_id)
                && valid_digest(&hop.manifest_sha256)
                && hop.source_agent == source
                && valid_id(&hop.source_agent)
                && valid_id(&hop.target_agent)
                && (0..MAX_INTEGER as i64).contains(&hop.imported_at)
                && (1..=MAX_INTEGER).contains(&hop.revision)
        })
}

pub fn valid_id(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredMessage {
    pub message: Message,
    pub sender: Agent,
    pub recipient: Agent,
    pub files: Vec<RecoveredFile>,
    pub historical: bool,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveredFile {
    pub file_index: u32,
    pub name: String,
    pub media_type: String,
    pub byte_length: u64,
    pub sha256: String,
    pub state: String,
    pub original_file_id: Option<String>,
}
