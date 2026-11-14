//! An owner-authorized, private snapshot of completed configuration decisions.
//! Page hashes permit bounded, out-of-order transfer without trusting the relay.
use super::*;

pub const PAGE_BYTES: usize = 256 * 1024;
pub const MAX_BYTES: usize = 80 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 65536;
pub const MAX_MANIFEST_BYTES: usize = 128 * 1024;
const PAGE_DOMAIN: &[u8] = b"gent/owner-journal-page/v1\0";
const MANIFEST_DOMAIN: &[u8] = b"gent/owner-journal-manifest/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub bytes: usize,
    pub digest: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub candidate: Digest,
    pub base: Checkpoint,
    pub entries: usize,
    pub bytes: usize,
    pub pages: Vec<Page>,
}

fn page_digest(candidate: &Digest, index: usize, body: &[u8]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(PAGE_DOMAIN);
    hash.update(candidate);
    hash.update((index as u64).to_be_bytes());
    hash.update(body);
    hash.finalize().into()
}

impl Manifest {
    pub fn new(candidate: &SignedOwnerCandidate, entries: usize, body: &[u8]) -> Result<Self> {
        ensure!(
            !body.is_empty() && body.len() <= MAX_BYTES,
            "owner journal size exceeds limit"
        );
        let candidate_digest = candidate.digest()?;
        let manifest = Self {
            version: 1,
            candidate: candidate_digest,
            base: candidate.candidate.base.clone(),
            entries,
            bytes: body.len(),
            pages: body
                .chunks(PAGE_BYTES)
                .enumerate()
                .map(|(index, body)| Page {
                    bytes: body.len(),
                    digest: page_digest(&candidate_digest, index, body),
                })
                .collect(),
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && self.candidate != [0; 32]
                && self.base.state_hash != [0; 32]
                && self.base.revision <= MAX_SAFE_INTEGER,
            "invalid owner journal binding"
        );
        ensure!(
            self.entries <= MAX_ENTRIES
                && self.bytes > 0
                && self.bytes <= MAX_BYTES
                && self.pages.len() == self.bytes.div_ceil(PAGE_BYTES),
            "invalid owner journal limits"
        );
        for (index, page) in self.pages.iter().enumerate() {
            ensure!(
                page.bytes == (self.bytes - index * PAGE_BYTES).min(PAGE_BYTES)
                    && page.digest != [0; 32],
                "invalid owner journal page"
            );
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(self, MAX_MANIFEST_BYTES)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = decode(bytes, MAX_MANIFEST_BYTES)?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn digest(&self) -> Result<Digest> {
        self.validate()?;
        digest(MANIFEST_DOMAIN, self, MAX_MANIFEST_BYTES)
    }

    pub fn verify(
        &self,
        baseline: &VerifiedState,
        candidate: &SignedOwnerCandidate,
        authorization: &SignedOwnerTransition,
    ) -> Result<()> {
        baseline.verify_owner_authorization(candidate, authorization)?;
        ensure!(
            self.candidate == candidate.digest()?
                && self.base == candidate.candidate.base
                && authorization
                    .transition
                    .successor
                    .as_ref()
                    .and_then(|s| s.journal)
                    == Some(self.digest()?),
            "owner journal does not match signed handoff"
        );
        Ok(())
    }

    pub fn verify_page(&self, index: usize, body: &[u8]) -> Result<()> {
        self.validate()?;
        let page = self
            .pages
            .get(index)
            .context("owner journal page outside manifest")?;
        ensure!(
            body.len() == page.bytes && page_digest(&self.candidate, index, body) == page.digest,
            "owner journal page does not match manifest"
        );
        Ok(())
    }
}
