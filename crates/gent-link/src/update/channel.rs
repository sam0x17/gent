//! Channel selection is signed cluster state. Its local receipt is scoped to
//! this installation and canonical Gent home, independently of auto-update.
use super::install::{Installation, hash};
use anyhow::Result;
use gent_protocol::ReleaseChannel;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    applied: ReleaseChannel,
    candidate: Option<Candidate>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    channel: ReleaseChannel,
    hash: String,
}

fn filename(home: &Path) -> Result<String> {
    let home = home.canonicalize()?;
    let key = Sha256::digest(home.as_os_str().as_encoded_bytes());
    Ok(format!("channel-{key:x}.json"))
}

impl Installation {
    pub fn applied_channel(&self, home: &Path) -> Result<ReleaseChannel> {
        let receipt: Receipt = self.read(&filename(home)?)?.unwrap_or_default();
        // An older updater can finish the v1 activation journal, or this
        // process can exit after clearing it and before compacting the receipt.
        if let Some(candidate) = receipt.candidate
            && self.pending()?.is_none()
            && hash(&self.binary)? == candidate.hash
        {
            return Ok(candidate.channel);
        }
        Ok(receipt.applied)
    }

    pub fn confirm_channel(&self, home: &Path, channel: ReleaseChannel) -> Result<()> {
        self.write(
            &filename(home)?,
            &Receipt {
                applied: channel,
                candidate: None,
            },
        )
    }

    pub fn prepare_channel(
        &self,
        home: &Path,
        channel: ReleaseChannel,
        new_hash: &str,
    ) -> Result<()> {
        let applied = self.applied_channel(home)?;
        let candidate = (channel != applied).then(|| Candidate {
            channel,
            hash: new_hash.into(),
        });
        self.write(&filename(home)?, &Receipt { applied, candidate })
    }

    // The pending journal has already been cleared and the file hash checked.
    // A failed compaction still leaves the durable, hash-bound receipt usable.
    pub fn finish_channel(&self, home: &Path, installed_hash: &str) -> Result<()> {
        let name = filename(home)?;
        if let Some(Receipt {
            applied,
            candidate: Some(candidate),
        }) = self.read(&name)?
        {
            let channel = if candidate.hash == installed_hash {
                candidate.channel
            } else {
                applied
            };
            self.confirm_channel(home, channel)?;
        }
        Ok(())
    }
}
