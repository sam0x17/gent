//! A deterministic radix Merkle tree over stable registration metadata.
//! Polling and activity timestamps do not change its hashes.
use crate::messages::{Registration, directory::*};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) struct Tree {
    entries: Vec<(String, Registration)>,
    summaries: BTreeMap<String, Summary>,
}

pub(super) fn validate_prefix(prefix: &str) -> Result<()> {
    ensure!(
        prefix.len() <= MAX_DEPTH
            && prefix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid directory prefix"
    );
    Ok(())
}

pub(super) fn key(id: &str) -> String {
    format!("{:x}", Sha256::digest(id.as_bytes()))
}

fn leaf(prefix: &str, entries: &[(String, Registration)]) -> Result<Summary> {
    let mut hash = Sha256::new();
    hash.update(b"gent/directory-leaf/v1\0");
    hash.update((prefix.len() as u64).to_be_bytes());
    hash.update(prefix.as_bytes());
    hash.update((entries.len() as u64).to_be_bytes());
    for (_, chat) in entries {
        let bytes = serde_json::to_vec(chat)?;
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(Summary {
        hash: hash.finalize().into(),
        count: entries.len(),
    })
}

pub(super) fn branch(prefix: &str, children: &[Summary; 16]) -> Result<Summary> {
    validate_prefix(prefix)?;
    let count: usize = children
        .iter()
        .map(|child| child.count.min(MAX_CHATS + 1))
        .sum();
    ensure!(
        prefix.len() < MAX_DEPTH && (LEAF_LIMIT + 1..=MAX_CHATS).contains(&count),
        "invalid directory branch"
    );
    let mut hash = Sha256::new();
    hash.update(b"gent/directory-branch/v1\0");
    hash.update((prefix.len() as u64).to_be_bytes());
    hash.update(prefix.as_bytes());
    for child in children {
        hash.update((child.count as u64).to_be_bytes());
        hash.update(child.hash);
    }
    Ok(Summary {
        hash: hash.finalize().into(),
        count,
    })
}

impl Tree {
    pub(super) fn new(chats: Vec<Registration>) -> Result<Self> {
        ensure!(chats.len() <= MAX_CHATS, "directory tree capacity exceeded");
        let mut entries: Vec<_> = chats
            .into_iter()
            .map(|chat| (key(&chat.id), chat))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        ensure!(
            entries.windows(2).all(|p| p[0].0 != p[1].0),
            "duplicate directory identity"
        );
        let mut tree = Self {
            entries,
            summaries: BTreeMap::new(),
        };
        tree.build("", 0, tree.entries.len())?;
        Ok(tree)
    }

    fn build(&mut self, prefix: &str, start: usize, end: usize) -> Result<Summary> {
        let summary = if end - start <= LEAF_LIMIT {
            leaf(prefix, &self.entries[start..end])?
        } else {
            ensure!(prefix.len() < MAX_DEPTH, "directory hash collision");
            let mut at = start;
            let mut children = [Summary {
                hash: [0; 32],
                count: 0,
            }; 16];
            for (index, digit) in "0123456789abcdef".chars().enumerate() {
                let child = format!("{prefix}{digit}");
                let begin = at;
                while at < end && self.entries[at].0.starts_with(&child) {
                    at += 1;
                }
                children[index] = self.build(&child, begin, at)?;
            }
            branch(prefix, &children)?
        };
        self.summaries.insert(prefix.into(), summary);
        Ok(summary)
    }

    pub(super) fn summary(&self, prefix: &str) -> Result<Summary> {
        validate_prefix(prefix)?;
        if let Some(summary) = self.summaries.get(prefix) {
            return Ok(*summary);
        }
        let entries = self
            .entries
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .cloned()
            .collect::<Vec<_>>();
        // A prefix below a cached leaf still has at most LEAF_LIMIT entries.
        leaf(prefix, &entries)
    }

    pub(super) fn reply(&self, prefix: &str) -> Result<Reply> {
        if self.summary(prefix)?.count <= LEAF_LIMIT {
            Ok(Reply::Leaves {
                chats: self
                    .entries
                    .iter()
                    .filter(|(key, _)| key.starts_with(prefix))
                    .map(|(_, chat)| chat.clone())
                    .collect(),
            })
        } else {
            let mut children = [Summary {
                hash: [0; 32],
                count: 0,
            }; 16];
            for (index, digit) in "0123456789abcdef".chars().enumerate() {
                children[index] = self.summary(&format!("{prefix}{digit}"))?;
            }
            Ok(Reply::Branch {
                children: Box::new(children),
            })
        }
    }
}
