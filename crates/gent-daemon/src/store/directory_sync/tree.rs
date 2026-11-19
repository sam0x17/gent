//! A deterministic radix Merkle tree over stable registration metadata.
//! Polling and activity timestamps do not change its hashes.
use crate::messages::{Registration, directory::*};
use anyhow::{Context, Result, ensure};
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
    /// A bounded, complete partition. Expand wide levels first; a large branch
    /// remains coarse when the budget is exhausted. Never include chat IDs.
    pub(super) fn snapshot(&self, sequence: u64) -> Result<Snapshot> {
        let root = self.summary("")?;
        let mut frontier = vec![Branch {
            prefix: String::new(),
            summary: root,
        }];
        let mut at = 0;
        while at < frontier.len() && frontier.len() + 15 <= MAX_FRONTIER {
            if frontier[at].summary.count > LEAF_LIMIT {
                let parent = frontier.remove(at);
                for digit in "0123456789abcdef".chars() {
                    let prefix = format!("{}{digit}", parent.prefix);
                    frontier.push(Branch {
                        summary: self.summary(&prefix)?,
                        prefix,
                    });
                }
            } else {
                at += 1;
            }
        }
        frontier.sort_by(|a, b| a.prefix.cmp(&b.prefix));
        Ok(Snapshot {
            sequence,
            root,
            frontier,
        })
    }

    pub(super) fn differing(
        &self,
        remote: &Snapshot,
        after: &str,
    ) -> Result<Vec<(String, Registration)>> {
        let mut prefixes = Vec::new();
        for branch in &remote.frontier {
            if self.summary(&branch.prefix)? != branch.summary {
                prefixes.push(branch.prefix.as_str());
            }
        }
        Ok(self
            .entries
            .iter()
            .filter(|(key, _)| key.as_str() > after && prefixes.iter().any(|p| key.starts_with(p)))
            .take(PUSH_LIMIT + 1)
            .cloned()
            .collect())
    }

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

/// Reconstruct the root from a prefix-free partition. A forged, overlapping or
/// incomplete frontier cannot suppress a repair or claim a matching directory.
pub(super) fn validate_snapshot(snapshot: &Snapshot) -> Result<()> {
    ensure!(
        snapshot.sequence > 0
            && snapshot.sequence <= i64::MAX as u64
            && snapshot.root.count <= MAX_CHATS
            && !snapshot.frontier.is_empty()
            && snapshot.frontier.len() <= MAX_FRONTIER,
        "invalid directory snapshot bounds"
    );
    let mut summaries = BTreeMap::new();
    for branch in &snapshot.frontier {
        validate_prefix(&branch.prefix)?;
        ensure!(
            branch.summary.count <= MAX_CHATS
                && summaries
                    .insert(branch.prefix.clone(), branch.summary)
                    .is_none(),
            "invalid directory frontier"
        );
    }
    let mut previous: Option<&str> = None;
    for prefix in summaries.keys() {
        ensure!(
            previous.is_none_or(|p| !prefix.starts_with(p)),
            "overlapping directory frontier"
        );
        previous = Some(prefix);
    }
    while !(summaries.len() == 1 && summaries.contains_key("")) {
        let prefix = summaries
            .keys()
            .max_by_key(|p| p.len())
            .context("empty directory frontier")?
            .clone();
        ensure!(!prefix.is_empty(), "incomplete directory frontier");
        let parent = &prefix[..prefix.len() - 1];
        let mut children = [Summary {
            hash: [0; 32],
            count: 0,
        }; 16];
        for (i, digit) in "0123456789abcdef".chars().enumerate() {
            children[i] = summaries
                .remove(&format!("{parent}{digit}"))
                .context("incomplete directory frontier")?;
        }
        summaries.insert(parent.into(), branch(parent, &children)?);
    }
    ensure!(
        summaries[""] == snapshot.root,
        "invalid directory frontier root"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chats(count: usize) -> Vec<Registration> {
        (0..count)
            .map(|i| Registration {
                id: format!("chat-{i}"),
                node: "node".into(),
                nonce: None,
                legacy: None,
                generation: 1,
                name: format!("name-{i}"),
                provider: "test".into(),
                revoked: false,
            })
            .collect()
    }

    #[test]
    fn bounded_frontier_covers_large_trees_and_rejects_missing_or_overlapping_hashes() {
        for count in [0, 16, 17, 80, MAX_CHATS] {
            let tree = Tree::new(chats(count)).unwrap();
            let snapshot = tree.snapshot(1).unwrap();
            assert!(snapshot.frontier.len() <= MAX_FRONTIER);
            assert!(serde_json::to_vec(&snapshot).unwrap().len() < 32 * 1024);
            validate_snapshot(&snapshot).unwrap();
            assert!(tree.differing(&snapshot, "").unwrap().is_empty());
            let mut corrupt = snapshot.clone();
            corrupt.root.hash[0] ^= 1;
            assert!(validate_snapshot(&corrupt).is_err());
            let mut corrupt = snapshot.clone();
            corrupt.frontier.pop();
            assert!(validate_snapshot(&corrupt).is_err());
            let mut corrupt = snapshot;
            corrupt.frontier.push(corrupt.frontier[0].clone());
            assert!(validate_snapshot(&corrupt).is_err());
        }
    }

    #[test]
    fn a_missing_chat_pushes_only_its_differing_bucket() {
        let full = chats(120);
        let tree = Tree::new(full.clone()).unwrap();
        let partial = Tree::new(full[1..].to_vec()).unwrap();
        let snapshot = partial.snapshot(2).unwrap();
        let differing = tree.differing(&snapshot, "").unwrap();
        assert!(differing.iter().any(|(_, r)| r.id == full[0].id));
        assert!(differing.len() <= LEAF_LIMIT + 1);
    }
}
