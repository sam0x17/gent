//! A private, local record of the publishers the user has hidden in this profile.
use super::Row;
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result};
use gent_daemon::config::Config;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Label {
    pub(super) chat: String,
    pub(super) title: String,
}

impl From<&Row> for Label {
    fn from(row: &Row) -> Self {
        Self {
            chat: row.chat.clone(),
            title: row.board.title.clone(),
        }
    }
}

pub(super) type Hidden = BTreeMap<Uuid, Label>;

pub(super) fn path(home: &Path, cfg: &Config) -> PathBuf {
    let scope = serde_json::json!([
        cfg.cluster.id,
        cfg.service
            .as_ref()
            .map(|s| (s.origin.trim_end_matches('/'), &s.account_id))
    ]);
    let digest = Sha256::digest(scope.to_string().as_bytes());
    home.join(format!("desktop-hidden-boards-{digest:x}.json"))
}

fn read(file: &Path) -> Result<(Snapshot, Hidden)> {
    let snapshot = Snapshot::read(file)?;
    snapshot.private()?;
    let hidden = match &snapshot.text {
        Some(text) => serde_json::from_str(text).context("Invalid hidden dashboard preferences")?,
        None => Hidden::new(),
    };
    Ok((snapshot, hidden))
}

fn label_changed(hidden: &Hidden, row: &Row) -> bool {
    hidden
        .get(&row.agent)
        .is_some_and(|label| label.chat != row.chat || label.title != row.board.title)
}

pub(super) fn for_rows(file: &Path, rows: &[Row]) -> Result<Hidden> {
    let (_, hidden) = read(file)?;
    if rows.iter().any(|row| label_changed(&hidden, row)) {
        return edit(file, |hidden| {
            for row in rows {
                if label_changed(hidden, row) {
                    hidden.insert(row.agent, Label::from(row));
                }
            }
        });
    }
    Ok(hidden)
}

pub(super) fn edit(file: &Path, change: impl FnOnce(&mut Hidden)) -> Result<Hidden> {
    let _lock = managed_file::lock(&file.with_extension("lock"))?;
    let (snapshot, mut hidden) = read(file)?;
    change(&mut hidden);
    if hidden.is_empty() {
        snapshot.remove()?;
    } else {
        snapshot.write(&serde_json::to_string(&hidden)?)?;
    }
    Ok(hidden)
}
