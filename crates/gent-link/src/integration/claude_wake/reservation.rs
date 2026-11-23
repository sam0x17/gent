//! One outstanding native prompt per bound session. Claude may skip a plugin's
//! own middleware on re-entry, so the independent UserPromptSubmit guard admits
//! its tagged prompt once. Ordinary input never opens this file.
use super::babysit::Record;
use crate::managed_file::{Snapshot, lock};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

pub(super) const PREFIX: &str = "Continue working on the current goal.\n\n[Gent goal resume ";

pub(super) fn prompt(installation: &str, attempt: Uuid) -> String {
    format!("{PREFIX}{installation} {attempt}]")
}

#[derive(Serialize, Deserialize)]
pub(super) struct Reservation {
    attempt: Uuid,
    failure: Record,
    end: u64,
    admitted: bool,
}

impl Reservation {
    pub fn arm(path: &Path, attempt: Uuid, failure: Record, end: u64) -> Result<()> {
        let _lock = lock(&path.with_extension("resume-lock"))?;
        let snapshot = Snapshot::read(path)?;
        snapshot.private()?;
        snapshot.write(&serde_json::to_string(&Self {
            attempt,
            failure,
            end,
            admitted: false,
        })?)
    }

    fn read(snapshot: &Snapshot, attempt: Uuid) -> Result<Self> {
        snapshot.private()?;
        let ticket: Self = serde_json::from_str(
            snapshot
                .text
                .as_deref()
                .context("missing goal reservation")?,
        )?;
        ensure!(ticket.attempt == attempt, "goal reservation changed");
        Ok(ticket)
    }

    pub fn admit(
        path: &Path,
        attempt: Uuid,
        directory: &Path,
        session: &str,
        prompt: &str,
    ) -> Result<bool> {
        let _lock = lock(&path.with_extension("resume-lock"))?;
        let snapshot = Snapshot::read(path)?;
        let mut ticket = Self::read(&snapshot, attempt)?;
        if ticket.admitted {
            return Ok(false);
        }
        if ticket
            .failure
            .current(directory, session, Some((ticket.end, prompt)))?
            .is_none()
        {
            snapshot.remove()?;
            return Ok(false);
        }
        ticket.admitted = true;
        snapshot.write(&serde_json::to_string(&ticket)?)?;
        Ok(true)
    }

    pub fn confirm(path: &Path, attempt: Uuid) -> Result<()> {
        let _lock = lock(&path.with_extension("resume-lock"))?;
        let snapshot = Snapshot::read(path)?;
        ensure!(
            Self::read(&snapshot, attempt)?.admitted,
            "goal continuation was never admitted"
        );
        snapshot.remove()
    }
}
