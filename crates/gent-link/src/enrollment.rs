//! Code-authenticated invitation delivery over the account service. Cluster
//! joining continues through the existing Noise protocol and durable journals.
mod approval;
mod joining;
mod storage;
pub use approval::{ApproveArgs, approve};
pub use joining::join;
pub(crate) use joining::pending;

use crate::{
    auth,
    managed_file::{self, Snapshot},
};
use anyhow::{Context, Result, ensure};
use gent_crypto::pairing::Code;
use gent_daemon::config;
use gent_protocol::service::pairing::{LIFETIME, Record};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    version: u8,
    name: String,
    service: String,
}

fn check_record(record: &Record, id: &str, cluster: &str, created: u64) -> Result<()> {
    ensure!(
        record.id == id
            && record.cluster_id == cluster
            && record.created_at == created
            && record.expires_at == created.saturating_add(LIFETIME),
        "pairing request binding changed"
    );
    Ok(())
}

fn prompt(label: &str) -> Result<Zeroizing<String>> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "pairing approval needs a terminal, or --code-file with --yes"
    );
    eprint!("{label}");
    io::stderr().flush()?;
    let mut input = Zeroizing::new(String::new());
    io::stdin().lock().take(1025).read_line(&mut input)?;
    ensure!(
        input.len() <= 1024 && input.ends_with('\n'),
        "invalid or incomplete pairing input"
    );
    Ok(Zeroizing::new(input.trim().into()))
}
