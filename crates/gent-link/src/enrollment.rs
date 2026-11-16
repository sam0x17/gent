//! Code-authenticated invitation delivery over the account service. Cluster
//! joining continues through the existing Noise protocol and durable journals.
mod issuing;
mod joining;
mod storage;
pub use issuing::{AddArgs, add};
pub use joining::join;
pub(crate) use joining::pending;

use crate::{
    auth,
    managed_file::{self, Snapshot},
};
use anyhow::{Context, Result, ensure};
use gent_crypto::pairing::Code;
use gent_daemon::config;
use gent_protocol::service::pairing::LIFETIME;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

fn prompt(label: &str) -> Result<Zeroizing<String>> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "enter a node invitation code, or use --code-file PRIVATE_FILE"
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
