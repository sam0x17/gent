//! Account state belongs to this node's single home.
use super::*;
use std::path::PathBuf;

pub(crate) fn directory(home: &Path) -> Result<PathBuf> {
    crate::node_home::resolve(home, None)?;
    managed_file::normalize(&home.join("auth"))
}
