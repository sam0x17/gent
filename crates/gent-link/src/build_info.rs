use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Build {
    pub package: String,
    pub version: String,
    pub commit: String,
    pub dirty: bool,
    pub target: String,
    pub update_protocol: u32,
    pub test_build: bool,
}

pub(crate) fn current() -> Build {
    Build {
        package: "gent-link".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        commit: env!("GENT_COMMIT").into(),
        dirty: env!("GENT_DIRTY") != "false",
        target: env!("GENT_TARGET").into(),
        update_protocol: 1,
        test_build: cfg!(feature = "test-updates"),
    }
}

pub(crate) fn valid_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
