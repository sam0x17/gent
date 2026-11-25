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

// Keep updater protocol v1 Build and its activation-journal equality intact.
// Older publishers only include the original Build fields in pending.json.
#[derive(Serialize, Deserialize)]
pub(crate) struct Version {
    #[serde(flatten)]
    pub build: Build,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_commit: Option<String>,
}

pub(crate) fn version() -> Version {
    Version {
        build: current(),
        bootstrap_commit: bootstrap_commit().map(str::to_owned),
    }
}

pub(crate) fn bootstrap_commit() -> Option<&'static str> {
    option_env!("GENT_BOOTSTRAP_COMMIT").filter(|pin| valid_commit(pin))
}

pub(crate) fn current() -> Build {
    Build {
        package: "gent-link".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        commit: env!("GENT_COMMIT").into(),
        dirty: env!("GENT_DIRTY") != "false",
        target: env!("GENT_TARGET").into(),
        update_protocol: 1,
        test_build: cfg!(any(feature = "test-updates", feature = "test-web-bridge"))
            || gent_daemon::entitlements::FIXTURE_AUTHORITY,
    }
}

pub(crate) fn valid_commit(commit: &str) -> bool {
    commit.len() == 40
        && commit
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
