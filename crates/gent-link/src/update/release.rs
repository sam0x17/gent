//! Git release backend. Discovery and staging can later be replaced with a
//! crates.io backend without changing publication or daemon activation.
use anyhow::{Context, Result, ensure};
use gent_daemon::release_channel::{self, ReleaseChannel};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

pub(super) const REPOSITORY: &str = "https://github.com/sam0x17/gent.git";
const SSH_REPOSITORY: &str = "ssh://git@github.com/sam0x17/gent.git";

const LEGACY_STABLE: &str = "2e07f9214f1e119c4c181fe135c12c32f569e38c";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Resolution {
    pub release_ref: String,
    pub advertised_commit: String,
    pub resolved_ref: String,
    pub source: String,
    pub blessed_commit: String,
}

impl Resolution {
    pub fn matches_build(&self, build: &crate::build_info::Build, pin: Option<&str>) -> bool {
        build.commit == self.blessed_commit
            && !build.dirty
            && (self.resolved_ref != BOOTSTRAP.reference
                || pin == Some(self.blessed_commit.as_str()))
    }
}

pub(super) struct Release {
    pub resolution: Resolution,
    pub repository: String,
}

pub(super) fn repository() -> Result<String> {
    #[cfg(feature = "test-updates")]
    if let Ok(path) = std::env::var("GENT_TEST_UPDATE_REPOSITORY") {
        ensure!(
            path.starts_with("file:///"),
            "update proofs require a local repository"
        );
        return Ok(path);
    }
    Ok(REPOSITORY.into())
}

/// Only these two refs may authorize an installation. Older updaters and
/// release tooling use the stable tag, including its annotated form.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ReleaseRef {
    pub channel: ReleaseChannel,
    pub reference: &'static str,
    pub source: &'static str,
    peeled: Option<&'static str>,
}

pub(super) const STABLE: ReleaseRef = ReleaseRef {
    channel: ReleaseChannel::Stable,
    reference: "refs/tags/stable",
    source: "github_stable_tag",
    peeled: Some("refs/tags/stable^{}"),
};
const BOOTSTRAP: ReleaseRef = ReleaseRef {
    channel: ReleaseChannel::Stable,
    reference: "refs/tags/channel-v1-bootstrap",
    source: "github_channel_bootstrap_tag",
    peeled: Some("refs/tags/channel-v1-bootstrap^{}"),
};
pub(super) const BETA: ReleaseRef = ReleaseRef {
    channel: ReleaseChannel::Beta,
    reference: "refs/heads/beta",
    source: "github_beta_branch",
    peeled: None,
};

impl ReleaseRef {
    pub fn current(home: &Path) -> Result<Self> {
        let channel = release_channel::current(home).map_err(|_| {
            anyhow::anyhow!("cannot determine the release channel for this Gent home")
        })?;
        Ok(match channel {
            ReleaseChannel::Stable => STABLE,
            ReleaseChannel::Beta => BETA,
        })
    }

    pub fn parse<'a>(self, lines: impl Iterator<Item = &'a str>) -> Result<String> {
        let mut direct = None;
        let mut peeled = None;
        for line in lines {
            let (sha, reference) = line.split_once('\t').context("invalid Git ref response")?;
            ensure!(
                crate::build_info::valid_commit(sha),
                "invalid Git revision for {}",
                self.reference
            );
            let target = if reference == self.reference {
                &mut direct
            } else if self.peeled == Some(reference) {
                &mut peeled
            } else {
                anyhow::bail!("unexpected reference when resolving {}", self.reference);
            };
            ensure!(
                target.replace(sha).is_none(),
                "duplicate Git reference {reference}"
            );
        }
        let direct = direct.with_context(|| format!("the repository has no {}", self.reference))?;
        Ok(peeled.unwrap_or(direct).into())
    }

    async fn list_refs(self, repository: &str) -> Result<Vec<u8>> {
        let namespace = match self.channel {
            ReleaseChannel::Stable => "--tags",
            ReleaseChannel::Beta => "--heads",
        };
        let mut command = Command::new("git");
        command
            .args([
                "ls-remote",
                "--exit-code",
                namespace,
                repository,
                self.reference,
            ])
            .args(self.peeled);
        if self == STABLE {
            command.arg(BOOTSTRAP.reference).args(BOOTSTRAP.peeled);
        }
        super::process::capture(&mut command, 512, Duration::from_secs(30)).await
    }

    // Both tags come from one advertisement of the same official repository.
    // A missing bootstrap tag matters only during the single legacy exception.
    fn advertisement(
        self,
        response: &str,
        build: &crate::build_info::Build,
        pin: Option<&str>,
    ) -> Result<Resolution> {
        let (floor, selected): (Vec<_>, Vec<_>) = response.lines().partition(|line| {
            self == STABLE
                && line
                    .split_once('\t')
                    .is_some_and(|(_, r)| r == BOOTSTRAP.reference || Some(r) == BOOTSTRAP.peeled)
        });
        let advertised = self.parse(selected.into_iter())?;
        let (effective, commit) = if self == STABLE && advertised == LEGACY_STABLE {
            ensure!(
                !build.dirty && crate::build_info::valid_commit(&build.commit),
                "legacy stable requires a clean, revision-identified bootstrap-aware updater"
            );
            let expected = pin
                .filter(|sha| crate::build_info::valid_commit(sha) && *sha != LEGACY_STABLE)
                .context("legacy stable requires a qualified channel-v1 bootstrap pin")?;
            let commit = BOOTSTRAP.parse(floor.into_iter())?;
            ensure!(
                commit == expected,
                "channel-v1 bootstrap tag differs from the qualified pin"
            );
            (BOOTSTRAP, commit)
        } else {
            (self, advertised.clone())
        };
        Ok(Resolution {
            release_ref: self.reference.into(),
            advertised_commit: advertised,
            resolved_ref: effective.reference.into(),
            source: effective.source.into(),
            blessed_commit: commit,
        })
    }

    pub async fn resolve(self) -> Result<Release> {
        let primary = repository()?;
        let (repository, bytes) = match self.list_refs(&primary).await {
            Ok(bytes) => (primary, bytes),
            Err(error) if primary.starts_with("file://") => {
                return Err(error).with_context(|| format!("cannot resolve {}", self.reference));
            }
            Err(_) => (SSH_REPOSITORY.into(), self.list_refs(SSH_REPOSITORY).await.with_context(|| format!(
                "cannot read {} over HTTPS or SSH; check the ref and repository access from the daemon's environment", self.reference
            ))?),
        };
        let resolution = self.advertisement(
            std::str::from_utf8(&bytes)?,
            &crate::build_info::current(),
            crate::build_info::bootstrap_commit(),
        )?;
        Ok(Release {
            resolution,
            repository,
        })
    }
}

fn cargo() -> Result<PathBuf> {
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cargo")));
    if let Some(path) = home.map(|p| p.join("bin/cargo"))
        && path.is_file()
    {
        return Ok(path);
    }
    Ok("cargo".into())
}

pub(super) async fn stage(
    release: &Release,
    root: &Path,
    cache: &Path,
    installed: &str,
    log: &Path,
) -> Result<PathBuf> {
    let commit = &release.resolution.blessed_commit;
    ensure!(
        crate::build_info::valid_commit(commit),
        "invalid update revision"
    );
    let target = super::cache::prepare(cache, installed).await?;
    let executable = cargo()?;
    let mut command = super::priority::command(&executable);
    command
        .args([
            "install",
            "--git",
            &release.repository,
            "--rev",
            commit,
            "--locked",
            "--force",
            "--root",
        ])
        .arg(root)
        .arg("gent-link")
        .env("CARGO_TARGET_DIR", &target)
        // Keep intermediates beside artifacts so cache invalidation also works
        // when the user's Cargo configuration redirects build.build-dir.
        .env("CARGO_BUILD_BUILD_DIR", &target)
        .env("CARGO_NET_GIT_FETCH_WITH_CLI", "true");
    if std::env::var_os("CARGO_BUILD_JOBS").is_none() {
        command.env("CARGO_BUILD_JOBS", "2");
    }
    if let Some(parent) = executable.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut paths = vec![parent.to_owned()];
        if let Some(existing) = std::env::var_os("PATH") {
            paths.extend(std::env::split_paths(&existing));
        }
        command.env("PATH", std::env::join_paths(paths)?);
    }
    #[cfg(feature = "test-updates")]
    command.args(["--features", "test-updates"]);
    super::process::build(&mut command, log).await?;
    super::install::snapshot_artifact(&root.join("bin/gent"))
}

/// Retain the current release and its rollback cache. Only SHA-named directories
/// created by this backend are eligible; unrelated files and links are kept.
pub(super) async fn prune(cache: &Path, keep: &[&str]) -> Result<()> {
    let mut entries = tokio::fs::read_dir(cache).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if crate::build_info::valid_commit(name)
            && !keep.contains(&name)
            && entry.file_type().await?.is_dir()
        {
            tokio::fs::remove_dir_all(entry.path()).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod floor_tests {
    use super::*;

    #[test]
    fn the_legacy_exception_requires_the_exact_clean_source_pin_and_tag() {
        let sha = "a".repeat(40);
        let tag = "b".repeat(40);
        let mut build = crate::build_info::current();
        build.commit = sha.clone();
        build.dirty = false;
        let mut pin = Some(sha.as_str());
        let legacy = format!("{LEGACY_STABLE}\trefs/tags/stable\n");
        let floor = format!(
            "{tag}\trefs/tags/channel-v1-bootstrap\n{sha}\trefs/tags/channel-v1-bootstrap^{{}}\n"
        );
        let result = STABLE
            .advertisement(&format!("{legacy}{floor}"), &build, pin)
            .unwrap();
        assert_eq!(result.resolved_ref, BOOTSTRAP.reference);
        assert!(result.matches_build(&build, pin));
        for extra in [
            String::new(),
            floor.repeat(2),
            format!("{tag}\trefs/tags/channel-v1-bootstrap\n"),
            format!("{sha}\trefs/heads/channel-v1-bootstrap\n"),
        ] {
            assert!(
                STABLE
                    .advertisement(&format!("{legacy}{extra}"), &build, pin)
                    .is_err()
            );
        }
        pin = None;
        assert!(!result.matches_build(&build, pin));
        assert!(
            STABLE
                .advertisement(&format!("{legacy}{floor}"), &build, pin)
                .is_err()
        );
        let promoted = STABLE
            .advertisement(&format!("{sha}\trefs/tags/stable\n"), &build, pin)
            .unwrap();
        assert_eq!(promoted.blessed_commit, result.blessed_commit);
        assert!(promoted != result); // same bytes, different authorizing ref
        assert_eq!(promoted.resolved_ref, STABLE.reference);
        assert_eq!(
            BETA.advertisement(&format!("{sha}\trefs/heads/beta\n"), &build, pin)
                .unwrap()
                .resolved_ref,
            BETA.reference
        );
        pin = Some(sha.as_str());
        build.dirty = true;
        assert!(
            STABLE
                .advertisement(&format!("{legacy}{floor}"), &build, pin)
                .is_err()
        );
    }
}
