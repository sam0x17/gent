//! Git release backend. Discovery and staging can later be replaced with a
//! crates.io backend without changing publication or daemon activation.
use anyhow::{Context, Result, ensure};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;

pub(super) const REPOSITORY: &str = "https://github.com/sam0x17/gent.git";
const SSH_REPOSITORY: &str = "ssh://git@github.com/sam0x17/gent.git";

pub(super) struct Release {
    pub commit: String,
    pub repository: String,
}

pub(super) fn repository() -> String {
    #[cfg(feature = "test-updates")]
    if let Ok(path) = std::env::var("GENT_TEST_UPDATE_REPOSITORY") {
        assert!(
            path.starts_with("file:///"),
            "update proofs require a local repository"
        );
        return path;
    }
    REPOSITORY.into()
}

pub(super) fn parse(bytes: &[u8]) -> Result<String> {
    let mut direct = None;
    let mut peeled = None;
    for line in std::str::from_utf8(bytes)?.lines() {
        let (sha, reference) = line
            .split_once('\t')
            .context("invalid stable tag response")?;
        ensure!(
            crate::build_info::valid_commit(sha),
            "invalid stable tag revision"
        );
        let target = match reference {
            "refs/tags/stable" => &mut direct,
            "refs/tags/stable^{}" => &mut peeled,
            _ => anyhow::bail!("unexpected stable tag reference"),
        };
        ensure!(
            target.replace(sha.to_owned()).is_none(),
            "duplicate stable tag reference"
        );
    }
    ensure!(direct.is_some(), "the repository has no stable tag");
    Ok(peeled.or(direct).unwrap())
}

async fn resolve_from(repository: &str) -> Result<Release> {
    let mut command = Command::new("git");
    command.args([
        "ls-remote",
        "--exit-code",
        "--tags",
        repository,
        "refs/tags/stable",
        "refs/tags/stable^{}",
    ]);
    let commit =
        parse(&super::process::capture(&mut command, 512, Duration::from_secs(30)).await?)?;
    Ok(Release {
        commit,
        repository: repository.into(),
    })
}

pub(super) async fn resolve() -> Result<Release> {
    let primary = repository();
    match resolve_from(&primary).await {
        Ok(release) => Ok(release),
        // Disposable proofs must never fall back to a network repository.
        Err(error) if primary.starts_with("file://") => Err(error),
        Err(_) => resolve_from(SSH_REPOSITORY).await.context(
            "cannot read GitHub's stable tag over HTTPS or SSH; check repository access from the daemon's environment"
        ),
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
    let commit = &release.commit;
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
