//! Edit a private draft, then compare and save under the daemon's config lock.
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result, ensure};
use gent_daemon::{config, recovery};
use std::{
    fs,
    io::IsTerminal,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
};

#[derive(clap::Args)]
pub(crate) struct Options {
    /// Editor command and literal arguments; defaults to VISUAL, EDITOR, then vi. GUI editors need their wait option.
    #[arg(long)]
    editor: Option<String>,
}

fn arguments(command: &str) -> Result<Vec<String>> {
    ensure!(
        command.len() <= 16 * 1024 && !command.chars().any(char::is_control),
        "editor command exceeds limits or contains control characters"
    );
    let args = shlex::split(command).context("editor command has unmatched quotes")?;
    ensure!(
        !args.is_empty() && !args[0].is_empty() && args.len() <= 64,
        "editor command must name a program with at most 63 arguments"
    );
    Ok(args)
}

pub(crate) fn parse(text: &str) -> Result<config::Config> {
    // TOML and policy errors can contain private values. Report only the type
    // of failure, leaving the original text in its private draft.
    let value: config::Config = toml::from_str(text)
        .map_err(|_| anyhow::anyhow!("configuration has invalid TOML or field types"))?;
    value.validate().map_err(|_| {
        anyhow::anyhow!("configuration has invalid identity, routing, labels or policy")
    })?;
    Ok(value)
}

fn protected(before: &config::Config, after: &config::Config) -> Result<()> {
    ensure!(
        before.version == after.version
            && before.applied_revision == after.applied_revision
            && before.node.id == after.node.id
            && before.cluster.id == after.cluster.id
            && before.cluster.local_only == after.cluster.local_only
            && before.service == after.service,
        "identity, revision and service metadata must be changed through their Gent commands"
    );
    if before.service.is_some() {
        ensure!(
            serde_json::to_value(&before.relay)? == serde_json::to_value(&after.relay)?,
            "service relay routing must be changed through Gent setup commands"
        );
    }
    for field in [
        "contexts",
        "account_source",
        "profile_setup",
        "gateway_registry",
        "host_recovery",
        "hosted_parent",
        "portable_web",
        "local_features",
    ] {
        ensure!(
            before.extra.get(field) == after.extra.get(field),
            "managed local metadata must be changed through its Gent commands"
        );
    }
    Ok(())
}

pub(crate) fn open(home: &Path) -> Result<Snapshot> {
    recovery::ensure_active(home)?;
    let _lock = managed_file::lock(&home.join("config.lock"))?;
    let original = Snapshot::read(&config::path(home))?;
    original.private()?;
    let text = original
        .text
        .as_deref()
        .context("no Gent configuration to edit")?;
    parse(text)?;
    Ok(original)
}

pub(crate) fn save_text(
    home: &Path,
    original: &Snapshot,
    text: &str,
    verify_draft: impl FnOnce() -> Result<()>,
) -> Result<Option<Snapshot>> {
    ensure!(
        text.len() as u64 <= managed_file::LIMIT,
        "configuration is too large"
    );
    if original.text.as_deref() == Some(text) {
        return Ok(None);
    }
    let before = parse(original.text.as_deref().unwrap())?;
    let after = parse(text)?;
    protected(&before, &after)?;
    let _lock = managed_file::lock(&home.join("config.lock"))?;
    recovery::ensure_active(home)?;
    original.verify().map_err(|_| {
        anyhow::anyhow!(
            "configuration changed while the editor was open; the current file was preserved"
        )
    })?;
    verify_draft()?;
    // Snapshot writes retain comments and formatting, publish atomically,
    // and compare once more immediately before rename. The lock is shared
    // with daemon projections and local settings commands, never the editor.
    original.write(text)?;
    let saved = Snapshot::read(&original.path)?;
    ensure!(
        saved.text.as_deref() == Some(text),
        "configuration changed immediately after saving"
    );
    Ok(Some(saved))
}

struct Draft {
    home: PathBuf,
    original: Snapshot,
    directory: tempfile::TempDir,
    path: PathBuf,
}

impl Draft {
    fn prepare(home: &Path) -> Result<Self> {
        let home = managed_file::normalize(home)?;
        ensure!(
            home.to_str()
                .is_some_and(|s| !s.chars().any(char::is_control)),
            "configuration directory must be UTF-8 without control characters"
        );
        recovery::ensure_active(&home)?;
        ensure!(
            home.is_dir(),
            "initialize this node before editing its configuration"
        );
        config::private_dir(&home)?;
        let original = open(&home)?;
        let text = original.text.as_deref().unwrap();
        let directory = tempfile::Builder::new()
            .prefix(".config-edit-")
            .tempdir_in(&home)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let path = directory.path().join("config.toml");
        config::write_private(&path, text.as_bytes())?;
        Ok(Self {
            home,
            original,
            directory,
            path,
        })
    }

    fn save(&self) -> Result<bool> {
        config::private_dir(self.directory.path())?;
        let draft = Snapshot::read(&self.path)?;
        draft.private()?;
        let text = draft.text.as_deref().context("editor removed the draft")?;
        save_text(&self.home, &self.original, text, || draft.verify()).map(|saved| saved.is_some())
    }

    fn preserve(self, error: anyhow::Error) -> anyhow::Error {
        let path = self.directory.keep().join("config.toml");
        error.context(format!("draft retained at {}", path.display()))
    }
}

pub(crate) async fn execute(
    root: &Path,
    selected: Option<&str>,
    options: Options,
    json: bool,
) -> Result<()> {
    ensure!(
        !json && std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        "config edit requires an interactive terminal without --json; use gent config path and gent config validate for scripted edits"
    );
    // Resolve once before opening the editor. Configuration errors can include TOML
    // values; keep them private just like draft validation errors.
    let home = crate::node_home::resolve(root, selected).map_err(|_| {
        anyhow::anyhow!(
            "cannot open this node; config edit requires valid existing configuration without legacy profiles"
        )
    })?;
    let command = options
        .editor
        .or_else(|| {
            ["VISUAL", "EDITOR"].into_iter().find_map(|name| {
                std::env::var(name)
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            })
        })
        .unwrap_or_else(|| "vi".into());
    let args = arguments(&command)?;
    let draft = Draft::prepare(&home)?;
    println!("Editing a private draft at {}", draft.path.display());
    let outcome = async {
        let status = tokio::process::Command::new(&args[0])
            .args(&args[1..])
            .arg(&draft.path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .status()
            .await
            .context("could not run the configured editor")?;
        ensure!(
            status.success(),
            "editor exited unsuccessfully; configuration was not saved"
        );
        draft.save()
    }
    .await;
    match outcome {
        Ok(true) => println!(
            "Saved {}. Run gent config apply to publish shared settings.",
            draft.original.path.display()
        ),
        Ok(false) => println!("No configuration changes from the editor."),
        Err(error) => return Err(draft.preserve(error)),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
