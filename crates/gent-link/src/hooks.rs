//! Interactive PATH/completion setup. Shell startup never contacts the daemon.
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ops::Range,
    path::{Path, PathBuf},
};

const BEGIN: &str = "# >>> gent shell v1:";
const END: &str = "# <<< gent shell <<<\n";
const EDITED: &str = "Gent shell block is incomplete or edited; preserve your edits and restore the original block before retrying";

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}
impl Shell {
    pub fn generator(self) -> clap_complete::Shell {
        match self {
            Self::Bash => clap_complete::Shell::Bash,
            Self::Zsh => clap_complete::Shell::Zsh,
            Self::Fish => clap_complete::Shell::Fish,
        }
    }
    pub(crate) fn detected(value: Option<&std::ffi::OsStr>) -> Result<Self> {
        match value
            .and_then(|v| Path::new(v).file_name())
            .and_then(|v| v.to_str())
        {
            Some("bash") => Ok(Self::Bash),
            Some("zsh") => Ok(Self::Zsh),
            Some("fish") => Ok(Self::Fish),
            _ => anyhow::bail!("cannot detect a supported shell; pass --shell bash, zsh, or fish"),
        }
    }
}

#[derive(clap::Args, Default)]
pub struct Options {
    /// Shell to configure (default: the shell named by SHELL).
    #[arg(long)]
    pub(crate) shell: Option<Shell>,
    /// Startup file (default: the selected shell's standard user configuration).
    #[arg(long)]
    pub(crate) rc_file: Option<PathBuf>,
}
impl Options {
    fn resolve(self) -> Result<(Shell, PathBuf)> {
        let shell = self
            .shell
            .map(Ok)
            .unwrap_or_else(|| Shell::detected(std::env::var_os("SHELL").as_deref()))?;
        let path = match self.rc_file {
            Some(path) => path,
            None => default_path(
                shell,
                std::env::var_os("HOME").as_deref().map(Path::new),
                std::env::var_os("ZDOTDIR").as_deref().map(Path::new),
                std::env::var_os("XDG_CONFIG_HOME")
                    .as_deref()
                    .map(Path::new),
            )?,
        };
        Ok((shell, managed_file::normalize(&path)?))
    }
}
fn default_path(
    shell: Shell,
    home: Option<&Path>,
    zdotdir: Option<&Path>,
    config_home: Option<&Path>,
) -> Result<PathBuf> {
    if shell == Shell::Fish {
        let root = config_home
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|p| p.join(".config")))
            .context("cannot locate Fish configuration; pass --rc-file")?;
        return Ok(root.join("fish/config.fish"));
    }
    let root = if shell == Shell::Zsh {
        zdotdir.filter(|p| !p.as_os_str().is_empty()).or(home)
    } else {
        home
    };
    Ok(root
        .context("cannot locate shell configuration; pass --rc-file")?
        .join(if shell == Shell::Bash {
            ".bashrc"
        } else {
            ".zshrc"
        }))
}

#[derive(Subcommand)]
pub enum Command {
    /// Inspect the managed block without changing shell configuration.
    Status(Options),
    /// Add PATH and completion setup to the selected interactive startup file.
    Install(Options),
    /// Remove only the unmodified Gent block. Existing shells keep loaded setup.
    #[command(alias = "remove")]
    Uninstall(Options),
}
impl Default for Command {
    fn default() -> Self {
        Self::Status(Options::default())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    version: u8,
    shell: Shell,
    binary: PathBuf,
}
impl Spec {
    fn render(&self) -> Result<String> {
        ensure!(
            self.version == 1 && self.binary.is_absolute(),
            "unsupported Gent shell block"
        );
        let executable = self
            .binary
            .to_str()
            .context("Gent executable path must be UTF-8")?;
        ensure!(
            !executable.chars().any(char::is_control),
            "Gent executable path cannot contain control characters"
        );
        let parent = self
            .binary
            .parent()
            .and_then(Path::to_str)
            .context("missing executable directory")?;
        ensure!(
            !parent.contains(':'),
            "Gent executable directory cannot contain ':' when installing PATH setup"
        );
        let binary = quote(executable);
        let directory = quote(parent);
        let path = format!(
            r#"    case ":${{PATH-}}:" in
        *:{directory}:*) ;;
        *) export PATH={directory}"${{PATH:+:$PATH}}" ;;
    esac
"#
        );
        let body = match self.shell {
            Shell::Bash => format!(
                r#"if [ -n "${{BASH_VERSION-}}" ] && [[ $- == *i* ]] && [ -x {binary} ]; then
{path}    eval "$({binary} completions bash)"
fi
"#
            ),
            Shell::Zsh => format!(
                r#"if [[ -n "${{ZSH_VERSION-}}" && -o interactive && -x {binary} ]]; then
{path}    if (( ! $+functions[compdef] )); then
        autoload -Uz compinit
        compinit -i
    fi
    source <({binary} completions zsh)
fi
"#
            ),
            Shell::Fish => {
                let binary = fish_quote(executable);
                let directory = fish_quote(parent);
                format!(
                    r#"if status is-interactive; and test -x {binary}
    if not contains -- {directory} $PATH
        set -gx PATH {directory} $PATH
    end
    {binary} completions fish | source
end
"#
                )
            }
        };
        let metadata = STANDARD.encode(serde_json::to_vec(self)?);
        Ok(format!("\n{BEGIN}{metadata}\n{body}{END}"))
    }
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}
fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

struct Block {
    spec: Spec,
    range: Range<usize>,
}
fn read(text: &str, shell: Shell) -> Result<Option<Block>> {
    let starts: Vec<_> = text.match_indices("# >>> gent shell").collect();
    let ends: Vec<_> = text.match_indices("# <<< gent shell").collect();
    if starts.is_empty() && ends.is_empty() {
        return Ok(None);
    }
    ensure!(starts.len() == 1 && ends.len() == 1, EDITED);
    let start = starts[0].0;
    ensure!(start > 0 && text.as_bytes()[start - 1] == b'\n', EDITED);
    let header = text[start..].lines().next().context(EDITED)?;
    let encoded = header.strip_prefix(BEGIN).context(EDITED)?;
    ensure!(encoded.len() <= 8192, EDITED);
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!(EDITED))?;
    let spec: Spec = serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!(EDITED))?;
    ensure!(
        spec.shell == shell,
        "Gent block targets another shell; pass the shell used for installation"
    );
    let expected = spec.render()?;
    let end = (start - 1).checked_add(expected.len()).context(EDITED)?;
    ensure!(text.get(start - 1..end) == Some(expected.as_str()), EDITED);
    Ok(Some(Block {
        spec,
        range: start - 1..end,
    }))
}

fn modify(path: &Path, shell: Shell, binary: Option<PathBuf>) -> Result<bool> {
    // An absent uninstall is read-only. Existing targets are read under the
    // shared lock so another Gent installer cannot race the initial snapshot.
    if binary.is_none()
        && std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return Ok(false);
    }
    let desired = binary.map(|binary| Spec {
        version: 1,
        shell,
        binary,
    });
    let replacement = desired
        .as_ref()
        .map(Spec::render)
        .transpose()?
        .unwrap_or_default();
    let parent = path
        .parent()
        .context("missing shell configuration directory")?;
    managed_file::directory(parent)?;
    let hash = format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes()));
    let _guard = managed_file::lock(&parent.join(format!(".gent-shell-{}.lock", &hash[..32])))?;
    let snapshot = Snapshot::read(path)?;
    let original = snapshot.text.as_deref().unwrap_or("");
    let block = read(original, shell)?;
    let text = match block {
        Some(block) => format!(
            "{}{}{}",
            &original[..block.range.start],
            replacement,
            &original[block.range.end..]
        ),
        None if desired.is_some() => format!("{original}{replacement}"),
        None => return Ok(false),
    };
    if text == original {
        return Ok(false);
    }
    snapshot.write(&text)?;
    Ok(true)
}
fn inspect(path: &Path, shell: Shell) -> Result<Value> {
    let snapshot = Snapshot::read(path)?;
    let block = read(snapshot.text.as_deref().unwrap_or(""), shell)?;
    let mut result = json!({"shell":shell,"rc_file":path,"state":if block.is_some() {"installed"} else {"absent"},"current_shell_verified":false});
    if let Some(block) = block {
        result["binary"] = json!(block.spec.binary);
        result["binary_available"] = json!(block.spec.binary.is_file());
    }
    if shell == Shell::Bash {
        result["login_shells"] = "Bash login shells must source this file; use --rc-file to select a login startup file if needed.".into();
    }
    Ok(result)
}
pub fn execute(command: Command) -> Result<Value> {
    let (options, change) = match command {
        Command::Status(options) => (options, None),
        Command::Install(options) => (options, Some(true)),
        Command::Uninstall(options) => (options, Some(false)),
    };
    let (shell, path) = options.resolve()?;
    let changed = if let Some(install) = change {
        let binary = install
            .then(|| std::fs::canonicalize(std::env::current_exe()?))
            .transpose()?;
        modify(&path, shell, binary)?
    } else {
        false
    };
    let mut result = inspect(&path, shell)?;
    if let Some(install) = change {
        result["changed"] = json!(changed);
        result["action"] = if install { "installed" } else { "uninstalled" }.into();
        result["next"] = "Open a new shell to use the updated startup configuration.".into();
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
