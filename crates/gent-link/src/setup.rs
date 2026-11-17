//! Compose existing recoverable commands into the daemon installer. Enrollment
//! and login keep their own journals, locks and trust checks.
use crate::{DaemonCommand, auth, cluster, hooks, invitations, managed_file, service};
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use gent_daemon::config;
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};

#[derive(Args, Default)]
pub struct Options {
    /// Create a service cluster, or resume creation under this original name.
    #[arg(long = "new", conflicts_with_all = ["local", "invite_file"])]
    new_cluster: Option<String>,
    /// Join using a privately transferred invitation file.
    #[arg(long, conflicts_with = "local")]
    invite_file: Option<PathBuf>,
    /// Name of the joining node (reuse its original name when retrying).
    #[arg(long, requires = "invite_file")]
    name: Option<String>,
    /// Explicitly replace an interrupted join's invitation, preserving its key.
    #[arg(long = "continue", requires = "invite_file")]
    replace: bool,
    /// Alternate account service; never inferred from an invitation file.
    #[arg(long, conflicts_with = "local")]
    service: Option<String>,
    /// Allow GitHub device login when setup needs authentication.
    #[arg(long, conflicts_with_all = ["local", "no_browser", "no_input"])]
    headless: bool,
    /// Allow browser login, printing the URL instead of opening the browser.
    #[arg(long, conflicts_with_all = ["local", "no_input"])]
    no_browser: bool,
    /// Never prompt or start login. Use an existing login and explicit setup flags.
    #[arg(long)]
    no_input: bool,
    /// Linux: keep user services running after logout and start them at boot.
    /// Enables systemd linger for this OS user; may require administrator setup.
    #[arg(long)]
    linger: bool,
    /// Install shell PATH and completion setup after the daemon starts.
    #[arg(long)]
    hooks: bool,
    /// Shell for --hooks (otherwise detected from SHELL).
    #[arg(long, requires = "hooks")]
    shell: Option<hooks::Shell>,
    /// Startup file for --hooks, preserving unrelated content.
    #[arg(long, requires = "hooks")]
    rc_file: Option<PathBuf>,
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    Existing,
    Local(String),
    Connect(Option<String>),
    CodeJoin {
        code: String,
    },
    Join {
        file: PathBuf,
        name: String,
        replace: bool,
    },
}

fn answer(reader: &mut impl BufRead, writer: &mut impl Write, prompt: &str) -> Result<String> {
    write!(writer, "{prompt}")?;
    writer.flush()?;
    let mut line = String::new();
    let count = reader.take(4097).read_line(&mut line)?;
    ensure!(
        count > 0,
        "setup cancelled: input closed; rerun gent daemon install"
    );
    ensure!(
        count <= 4096 && line.ends_with('\n'),
        "setup input is too long or incomplete"
    );
    let line = line.strip_suffix('\n').expect("newline checked");
    let line = line.strip_suffix('\r').unwrap_or(line);
    ensure!(
        !line.chars().any(char::is_control),
        "setup input contains control characters"
    );
    Ok(line.trim().into())
}

fn prompt(interactive: bool, text: &str, missing: &str) -> Result<String> {
    ensure!(interactive, "{missing}");
    answer(&mut io::stdin().lock(), &mut io::stderr().lock(), text)
}

fn present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn plan(
    home: &Path,
    local: Option<String>,
    options: &mut Options,
    interactive: bool,
) -> Result<Plan> {
    // Snapshot rejects linked or malformed files even if Path::exists would
    // hide a broken symlink. Loading TOML retains the usual configuration checks.
    let configured = managed_file::Snapshot::read(&config::path(home))?
        .text
        .is_some();
    let cfg = configured.then(|| config::load(home)).transpose()?;
    let service = cluster::installation(home)?;
    let joining = invitations::installation(home)?;
    let staged = present(&config::pending_join(home)?)?;
    let pinned_service = service
        .as_ref()
        .map(|s| s.service.as_str())
        .or_else(|| {
            cfg.as_ref()
                .and_then(|c| c.service.as_ref())
                .map(|s| s.origin.as_str())
        })
        .or_else(|| {
            joining
                .as_ref()
                .map(|j| j.offer.offer.service.account_origin.as_str())
        });
    if let Some(pinned) = pinned_service {
        if let Some(requested) = &options.service {
            ensure!(
                auth::origin(requested)? == auth::origin(pinned)?,
                "this node is pinned to another service; rerun without --service"
            );
        }
        options.service = Some(pinned.into());
    }
    if let Some(name) = local {
        config::label(&name)?;
        ensure!(
            service.is_none() && cfg.as_ref().is_none_or(|c| c.service.is_none()),
            "this node uses service enrollment; rerun gent daemon install without --local"
        );
        ensure!(
            !staged && joining.is_none(),
            "a node join is pending; rerun the original join command"
        );
        ensure!(
            cfg.as_ref()
                .is_none_or(|c| c.cluster.local_only && c.cluster.name == name),
            "this node already belongs to a cluster; run gent node reset before enrolling in another cluster"
        );
        return Ok(Plan::Local(name));
    }
    if let Some(name) = &options.new_cluster {
        config::label(name)?;
        ensure!(
            !staged && joining.is_none(),
            "this node has invitation or join state; resume its original join"
        );
        if let Some(saved) = &service {
            ensure!(
                saved.owner && saved.name == *name,
                "cluster creation options changed; rerun with the original name or without --new"
            );
            return Ok(if saved.pending {
                Plan::Connect(None)
            } else {
                Plan::Existing
            });
        }
        ensure!(
            !configured,
            "already configured; existing identity was preserved; omit --new"
        );
    }
    if options.invite_file.is_none()
        && options.new_cluster.is_none()
        && !configured
        && let Some((file, name)) = crate::enrollment::pending(home)?
    {
        return Ok(Plan::Join {
            file,
            name,
            replace: false,
        });
    }
    if options.invite_file.is_none() && staged {
        ensure!(
            joining.is_some(),
            "an SSH join is pending; rerun the original gent cluster join command"
        );
        options.invite_file = Some(PathBuf::from(prompt(
            interactive,
            "Original private invitation file: ",
            "a join is pending; rerun gent daemon install --invite-file FILE --name NODE, or the original gent cluster join command",
        )?));
    }
    if options.invite_file.is_none()
        && !configured
        && service.is_none()
        && options.new_cluster.is_none()
    {
        if joining.is_some() {
            options.invite_file = Some(PathBuf::from(prompt(
                interactive,
                "Original private invitation file: ",
                "an invitation join is pending; pass --invite-file FILE and the original --name NODE",
            )?));
        } else {
            if home.exists() {
                ensure!(
                    std::fs::read_dir(home)?.all(|e| e.is_ok_and(|e| matches!(
                        e.file_name().to_str(),
                        Some("auth" | "service.lock" | "daemon.lock")
                    ))),
                    "state exists without config.toml; restore it before installing"
                );
            }
            let choice = prompt(
                interactive,
                "Set up Gent: [1] Create a cluster  [2] Join with a node invitation code  [3] Join with an invitation file  [q] Cancel: ",
                "no Gent configuration; use --new NAME or --invite-file FILE --name NODE after gent auth login, or --local NAME for development",
            )?;
            match choice.as_str() {
                "1" | "new" => options.new_cluster = Some(prompt(true, "Cluster name: ", "")?),
                "2" | "join" => {
                    return Ok(Plan::CodeJoin {
                        code: prompt(true, "Node invitation code: ", "")?,
                    });
                }
                "3" | "invitation" => {
                    options.invite_file = Some(PathBuf::from(prompt(
                        true,
                        "Private invitation file: ",
                        "",
                    )?))
                }
                "q" | "quit" => bail!("setup cancelled; no cluster was created"),
                _ => bail!("choose 1 to create a cluster or 2 to join; rerun gent daemon install"),
            }
        }
    }
    if let Some(file) = &options.invite_file {
        ensure!(
            (!configured && !staged) || joining.is_some(),
            "invitation join journal is missing; existing node state was preserved"
        );
        let invitation = invitations::decode_file(file)?;
        let name = options
            .name
            .clone()
            .or_else(|| joining.as_ref().map(|j| j.name.clone()))
            .map(Ok)
            .unwrap_or_else(|| prompt(interactive, "Node name: ", "joining needs --name NODE"))?;
        config::label(&name)?;
        if let (Some(cfg), Some(saved)) = (&cfg, &joining)
            && saved.complete
            && !staged
        {
            ensure!(
                saved.offer == *invitation.offer()
                    && saved.name == name
                    && saved.offer.offer.anchor.cluster_id == cfg.cluster.id
                    && saved
                        .node
                        .as_ref()
                        .is_some_and(|node| node.id == cfg.node.id),
                "installed node does not match this invitation; existing state was preserved"
            );
            return Ok(if service.as_ref().is_some_and(|s| s.pending) {
                Plan::Connect(None)
            } else {
                Plan::Existing
            });
        }
        return Ok(Plan::Join {
            file: file.clone(),
            name,
            replace: options.replace,
        });
    }
    if let Some(name) = &options.new_cluster {
        config::label(name)?;
        return Ok(Plan::Connect(Some(name.clone())));
    }
    if service.as_ref().is_some_and(|s| s.pending) {
        ensure!(
            service.as_ref().is_some_and(|s| s.owner) || configured,
            "joined configuration is missing; resume its original join or restore it"
        );
        return Ok(Plan::Connect(None));
    }
    ensure!(
        configured,
        "no configuration; use --new NAME or --invite-file FILE --name NODE"
    );
    Ok(Plan::Existing)
}

pub async fn install(
    home: &Path,
    local: Option<String>,
    mut options: Options,
    human: bool,
) -> Result<Value> {
    let home = managed_file::normalize(home)?;
    service::validate_linger(options.linger)?;
    let interactive =
        human && !options.no_input && io::stdin().is_terminal() && io::stderr().is_terminal();
    if let Some(origin) = &options.service {
        auth::origin(origin)?;
    }
    service::preflight(&home).await?;
    let plan = plan(&home, local, &mut options, interactive)?;
    if interactive
        && !matches!(plan, Plan::Existing)
        && !options.hooks
        && let Ok(shell) = hooks::Shell::detected(std::env::var_os("SHELL").as_deref())
    {
        let choice = prompt(true, "Install shell PATH and completions? [y/N]: ", "")?;
        match choice.to_ascii_lowercase().as_str() {
            "y" | "yes" => {
                options.hooks = true;
                options.shell = Some(shell);
            }
            "" | "n" | "no" => {}
            _ => bail!("answer y or n; rerun gent daemon install"),
        }
    }
    if options.hooks && options.shell.is_none() {
        options.shell = Some(hooks::Shell::detected(
            std::env::var_os("SHELL").as_deref(),
        )?);
    }
    let needs_login = matches!(
        plan,
        Plan::Connect(_) | Plan::Join { .. } | Plan::CodeJoin { .. }
    );
    if needs_login {
        if interactive || options.headless || options.no_browser {
            if human {
                eprintln!("Checking GitHub sign-in for Gent setup...");
            }
            auth::execute(
                &home,
                auth::Command::Login {
                    headless: options.headless,
                    no_browser: options.no_browser,
                    service: options.service.clone(),
                },
            )
            .await?;
        } else {
            let login = auth::Service::open(&home).await.context(
                "setup needs an active login; run gent auth login, then rerun this command",
            )?;
            if let Some(origin) = &options.service {
                ensure!(
                    login.origin()? == auth::origin(origin)?,
                    "sign into the selected Gent service first"
                );
            }
        }
    }
    let mut enrollment = None;
    let local = match plan {
        Plan::Existing => None,
        Plan::CodeJoin { code } => {
            enrollment = Some(
                crate::enrollment::join(&home, {
                    let mut args = crate::pairing::JoinArgs::code(Some(code));
                    args.no_daemon = true;
                    args
                })
                .await?,
            );
            None
        }
        Plan::Local(name) => Some(name),
        Plan::Connect(name) => {
            enrollment = Some(cluster::connect(&home, name.as_deref()).await.context(
                "cluster setup is incomplete; rerun this command to preserve its identity",
            )?);
            None
        }
        Plan::Join {
            file,
            name,
            replace,
        } => {
            enrollment = Some(invitations::join(&home, &file, None, &name, replace).await
                .context("invitation setup is incomplete; rerun with the same file and node name; a replacement invitation requires --continue")?);
            None
        }
    };
    let mut result = service::execute(
        &home,
        DaemonCommand::Install {
            local,
            setup: Options::default(),
        },
    )
    .await?;
    if config::load(&home)?.service.is_some() {
        let status = crate::owner(&home, gent_protocol::OwnerOp::Status).await?;
        let nodes = crate::owner(&home, gent_protocol::OwnerOp::Nodes).await?;
        if status["authority"]["mode"] == "legacy" && nodes.as_array().is_some_and(|n| n.len() == 1)
        {
            crate::peer_configuration::upgrade(&home).await.context(
                "daemon is installed; finish configuration migration with gent cluster upgrade",
            )?;
        }
    }
    if options.linger {
        service::enable_linger()
            .await
            .context("daemon is installed, but startup without login could not be enabled")?;
        result = service::execute(&home, DaemonCommand::Status).await?;
    }
    if let Some(enrollment) = enrollment {
        result["enrollment"] = enrollment;
    }
    if options.hooks {
        result["hooks"] = hooks::execute(hooks::Command::Install(hooks::Options {
            shell: options.shell, rc_file: options.rc_file,
        })).context("daemon is installed; shell setup failed; retry gent hooks install with the same shell/path")?;
    }
    result["next"] = json!(
        "Connect your agents with gent integration install codex and gent integration install claude-code."
    );
    if human {
        eprintln!("{}", result["next"].as_str().unwrap());
    }
    Ok(result)
}

#[cfg(test)]
mod tests;
