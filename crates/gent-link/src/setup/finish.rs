//! Optional setup steps run after enrollment and service readiness. Each uses
//! the same installer as its standalone command, so partial setup is retryable.
use super::*;
use crate::{integration, ui};
use integration::Host;

pub(crate) fn discovery(
    home: &Path,
    result: &mut Value,
    preference: Option<bool>,
    interactive: bool,
) -> Result<()> {
    let preference = if preference.is_none() && interactive {
        eprintln!(
            "Gent can publish supported native chat names to your cluster and wake them for incoming messages. Host approvals still apply."
        );
        Some(ask(
            "Make all supported chats on this system discoverable by Gent?",
            true,
        )?)
    } else {
        preference
    };
    if let Some(enabled) = preference {
        integration::discovery::configure(home, enabled)
            .context("set chat discovery with gent node discovery enable or disable")?;
    }
    result["chat_discovery_enabled"] = json!(config::load(home)?.discovery()?.enabled);
    Ok(())
}

fn record(result: &mut Value, name: &str, action: Result<Value>, retry: &str, interactive: bool) {
    let entry = match action {
        Ok(value) => {
            if interactive {
                eprintln!("  {name}: configured.");
            }
            json!({"step":name,"state":"configured","result":value})
        }
        Err(error) => {
            result["setup_complete"] = json!(false);
            let error = format!("{error:#}");
            if interactive {
                eprintln!(
                    "  {name}: {}\n  Retry: {retry}",
                    crate::display::visible(&error)
                );
            }
            json!({"step":name,"state":"failed","error":error,"retry":retry})
        }
    };
    result["setup_steps"].as_array_mut().unwrap().push(entry);
}

async fn integrations(home: &Path, result: &mut Value) -> Result<()> {
    eprintln!(
        "\nChoose the integrations you use. New installations include automatic incoming-message delivery; existing delivery settings are preserved."
    );
    for (host, vscode, label, default) in [
        (Host::Codex, false, "Codex CLI", true),
        (Host::Codex, true, "Codex in VS Code", true),
        (
            Host::ClaudeCode,
            false,
            "Claude Code (CLI and VS Code)",
            true,
        ),
    ] {
        if !ask(&format!("Set up Gent for {label}?"), default)? {
            result["setup_steps"]
                .as_array_mut()
                .unwrap()
                .push(json!({"step":label,"state":"skipped"}));
            continue;
        }
        let retry = format!(
            "gent integration install {}{}",
            host.name(),
            if vscode { " --vscode" } else { "" }
        );
        let installed = {
            let _progress = ui::Progress::start(&format!("Configuring {label}"));
            integration::setup_install(home, host, vscode)
        };
        let start_codex = installed.as_ref().is_ok_and(|status| {
            host == Host::Codex
                && status["delivery"]["mode"] == "wake"
                && status["vscode"]["transport"] != "provider_switcher"
        });
        let next = installed
            .as_ref()
            .ok()
            .and_then(|v| v["next"].as_str())
            .map(str::to_owned);
        record(result, label, installed, &retry, true);
        if start_codex {
            let started = {
                let _progress = ui::Progress::start("Starting Codex background server");
                integration::setup_start_codex(home).await
            };
            record(
                result,
                "Codex background server",
                started,
                "gent integration start codex",
                true,
            );
        }
        if let Some(next) = next {
            eprintln!("  {}", crate::display::visible(&next));
        }
    }
    Ok(())
}

pub(crate) async fn after_join(
    home: &Path,
    result: &mut Value,
    interactive: bool,
    discover_chats: Option<bool>,
) -> Result<()> {
    let status = {
        let _progress = ui::Progress::start("Installing and starting Gent daemon");
        service::execute(
            home,
            DaemonCommand::Install {
                local: None,
                setup: Options::default(),
            },
        )
        .await
        .context("node enrolled; run gent setup to install and start its daemon")?
    };
    result["daemon"] = status["daemon"].clone();
    result["service"] = status["service"].clone();
    run(
        home,
        result,
        interactive,
        Options {
            discover_chats,
            ..Options::default()
        },
    )
    .await
    .context("node is enrolled and its daemon is installed; rerun gent setup to finish")
}

pub(super) async fn run(
    home: &Path,
    result: &mut Value,
    interactive: bool,
    mut options: Options,
) -> Result<()> {
    result["setup_complete"] = json!(true);
    result["setup_steps"] = json!([]);
    if interactive {
        eprintln!("\nGent daemon is running.");
        if !options.linger
            && result["service"]["backend"] == "systemd"
            && result["service"]["startup"]["trigger"] != "boot"
        {
            eprintln!(
                "Linux can keep this user's services running after logout and start them at boot."
            );
            if ask("Enable startup before login?", true)? {
                let enabled = service::enable_linger()
                    .await
                    .map(|_| json!({"enabled":true}));
                record(
                    result,
                    "Startup at boot",
                    enabled,
                    "gent daemon install --linger",
                    true,
                );
                result["service"] =
                    service::execute(home, DaemonCommand::Status).await?["service"].clone();
            }
        }
        integrations(home, result).await?;
        if !options.hooks {
            if let Ok(shell) = hooks::Shell::detected(std::env::var_os("SHELL").as_deref()) {
                if ask("Install shell PATH and completions?", true)? {
                    options.hooks = true;
                    options.shell = Some(shell);
                }
            } else {
                eprintln!(
                    "Shell not recognized. Set up completions later with gent hooks install --shell zsh, bash or fish."
                );
            }
        }
    }
    if options.hooks {
        let mut retry = "gent hooks install".to_owned();
        if let Some(shell) = options.shell {
            retry.push_str(&format!(
                " --shell {}",
                serde_json::to_value(shell)?.as_str().unwrap()
            ));
        }
        if let Some(path) = &options.rc_file {
            let path = path.to_str().context("shell startup path must be UTF-8")?;
            retry.push_str(&format!(" --rc-file '{}'", path.replace('\'', "'\"'\"'")));
        }
        let installed = hooks::execute(hooks::Command::Install(hooks::Options {
            shell: options.shell,
            rc_file: options.rc_file,
        }));
        if let Ok(value) = &installed {
            result["hooks"] = value.clone();
        }
        record(result, "Shell hooks", installed, &retry, interactive);
    }
    let configured = discovery(home, result, options.discover_chats, interactive)
        .map(|_| json!({"configured":true}));
    record(
        result,
        "Chat discovery",
        configured,
        "gent node discovery enable or disable",
        interactive,
    );
    result["next"] = json!(if result["setup_complete"] == false {
        "Gent is running. Some optional setup steps need attention; use their retry commands or rerun gent setup."
    } else if interactive {
        "Setup complete. Reload hosts for any integrations you installed, then ask a chat to connect to Gent. Use gent ls to see connected chats, or rerun gent setup to add integrations."
    } else {
        "Run gent setup in a terminal to choose integrations, or use gent integration install codex and gent integration install claude-code."
    });
    if interactive {
        eprintln!("\n{}", result["next"].as_str().unwrap());
    }
    Ok(())
}
