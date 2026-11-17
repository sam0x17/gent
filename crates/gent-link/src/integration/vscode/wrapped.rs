//! Per-window native transport behind another extension's model adapter.
//! The adapter owns provider configuration, credentials and the real CLI path.
use super::{Args, LIMIT, install, transport};
use anyhow::{Context, Result, ensure};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{io::BufReader, process::Command};

fn command(
    invocation: &[OsString],
    home: &Path,
    binary: &Path,
    socket: &Path,
) -> Result<(PathBuf, Vec<OsString>)> {
    ensure!(
        !invocation.is_empty() && invocation.len() <= 128,
        "invalid wrapped Codex invocation"
    );
    let executable = PathBuf::from(&invocation[0]);
    ensure!(
        executable.is_absolute()
            && executable.is_file()
            && std::fs::canonicalize(&executable)? != binary,
        "Codex wrapper needs the real native executable"
    );
    let mut index = 1;
    while index < invocation.len() {
        match invocation[index].to_str() {
            Some("-c" | "--config" | "--enable" | "--disable") => {
                let value = invocation
                    .get(index + 1)
                    .context("missing Codex option value")?;
                ensure!(value.len() <= 32768, "Codex option exceeds size limit");
                index += 2;
            }
            Some("app-server") => break,
            _ => anyhow::bail!("unsupported Codex wrapper invocation"),
        }
    }
    ensure!(
        index < invocation.len(),
        "Codex wrapper accepts only app-server launches"
    );
    ensure!(
        invocation[index + 1..]
            .iter()
            .all(|s| s == "--analytics-default-enabled"),
        "unsupported Codex app-server transport options"
    );
    let mut arguments = invocation[1..index].to_vec();
    let mcp = [
        "--home",
        home.to_str().context("invalid Gent home")?,
        "mcp",
        "serve",
        "--host",
        "codex",
        "--wake-socket",
        socket.to_str().context("invalid socket")?,
    ];
    let values = toml::Value::Array(
        mcp.into_iter()
            .map(|s| toml::Value::String(s.into()))
            .collect(),
    );
    arguments.extend([
        OsString::from("-c"),
        OsString::from(format!(
            "mcp_servers.gent.command={}",
            toml::Value::String(binary.to_str().context("invalid Gent executable")?.into())
        )),
        OsString::from("-c"),
        OsString::from(format!("mcp_servers.gent.args={values}")),
    ]);
    arguments.extend_from_slice(&invocation[index..]);
    arguments.extend([
        OsString::from("--listen"),
        OsString::from(format!("unix://{}", socket.display())),
    ]);
    Ok((executable, arguments))
}

pub(crate) async fn execute(home: &Path, args: Args) -> Result<()> {
    install::codex_wrapper_target(home, &args.config_dir, &args.installation_id)?;
    // A short private path fits macOS's Unix socket limit, independent of the
    // user's long Library/Application Support or CODEX_HOME paths.
    let directory = tempfile::Builder::new()
        .prefix("gent-codex-")
        .tempdir_in("/tmp")?;
    let socket = directory.path().join("host.sock");
    let binary = std::fs::canonicalize(std::env::current_exe()?)?;
    let (executable, arguments) = command(&args.invocation, home, &binary, &socket)?;
    // Register before spawning so an editor closing during startup cannot
    // terminate this wrapper before it can clean up its native child.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut child = Command::new(executable)
        .args(arguments)
        .env("CODEX_HOME", &args.config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start wrapped Codex")?;
    let session = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let host = loop {
            ensure!(
                child.try_wait()?.is_none(),
                "wrapped Codex exited before its socket was ready"
            );
            let connection = tokio::time::timeout_at(
                deadline,
                crate::wake::codex::connect_socket(&socket, LIMIT),
            )
            .await
            .context("wrapped Codex startup timed out")?;
            match connection {
                Ok(host) => break host,
                Err(error)
                    if error.chain().any(|e| {
                        e.downcast_ref::<std::io::Error>().is_some_and(|e| {
                            matches!(
                                e.kind(),
                                std::io::ErrorKind::NotFound
                                    | std::io::ErrorKind::ConnectionRefused
                            )
                        })
                    }) =>
                {
                    tokio::time::timeout_at(
                        deadline,
                        tokio::time::sleep(Duration::from_millis(50)),
                    )
                    .await
                    .context("wrapped Codex startup timed out")?;
                }
                Err(error) => return Err(error),
            }
        };
        install::codex_wrapper_target(home, &args.config_dir, &args.installation_id)?;
        tokio::select! {
            result = transport(BufReader::new(tokio::io::stdin()), tokio::io::stdout(), host) => result,
            result = child.wait() => { result?; Ok(()) },
        }
    };
    let result = tokio::select! {
        result = session => result,
        _ = terminate.recv() => Ok(()),
        _ = hangup.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
    };
    // This host belongs to this IDE window. Closing it never restarts or kills
    // the user's separate Codex background daemon.
    if child.try_wait()?.is_none() {
        if let Some(pid) = child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32))
        {
            // Give the native host a chance to close its MCP children first.
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
        }
        if tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .is_err()
        {
            child.start_kill()?;
        }
    }
    child.wait().await?;
    drop(directory);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrapper_preserves_provider_options_and_pins_only_gent_and_transport() {
        let original: Vec<OsString> = [
            "/bin/sh",
            "-c",
            "model_providers.fixture.env_key=\"PRIVATE_FIXTURE_KEY\"",
            "--enable",
            "code_mode_host",
            "app-server",
            "--analytics-default-enabled",
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        let (binary, args) = command(
            &original,
            Path::new("/tmp/gent '$ literal"),
            Path::new("/tmp/real-gent"),
            Path::new("/tmp/host.sock"),
        )
        .unwrap();
        assert_eq!(binary, Path::new("/bin/sh"));
        assert_eq!(&args[..4], &original[1..5]);
        assert_eq!(
            &args[args.len() - 2..],
            [
                OsString::from("--listen"),
                OsString::from("unix:///tmp/host.sock")
            ]
        );
        for invalid in [
            vec!["/bin/sh", "app-server", "--listen", "stdio://"],
            vec!["/bin/sh", "--version"],
            vec!["/bin/sh", "-c"],
        ] {
            assert!(
                command(
                    &invalid.into_iter().map(Into::into).collect::<Vec<_>>(),
                    Path::new("/tmp/gent"),
                    Path::new("/tmp/real-gent"),
                    Path::new("/tmp/host.sock")
                )
                .is_err()
            );
        }
    }
}
