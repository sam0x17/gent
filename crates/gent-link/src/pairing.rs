use anyhow::{Context, Result, ensure};
use clap::Args;
use gent_daemon::pairing::{self, Options, Peer};
use gent_protocol::{MAX_FRAME_BYTES, OwnerOp, PairingOp, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io::IsTerminal, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
};

#[derive(Args)]
#[command(
    after_help = "Example: gent cluster join CLUSTER_UUID --via sam@owner-host --name laptop\nSSH host keys must already be trusted. The owner daemon must be running."
)]
pub struct JoinArgs {
    cluster: String,
    /// SSH destination of an existing owner node (for example sam@studio).
    #[arg(long)]
    via: String,
    /// Friendly name of this new node.
    #[arg(long)]
    name: String,
    /// Gent executable on the owner machine, if absent from its SSH PATH.
    #[arg(long, default_value = "gent")]
    remote_gent: String,
    /// Gent state directory on the owner machine (default: its ~/.gent).
    #[arg(long)]
    remote_home: Option<String>,
    /// Override the imported development relay origin, for example with a local SSH tunnel.
    #[arg(long)]
    relay_endpoint: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    cluster: String,
    action: PairingOp,
}

fn shell_word(word: &str) -> Result<String> {
    ensure!(
        !word.is_empty() && !word.chars().any(char::is_control),
        "invalid remote path"
    );
    Ok(format!("'{}'", word.replace('\'', "'\"'\"'")))
}
fn remote_command(args: &JoinArgs) -> Result<Command> {
    ensure!(
        !args.via.is_empty()
            && !args.via.starts_with('-')
            && args
                .via
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"@._-:[]".contains(&c)),
        "invalid SSH destination; use a host alias or user@host"
    );
    let mut words = vec![shell_word(&args.remote_gent)?];
    if let Some(home) = &args.remote_home {
        words.extend(["--home".into(), shell_word(home)?]);
    }
    words.extend(["cluster".into(), "pairing-serve".into()]);
    let mut command = Command::new("ssh");
    command.args([
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
        "--",
        &args.via,
        &words.join(" "),
    ]);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    Ok(command)
}

struct Remote {
    command: Command,
    cluster: String,
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<BufReader<ChildStdout>>,
}
impl Peer for Remote {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        tokio::time::timeout(Duration::from_secs(30), async {
            if self.child.is_none() {
                let mut child = self.command.spawn().context("start SSH pairing channel")?;
                self.input = child.stdin.take();
                self.output = child.stdout.take().map(BufReader::new);
                self.child = Some(child);
            }
            let input = self.input.as_mut().context("missing pairing input")?;
            write_frame(
                input,
                &WireRequest {
                    cluster: self.cluster.clone(),
                    action,
                },
            )
            .await?;
            let wire = read_frame(self.output.as_mut().context("missing pairing output")?)
                .await?
                .context(
                    "SSH pairing channel closed; check the owner daemon and remote Gent path",
                )?;
            match serde_json::from_slice::<Response>(&wire)? {
                Response::Ok(value) => Ok(value),
                Response::Error(message) => anyhow::bail!("owner refused pairing: {message}"),
            }
        })
        .await
        .context("SSH pairing timed out; rerun the join command to resume")?
    }
}

pub async fn join(home: &Path, args: JoinArgs) -> Result<Value> {
    let mut peer = Remote {
        command: remote_command(&args)?,
        cluster: args.cluster.clone(),
        child: None,
        input: None,
        output: None,
    };
    let result = pairing::join(
        home,
        Options {
            cluster: &args.cluster,
            name: &args.name,
            relay_endpoint: args.relay_endpoint.as_deref(),
        },
        &mut peer,
    )
    .await?;
    drop(peer.input.take());
    // Installation already committed. A dropped SSH exit status must not report
    // a failed join; the daemon can operate without the pairing process afterward.
    if let Some(child) = &mut peer.child {
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    }
    Ok(result)
}

async fn read_frame(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Option<Vec<u8>>> {
    let mut frame = Vec::new();
    loop {
        let bytes = reader.fill_buf().await?;
        if bytes.is_empty() {
            ensure!(frame.is_empty(), "incomplete pairing frame");
            return Ok(None);
        }
        let end = bytes.iter().position(|b| *b == b'\n').map(|i| i + 1);
        let n = end.unwrap_or(bytes.len());
        ensure!(
            frame.len() + n <= MAX_FRAME_BYTES,
            "pairing frame too large"
        );
        frame.extend_from_slice(&bytes[..n]);
        reader.consume(n);
        if end.is_some() {
            return Ok(Some(frame));
        }
    }
}
async fn write_frame(writer: &mut (impl AsyncWrite + Unpin), value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= MAX_FRAME_BYTES, "pairing frame too large");
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn serve(home: &Path) -> Result<()> {
    ensure!(
        !std::io::stdin().is_terminal(),
        "pairing-serve is a private pipe protocol; use gent cluster join --via HOST"
    );
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    while let Some(wire) = read_frame(&mut input).await? {
        let request: WireRequest = serde_json::from_slice(&wire)?;
        let response = match super::owner(
            home,
            OwnerOp::Pair {
                cluster_id: request.cluster,
                action: request.action,
            },
        )
        .await
        {
            Ok(value) => Response::Ok(value),
            Err(error) => Response::Error(error.to_string()),
        };
        write_frame(&mut output, &response).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ssh_arguments_preserve_remote_paths_and_require_authentication() {
        let mut args = JoinArgs {
            cluster: "cluster".into(),
            via: "sam@studio".into(),
            name: "laptop".into(),
            remote_gent: "/tmp/gent's bin/$(touch injected)".into(),
            remote_home: Some("/tmp/private home".into()),
            relay_endpoint: None,
        };
        let command = remote_command(&args).unwrap();
        let argv: Vec<_> = command
            .as_std()
            .get_args()
            .map(|a| a.to_str().unwrap())
            .collect();
        assert!(argv.contains(&"StrictHostKeyChecking=yes"));
        assert!(argv.contains(&"ForwardAgent=no"));
        assert_eq!(
            argv.last().unwrap(),
            &"'/tmp/gent'\"'\"'s bin/$(touch injected)' --home '/tmp/private home' cluster pairing-serve"
        );
        for bad in ["-oProxyCommand=evil", "host;touch file", "host\nother"] {
            args.via = bad.into();
            assert!(remote_command(&args).is_err());
        }
    }
    #[tokio::test]
    async fn frames_preserve_boundaries_and_reject_oversized_or_incomplete_input() {
        let mut input = BufReader::new(b"one\ntwo\n".as_slice());
        assert_eq!(read_frame(&mut input).await.unwrap().unwrap(), b"one\n");
        assert_eq!(read_frame(&mut input).await.unwrap().unwrap(), b"two\n");
        assert!(read_frame(&mut input).await.unwrap().is_none());
        assert!(
            read_frame(&mut BufReader::new(b"incomplete".as_slice()))
                .await
                .is_err()
        );
        let bytes = vec![b'x'; MAX_FRAME_BYTES + 1];
        assert!(
            read_frame(&mut BufReader::new(bytes.as_slice()))
                .await
                .is_err()
        );
    }
}
