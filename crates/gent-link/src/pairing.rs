use anyhow::{Context, Result, ensure};
use clap::Args;
use gent_daemon::pairing::{self, Options, Peer, ServiceRelay};
use gent_protocol::{MAX_FRAME_BYTES, OwnerOp, PairingOp, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
};

#[derive(Args)]
#[command(
    after_help = "Run gent node add NAME on an existing cluster node, then gent cluster join CODE on the new machine.\nPrivate-file and trusted SSH enrollment remain available through --invite-file and --via."
)]
pub struct JoinArgs {
    /// One-time node invitation code; a cluster UUID only with --via.
    pub(crate) cluster: Option<String>,
    /// SSH destination of an existing owner node (for example sam@studio).
    #[arg(long, conflicts_with = "invite_file")]
    pub(crate) via: Option<String>,
    /// Private invitation received through a trusted channel; pairing uses the relay.
    #[arg(long)]
    pub(crate) invite_file: Option<PathBuf>,
    /// Replace a staged invitation while preserving its original node identity.
    #[arg(long = "continue", requires = "invite_file")]
    continue_invitation: bool,
    /// Node name for SSH or private-file enrollment; codes supply their own name.
    #[arg(long, default_value = "")]
    pub(crate) name: String,
    /// Read a node invitation code from an owner-private file.
    #[arg(long, conflicts_with_all = ["via", "invite_file", "cluster"])]
    pub(crate) code_file: Option<PathBuf>,
    /// Enroll without installing a background service (for managed environments).
    #[arg(long, conflicts_with_all = ["via", "invite_file"])]
    pub(crate) no_daemon: bool,
    /// Retire this lost joined node and enroll a fresh identity through SSH.
    #[arg(long, conflicts_with = "invite_file")]
    replace_node: Option<String>,
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

impl JoinArgs {
    pub(crate) fn code(cluster: Option<String>) -> Self {
        Self {
            cluster,
            name: String::new(),
            via: None,
            invite_file: None,
            continue_invitation: false,
            code_file: None,
            no_daemon: false,
            replace_node: None,
            remote_gent: "gent".into(),
            remote_home: None,
            relay_endpoint: None,
        }
    }
    pub(crate) fn code_route(&self) -> Result<bool> {
        let code = self.via.is_none() && self.invite_file.is_none();
        if code {
            ensure!(
                self.remote_home.is_none()
                    && self.relay_endpoint.is_none()
                    && self.remote_gent == "gent"
                    && self.replace_node.is_none()
                    && !self.continue_invitation,
                "pairing codes do not accept SSH options or replacement/continuation overrides"
            );
        }
        Ok(code)
    }
    pub(crate) fn with_invitation(mut self, file: PathBuf, cluster: String) -> Self {
        self.cluster = Some(cluster);
        self.invite_file = Some(file);
        self.code_file = None;
        self.no_daemon = false;
        self
    }
    pub(crate) fn invitation_intent(
        file: &Path,
        name: &str,
        cluster: Option<&str>,
    ) -> Result<crate::contexts::provision::Intent> {
        let invitation = crate::invitations::decode_file(file)?;
        let offer = &invitation.offer().offer;
        ensure!(
            cluster.is_none_or(|id| id == offer.anchor.cluster_id),
            "invitation belongs to another cluster"
        );
        Ok(crate::contexts::provision::Intent::Join {
            cluster: offer.anchor.cluster_id.clone(),
            name: name.into(),
            route: serde_json::json!({"kind":"invitation","anchor":offer.anchor,"service":offer.service}),
        })
    }
    pub(crate) fn intent(&self) -> Result<crate::contexts::provision::Intent> {
        if let Some(file) = &self.invite_file {
            ensure!(
                self.remote_home.is_none()
                    && self.relay_endpoint.is_none()
                    && self.remote_gent == "gent",
                "invitation joins do not accept SSH paths or relay overrides"
            );
            return Self::invitation_intent(file, &self.name, self.cluster.as_deref());
        }
        remote_command(self)?;
        let mut route = serde_json::json!({"kind":"ssh","via":self.via,"remote_home":self.remote_home,
                "remote_gent":self.remote_gent,"relay_endpoint":self.relay_endpoint});
        if let Some(target) = &self.replace_node {
            route["replace_node"] = serde_json::json!(target);
        }
        Ok(crate::contexts::provision::Intent::Join {
            cluster: self
                .cluster
                .clone()
                .context("SSH joining requires a cluster ID")?,
            name: self.name.clone(),
            route,
        })
    }
    pub(crate) fn existing(&self, home: &Path, pinned_node: Option<&str>) -> Result<Option<Value>> {
        if crate::managed_file::Snapshot::read(&gent_daemon::config::path(home))?
            .text
            .is_none()
        {
            return Ok(None);
        }
        if gent_daemon::config::pending_join(home)?.exists() {
            return Ok(None);
        }
        let cfg = crate::contexts::inspect(home)?;
        let replacement = pairing::installed_replacement(home)?;
        ensure!(
            self.replace_node
                .as_ref()
                .is_none_or(|id| replacement.as_ref().is_some_and(|target| &target.id == id)),
            "installed node does not match the requested replacement"
        );
        if let Some(file) = &self.invite_file {
            let saved = crate::invitations::installation(home)?
                .context("invitation setup record is missing")?;
            ensure!(
                replacement == saved.offer.offer.replaces,
                "installed replacement differs from the invitation"
            );
            if !saved.complete {
                return Ok(None);
            }
            let invitation = crate::invitations::decode_file(file)?;
            ensure!(
                saved.offer == *invitation.offer()
                    && saved.name == self.name
                    && saved.offer.offer.anchor.cluster_id == cfg.cluster.id
                    && saved.node.is_some_and(|node| node.id == cfg.node.id),
                "installed node does not match this invitation"
            );
        } else {
            ensure!(
                self.cluster.as_deref() == Some(&cfg.cluster.id)
                    && pinned_node.map_or(self.name == cfg.node.name, |node| node == cfg.node.id),
                "installed node does not match the requested join"
            );
        }
        if crate::cluster::installation(home)?.is_some_and(|s| s.pending) {
            return Ok(None);
        }
        Ok(Some(
            serde_json::json!({"joined":true,"already_configured":true,"cluster":cfg.cluster,"node":cfg.node,
                "replaced_node":replacement.map(|target|target.id)}),
        ))
    }
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
    let via = args
        .via
        .as_deref()
        .context("SSH joining requires --via HOST")?;
    ensure!(
        !via.is_empty()
            && !via.starts_with('-')
            && via
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
        via,
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
    home: PathBuf,
    service: Option<crate::auth::Service>,
    command: Command,
    cluster: String,
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<BufReader<ChildStdout>>,
}
impl Peer for Remote {
    async fn prepare_service(&mut self, relay: &ServiceRelay) -> Result<()> {
        if self.service.is_none() {
            self.service = Some(crate::auth::Service::open(&self.home).await?);
        }
        let service = self.service.as_ref().expect("login loaded");
        ensure!(
            service.origin()? == crate::auth::origin(&relay.account.origin)?
                && service.session.account_id == relay.account.account_id,
            "sign into the owner's Gent service and account before joining"
        );
        let endpoint = crate::auth::origin(&relay.relay_endpoint)?;
        ensure!(
            endpoint.scheme() == "https" || service.origin()?.scheme() == "http",
            "an HTTPS account service cannot select an insecure relay"
        );
        service.require_cluster_owner(&self.cluster).await
    }
    async fn provision_service(
        &mut self,
        runtime: &Path,
        home: &Path,
        relay: &ServiceRelay,
    ) -> Result<()> {
        crate::cluster::provision_joined(
            runtime,
            home,
            self.service
                .as_ref()
                .context("service login was not prepared")?,
            relay,
        )
        .await
    }
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
    if let Some(file) = &args.invite_file {
        ensure!(
            args.remote_home.is_none()
                && args.relay_endpoint.is_none()
                && args.remote_gent == "gent",
            "invitation joins do not accept SSH paths or relay overrides"
        );
        return crate::invitations::join(
            home,
            file,
            args.cluster.as_deref(),
            &args.name,
            args.continue_invitation,
        )
        .await;
    }
    let cluster = args
        .cluster
        .as_deref()
        .context("SSH joining requires a cluster ID")?;
    let mut peer = Remote {
        home: crate::managed_file::normalize(home)?,
        service: None,
        command: remote_command(&args)?,
        cluster: cluster.into(),
        child: None,
        input: None,
        output: None,
    };
    let result = pairing::join(
        home,
        Options {
            cluster,
            name: &args.name,
            relay_endpoint: args.relay_endpoint.as_deref(),
            replace_node: args.replace_node.as_deref(),
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
    let mut result = result;
    if let Some(target) = pairing::installed_replacement(home)? {
        result["replaced_node"] = serde_json::json!(target.id);
        result["recovery"] = serde_json::json!(
            "fresh identity and streams; historical agents and work were not imported"
        );
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
            code_file: None,
            no_daemon: false,
            cluster: Some("cluster".into()),
            via: Some("sam@studio".into()),
            invite_file: None,
            continue_invitation: false,
            name: "laptop".into(),
            replace_node: None,
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
            args.via = Some(bad.into());
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
