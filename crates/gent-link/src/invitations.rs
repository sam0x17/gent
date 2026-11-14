//! Private-file invitation commands. Only local owner RPC carries the offer's
//! secrets; service registration receives the routing digest and opaque IDs.
mod joining;
mod journal;
pub use joining::join;
pub(crate) use journal::installation;

use crate::{
    auth,
    managed_file::{self, Snapshot},
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Subcommand};
use gent_crypto::invitation::{Invitation, MAX_INVITATION_BYTES};
use gent_daemon::config;
use gent_protocol::{InvitationOp, OwnerOp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Args)]
pub struct InviteArgs {
    /// Save the private invitation here. Transfer it through a trusted private channel.
    #[arg(long)]
    out: PathBuf,
    /// Give the new node messaging access without configuration-editing authority.
    #[arg(long)]
    no_configure: bool,
    /// Explicitly continue an interrupted join for this already-enrolled node ID.
    #[arg(long)]
    continue_node: Option<String>,
    /// Authorize a fresh identity to replace this exact lost joined node.
    #[arg(long, conflicts_with = "continue_node")]
    replace_node: Option<String>,
}
#[derive(Subcommand)]
pub enum Command {
    List,
    /// Close native admission, then revoke service routing. Retry if offline.
    Revoke {
        id: String,
    },
}

fn private(path: &Path) -> Result<Snapshot> {
    let snapshot = Snapshot::read(path)?;
    snapshot.private()?;
    Ok(snapshot)
}
pub(crate) fn decode_file(path: &Path) -> Result<Invitation> {
    let snapshot = private(path)?;
    let text = snapshot
        .text
        .context("private invitation file is missing")?;
    ensure!(
        text.len() <= MAX_INVITATION_BYTES,
        "invitation file too large"
    );
    Invitation::decode(text.as_bytes())
}

pub(crate) struct Installation {
    pub name: String,
    pub offer: gent_crypto::invitation::SignedOffer,
    pub node: Option<gent_crypto::invitation::ClaimedNode>,
    pub complete: bool,
}
async fn local(home: &Path, action: InvitationOp) -> Result<Value> {
    crate::owner(home, OwnerOp::Invitation { action }).await
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Creation {
    version: u8,
    request: String,
    output: PathBuf,
    cluster: String,
    node: String,
    session: String,
    configure: bool,
    continuation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replace_node: Option<String>,
}

fn clean_creation_records(directory: &Path, retain: &Path) -> Result<usize> {
    let mut count = 0;
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        count += 1;
        ensure!(count <= 128, "invitation creation journal exceeds capacity");
        if path == retain {
            continue;
        }
        let snapshot = private(&path)?;
        let record: Creation = serde_json::from_str(
            snapshot
                .text
                .as_deref()
                .context("missing invitation creation record")?,
        )
        .map_err(|_| anyhow::anyhow!("invalid invitation creation record"))?;
        let issued = Uuid::parse_str(&record.request)?
            .get_timestamp()
            .context("invalid invitation creation time")?
            .to_unix()
            .0;
        if auth::now()? >= issued.saturating_add(gent_crypto::invitation::OFFER_LIFETIME) {
            snapshot.verify()?;
            std::fs::remove_file(path)?;
            count -= 1;
        }
    }
    Ok(count)
}

pub async fn create(home: &Path, args: InviteArgs) -> Result<Value> {
    let home = managed_file::normalize(home)?;
    let cfg = config::load(&home)?;
    let output = managed_file::normalize(&args.out)?;
    let destination = private(&output)?;
    let directory = home.join("invitations");
    config::private_dir(&directory)?;
    let _lock = managed_file::lock(&directory.join("lock"))?;
    let service = auth::Service::open(&home).await?;
    let account = cfg
        .service
        .as_ref()
        .context("run gent cluster connect before issuing invitations")?;
    ensure!(
        service.origin()? == auth::origin(&account.origin)?
            && service.session.account_id == account.account_id,
        "sign into this node's Gent service and account"
    );
    let key = format!(
        "{:x}",
        Sha256::digest(output.as_os_str().as_encoded_bytes())
    );
    let path = directory.join(format!("{key}.json"));
    let count = clean_creation_records(&directory, &path)?;
    let saved = private(&path)?;
    let record: Creation = match saved.text.as_deref() {
        Some(text) => serde_json::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid invitation creation record"))?,
        None => {
            ensure!(
                count < 128,
                "invitation creation capacity reached; wait for pending invitations to expire"
            );
            ensure!(
                destination.text.is_none(),
                "invitation output already exists; choose a new file"
            );
            let value = Creation {
                version: 1,
                request: Uuid::now_v7().to_string(),
                output: output.clone(),
                cluster: cfg.cluster.id.clone(),
                node: cfg.node.id.clone(),
                session: service.session_hash(),
                configure: !args.no_configure,
                continuation: args.continue_node.clone(),
                replace_node: args.replace_node.clone(),
            };
            saved.write(&serde_json::to_string(&value)?)?;
            value
        }
    };
    ensure!(
        record.version == 1
            && record.output == output
            && record.cluster == cfg.cluster.id
            && record.node == cfg.node.id
            && record.session == service.session_hash()
            && record.configure == !args.no_configure
            && record.continuation == args.continue_node
            && record.replace_node == args.replace_node,
        "invitation retry options or issuing login changed; use the original options and login, or a new output file"
    );
    let value = local(
        &home,
        InvitationOp::Create {
            request_id: record.request.clone(),
            can_configure: record.configure,
            continuation: record.continuation.clone(),
            replace_node: record.replace_node.clone(),
        },
    )
    .await?;
    let bytes = zeroize::Zeroizing::new(
        STANDARD.decode(
            value["private_invitation"]
                .as_str()
                .context("missing private invitation")?,
        )?,
    );
    let text = std::str::from_utf8(&bytes).context("invalid private invitation encoding")?;
    let invitation = Invitation::decode(text.as_bytes())?;
    let offer = &invitation.offer().offer;
    invitation.offer().verify(&offer.anchor, auth::now()?)?;
    ensure!(
        offer.anchor.cluster_id == cfg.cluster.id
            && offer.issuer_id == cfg.node.id
            && (offer.can_configure == record.configure
                || (record.replace_node.is_some() && record.configure && !offer.can_configure)),
        "local invitation identity changed"
    );
    use gent_crypto::invitation::Purpose;
    ensure!(
        match (&offer.purpose, &record.continuation, &record.replace_node) {
            (Purpose::NewNode, None, None) => offer.replaces.is_none(),
            (Purpose::NewNode, None, Some(id)) => offer
                .replaces
                .as_ref()
                .is_some_and(|target| &target.id == id),
            (Purpose::Continue { node }, Some(id), None) => &node.id == id,
            _ => false,
        },
        "local invitation purpose changed"
    );
    ensure!(
        destination
            .text
            .as_ref()
            .is_none_or(|previous| previous == text),
        "invitation output changed; existing file preserved"
    );
    service.register_invitation(invitation.offer()).await?;
    local(
        &home,
        InvitationOp::Activate {
            id: offer.id.clone(),
        },
    )
    .await?;
    destination.write(text)?;
    Ok(
        json!({"invitation":offer.id,"file":output,"expires_at":offer.expires_at,
        "can_configure":offer.can_configure,"replaces":offer.replaces,"next":"Transfer this private file through a trusted channel, then run gent cluster join --invite-file FILE --name NODE."}),
    )
}

pub async fn execute(home: &Path, command: Command) -> Result<Value> {
    match command {
        Command::List => local(home, InvitationOp::List).await,
        Command::Revoke { id } => {
            // Close native access even if the account service cannot be reached.
            local(home, InvitationOp::Revoke { id: id.clone() }).await?;
            let result = async {
                let cfg = config::load(home)?;
                let account = cfg.service.context("missing service binding")?;
                let service = auth::Service::open(home).await?;
                ensure!(
                    service.origin()? == auth::origin(&account.origin)?
                        && service.session.account_id == account.account_id,
                    "sign into this node's Gent service and account"
                );
                service.revoke_invitation(&cfg.cluster.id, &id).await
            }
            .await;
            result.context("native invitation admission is closed; service revocation is pending, rerun this command")?;
            Ok(json!({"invitation":id,"revoked":true}))
        }
    }
}

#[cfg(test)]
mod tests;
