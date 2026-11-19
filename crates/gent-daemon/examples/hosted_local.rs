//! Isolated proof helper: prepare an already joined child through the parent's
//! owner socket, activate its signed mapping, then serve only its local proxy.
use anyhow::{Result, ensure};
use gent_daemon::{config, hosted, request};
use gent_protocol::{ConfigurationEdit, OwnerOp, Request};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 2,
        "usage: hosted_local PARENT_HOME JOINED_CHILD_HOME"
    );
    let parent = PathBuf::from(&args[0]);
    let child = PathBuf::from(&args[1]);
    let parent_id = config::load(&parent)?.node.id;
    let child_id = config::load(&child)?.node.id;
    let credential = Zeroizing::new(config::read_private(&parent.join("owner.key"))?);
    for action in [
        OwnerOp::PrepareHostedNode {
            node_id: child_id.clone(),
            home: child.clone(),
        },
        OwnerOp::Configure {
            request_id: gent_crypto::scoped_id(
                b"gent/hosted-local-proof/v1\0",
                &[parent_id.as_bytes(), child_id.as_bytes()],
            )
            .to_string(),
            edit: ConfigurationEdit::HostNode {
                node_id: child_id,
                parent: parent_id,
            },
        },
    ] {
        let value = request(
            &parent,
            Request::Owner {
                credential: credential.to_string(),
                action,
            },
        )
        .await?;
        ensure!(
            value["state"] != "rejected",
            "hosted fixture activation rejected"
        );
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    hosted::run(&child, async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    })
    .await
}
