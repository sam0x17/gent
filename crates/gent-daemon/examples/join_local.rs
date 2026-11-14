//! Test helper: enroll a second temporary daemon through an owner's local Unix
//! socket. Requires that OS user's owner credential, just like SSH pairing.
use anyhow::{Result, ensure};
use gent_daemon::{
    config,
    pairing::{self, Peer},
    request,
};
use gent_protocol::{OwnerOp, PairingOp, Request};
use serde_json::Value;
use std::path::PathBuf;
use zeroize::Zeroizing;

struct LocalOwner {
    home: PathBuf,
    cluster: String,
    credential: Zeroizing<String>,
}
impl Peer for LocalOwner {
    async fn call(&mut self, action: PairingOp) -> Result<Value> {
        request(
            &self.home,
            Request::Owner {
                credential: self.credential.to_string(),
                action: OwnerOp::Pair {
                    cluster_id: self.cluster.clone(),
                    action,
                },
            },
        )
        .await
    }
}
#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(args.len() == 2, "usage: join_local OWNER_HOME NEW_HOME");
    let home = PathBuf::from(&args[0]);
    let cluster = config::load(&home)?.cluster.id;
    let credential = Zeroizing::new(config::read_private(&home.join("owner.key"))?);
    let mut owner = LocalOwner {
        home,
        cluster: cluster.clone(),
        credential,
    };
    let result = pairing::join(
        &PathBuf::from(&args[1]),
        pairing::Options {
            replace_node: None,
            cluster: &cluster,
            name: "second-mac-node",
            relay_endpoint: None,
        },
        &mut owner,
    )
    .await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
