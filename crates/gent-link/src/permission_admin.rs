use super::*;

#[derive(Subcommand)]
pub(crate) enum Command {
    /// List owner-visible agent delegations and retired grant IDs.
    List,
    /// Read durable agent-edit audit records, including requests from other nodes.
    History {
        #[arg(long = "agent")]
        administrator: Option<String>,
        #[arg(long)]
        before: Option<u64>,
    },
    /// Delegate exact-pair editing within selectors (*, same-node, node:UUID, group:NAME or agent UUID).
    Grant {
        administrator: String,
        actor: String,
        peer: String,
        #[arg(long, value_enum, num_args=1.., required=true)]
        permission: Vec<PermissionName>,
        #[arg(long, default_value_t = 86400)]
        ttl_seconds: u64,
    },
    /// Stop future edits. Already accepted permission rules remain in force.
    Revoke { grant: String },
}

pub(crate) async fn run(
    home: &std::path::Path,
    request_id: &str,
    command: Command,
) -> Result<Value> {
    match command {
        Command::List => owner(home, OwnerOp::PermissionAdmins).await,
        Command::History {
            administrator,
            before,
        } => {
            owner(
                home,
                OwnerOp::PermissionAdminHistory {
                    administrator,
                    before,
                },
            )
            .await
        }
        Command::Grant {
            administrator,
            actor,
            peer,
            permission,
            ttl_seconds,
        } => {
            configure(
                home,
                request_id,
                ConfigurationEdit::GrantPermissionAdmin {
                    grant_id: request_id.into(),
                    administrator,
                    actor: selector(actor)?,
                    peer: selector(peer)?,
                    permissions: permission
                        .into_iter()
                        .map(|p| match p {
                            PermissionName::Enumerate => Permission::Enumerate,
                            PermissionName::Receive => Permission::Receive,
                            PermissionName::Send => Permission::Send,
                        })
                        .collect(),
                    lifetime_seconds: ttl_seconds,
                },
            )
            .await
        }
        Command::Revoke { grant } => {
            configure(
                home,
                request_id,
                ConfigurationEdit::RevokePermissionAdmin { grant_id: grant },
            )
            .await
        }
    }
}
