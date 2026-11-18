use super::*;
use gent_protocol::administration::GroupAction;

#[derive(Subcommand)]
pub(crate) enum Command {
    List,
    Show {
        name: String,
    },
    /// Create an empty group. Add members with `gent group member add`.
    #[command(alias = "create")]
    New {
        name: String,
    },
    /// Delete a group after removing every rule and grant that references it.
    #[command(alias = "remove")]
    Delete {
        name: String,
    },
    Member {
        #[command(subcommand)]
        command: Members,
    },
    Admin {
        #[command(subcommand)]
        command: Admin,
    },
}

#[derive(Subcommand)]
pub(crate) enum Members {
    Add {
        group: String,
        #[arg(required = true, num_args = 1..=32, value_name = "CHAT_ID")]
        agents: Vec<String>,
    },
    Remove {
        group: String,
        #[arg(required = true, num_args = 1..=32, value_name = "CHAT_ID")]
        agents: Vec<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum Action {
    Add,
    Remove,
}
impl From<Action> for GroupAction {
    fn from(action: Action) -> Self {
        match action {
            Action::Add => Self::Add,
            Action::Remove => Self::Remove,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum Admin {
    List,
    History {
        #[arg(long = "chat", alias = "agent", value_name = "CHAT_ID")]
        administrator: Option<String>,
        #[arg(long)]
        before: Option<u64>,
    },
    /// Delegate membership changes. These affect ALL rules and existing editing
    /// scopes referencing the group, including the administrator's own access.
    Grant {
        administrator: String,
        group: String,
        /// Permitted members: *, same-node (relative to admin), node:UUID, group:NAME or chat UUID.
        members: String,
        #[arg(long, value_enum, num_args = 1.., required = true)]
        action: Vec<Action>,
        #[arg(long, default_value_t = 86400)]
        ttl_seconds: u64,
    },
    /// Stop future membership edits; accepted changes remain in effect.
    Revoke {
        grant: String,
    },
}

pub(crate) async fn run(
    home: &std::path::Path,
    request: &str,
    command: Option<Command>,
) -> Result<Value> {
    let edit = match command.unwrap_or(Command::List) {
        Command::List => return owner(home, OwnerOp::Groups { name: None }).await,
        Command::Show { name } => return owner(home, OwnerOp::Groups { name: Some(name) }).await,
        Command::New { name } => ConfigurationEdit::CreateGroup { name },
        Command::Delete { name } => ConfigurationEdit::DeleteGroup { name },
        Command::Member { command } => match command {
            Members::Add { group, agents } => ConfigurationEdit::GroupMembers {
                group,
                members: agents,
                action: GroupAction::Add,
            },
            Members::Remove { group, agents } => ConfigurationEdit::GroupMembers {
                group,
                members: agents,
                action: GroupAction::Remove,
            },
        },
        Command::Admin { command } => match command {
            Admin::List => return owner(home, OwnerOp::GroupAdmins).await,
            Admin::History {
                administrator,
                before,
            } => {
                return owner(
                    home,
                    OwnerOp::GroupAdminHistory {
                        administrator,
                        before,
                    },
                )
                .await;
            }
            Admin::Grant {
                administrator,
                group,
                members,
                action,
                ttl_seconds,
            } => ConfigurationEdit::GrantGroupAdmin {
                grant_id: request.into(),
                administrator,
                group,
                members: selector(members)?,
                actions: action.into_iter().map(Into::into).collect(),
                lifetime_seconds: ttl_seconds,
            },
            Admin::Revoke { grant } => ConfigurationEdit::RevokeGroupAdmin { grant_id: grant },
        },
    };
    configure(home, request, edit).await
}
