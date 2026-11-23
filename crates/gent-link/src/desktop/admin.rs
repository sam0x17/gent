//! Typed desktop actions. Both native views submit the same commands on a private pipe.
use crate::{
    auth, build_info, configure, enrollment, node, node_home, owner, pairing, setup, update,
};
use anyhow::{Context, Result};
use gent_daemon::config;
use gent_protocol::{
    ConfigurationEdit, Effect, OwnerOp, Permission, Rule, Selector, administration::RuleDecision,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    Manage { action: Action },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    CheckUpdate,
    SignIn,
    SignOut,
    Create {
        name: String,
    },
    Join {
        code: String,
    },
    FinishSetup,
    Invite {
        name: String,
        role: Role,
    },
    RemoveNode {
        id: Uuid,
    },
    Unregister {
        id: Uuid,
    },
    NodeRole {
        id: Uuid,
        role: Role,
    },
    SetRule {
        actor: String,
        peer: String,
        permission: Permission,
        decision: RuleDecision,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Role {
    Admin,
    Member,
}
impl Action {
    fn page(&self) -> &'static str {
        match self {
            Self::CheckUpdate => "about",
            Self::Invite { .. } | Self::RemoveNode { .. } | Self::NodeRole { .. } => "nodes",
            Self::Unregister { .. } => "chats",
            Self::SetRule { .. } => "permissions",
            _ => "cluster",
        }
    }
    pub(super) fn error(&self, error: &str) -> Value {
        json!({"page":self.page(),"operation":true,"error":error})
    }
    pub(super) async fn respond(self, home: &Path) -> Value {
        let page = self.page();
        match self.run(home).await {
            Ok(mut value) => {
                value["page"] = json!(page);
                value["operation"] = json!(true);
                value
            }
            Err(error) => json!({"page":page,"operation":true,"error":format!("{error:#}")}),
        }
    }
    async fn run(self, home: &Path) -> Result<Value> {
        let notice = match self {
            Self::CheckUpdate => {
                let result = update::desktop_check().await?;
                let stable = result["blessed_commit"]
                    .as_str()
                    .context("missing stable revision")?;
                if result["update_available"] == true {
                    format!(
                        "Update available · stable {}",
                        &stable[..stable.len().min(12)]
                    )
                } else {
                    "You’re running the current stable release.".into()
                }
            }
            Self::SignIn => {
                auth::desktop_login(home).await?;
                "Signed in to Gent.".into()
            }
            Self::SignOut => {
                let result = auth::execute(home, auth::Command::Logout).await?;
                if result["status"] == "signed_out" {
                    "Signed out.".into()
                } else {
                    "Sign-out pending. Retry when the service is reachable.".into()
                }
            }
            Self::Create { name } => {
                node_home::provision::install(
                    home,
                    None,
                    setup::Options::desktop(Some(name)),
                    false,
                )
                .await?;
                "Cluster created and daemon installed.".into()
            }
            Self::Join { code } => {
                let mut args = pairing::JoinArgs::code(
                    (!code.trim().is_empty()).then(|| code.trim().to_owned()),
                );
                args.no_input = true;
                enrollment::join(home, args).await?;
                "Joined the cluster and installed the daemon.".into()
            }
            Self::FinishSetup => {
                node_home::provision::install(home, None, setup::Options::desktop(None), false)
                    .await?;
                "Daemon setup complete.".into()
            }
            Self::Invite { name, role } => {
                let directory = tempfile::tempdir()?;
                let file = directory.path().join("invite");
                let options = enrollment::AddArgs::invitation(
                    name.clone(),
                    matches!(role, Role::Admin),
                    file.clone(),
                );
                enrollment::add(home, options).await?;
                return Ok(json!({"notice":format!("Invitation for {name}"),
                    "private_code":std::fs::read_to_string(&file)?}));
            }
            Self::RemoveNode { id } => {
                let result = node::remove(home, id.to_string()).await?;
                if result["state"] == "queued" {
                    "Removal queued for cluster approval.".into()
                } else if result["service_status"] == "pending" {
                    "Membership removed. Service revocation is pending.".into()
                } else {
                    "Node removed from the cluster.".into()
                }
            }
            Self::NodeRole { id, role } => {
                let result = configure(
                    home,
                    &Uuid::new_v4().to_string(),
                    ConfigurationEdit::DelegateNode {
                        node_id: id.to_string(),
                        allow: matches!(role, Role::Admin),
                    },
                )
                .await?;
                return change_result(&result);
            }
            Self::Unregister { id } => {
                let result = owner(
                    home,
                    OwnerOp::Revoke {
                        agent_id: id.to_string(),
                    },
                )
                .await?;
                if result["revoked"] == true {
                    "Chat unregistered.".into()
                } else {
                    "Unregistration queued for the hosting node. Refresh to check its registration."
                        .into()
                }
            }
            Self::SetRule {
                actor,
                peer,
                permission,
                decision,
            } => {
                let effect = match decision {
                    RuleDecision::Allow => Some(Effect::Allow),
                    RuleDecision::Deny => Some(Effect::Deny),
                    RuleDecision::Inherit => None,
                };
                let id = Uuid::new_v4().to_string();
                let result = configure(
                    home,
                    &id,
                    ConfigurationEdit::SetPermissionRule {
                        actor: crate::selector(actor)?,
                        peer: crate::selector(peer)?,
                        permission,
                        effect,
                    },
                )
                .await?;
                return change_result(&result);
            }
        };
        Ok(json!({"notice":notice}))
    }
}

fn change_result(result: &Value) -> Result<Value> {
    let state = result["state"]
        .as_str()
        .context("missing configuration request status")?;
    anyhow::ensure!(
        state != "rejected",
        "Change rejected: {}",
        result["reason"].as_str().unwrap_or("unknown reason")
    );
    Ok(json!({"notice":format!("Configuration change: {state}")}))
}

pub(super) fn about() -> Value {
    let build = build_info::current();
    json!({"title":"Gent","detail":format!("Version {} · {}{}\nCopyright © 2026 Gent contributors",
        build.version,build.commit.chars().take(12).collect::<String>(),if build.dirty {" (development)"} else {""}),
        "actions":[{"kind":"check_update","title":"Check for updates"}]})
}

pub(super) fn cluster(home: &Path) -> Result<Value> {
    let account = auth::desktop_account(home)?;
    let state = account["state"].as_str().unwrap_or("Unknown");
    let mut actions = Vec::new();
    if state != "Signed in" && state != "Sign-out pending" {
        actions.push(json!({"kind":"sign_in","title":"Sign in with GitHub"}));
    }
    if state != "Signed out" {
        actions.push(json!({"kind":"sign_out","title":"Sign out","confirm":"Sign out of the Gent account on this machine?"}));
    }
    let title = if config::path(home).try_exists()? {
        let cfg = node_home::inspect(home)?;
        actions.push(json!({"kind":"finish_setup","title":"Install or repair daemon…","confirm":"Install and start the user service for this node?"}));
        format!("{} · {}", cfg.cluster.name, cfg.node.name)
    } else {
        actions.push(json!({"kind":"create","title":"Create cluster…","submit":"Create cluster",
            "fields":[{"key":"name","title":"Cluster name"}],"hint":"Create a cluster with your Gent account and start this node’s daemon."}));
        actions.push(json!({"kind":"join","title":"Join with invitation…","submit":"Join cluster",
            "fields":[{"key":"code","title":"Invitation code","secret":true}],
            "hint":"Use the one-time code from Nodes on an enrolled machine. Sign in to the same Gent account first."}));
        if enrollment::pending(home)?.is_some() {
            actions.push(json!({"kind":"join","title":"Resume pending join","values":{"code":""}}));
        }
        "Set up this node".into()
    };
    let login = account["login"]
        .as_str()
        .map(|s| format!(" · @{s}"))
        .unwrap_or_default();
    Ok(json!({"title":title,"detail":format!("Gent account: {state}{login}"),"actions":actions}))
}

fn role_field() -> Value {
    json!({"key":"role","title":"Node permissions","choices":[["admin","Admin"],["member","Messaging only"]]})
}

pub(super) fn directory_actions(chats: bool) -> Value {
    if chats {
        return json!([{"kind":"unregister","title":"Unregister chat…","row":true,
        "confirm":"Unregister this conversation? Its Gent binding will lose access. The conversation stays in its host app."}]);
    }
    json!([{"kind":"invite","title":"Add node…","submit":"Create invitation",
        "hint":"Give this one-time code to the new node. It expires after 15 minutes.",
        "fields":[{"key":"name","title":"New node name"},role_field()]},
        {"kind":"node_role","title":"Change role…","row":true,"submit":"Change role","fields":[role_field()],
        "hint":"Admin nodes can change cluster configuration and permissions."},
        {"kind":"remove_node","title":"Remove node…","row":true,
        "confirm":"Remove this node from membership and revoke its cluster access?"}])
}

fn selector_key(selector: &Selector) -> String {
    match selector {
        Selector::All => "*".into(),
        Selector::SameNode => "same-node".into(),
        Selector::Agent(id) => id.clone(),
        Selector::Node(id) => format!("node:{id}"),
        Selector::Group(name) => format!("group:{name}"),
    }
}

pub(super) async fn permissions(home: &Path) -> Result<Value> {
    let snapshot = owner(home, OwnerOp::PermissionRules).await?;
    let nodes = owner(home, OwnerOp::Nodes).await?;
    let chats = owner(home, OwnerOp::Agents).await?;
    let mut choices = vec![
        ["*".to_owned(), "All chats".to_owned()],
        ["same-node".into(), "Chats on the same node".into()],
    ];
    for node in nodes.as_array().context("invalid node directory")? {
        if let (Some(id), Some(name)) = (node["id"].as_str(), node["name"].as_str()) {
            choices.push([format!("node:{id}"), format!("Node · {name}")]);
        }
    }
    for group in snapshot["groups"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        choices.push([format!("group:{group}"), format!("Group · {group}")]);
    }
    let mut entries: Vec<gent_protocol::directory::Entry> = serde_json::from_value(chats)?;
    entries.sort_by_cached_key(|e| e.agent.name.to_lowercase());
    for entry in entries {
        if !entry.retired && !entry.agent.revoked {
            choices.push([
                entry.agent.id.clone(),
                format!(
                    "{} · {} · {}",
                    entry.agent.name,
                    entry.node_name.unwrap_or(entry.agent.node_id),
                    entry.agent.id.chars().take(8).collect::<String>()
                ),
            ]);
        }
    }
    let rules: Vec<Rule> = serde_json::from_value(snapshot["rules"].clone())?;
    let labels: std::collections::HashMap<_, _> = choices.iter().map(|[k, v]| (k, v)).collect();
    let name = |s: &Selector| {
        let key = selector_key(s);
        labels.get(&key).map_or(key.clone(), |s| (*s).clone())
    };
    let lines: Vec<_> = rules
        .iter()
        .map(|r| {
            format!(
                "{:?} {:?}   {} → {}",
                r.effect,
                r.permission,
                name(&r.actor),
                name(&r.peer)
            )
        })
        .collect();
    let detail = if lines.is_empty() {
        "No explicit permission rules.".into()
    } else {
        lines.join("\n")
    };
    Ok(
        json!({"title":"Cluster permissions","detail":detail,"actions":[{"kind":"set_rule","title":"Edit permission…",
        "submit":"Apply rule","hint":"This replaces the selected rule across the cluster. Inherit removes that override. Any other matching deny still applies.",
        "fields":[{"key":"actor","title":"From","choices":choices},{"key":"peer","title":"To","choices":choices},
        {"key":"permission","title":"Permission","choices":[["send","Send"],["receive","Receive"],["enumerate","Discover"]]},
        {"key":"decision","title":"Decision","choices":[["deny","Deny"],["allow","Allow"],["inherit","Inherit"]]}]}]}),
    )
}
