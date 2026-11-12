# Gent CLI design

The Cargo package is `gent-link`; it installs the `gent` binary. These commands describe the planned interface. No CLI implementation or crates.io release is available yet.

## Command conventions

Use nouns to identify resources and verbs to change them. Bare status commands such as `gent`, `gent node`, `gent cluster`, `gent daemon`, `gent hooks`, and `gent auth` show the current state without modifying it. Plurals such as `gent nodes`, `gent clusters`, and `gent agents` list the corresponding resources. Explicit `status` subcommands are also available where they improve discoverability.

Every command has `--help`, examples, and errors that name the next useful command. Human output should be readable in a terminal. Support `--json` for structured output and stable exit codes for scripts. A scalar getter such as `gent node name` prints only its value and a newline. Put diagnostics on stderr, keep secrets out of output, and avoid prompts when stdin is not a terminal. Commands with missing required inputs should explain what is needed and exit rather than hang.

Interactive commands can guide missing setup steps. For automation, support explicit arguments and `--no-input`. Suggest close command matches without executing a guessed command. Destructive operations identify their target and require an explicit confirmation or documented noninteractive confirmation flag. Status, listing, and idempotent setup do not need repeated confirmations.

## Setup

With Rust and Cargo installed, the shortest intended setup is:

```sh
cargo install gent-link && gent daemon install
```

`gent daemon install` sets up and starts the service and guides any missing GitHub login and cluster enrollment. Start with macOS launchd and Linux systemd user services. Report login/startup requirements, and diagnose systems without a supported service manager. Offer shell-hook installation as part of that interactive setup. Each step is also available independently:

```sh
gent auth login
gent cluster join my-cluster-id
gent node name set my-node
gent daemon install
gent hooks install
gent cluster
```

Use `gent cluster new` to create a cluster instead of joining one. Creation can prompt for a name. Joining requires an invitation or existing membership and cryptographic enrollment approval; knowing a cluster ID does not grant access.

Setup must recover from an interrupted step and be safe to rerun. Preserve device identity, existing settings, and unrelated shell configuration. End with a concise status report and the next action, if any.

## Nodes and clusters

| Command | Behavior |
| --- | --- |
| `gent` | Show the current node, active cluster, authentication, and daemon status. |
| `gent node` | Show details for the current node. |
| `gent node name` | Print the current node's name. |
| `gent node name set my-node` | Rename the current node and publish its updated encrypted metadata to its joined clusters. |
| `gent nodes` | List all visible nodes in the active cluster with status and last-seen information. |
| `gent node show <node>` | Inspect a node by stable ID or unambiguous name. |
| `gent node revoke <node>` | Revoke a node's cluster membership through authorized enrollment and key-rotation procedures. |
| `gent cluster` | Show overall status for the active cluster, including node availability and configuration synchronization. |
| `gent cluster status` | Explicit alias for the same cluster status view. |
| `gent clusters` | List the user's configured or authorized clusters, marking the active one. |
| `gent cluster new [name]` | Create and select a cluster, establishing its initial owner keys and policy locally. |
| `gent cluster join <cluster-id>` | Join and select an existing cluster after authentication and authorized enrollment. |
| `gent cluster switch [cluster]` | Select an already joined cluster; show a picker when the argument is omitted in an interactive terminal. |
| `gent cluster invite` | Create an authorized enrollment invitation with an expiry. |
| `gent cluster leave` | Leave the active cluster after showing the consequences for local access and pending work. |

Names are display labels. Renaming a node must preserve its stable identity, keys, and policy relationships. Reject ambiguous name lookups with a list of authorized matches and their IDs. Human-readable cluster names and node names remain encrypted in routing storage; a hosted web bridge may see only the labels included in its agent's authorized view.

Changing the active cluster selects the default context for subsequent CLI commands. It does not move existing agents, pending messages, or relay attachments into another cluster, and it does not leave the old cluster. The daemon can maintain separate connections for joined clusters. An explicit `--cluster <id-or-name>` selects a cluster for one applicable command without changing the default. Keep identities, queues, keys, and policy isolated by cluster.

Node status should distinguish connected, disconnected, degraded, and unknown or stale information. A disconnected node can still have running local agents, so do not report that they have stopped. Show freshness when using cached state. Authorized owner CLI queries can list the cluster's nodes; agent-facing queries must respect that agent's enumeration permissions and avoid leaking hidden agents or counts.

## Daemon and shell hooks

| Command | Behavior |
| --- | --- |
| `gent daemon` / `gent daemon status` | Show installation, process, service-manager, and relay connection status. |
| `gent daemon install` | Register and start a service for the current user, including supported automatic startup. |
| `gent daemon uninstall` | Stop and remove the service registration, preserving configuration, keys, and stored state. |
| `gent daemon start` | Start the installed service. |
| `gent daemon stop` | Stop the service without uninstalling it. |
| `gent daemon restart` | Restart the service and retain identity and pending work. |
| `gent daemon logs` | Show local daemon diagnostics with sensitive values redacted. |
| `gent hooks` / `gent hooks status` | Show Gent shell-hook installation and detected shell support. |
| `gent hooks install` | Install shell hooks for a supported shell, detecting it where possible. |
| `gent hooks uninstall` | Remove only the hooks and configuration entries managed by Gent. |
| `gent hooks remove` | Alias for `gent hooks uninstall`. |
| `gent completions <shell>` | Emit completion definitions for a supported shell. |

Shell hooks must use a clearly marked managed block or dedicated sourced file. Repeated installation updates that block without duplication. Removal preserves unrelated user edits and explains any manual cleanup needed if the managed block has been altered. Shell hooks do not authorize uploading arbitrary command history or establish provider session identity by themselves. Provider-specific agent hooks and MCP registration belong to the integration commands below.

## Authentication and integrations

| Command | Behavior |
| --- | --- |
| `gent auth` / `gent auth status` | Show the signed-in account and session state without printing credentials. |
| `gent auth login` | Sign in with GitHub through a browser, with a device-code flow for headless machines. |
| `gent auth logout` | Revoke the applicable local service sessions and stop using them, preserving encryption identity and local data. |
| `gent integrations` | List supported provider integrations, setup state, and verified connection security mode. |
| `gent integration install <provider>` | Install or guide the supported MCP, skill, and provider-hook setup, disclosing any web bridge that can read content. |
| `gent integration uninstall <provider>` | Remove Gent-managed integration entries while preserving unrelated provider configuration. |

Service login establishes an account session. Cluster enrollment establishes permission to receive cluster keys and participate as a trusted endpoint. Account login, recovery, or a changed SQL membership record alone cannot grant access to encrypted data. Keep user session and daemon credential lifetimes explicit so logout has predictable behavior.

Codex and Claude Code CLI setup have equal priority on macOS and Linux. Report VS Code, desktop, web, and mobile support separately; detecting a provider CLI does not establish that its GUI integration works. Both mobile providers have equal priority, starting with iOS.

A web bridge must display: "This web connection is not end-to-end encrypted. Gent's hosted bridge and your AI provider can read messages and files shared through it." Record the authenticated user's choice for that connection. Setup and relay attachment must disclose the boundary, and status must retain it. Scripts must supply an explicit choice when required; absence of an interactive terminal cannot imply acceptance. Determine security mode from the verified route, not the application name or screen. A mobile connection must never silently inherit the web exception.

## Agents and diagnostics

Additional command families should follow the same grammar as their functionality is implemented:

| Command | Behavior |
| --- | --- |
| `gent agents` | List agents the caller may discover in the selected cluster. |
| `gent agent show <agent>` | Show permitted identity, location, availability, adapter capabilities, and connection security mode. |
| `gent message send <agent> [text] [--file <path>]` | Send text, files, screenshots, or images under the caller's authority; allow repeated `--file` arguments and messages without files. |
| `gent message reply <message-id> [text] [--file <path>]` | Reply within an authorized exchange, with optional files. |
| `gent message status <message-id>` | Show authenticated delivery and response state available to the caller. |
| `gent config` | Show a redacted effective configuration for the current node and selected cluster. |
| `gent config path` | Print `~/.gent/config.toml` as an absolute path. |
| `gent config validate` | Validate local TOML without publishing changes. |
| `gent config edit` | Open the configured editor on the local TOML file. |
| `gent config apply` | Validate local changes and publish authorized signed, encrypted cluster revisions, checking for conflicts. |
| `gent doctor` | Diagnose configuration, auth, daemon, hooks, integrations, and connectivity; provide concrete repair commands. |

Messages carry an explicit authenticated user or agent identity. Do not infer sender authority from the shell's active cluster or an agent ID passed as an argument. Relay and permission-management commands must expose their acting identity and target scope when added.

Incoming delivery wakes or resumes idle agents where supported, queues for busy agents, and never interrupts automatically. Expose pending state and the reason when an adapter requires a future user turn. Bound automatic exchanges and report when a limit is reached.

`~/.gent/config.toml` holds local settings, the active cluster selection, and separate profiles for joined clusters. Only each cluster's shared policy and authorized metadata are replicated to its members. Keep authentication secrets and private keys in an OS credential store or protected local key store outside TOML.
