# Gent CLI design

The Cargo package is `gent-link`; it installs the `gent` binary. This document describes the planned interface. A subset is implemented for local development; see the [local proof guide](local-proof.md) for the supported commands and current limits. There is no crates.io release yet.

## Command conventions

Use nouns to identify resources and verbs to change them. Bare status commands such as `gent`, `gent node`, `gent cluster`, `gent daemon`, `gent hooks`, and `gent auth` show the current state without modifying it. Plurals such as `gent nodes`, `gent clusters`, `gent agents`, and `gent providers` list the corresponding resources. `gent providers list` is an explicit listing form. Explicit `status` subcommands are also available where they improve discoverability.

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

The development build implements `gent cluster join CLUSTER_UUID --via user@owner-host --name laptop` using an already trusted SSH owner account and a configured development relay. Optional `--remote-gent`, `--remote-home`, and `--relay-endpoint` arguments select nondefault paths or a tunneled relay. It preserves node identity on interrupted retries and imports only the development transport credential, never the owner's signing key. Service-backed SSH joins now preserve prior login state and issue a separate node credential; sign into the same account and service first. They use the pinned relay origin and reject `--relay-endpoint` overrides. Private-file enrollment now supports `gent cluster invite --out FILE` and `gent cluster join --invite-file FILE --name NODE`, with list/revoke commands under `gent cluster invitations`. See [invitation enrollment](invitation-enrollment.md) for private transfer, retries, and explicit continuation. See [the tested SSH workflow](local-proof.md#join-another-machine-through-ssh).

To replace a lost joined node, run the SSH join from a fresh directory with `--replace-node OLD_NODE_UUID`, or have the owner issue `gent cluster invite --replace-node OLD_NODE_UUID --out FILE` and join using that private file. The owner retires the old identity and enrolls the new one in one signed revision. Retry using the same directory and options. Selected archived history and fresh conversation bindings can be recovered separately; activation of old encryption state and owner replacement remain unavailable. See [recovery](recovery.md#replace-a-lost-joined-node).

Setup must recover from an interrupted step and be safe to rerun. Preserve device identity, existing settings, and unrelated shell configuration. End with a concise status report and the next action, if any.

The current build guides missing login and cluster enrollment through `gent daemon install`. Use `--new NAME` or `--invite-file FILE --name NODE` for explicit choices, `--headless` for device login, and `--no-input` with an existing login for scripts. `--hooks --shell zsh` (also Bash/Fish) adds shell setup. Completed installs preserve identity and the running daemon; interrupted setup reuses the existing enrollment journals. See [service setup](service-setup.md) for retry behavior. `gent daemon install --local [NAME]` initializes a development cluster. `gent cluster connect` resumes setup or replaces a revoked/expired credential while the daemon is stopped; the daemon automatically renews active account sessions before expiry. See [daemon services](local-proof.md#daemon-services) for the tested systemd/launchd commands, startup context, and state preservation. `gent daemon status` exits 3 when stopped or unavailable while still returning structured status; lifecycle failures exit 1, and successful mutations exit 0.

`gent integration config codex` and `gent integration config claude-code` currently print MCP configuration fragments. The latter includes a required per-call host binding hook. `gent mcp serve --host HOST` selects persistent conversation credentials from host metadata; generic clients can still use explicit `--binding` files. See [host conversation bindings](local-proof.md#host-conversation-bindings) for setup and limitations. `gent integration install`, `status`, and `uninstall` now manage user-scope entries for both CLI hosts; `gent integrations` lists them. See [installation and recovery](local-proof.md#install-host-integrations) for paths, `--config-dir`, ownership, and status semantics. Zsh, Bash, and Fish shell setup is available through `gent hooks install`.

## Nodes and clusters

| Command | Behavior |
| --- | --- |
| `gent` | Show the current node, active cluster, authentication, and daemon status. |
| `gent node` | Show details for the current node. |
| `gent node name` | Print the current node's name. |
| `gent node name set my-node` | Rename the current node and publish its updated encrypted metadata to its joined clusters. |
| `gent node admin grant NODE_UUID` | On the active owner, authorize an enrolled node to submit configuration edits. |
| `gent node admin revoke NODE_UUID` | On the active owner, revoke that delegated capability; pending edits are checked at acceptance. |
| `gent nodes` | List all visible nodes in the active cluster with status and last-seen information. |
| `gent node show <node>` | Inspect a node by stable ID or unambiguous name. |
| `gent node revoke <node>` | Revoke a node's cluster membership through authorized enrollment and key-rotation procedures. |
| `gent cluster` | Show overall status for the active cluster, including node availability and configuration synchronization. |
| `gent cluster status` | Explicit alias for the same cluster status view. |
| `gent cluster connect` | Resume service setup or replace an invalid relay credential on an owner or joined node, preserving local identity. Stop the daemon first. |
| `gent cluster renew` | Renew the signed configuration lease locally on the owner, or request renewal from an authorized joined node. |
| `gent clusters` | List the user's configured or authorized clusters, marking the active one. |
| `gent cluster new [name]` | Create and select a cluster, establishing its initial owner keys and policy locally. |
| `gent cluster join <cluster-id>` | Join and select an existing cluster after authentication and authorized enrollment. |
| `gent cluster switch [cluster]` | Select an already joined cluster; show a picker when the argument is omitted in an interactive terminal. |
| `gent cluster invite --out FILE` | Create a private, single-node invitation; expires after 15 minutes. |
| `gent cluster invitations` | List this owner's invitation status without secrets. |
| `gent cluster invitations revoke ID` | Close local admission, then revoke service routing; retry if offline. |
| `gent cluster leave` | Leave the active cluster after showing the consequences for local access and pending work. |

Names are display labels. Renaming a node must preserve its stable identity, keys, and policy relationships. Reject ambiguous name lookups with a list of authorized matches and their IDs. Human-readable cluster names and node names remain encrypted in routing storage; a hosted web bridge may see only the labels included in its agent's authorized view.

Changing the active cluster selects the default context for subsequent CLI commands. It does not move existing agents, pending messages, or relay attachments into another cluster, and it does not leave the old cluster. The daemon can maintain separate connections for joined clusters. An explicit `--cluster <id-or-name>` selects a cluster for one applicable command without changing the default. Keep identities, queues, keys, and policy isolated by cluster.

Local profiles support `gent clusters`, `gent cluster add PATH`, `gent cluster switch [ID_OR_UNIQUE_NAME]` and `--cluster`. Creation and joining through an initialized primary directory reserve a separate profile and select it after setup succeeds. Explicit `gent daemon install --new`, `--local`, or `--invite-file --name` use the same journal; bare install uses the selected profile. Repeat the original setup command after interruption. Each profile has its own daemon, keys and state directory; managed service profiles share a pinned account-session store. Installed daemon and MCP entry points stay on their original cluster across switches. See [local cluster profiles](local-proof.md#local-cluster-profiles) for retry, shared-login and reconnect behavior.

Node status should distinguish connected, disconnected, degraded, and unknown or stale information. The current `gent nodes` command lists signed membership, reporting the current node as `local` and remote presence as `unknown`. Its `data_link` field reports an established encrypted link to the listed node's current signing key; it does not prove live connectivity. Additional peer links form automatically after joining. A disconnected node can still have running local agents, so do not report that they have stopped. Show freshness when using cached state. Authorized owner CLI queries can list the cluster's nodes; agent-facing queries must respect that agent's enumeration permissions and avoid leaking hidden agents or counts.

## Daemon and shell hooks

| Command | Behavior |
| --- | --- |
| `gent daemon` / `gent daemon status` | Show installation, process, service-manager, and relay connection status. |
| `gent daemon install` | Register and start a service for the current user, including supported automatic startup. |
| `gent daemon uninstall` | Stop and remove the service registration, preserving configuration, keys, and stored state. |
| `gent daemon start` | Start the installed service. |
| `gent daemon stop` | Stop the service without uninstalling it. |
| `gent daemon restart` | Restart the service and retain identity and pending work. |
| `gent daemon logs [--lines N]` | Show recent daemon diagnostics from the service journal or private log file. Keep credentials out of diagnostic output. |
| `gent hooks` / `gent hooks status` | Show Gent shell-hook installation and detected shell support. |
| `gent hooks install` | Install PATH and completion setup for Zsh, Bash, or Fish; detect from `SHELL` or accept `--shell`. |
| `gent hooks uninstall` | Remove only the hooks and configuration entries managed by Gent. |
| `gent hooks remove` | Alias for `gent hooks uninstall`. |
| `gent completions <shell>` | Emit completion definitions for `bash`, `zsh`, or `fish`, without requiring configured state. |

Shell hooks must use a clearly marked managed block or dedicated sourced file. Repeated installation updates that block without duplication. Removal preserves unrelated user edits and explains any manual cleanup needed if the managed block has been altered. Shell hooks do not authorize uploading arbitrary command history or establish provider session identity by themselves. Provider-specific agent hooks and MCP registration belong to the integration commands below. The implemented PATH/completion setup supports `--rc-file PATH`, preserves surrounding bytes, and refuses edited blocks. See [shell integration](local-proof.md#shell-integration) for startup files, activation, and tested versions.

## Authentication and integrations

| Command | Behavior |
| --- | --- |
| `gent auth` / `gent auth status` | Show the signed-in account and session state without printing credentials. |
| `gent auth login` | Sign in with GitHub through a browser, with a device-code flow for headless machines. |
| `gent auth renew` | Renew a currently active session during its final seven days, preserving credentials and encryption keys. The daemon also checks automatically. |
| `gent auth logout` | Disable and revoke this installation's service session, preserving encryption identity and local data. Retry if server revocation is pending. |
| `gent integrations` | Inspect Codex and Claude Code user-scope entries; effective host configuration is not yet verified. |
| `gent integration status [host]` | Inspect recorded installation, conflicts, or pending recovery without editing files. |
| `gent integration install <host>` | Install the common MCP server and required Claude identity hook in user settings. Skills and lifecycle hooks remain pending. |
| `gent integration uninstall <host>` | Remove Gent-managed integration entries while preserving unrelated host configuration. |
| `gent integration remove <host>` | Alias for `gent integration uninstall`. |
| `gent mcp serve` | Serve the shared MCP interface over stdio, connecting the host's registered agents to the local daemon. |
| `gent gateway` / `gent gateway status` | Inspect local remote-MCP grants and limits without probing a listener. |
| `gent gateway clients add NAME --conversation-key KEY --out FILE` | Export a private credential for a trusted host's conversation namespace. |
| `gent gateway clients add NAME ... --tls-client-ca FILE --tls-client-name DNS` | Additionally require a certificate chaining to the pinned CA with that exact DNS SAN. Applies to MCP access and OAuth token requests. |
| `gent gateway clients add NAME ... --subject-key KEY` | Require a distinct host-owned user metadata field, pin each OAuth grant to its first reported user, and scope conversations by user. |
| `gent gateway clients add NAME ... --oauth-metadata URL --oauth-resource URL --redirect-uri URL` | Import published signed-client metadata and public keys, retaining only owner-selected callbacks. |
| `gent gateway clients keys show ID` / `keys set ID --jwks FILE --expect-revision N` | Inspect or replace a signed client's keys without changing its grants or agents. |
| `gent gateway clients keys refresh ID --expect-revision N` | Explicitly re-fetch the client's metadata and keys, preserving its callback selection. |
| `gent gateway run ... --client-metadata ID` | Enable CIMD discovery and bounded runtime metadata/key refresh for an existing signed host. Repeat for additional hosts. |
| `gent gateway clients list` / `gent gateway clients revoke ID` | Inspect or revoke remote host grants. |
| `gent gateway run` | Serve Streamable HTTP in the foreground with explicit `--home` or `--cluster`; non-loopback listeners require direct TLS. |
| `gent gateway oauth requests` | Inspect pending OAuth client requests, callback URLs and decisions without displaying codes or tokens. |
| `gent gateway oauth approve ID` / `gent gateway oauth deny ID` | Decide a specific connection request as the local node owner. |

The [user-controlled gateway](gateway.md) uses authenticated host credentials and required per-call conversation metadata. `clients add --oauth-resource URL --redirect-uri URL` configures an [OAuth client](gateway-oauth.md) with PKCE and refresh support. Hosted provider support and native hosted attachment handles remain unverified.

The auth commands are implemented as a prototype. `gent auth login --headless` uses GitHub device authorization; SSH sessions select it automatically. `--no-browser` instead prints a browser authorization URL and waits on a local loopback callback. `--service ORIGIN` selects an account service. The default `https://api.gent.link` is not deployed. Both paths pass local fixture proofs on Linux and macOS; real GitHub consent remains unverified. See [account login](local-proof.md#account-login) before trying the commands.

Status checks the service without changing local state and never reports an offline cached identity as authenticated. Status exits 3 when signed out or unavailable. Logout disables the local credential before contacting the service; an offline attempt reports `revocation_pending`, exits 3 and can be retried. Interrupted login can also leave revocation pending until its session commits or the candidate's 15-minute creation window closes. Successful mutations exit 0; malformed state and other failures exit 1. `--json` supports these results without exposing credentials.

Service login establishes an account session. Cluster enrollment establishes permission to receive cluster keys and participate as a trusted endpoint. Account login, recovery, or a changed SQL membership record alone cannot grant access to encrypted data. Service sessions initially last 30 days; the daemon renews active sessions near expiry. Logout revokes dependent node credentials in the service-backed relay prototype; the shared-token development relay remains independent. Guided owner/invitation setup, service-backed SSH joining, automatic session renewal and manual reconnection through `gent cluster connect` are implemented. Private-file invitation enrollment passes local Worker proofs in both Linux/Mac directions, including actual-expiry continuation. Those proofs use synthetic login and SSH forwarding for local Workers. Real GitHub consent, deployed service validation and hosted agent enrollment remain unfinished.

Codex and Claude Code CLI setup have equal priority on macOS and Linux. Report VS Code, desktop, web, and mobile support separately; detecting a provider CLI does not establish that its GUI integration works. Both mobile providers have equal priority, starting with iOS.

A web bridge must display: "This web connection is not end-to-end encrypted. Gent's hosted bridge and your AI provider can read messages and files shared through it." Record the authenticated user's choice for that connection. Setup and relay attachment must disclose the boundary, and status must retain it. Scripts must supply an explicit choice when required; absence of an interactive terminal cannot imply acceptance. Determine security mode from the verified route, not the application name or screen. A mobile connection must never silently inherit the web exception.

## Providers

Providers are host labels announced by registered agents. Connecting a host to Gent's MCP server allows its agents to register, without configuring inference APIs in Gent. See [MCP hosts and agent registration](providers.md) for identity, delivery, and capability behavior.

| Command | Behavior |
| --- | --- |
| `gent providers` / `gent providers list` | List providers represented by visible agent registrations in the selected cluster, with node locations, availability, and known host capabilities. |
| `gent provider show <provider>` | Show permitted metadata and registered agents for a host label; never imply that the label authenticates an agent. |

Example host setup and inspection:

```sh
gent integration install codex
gent integration install claude-code
gent providers list
gent agents
```

For another MCP-capable host, configure `gent mcp serve` as its stdio server and use the same registration tools. Setup helpers may detect existing Codex and Claude Code integration configuration; model settings and credentials stay with those hosts. Provider listing reads Gent registrations and does not start inference or scan the network.

## Agents and diagnostics

Additional command families should follow the same grammar as their functionality is implemented:

| Command | Behavior |
| --- | --- |
| `gent agents` | List agents the caller may discover in the selected cluster. |
| `gent permission explain ACTOR_UUID PEER_UUID` | Explain current signed policy gates and matching rules under local owner authority. See [permission checks](permissions.md). |
| `gent group` / `gent group list` / `gent groups` | List owner-visible groups and members. |
| `gent group new NAME` / `gent group show NAME` / `gent group delete NAME` | Create, inspect, or delete an unreferenced group. |
| `gent group member add GROUP AGENT_UUID...` / `gent group member remove GROUP AGENT_UUID...` | Change up to 32 members while preserving unrelated membership. |
| `gent group admin grant ADMIN_UUID GROUP MEMBER_SELECTOR --action add remove` | Delegate group membership within an explicit member scope. This affects all rules and existing editing scopes using the group. |
| `gent group admin list` / `revoke GRANT_UUID` / `history [--agent UUID] [--before ROW]` | Inspect, revoke, and audit separate membership grants. See [group administration](administration.md#group-membership). |
| `gent permission admin grant ADMIN_UUID ACTOR_SELECTOR PEER_SELECTOR --permission ...` | Delegate expiring exact-pair permission editing within the selected scope; `--selector-rules` also permits persistent selector rules affecting hidden and future matches. See [agent administration](administration.md). |
| `gent permission admin list` / `revoke GRANT_UUID` | Inspect or revoke editing grants; already accepted rules remain in force. |
| `gent permission admin history [--agent UUID] [--before ROW]` | Page through local and received agent-edit audit records under owner authority. |
| `gent agent show <agent>` | Show permitted identity, location, availability, MCP/host capabilities, and connection security mode. |
| `gent files [status]` | Show local encrypted storage usage, tracked handoff copies, cleanup issues, and retained record counts under owner authority. |
| `gent files clean [--dry-run]` | Reap expired encrypted objects and process one bounded batch of expired handoff copies. Preserve changed, replaced, and untracked files; `--dry-run` previews without deleting. |
| `gent message send <agent> [text] [--file <path>]` | Send text, files, screenshots, or images under the caller's authority; allow repeated `--file` arguments and messages without files. |
| `gent message reply <message-id> [text] [--file <path>]` | Reply within an authorized exchange, with optional files. |
| `gent message status <message-id>` | Show authenticated delivery and response state available to the caller. |
| `gent config` | Show a redacted effective configuration for the current node and selected cluster. |
| `gent config path` | Print `~/.gent/config.toml` as an absolute path. |
| `gent config validate` | Validate local TOML without publishing changes. |
| `gent config edit` | Open the configured editor on the local TOML file. |
| `gent config apply` | Submit local cluster/node names and policy to the active owner; the newest accepted revision replaces earlier shared settings. |
| `gent config requests` | List the latest 100 configuration requests submitted on this node. |
| `gent config request REQUEST_UUID` | Inspect a request's queued, applied, or rejected status and its revision or rejection reason. |
| `gent doctor [--online]` | Inspect local configuration, auth, daemon, relay observations, hooks and MCP installation without changing state or starting inference. `--online` also checks the saved account session. See [diagnostics](diagnostics.md). |

Messages carry an explicit authenticated user or agent identity. Do not infer sender authority from the shell's active cluster or an agent ID passed as an argument. Relay and permission-management commands must expose their acting identity and target scope when added.

Configuration mutations accept `--request-id UUID` for retrying an identical proposal. A retry returns the original result; reusing the ID with different content fails. The CLI waits about five seconds for acceptance, then reports a durable `queued` request if the owner remains unavailable. Queued edits survive daemon restarts and do not change effective policy before acceptance. Rejected mutations exit nonzero; `gent config request` can inspect their recorded reason. See [configuration administration](local-proof.md#configuration-administration) for grants, retries, and offline behavior.

Incoming delivery wakes or resumes idle agents where the host supports it, queues for busy agents, and never interrupts automatically. Expose pending state and the reason when the host requires a future user turn or inbox check. Bound automatic exchanges and report when a limit is reached.

Distinguish a mobile notification from an agent turn or user response. A notification can invite the user to return without starting a turn. Server coordinators use the ordinary wake/queue policy and can continue authorized work while the phone is unavailable.

`~/.gent/config.toml` holds local settings, the active cluster selection, and separate profiles for joined clusters. Only each cluster's shared policy and authorized metadata are replicated to its members. Keep authentication secrets and private keys in an OS credential store or protected local key store outside TOML.

## Local message history (implemented)

| Command | Behavior |
| --- | --- |
| `gent history` / `gent history status` | Report Gent messages, payload usage, exchanges, import retries, relay selections, and pending events. |
| `gent history clean --dry-run` | Preview one bounded cleanup batch. |
| `gent history clean` | Retire exchanges seven days after expiry and eligible agent retry records. |

All support `--json`. Cleanup runs automatically at startup and every 15 minutes. These owner commands require no model call. Message limits and the UUIDv7 agent-request contract are documented in [message history and retries](local-proof.md#message-history-and-retries); encrypted transport and provider histories are separate.

## Encrypted transport storage (implemented)

| Command | Behavior |
| --- | --- |
| `gent transport` / `gent transport status` | Report packet quotas, receiver checkpoints, tombstones, replay evidence, full configuration history, and interrupted joins holding history. |
| `gent transport clean --dry-run` | Verify and preview one bounded compaction batch. |
| `gent transport clean` | Retire confirmed packet bodies, compact redundant copies and eligible full configurations, and discard old replay evidence. |

All support `--json` and use local owner authority. Authenticated receiver checkpoints allow confirmed ciphertext to retire and release packet capacity. Unconfirmed packets remain available for offline peers. See [encrypted transport storage](local-proof.md#encrypted-transport-storage) for limits, migration, and recovery boundaries.

## Backup and recovery

`gent backup keygen --output KEY` creates a private recovery identity. `gent backup create ARCHIVE --identity KEY` captures a stopped node. `verify` checks the complete archive; `inspect [--files]` verifies before returning its metadata. `gent backup extract ARCHIVE --identity KEY --output DIRECTORY` publishes a verified, guarded offline copy at a new path. Keys, archives and extraction outputs are never overwritten. Only `create` uses cluster selection. See [backup scope, limits and examples](recovery.md).

`gent history import ARCHIVE --identity KEY --from-agent OLD_UUID --agent CURRENT_UUID` assigns retained historical messages/files to an existing local agent. Use `--from-import IMPORT_UUID` instead to select an assignment saved in a later backup. `gent history imports` lists assignments; removal and restoration require their current access revision.

`gent agent recover ARCHIVE --identity KEY --from-agent OLD_UUID --name NAME` prepares a fresh agent and assigns that history. Choose `--binding NEW_PATH`, `--host codex|claude-code --conversation HOST_ID`, or `--gateway-client CLIENT_UUID --conversation HOST_ID`. Claude children also use `--subagent`; gateway hosts with a user policy require `--subject HOST_USER_ID`. The destination must be unused, and `--from-import` works here too. Reconnect the host to the replacement node after recovery. See [conversation recovery](recovery.md#recover-a-conversation-binding) for retry behavior and gateway authentication requirements.

Restored-node activation remains unimplemented. The CLI refuses state marked `recovery-required.json` before selecting a cluster profile or contacting a daemon. A copied profile registry cannot redirect commands to a live external node. Removing the marker does not make old encryption state safe to resume.
