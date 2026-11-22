# Gent CLI design

The Cargo package is `gent-link`; it installs the `gent` binary. This document describes the planned interface. A subset is implemented for local development; see the [local proof guide](local-proof.md) for the supported commands and current limits. There is no crates.io release yet.

## Command conventions

Use nouns to identify resources and verbs to change them. Bare status commands such as `gent`, `gent node`, `gent cluster`, `gent daemon`, `gent hooks`, and `gent auth` show the current state without modifying it. Plurals such as `gent nodes`, `gent clusters`, `gent chats`, and `gent providers` list the corresponding resources. `gent providers list` is an explicit listing form. Explicit `status` subcommands are also available where they improve discoverability.

The current `gent`, `gent cluster [status]`, `gent node`, `gent nodes`, `gent chats`, `gent chat show ID`, and `gent providers [list]` views use readable text by default. IDs remain complete for copying, timestamps use GMT, and empty inventories explain how registrations appear. `gent node` labels its source as local configuration and works with a stopped daemon; the live cluster and inventory views require the daemon. The cluster summary reports signed configuration and transport readiness. Use `gent auth` or `gent doctor` for account status.

`gent ls` and `gent list` are aliases for `gent chats`. They show the cluster's
known chats grouped by node name, with node connectivity, provider, last activity
and full IDs. Nodes and chats are sorted by name; duplicate names show the most
recent activity first and retain separate IDs. Empty nodes are included, and
offline nodes retain their known registrations. Retired registrations are
collapsed into a count. `--verbose` or `--json` shows the full flat directory,
including retired entries, their last known `node_name` and `node_id`.

`chat` and `chats` are the canonical command names. The older `agent` and
`agents` spellings remain accepted aliases, including their subcommands.
History selection uses `--from-chat` and `--chat`; the previous flags still work.
JSON directory entries expose `chat_id`, with `id` retained for existing callers.
MCP uses `gent_chats`; `gent_agents` remains a compatibility alias. Identity
responses expose `chat`, retaining `agent` for existing integrations. Names,
credentials and registration IDs are preserved through this terminology change.
See [protocol versions](security.md#protocol-versions) for node wire evolution.

`gent chats clear --dry-run` previews retired registrations eligible for removal
from this node's directory. `gent chats clear` clears those entries and their
summary count. It is retryable and preserves native conversations, retained
messages and revocation records. Other nodes keep their own directory views.
The `ls` and `list` aliases accept the same subcommands.

`gent resolve rtao` selects the exact matching active conversation with the most
recent `last_activity_at`. Use `--node NAME_OR_ID` or `--provider HOST` to narrow
the match, or supply a full chat ID. Missing or tied activity returns an
ambiguous result with candidates. Resolving never sends a message or starts a
model. The CLI uses local owner access; MCP `gent_resolve` first filters by the
calling chat's enumeration permissions. See [activity metadata](discovery.md#conversation-activity).

`gent chat show ID` also reports the registration generation. Use `gent chat rename ID NAME` on the hosting node to change its Gent label while preserving identity and permissions. `--expect-generation N` compares with a previous observation; without it, the CLI reads the generation before committing. See [chat renaming](providers.md#rename-a-chat) for concurrent edits, retries and the equivalent MCP tool.

Use `--json` for scripts and structured output. It preserves the existing response fields and values, including original labels. Human output escapes terminal controls, line separators and bidirectional formatting characters in labels. A paired link or an active registration does not prove that a remote daemon or host is currently running; the readable views keep those limits visible. Selecting `--home` or `--cluster` applies equally to human and JSON output.

Every command has `--help`, examples, and errors that name the next useful command. Human output should be readable in a terminal. Support `--json` for structured output and stable exit codes for scripts. A scalar getter such as `gent node name` prints only its value and a newline. Put diagnostics on stderr, keep secrets out of output, and avoid prompts when stdin is not a terminal. Commands with missing required inputs should explain what is needed and exit rather than hang.

Interactive commands can guide missing setup steps. For automation, support explicit arguments and `--no-input`. Suggest close command matches without executing a guessed command. Destructive operations identify their target and require an explicit confirmation or documented noninteractive confirmation flag. Status, listing, and idempotent setup do not need repeated confirmations.

## Setup

With Rust and Cargo installed, the shortest intended setup is:

```sh
cargo install gent-link && gent setup
```

`gent setup` (also `gent daemon install`) sets up and starts the service, guides any missing GitHub login and cluster enrollment, then asks about each host integration, shell completions and chat discovery. Start with macOS launchd and Linux systemd user services. Report login/startup requirements, and diagnose systems without a supported service manager. Offer shell-hook installation as part of that interactive setup. Each step is also available independently:

```sh
gent auth login
gent cluster join my-cluster-id
gent node name set my-node
gent daemon install
gent daemon install --linger # Linux: start at boot and remain after logout
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
| `gent node reset` | Archive local node state for fresh enrollment, keeping the GitHub login. |
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
| `gent cluster new [name]` | Create and select a cluster, establishing its initial owner keys and policy locally. |
| `gent node add NAME` | Issue a code labeled with the cluster and node names, granting admin rights by default, or continue that exact enrolled node. Add `--no-configure` for messaging-only membership. |
| `gent cluster join [CODE]` | Join as the assigned node and start the daemon. With no code, resume a saved join or prompt for a code. |
| `gent cluster invite --out FILE` | Create a private, single-node invitation; expires after 15 minutes. |
| `gent cluster invitations` | List this owner's invitation status without secrets. |
| `gent cluster invitations revoke ID` | Close local admission, then revoke service routing; retry if offline. |
| `gent cluster leave` | Leave the active cluster after showing the consequences for local access and pending work. |

Names are display labels. Renaming a node must preserve its stable identity, keys, and policy relationships. Reject ambiguous name lookups with a list of authorized matches and their IDs. Human-readable cluster names and node names remain encrypted in routing storage; a hosted web bridge may see only the labels included in its chat's authorized view.

Each node belongs to one cluster in `~/.gent`, shared by CLI commands and all chats. A second cluster creation or join is refused. `gent node reset` stops managed services, archives old state, removes its managed host entries, and preserves the GitHub session for fresh enrollment. See [re-enrollment](service-setup.md#re-enroll-an-existing-machine).

New nodes are admins by default. The `ADMIN` column in `gent nodes` shows `owner` for the cluster's signing owner, `yes` for other admins, and `no` for restricted nodes. Admins can submit cluster configuration edits; the owner signs those edits and controls enrollment and admin grants. Use `--no-configure` when inviting a restricted node, or `gent node admin revoke NODE_UUID` on the owner to restrict an existing node. Retrying enrollment preserves any explicit restriction. The JSON response keeps the signed `can_configure` delegation flag and adds `is_owner` (`null` if the owner cannot be determined); the owner has authority independently of that flag.

`gent nodes` lists signed membership and reports `local`, `connected`, `degraded`, `disconnected`, or `unknown`, with the last verified round trip and its age. Remote connectivity requires a matching encrypted probe reply within 30 seconds; successful evidence remains recent for 90 seconds unless a newer probe times out. Its `data_link` field records pairing to the current signing key, independently of connectivity. A disconnected node can still have running local chats. Authorized owner CLI queries can list the cluster's nodes; chat-facing queries retain their enumeration permissions. See [node connectivity](node-presence.md) for status reasons, restart behavior and the requirement to upgrade both nodes from pre-presence builds.

## Daemon and shell hooks

| Command | Behavior |
| --- | --- |
| `gent desktop` | Open the daemon status window and tray. |
| `gent desktop enable` / `gent desktop disable` | Enable or disable graphical login for the companion. |
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

Shell hooks must use a clearly marked managed block or dedicated sourced file. Repeated installation updates that block without duplication. Removal preserves unrelated user edits and explains any manual cleanup needed if the managed block has been altered. Shell hooks do not authorize uploading arbitrary command history or establish provider session identity by themselves. Provider-specific chat hooks and MCP registration belong to the integration commands below. The implemented PATH/completion setup supports `--rc-file PATH`, preserves surrounding bytes, and refuses edited blocks. See [shell integration](local-proof.md#shell-integration) for startup files, activation, and tested versions.

## Authentication and integrations

| Command | Behavior |
| --- | --- |
| `gent auth` / `gent auth status` | Show the signed-in account and session state without printing credentials. |
| `gent auth login` | Sign in with GitHub through a browser, with a device-code flow for headless machines. |
| `gent auth renew` | Renew a currently active session during its final seven days, preserving credentials and encryption keys. The daemon also checks automatically. |
| `gent auth logout` | Disable and revoke this installation's service session, preserving encryption identity and local data. Retry if server revocation is pending. |
| `gent integrations` | Inspect Codex and Claude Code user-scope entries; effective host configuration is not yet verified. |
| `gent integration status [host]` | Inspect recorded installation, conflicts, or pending recovery without editing files. |
| `gent integration status codex --live` | Probe the installed endpoint and report connectivity and a bounded loaded-thread count without starting a host or model turn. |
| `gent integration status claude-code --live` | Inspect native interactive/background session metadata without starting or resuming a conversation. Supports `--config-dir PATH` and `--host-binary PATH`; see [live status](wake.md#claude-live-status). |
| `gent integration start codex` | Start or reuse Codex's native background daemon for an intact default-socket `--wake` installation. Supports `--config-dir PATH` and `--host-binary PATH`. |
| `gent integration start claude-code SESSION_ID` | Reopen an existing native background session after checking its Gent binding and `--wake` installation. Takes the full native UUID; supports the same path options. See [Claude startup](wake.md#reopen-a-claude-background-chat). |
| `gent integration recovery enable codex THREAD_ID` | Select an existing loaded chat for node-local automatic startup and idle recovery. Supports `--config-dir PATH` and `--host-binary PATH`; see [recovery conditions](host-recovery.md). |
| `gent integration recovery enable claude-code SESSION_ID` | Select a running, registered native background chat for recovery after an idle crash. Requires saved native provider settings and the full session UUID; supports the same path options. |
| `gent integration recovery list` | Inspect selected chats and their persisted recovery budget without contacting a host. |
| `gent integration recovery inspect AGENT_ID` | Check a selection's native readiness without startup; Claude reports why an uncertain history or job needs owner review. |
| `gent integration recovery disable AGENT_ID` | Remove a recovery selection while leaving native hosts and ordinary MCP delivery running. |
| `gent integration install <host>` | Install MCP, identity binding and automatic host delivery by default. Codex VS Code adds `--vscode`; repeated installs retain that route. `--no-vscode` removes only the editor route; incoming messages always queue a turn. See [host setup](wake.md). |
| `gent integration uninstall <host>` | Remove Gent-managed integration entries while preserving unrelated host configuration. |
| `gent integration remove <host>` | Alias for `gent integration uninstall`. |
| `gent mcp serve` | Serve the shared MCP interface over stdio, connecting the host's registered chats to the local daemon. |
| `gent gateway` / `gent gateway status` | Inspect local remote-MCP grants and limits without probing a listener. |
| `gent gateway clients add NAME --conversation-key KEY --out FILE` | Export a private credential for a trusted host's conversation namespace. |
| `gent gateway clients add NAME ... --tls-client-ca FILE --tls-client-name DNS` | Additionally require a certificate chaining to the pinned CA with that exact DNS SAN. Applies to MCP access and OAuth token requests. |
| `gent gateway clients add NAME ... --subject-key KEY` | Require a distinct host-owned user metadata field, pin each OAuth grant to its first reported user, and scope conversations by user. |
| `gent gateway clients add NAME ... --oauth-metadata URL --oauth-resource URL --redirect-uri URL` | Import published signed-client metadata and public keys, retaining only owner-selected callbacks. |
| `gent gateway clients keys show ID` / `keys set ID --jwks FILE --expect-revision N` | Inspect or replace a signed client's keys without changing its grants or chats. |
| `gent gateway clients keys refresh ID --expect-revision N` | Explicitly re-fetch the client's metadata and keys, preserving its callback selection. |
| `gent gateway run ... --client-metadata ID` | Enable CIMD discovery and bounded runtime metadata/key refresh for an existing signed host. Repeat for additional hosts. |
| `gent gateway clients list` / `gent gateway clients revoke ID` | Inspect or revoke remote host grants. |
| `gent gateway run` | Serve Streamable HTTP in the foreground on this node; non-loopback listeners require direct TLS. |
| `gent gateway service [status]` | Inspect listener readiness and its systemd/launchd registration; exits 3 when unavailable. |
| `gent gateway service install` | Validate and save the complete listener options, then start its user service. |
| `gent gateway service start` / `stop` / `restart` | Control the installed listener independently of its daemon. |
| `gent gateway service logs [--lines N]` | Read the listener's journal or private log. |
| `gent gateway service uninstall` / `remove` | Remove the listener service, preserving the daemon, host grants and stored chat state. |
| `gent gateway oauth requests` | Inspect pending OAuth client requests, callback URLs and decisions without displaying codes or tokens. |
| `gent gateway oauth approve ID` / `gent gateway oauth deny ID` | Decide a specific connection request as the local node owner. |

The [user-controlled gateway](gateway.md) uses authenticated host credentials and required per-call conversation metadata. `clients add --oauth-resource URL --redirect-uri URL` configures an [OAuth client](gateway-oauth.md) with PKCE and refresh support. Hosted provider support and native hosted attachment handles remain unverified.

The auth commands are implemented as a prototype. `gent auth login --headless` uses GitHub device authorization; SSH sessions select it automatically. `--no-browser` instead prints a browser authorization URL and waits on a local loopback callback. `--service ORIGIN` selects an account service. The default `https://api.gent.link` is deployed for the private trial. GitHub device consent and hosted enrollment have been verified; browser callback acceptance remains separate. See [account login](local-proof.md#account-login) before trying the commands.

Status checks the service without changing local state and never reports an offline cached identity as authenticated. Status exits 3 when signed out or unavailable. Logout disables the local credential before contacting the service; an offline attempt reports `revocation_pending`, exits 3 and can be retried. Interrupted login can also leave revocation pending until its session commits or the candidate's 15-minute creation window closes. Successful mutations exit 0; malformed state and other failures exit 1. `--json` supports these results without exposing credentials.

Service login establishes an account session. Cluster enrollment establishes permission to receive cluster keys and participate as a trusted endpoint. Account login, recovery, or a changed SQL membership record alone cannot grant access to encrypted data. Service sessions initially last 30 days; the daemon renews active sessions near expiry. Logout revokes dependent node credentials in the service-backed relay prototype; the shared-token development relay remains independent. Guided owner/invitation setup, service-backed SSH joining, automatic session renewal and manual reconnection through `gent cluster connect` are implemented. Private-file invitation enrollment passes local Worker proofs in both Linux/Mac directions, including actual-expiry continuation. Those proofs use synthetic login and SSH forwarding for local Workers. Real GitHub device consent now passes against the deployed private trial. Code enrollment and encrypted messages/files pass between physical Linux and Mac endpoints through the deployed services. The live proof reuses one real account session; the local fixture separately checks independent sessions. Hosted chat enrollment remains unfinished.

Codex and Claude Code CLI setup have equal priority on macOS and Linux. Report VS Code, desktop, web, and mobile support separately; detecting a provider CLI does not establish that its GUI integration works. Both mobile providers have equal priority, starting with iOS.

A web bridge must display: "This web connection is not end-to-end encrypted. Gent's hosted bridge and your AI provider can read messages and files shared through it." Record the authenticated user's choice for that connection. Setup and relay attachment must disclose the boundary, and status must retain it. Scripts must supply an explicit choice when required; absence of an interactive terminal cannot imply acceptance. Determine security mode from the verified route, not the application name or screen. A mobile connection must never silently inherit the web exception.

## Providers

Providers are host labels announced by registered chats. Connecting a host to Gent's MCP server allows its chats to register, without configuring inference APIs in Gent. See [MCP hosts and chat registration](providers.md) for identity, delivery, and capability behavior.

| Command | Behavior |
| --- | --- |
| `gent providers` / `gent providers list` | List providers represented by visible chat registrations in the selected cluster, with node locations, availability, and known host capabilities. |
| `gent provider show <provider>` | Show permitted metadata and registered chats for a host label; never imply that the label authenticates a chat. |

Example host setup and inspection:

```sh
gent integration install codex
gent integration install claude-code
gent providers list
gent chats
```

For another MCP-capable host, configure `gent mcp serve` as its stdio server and use the same registration tools. Setup helpers may detect existing Codex and Claude Code integration configuration; model settings and credentials stay with those hosts. Provider listing reads Gent registrations and does not start inference or scan the network.

## Chats and diagnostics

Additional command families should follow the same grammar as their functionality is implemented:

| Command | Behavior |
| --- | --- |
| `gent chats` | List chats the caller may discover in the selected cluster. |
| `gent permission explain ACTOR_UUID PEER_UUID` | Explain current signed policy gates and matching rules under local owner authority. See [permission checks](permissions.md). |
| `gent permission inherit ACTOR PEER --permission enumerate receive send` | Remove overrides for the exact selectors and permissions, restoring the remaining cluster rules. |
| `gent group` / `gent group list` / `gent groups` | List owner-visible groups and members. |
| `gent group new NAME` / `gent group show NAME` / `gent group delete NAME` | Create, inspect, or delete an unreferenced group. |
| `gent group member add GROUP CHAT_UUID...` / `gent group member remove GROUP CHAT_UUID...` | Change up to 32 members while preserving unrelated membership. |
| `gent group admin grant ADMIN_UUID GROUP MEMBER_SELECTOR --action add remove` | Delegate group membership within an explicit member scope. This affects all rules and existing editing scopes using the group. |
| `gent group admin list` / `revoke GRANT_UUID` / `history [--chat UUID] [--before ROW]` | Inspect, revoke, and audit separate membership grants. See [group administration](administration.md#group-membership). |
| `gent permission admin grant ADMIN_UUID ACTOR_SELECTOR PEER_SELECTOR --permission ...` | Delegate expiring exact-pair permission editing within the selected scope; `--selector-rules` also permits persistent selector rules affecting hidden and future matches. See [chat administration](administration.md). |
| `gent permission admin list` / `revoke GRANT_UUID` | Inspect or revoke editing grants; already accepted rules remain in force. |
| `gent permission admin history [--chat UUID] [--before ROW]` | Page through local and received chat-edit audit records under owner authority. |
| `gent chat show <chat>` | Show permitted identity, location, availability, MCP/host capabilities, and connection security mode. |
| `gent files [status]` | Show local encrypted storage usage, tracked handoff copies, cleanup issues, and retained record counts under owner authority. |
| `gent files clean [--dry-run]` | Reap expired encrypted objects and process one bounded batch of expired handoff copies. Preserve changed, replaced, and untracked files; `--dry-run` previews without deleting. |
| `gent message send <chat> [text] [--file <path>]` | Send text, files, screenshots, or images under the caller's authority; allow repeated `--file` arguments and messages without files. |
| `gent message reply <message-id> [text] [--file <path>]` | Reply within an authorized exchange, with optional files. |
| `gent message status <message-id>` | Show authenticated delivery and response state available to the caller. |
| `gent config` | Show a redacted effective configuration for the current node and selected cluster. |
| `gent config path` | Print `~/.gent/config.toml` as an absolute path. |
| `gent config validate` | Validate local TOML without publishing changes. |
| `gent config edit [--editor COMMAND]` | Open a private draft with `VISUAL`, `EDITOR`, or `vi`; validate and save locally without publishing. Requires an interactive terminal. |
| `gent config apply` | Submit local cluster/node names and policy to the active owner; the newest accepted revision replaces earlier shared settings. |
| `gent config requests` | List the latest 100 configuration requests submitted on this node. |
| `gent config request REQUEST_UUID` | Inspect a request's queued, applied, or rejected status and its revision or rejection reason. |
| `gent doctor [--online]` | Inspect local configuration, auth, daemon, relay observations, hooks and MCP installation without changing state or starting inference. `--online` also checks the saved account session. See [diagnostics](diagnostics.md). |

Messages carry an explicit authenticated user or chat identity. Do not infer sender authority from the shell's active cluster or a chat ID passed as an argument. Relay and permission-management commands must expose their acting identity and target scope when added.

`gent config edit` edits this node’s `~/.gent/config.toml`. `--editor COMMAND` overrides the environment; quote executable paths and arguments containing spaces. Arguments are passed literally without shell expansion. GUI editors need their wait option, for example `gent config edit --editor 'code --wait'`. `--json` and redirected stdin or stdout are refused. See [editing configuration](local-proof.md#edit-local-configuration) for validation, conflicts and retained drafts.

Configuration mutations accept `--request-id UUID` for retrying an identical proposal. A retry returns the original result; reusing the ID with different content fails. The CLI waits about five seconds for acceptance, then reports a durable `queued` request if the owner remains unavailable. Queued edits survive daemon restarts and do not change effective policy before acceptance. Rejected mutations exit nonzero; `gent config request` can inspect their recorded reason. See [configuration administration](local-proof.md#configuration-administration) for grants, retries, and offline behavior.

Queued status includes `payload_retained`, indicating whether this node still has the full input after transport cleanup. New requests retain it until their authenticated result commits. Older missing payloads can be restored by retrying the identical proposal with its original request ID; a summary alone cannot recreate a policy. `gent history` reports the separate pending-payload budget and missing count. Automatic rerouting to a successor is still part of the unfinished owner-activation workflow.

Incoming delivery wakes or resumes idle chats where the host supports it, queues for busy chats, and never interrupts automatically. Expose pending state and the reason when the host requires a future user turn or inbox check. Bound automatic exchanges and report when a limit is reached.

Distinguish a mobile notification from a chat turn or user response. A notification can invite the user to return without starting a turn. Server coordinators use the ordinary wake/queue policy and can continue authorized work while the phone is unavailable.

`~/.gent/config.toml` holds local settings and the node’s sole cluster configuration. Only each cluster's shared policy and authorized metadata are replicated to its members. Keep authentication secrets and private keys in an OS credential store or protected local key store outside TOML.

## Local message history (implemented)

| Command | Behavior |
| --- | --- |
| `gent history` / `gent history status` | Report Gent messages, payload usage, exchanges, import retries, relay selections, and pending events. |
| `gent history clean --dry-run` | Preview one bounded cleanup batch. |
| `gent history clean` | Retire exchanges seven days after expiry and eligible chat retry records. |

All support `--json`. Cleanup runs automatically at startup and every 15 minutes. These owner commands require no model call. Message limits and the UUIDv7 chat-request contract are documented in [message history and retries](local-proof.md#message-history-and-retries); encrypted transport and provider histories are separate.

## Encrypted transport storage (implemented)

| Command | Behavior |
| --- | --- |
| `gent transport` / `gent transport status` | Report packet quotas, receiver checkpoints, tombstones, replay evidence, full configuration history, and interrupted joins holding history. |
| `gent transport clean --dry-run` | Verify and preview one bounded compaction batch. |
| `gent transport clean` | Retire confirmed packet bodies, compact redundant copies and eligible full configurations, and discard old replay evidence. |

All support `--json` and use local owner authority. Authenticated receiver checkpoints allow confirmed ciphertext to retire and release packet capacity. Unconfirmed packets remain available for offline peers. See [encrypted transport storage](local-proof.md#encrypted-transport-storage) for limits, migration, and recovery boundaries.

## Backup and recovery

`gent recovery status` reports the selected node's owner epoch, signing stop, local handoff preparation counts and decision-journal storage reservations. It requires local owner RPC access and returns no signing keys or journal contents. Handoff preparation remains a trusted Rust API; CLI activation is unavailable. See [owner succession](owner-succession.md).

`gent recovery challenge --out FILE` pins the selected node's accepted configuration in a private challenge. `gent recovery witness CHALLENGE --out FILE` records its node-signed observation. `gent recovery inspect CHALLENGE [REPORTS...]` compares reports offline, showing missing nodes and differing or conflicting checkpoints without changing authority. Challenge and witness require local owner RPC access; inspection needs no daemon and rejects `--cluster`. Files must be private, outputs must be new, and collection must finish within 15 minutes. See [owner recovery evidence and its limits](owner-recovery.md). Owner replacement remains unfinished.

`gent backup keygen --output KEY` creates a private recovery identity. `gent backup create ARCHIVE --identity KEY` captures a stopped node. `verify` checks the complete archive; `inspect [--files]` verifies before returning its metadata. `gent backup extract ARCHIVE --identity KEY --output DIRECTORY` publishes a verified, guarded offline copy at a new path. Keys, archives and extraction outputs are never overwritten. Only `create` uses cluster selection. See [backup scope, limits and examples](recovery.md).

`gent history import ARCHIVE --identity KEY --from-chat OLD_UUID --chat CURRENT_UUID` assigns retained historical messages/files to an existing local chat. Use `--from-import IMPORT_UUID` instead to select an assignment saved in a later backup. `gent history imports` lists assignments; removal and restoration require their current access revision.

`gent chat recover ARCHIVE --identity KEY --from-chat OLD_UUID --name NAME` prepares a fresh chat and assigns that history. Choose `--binding NEW_PATH`, `--host codex|claude-code --conversation HOST_ID`, or `--gateway-client CLIENT_UUID --conversation HOST_ID`. Claude children also use `--subagent`; gateway hosts with a user policy require `--subject HOST_USER_ID`. The destination must be unused, and `--from-import` works here too. Reconnect the host to the replacement node after recovery. See [conversation recovery](recovery.md#recover-a-conversation-binding) for retry behavior and gateway authentication requirements.

Restored-node activation remains unimplemented. The CLI refuses state marked `recovery-required.json` before contacting a daemon. Archived node state cannot redirect commands to a live directory. Removing the marker does not make old encryption state safe to resume.

## Synchronization progress

`gent sync` (or `gent sync status`) reports this daemon's encrypted transport
progress, queued outgoing records, packet counters and recent contact. `gent ls`
and cluster status include a compact summary. Use `--json` for the full snapshot;
`gent ls --json` retains its existing chat array.

States distinguish startup, peer connection setup, catch-up, retries, expired
cluster authority and idle transport. Counters reset when the daemon starts.
Idle means no known local transport backlog, not a complete cluster directory:
offline nodes and native host discovery may still have additional chats. Removed
nodes do not contribute to the outgoing queue count.
