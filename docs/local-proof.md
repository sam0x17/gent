# Local development proof

The development implementation connects local and directly paired remote agents through the same stdio MCP tools. It has no model API clients or provider catalog. Unknown host labels work without adding Gent code. The daemon owns identity, policy, and durable delivery; each host retains inference and its broader conversation history.

This proof runs on macOS and Linux. Agent messages and attachments stay in the trusted user's local SQLite database. An optional development relay carries end-to-end encrypted configuration, agent announcements, messages, and files between SSH-paired nodes. A separate account and service-relay prototype runs through local Workers; no production service is deployed. Other software running as the same user can access endpoint state and credentials. Do not treat an agent with unrestricted shell access as isolated from the operating-system user.

The source CLI also has [recoverable service setup](service-setup.md), tested against local Workers with independent credentials for owner and joined nodes. Additional nodes can join through a trusted SSH owner account or a [private invitation file](invitation-enrollment.md). These local proofs do not establish deployed service access or real GitHub consent.

## Build and verify

Use Rust 1.98 or newer and Python 3 for the process-level test. Run from this repository's root:

```sh
cargo build --locked --bin gent
cargo test --workspace --locked
python3 scripts/smoke_mcp.py target/debug/gent
```

The smoke test starts a daemon and three independent MCP clients in a temporary directory. It checks registration, hidden peers, default-deny permissions, image bytes and MCP image content blocks, scoped replies, duplicate suppression, restart recovery, and revocation. It also checks relay grants, ordered turns, progress, cancellation, and final responses with images through the public tools. It makes no model calls and removes its test state afterward. These checks passed on Linux x86_64 and macOS arm64. The SSH pairing proof additionally passes those relay turns across the two physical machines through the local Worker, including both daemon restarts.

Separate real-host tests pass for Codex and Claude Code CLIs on both OSes using explicit bindings and host-supplied conversation metadata. Each host registers a synthetic conversation, resumes after a daemon restart, retrieves and identifies an image, and replies with identical file bytes. The host-metadata proof also checks concurrent chats using the same connector configuration and isolation after a fork. Automatic idle wake/resume remains untested.

To run those tests with an already authenticated host:

```sh
python3 scripts/prove_host.py --host codex
python3 scripts/prove_host.py --host claude-code
```

These opt-in tests consume model usage and create a synthetic conversation in the host's session store. They retain private temporary Gent state for inspection and stop their test daemons afterward. Existing host settings are not edited. Codex defaults to isolated per-run settings; add `--use-host-config` when its model access depends on a configured provider. That option requires Python 3.11 or newer and disables other configured MCP servers and plugins for the invocation. See the script's `--help` for a binary-path override.

For source installation:

```sh
cargo install --locked --path crates/gent-link
```

The installed binary is `gent`. Packages remain unpublished; `cargo install gent-link` is a future release interface.

## Start a local cluster

Choose a dedicated state directory; Gent creates it with private permissions. Existing directories must already be private. The default is `~/.gent`; `--home` overrides `GENT_HOME`, which overrides that default.

```sh
export GENT_HOME="$HOME/.gent-dev"
gent daemon install --local demo
```

This initializes an unconfigured development cluster and starts a service for the current user. On an already configured or SSH-joined node, use `gent daemon install`; it preserves the existing configuration and identity. In another terminal, set the same `GENT_HOME` and inspect it:

```sh
export GENT_HOME="$HOME/.gent-dev"
gent daemon status
gent node name set workstation
gent node name
gent cluster
gent config path
```

`--local` is required to create a development cluster. This build supports one local cluster per state directory. For foreground use, run `gent cluster new demo --local` followed by `gent daemon run`; stop it with Ctrl-C or SIGTERM. A restart preserves identities, permissions, and queued messages. For an account service, `gent daemon install` guides login and owner/invitation enrollment; see [service setup](service-setup.md) for explicit choices and noninteractive use. Multi-cluster selection remains future work.

## Account login

The CLI implements `gent auth` / `gent auth status`, `gent auth login` and `gent auth logout`. The default account origin, `https://api.gent.link`, is not deployed. These commands require a configured account service and dedicated GitHub OAuth app; they do not create or enroll a local encrypted cluster.

Normal login opens the browser and waits for an ephemeral IPv4 loopback callback. `--no-browser` prints the URL without opening it, retaining the local callback. `--headless` uses GitHub's device-code flow, which SSH sessions select by default. `--service ORIGIN` selects a configured service, allowing HTTPS or loopback HTTP for development. The CLI requests no GitHub scopes and never saves the GitHub token.

Gent saves its own service credential in private `auth/session.json` beneath the selected Gent home. The credential is saved before exchange so a lost response can be recovered by status or a repeated login. Sessions last 30 days. A valid existing session is reused; login and logout preserve existing cluster configuration and encryption keys.

Status is read-only and checks the service before reporting an active session. Offline cached account information is not authenticated. Logout first disables the local credential, then asks the service to revoke it. If offline, it reports `revocation_pending`; retry logout when connected. An interrupted login can also leave revocation pending until its session commits or its 15-minute creation window closes. Pending revocation and inactive/unavailable status exit 3, successful mutations exit 0, and malformed state or other failures exit 1. `--json` provides structured output without credentials.

Native Linux and Mac proofs exercise the actual CLI against a local Rust account Worker backed by D1 and a synthetic GitHub provider. They cover browser callback/state/PKCE validation, device polling and slow-down, private credential storage, rejected links, interrupted-login recovery, offline logout and byte-identical existing cluster files. The browser proof sends the callback over HTTP; it does not launch a GUI browser or exercise real GitHub consent.

`scripts/prove_auth.py` is the public CLI portion of that private service harness. The optional `test-auth-provider` build feature accepts an explicit fixture provider only when both it and the account service are loopback origins. Default builds omit this override. `scripts/prove_setup.py` includes guided-install checks from `prove_guided.py`: real service installation, terminal choices/cancellation, interrupted credential provisioning, repeated installs and shell-file preservation. Real GitHub consent and production deployment remain unverified. Service logout leaves the separate development relay credential unchanged; it revokes dependent credentials issued for the service-backed relay prototype.

`scripts/prove_renewal.py` accepts a private synthetic near-expiry session from the account harness. It checks automatic renewal inside the actual systemd/launchd daemon, lost-response recovery after restart, account pinning and disabled-login refusal, explicit `gent auth renew`, logout and unchanged keys/credentials. It uses a closed relay port; the private harness separately tests ciphertext and notification access past the old deadline. The script checks startup/restart maintenance, without waiting for the hourly timer or a production-length 30-day session.

## Service-backed transport proof

The daemon can now use an individual node credential from the account service instead of a shared development token. The separate private relay build checks live account/node authority and isolates storage and notifications by cluster. Its local proofs pass on Linux and macOS with distinct node credentials for MLS configuration synchronization, plus 32 MiB encrypted file transfers and endpoint restart. See [service-backed relay authority](security.md#service-backed-relay-authority) for the boundary and revocation semantics.

`wrangler_transports_actual_encrypted_configuration` accepts an optional `GENT_TEST_RELAY_PEER_TOKEN_FILE` pointing to the second endpoint's private credential. `wrangler_transports_encrypted_file_objects_with_endpoint_restart` also accepts a service node credential through its existing private token-file parameter. The private harness issues these fixture credentials and runs the real Workers; the public tests do not create service accounts themselves.

These two tests are transport component proofs: service node labels are fixture IDs, and trusted test code distributes the cryptographic state. Separate CLI proofs now provision actual node IDs and independent credentials through owner setup and SSH or private-file enrollment. `gent cluster connect` reconnects an installed node after credential loss or expiry while preserving its signing identity. Development-cluster migration and hosted agent enrollment remain unfinished. SSH development pairing uses its shared development token; service-backed joins provision each node's own credential.

## Daemon services

```sh
gent daemon install
gent daemon status
gent daemon stop
gent daemon start
gent daemon restart
gent daemon logs --lines 100
gent daemon uninstall
```

These are independent lifecycle examples. Install registers and starts a systemd user service on Linux or a LaunchAgent on macOS. It requires an existing configuration unless `--local [NAME]` is supplied, which creates a development cluster only when none is configured. Omitting the optional name uses `default`. Repeating install preserves identities and does not restart an unchanged running service. After upgrading the binary at the same path, use `gent daemon restart` to run the new version. Installing from a different binary path updates the managed definition and restarts the service.

Service names derive from the canonical state directory, so different `--home` directories have independent registrations. `gent daemon status --json` reports the service file, backend, manager state, PID, startup enablement, and authenticated daemon readiness. An established service registration does not prove the daemon is responding. Status exits 0 when the daemon responds and 3 when stopped or unavailable; command failures exit 1. Successful stop and uninstall exit 0. When reachable, existing node, cluster, and authority fields remain available in status output.

Linux definitions live under `$XDG_CONFIG_HOME/systemd/user` or `~/.config/systemd/user`. Startup follows the systemd user manager; remaining active after logout or starting without login depends on the host's linger configuration. Gent does not change linger or install a system-wide service. On macOS, definitions live under `~/Library/LaunchAgents`. Gent uses the current GUI domain when available and otherwise the user's background domain, including SSH sessions. It supports both Aqua and Background session types. Actual logout/reboot and transitions between GUI and headless sessions have not been tested. Systems without an available user service manager can use `gent daemon run`.

Definitions contain the executable and state paths, with no Gent credentials or encryption keys. Gent refuses to overwrite or remove edited, unrelated, shared, symlinked, or hard-linked service files. It also refuses to control a foreground daemon as though it were the installed service. Stop that foreground process before installing the service. Installation and removal preserve unrelated files in the service directory. A per-state lock prevents concurrent lifecycle mutations.

Uninstall stops and removes the service while retaining TOML, keys, SQLite state, bindings, and diagnostics. It is safe to repeat. Linux diagnostics come from the unit's journal; macOS writes a private `daemon.log` in the state directory. `gent daemon logs --lines N` returns recent lines, with macOS reads bounded to the last 2 MiB. Service status extracts lifecycle fields from launchd output without exposing its inherited environment. macOS log rotation remains future work; systemd journal retention follows the host's settings.

The opt-in proof creates a temporary service under the actual user manager, exercises lifecycle and crash recovery, retains a queued MCP PNG across restarts and reinstall, verifies literal paths and service-file protections, and checks that foreground processes remain separate:

```sh
python3 scripts/prove_service.py target/debug/gent
```

It uses synthetic agents without model calls. It removes its temporary service and files afterward, retaining the directory if cleanup fails. It passed against the Linux systemd user manager and the Mac Studio's headless launchd user domain. OS-managed journal records and launchd enablement preferences can remain after service removal.

## Connect an MCP client

Configure the host to launch the following command, with absolute paths to the binary, state directory, and binding file:

```sh
gent --home /absolute/private/state mcp serve --binding /absolute/private/state/bindings/chat-a.key
```

Gent creates the binding file when absent. The owner or host must choose a different binding file for every conversation. The file is a credential; never paste its contents into a chat or tool argument. A second active MCP process cannot lock the same binding. Reusing the file after that process exits reconnects to the same agent and pending inbox. A private `chat-a.key.scope.json` sidecar pins its cluster, node and credential digest; retain it with the binding. Another cluster cannot reuse that binding after a default-context switch. An existing binding without a scope needs its original `--home` or `--cluster` once to establish the pin. Without `--binding` or `--host`, each MCP process gets a fresh ephemeral identity.

A host-wide MCP configuration may be shared by multiple chats. Use the host binding mode below for supported hosts. A fixed `--binding` in shared configuration gives every chat the same credential; changing the display name does not create another identity.

The host invokes `gent_register` with a display `name` and arbitrary `provider` label, then calls `gent_identity` to inspect its location. The daemon supplies its node and agent IDs. Registration does not grant messaging or discovery rights. The same tools work regardless of whether the host runs a cloud model or a local model.

| Tool | Purpose |
| --- | --- |
| `gent_register` | Register this authenticated connection. |
| `gent_identity` | Inspect its bound identity and node. |
| `gent_agents` | List peers allowed by enumeration policy. |
| `gent_send` | Open an authorized exchange with text and optional file bytes. |
| `gent_reply` | Reply to a received message within its bounded exchange. |
| `gent_inbox` | Retrieve pending permitted messages and files. |
| `gent_ack` | Record receipt of a message; this does not claim work is complete. |
| `gent_message_status` | Inspect queued, delivered, expired, or revoked state. |
| `gent_relay_attach` | Save a selected target under an owner grant and ordinary message permissions. |
| `gent_relay_status` | Inspect the current selection or a specific saved attachment. |
| `gent_relay_detach` | Detach a specific attachment without cancelling messages. |
| `gent_relay_send` | Forward one turn to the explicitly selected attachment. |
| `gent_relay_turns` | Recover this intermediary's turn IDs across all attachments. |
| `gent_relay_turn_status` | Retrieve status and paged responses with files without resending. |
| `gent_relay_next` | Retrieve the target's first unfinished relay turn. |
| `gent_relay_respond` | Report progress or a final complete/cancelled outcome. |
| `gent_relay_cancel` | Request cancellation of a specific pending turn. |

## Persistent relay selection

The owner can grant one intermediary agent access to select one target:

```sh
gent relay grant INTERMEDIARY_UUID TARGET_UUID --ttl-seconds 86400
gent relay grants
gent relay attachments
gent relay revoke GRANT_UUID
```

Both agents must already be registered and known to the signing owner. Grants last one day by default, with a seven-day maximum. They supplement enumeration/send/receive policy; they do not grant those permissions. Authorized joined nodes submit these edits through the existing configuration proposal path. `gent config requests` shows acceptance or rejection. Use the global `--request-id UUID` for an exact CLI retry; that UUID is also the grant ID.

The intermediary calls `gent_relay_attach` with `target` and a new UUIDv7 `request_id` from `gent_request_ids`. Selection persists across daemon and MCP restarts. Selecting a different target detaches the previous attachment atomically. Retrying an older selection returns its saved state and does not reactivate it. Detach names an attachment ID, so delayed control calls cannot detach a later selection. Revoked grant IDs stay retired; a new grant requires a new attachment. Status hides target details if enumeration is revoked. `gent relay attachments` is an owner view of the newest 100 local records.

Attaching sends nothing. Tool results report `supports_turns: true`. `gent_relay_send` forwards text and files under a stable request ID and returns a `turn_id`. Status checks never resubmit work. `gent_relay_turns` recovers saved turn IDs, including those from detached or replaced attachments. Its pages contain 50 entries; use `next_after` as `after_turn_id` to continue. `gent_relay_turn_status` returns responses with a bounded page size; continue with `after_message_id` when `has_more` is true. Both IDs and replies retain the original target after a switch.

The target receives turns in its daemon's durable arrival order, shared by all intermediaries. `gent_relay_next` keeps returning the first unfinished turn even after acknowledgment. The ordinary inbox also omits later relay turns. `gent_relay_respond` reports `progress`, `complete`, or `cancelled`; only a final outcome advances the queue. Each turn permits 16 target responses, reserving the final slot for completion. A temporary permission block pauses the head. Expired turns and permanently revoked grants leave the queue; already running host work is not forcibly stopped.

`gent_relay_cancel` requests cancellation without detaching or marking work complete. The target must handle it and report its outcome. Cancellation can cross an already completed response in flight without changing that outcome. Detach, a tool timeout, or a restart does not cancel pending work. After uncertain host execution, reconcile with the host's actual work state before replaying consequential actions. Gent persists message delivery and protocol state; it does not guarantee exactly-once host execution.

Forwarded messages remain attributed to the intermediary, without a claim of human authorship or permission to execute. Security mode currently describes local-daemon or encrypted daemon-to-daemon transport; hosted/web/mobile bridges are not implemented. File limits remain four attachments totaling 1 MiB decoded per message.

## Shell integration

Gent supports Zsh, Bash, and Fish. Shell setup adds the Gent executable directory to PATH when absent and loads completion for the current CLI. Install it independently of node enrollment:

```sh
gent hooks install
gent hooks status
gent hooks install --shell zsh
gent hooks install --shell bash
gent hooks install --shell fish
gent hooks uninstall
```

`gent hooks` is the status form; `gent hooks remove` aliases uninstall. Detection follows `SHELL`; specify `--shell` when using a different shell. The default startup files are `~/.bashrc`, `$ZDOTDIR/.zshrc` (or `~/.zshrc`), and `$XDG_CONFIG_HOME/fish/config.fish` (or `~/.config/fish/config.fish`). `--rc-file PATH` on install, status, and uninstall selects a custom file. Bash login shells must source `.bashrc`, or installation must target the intended login file explicitly. Open a new shell after installation or removal; an existing shell retains the functions and PATH it already loaded.

The installer owns one marked block containing the executable path and shell type. It preserves surrounding bytes and existing file modes, including a missing final newline. Repeated installation updates that block without duplication; running installation from a different Gent binary updates its path. Uninstall removes only an intact managed block and preserves later edits elsewhere in the file. An altered, incomplete, duplicate, or wrong-shell block requires manual resolution. Symlinked/hard-linked files and files or parent directories writable by other users are refused. A private lock beside the startup file serializes Gent writers, and an atomic file replacement commits the update. The lock file may remain after removal. External editors can still race the final rename, so close them during installation.

Setup runs only in interactive shells when the recorded binary is executable. Zsh initializes its completion system if necessary with `compinit -i`, which ignores insecure completion directories. Bash evaluates the completion output synchronously for compatibility with macOS's Bash 3.2. Fish sources its generated completions and adds only the missing PATH entry. Executable directories containing a colon are rejected because PATH uses colon separators. Startup does not contact the daemon, read Gent state, select a cluster, capture history, or start an agent turn. The global `--home` setting is not embedded into shell setup; normal CLI state selection still applies.

`gent completions bash|zsh|fish` writes a standalone completion script for custom dotfile management. It works without a configured Gent node. Status is read-only and reports the saved block, executable availability, and startup file; it cannot inspect the calling shell's loaded functions. Successful status and changes exit 0; malformed blocks, file protection failures, and unsupported shell detection exit 1.

The isolated proof checks concurrent setup, actual interactive startup, nested command completion, literal quotes/dollar signs/backslashes in executable paths, repeated sourcing, noninteractive and missing-binary guards, and exact removal:

```sh
python3 scripts/smoke_hooks.py --fish /path/to/fish
```

Use `--bash` or `--zsh` for nondefault executable paths. It passes with Linux Bash 5.3.9/Zsh 5.9 and macOS Bash 3.2.57/Zsh 5.9, plus Fish 4.9.3 on both machines. The Zsh proof presses Tab in a real pseudo-terminal. Fish was tested from temporary official release binaries; no installed or default shell was changed. Five Rust tests additionally cover ownership, preservation, malformed blocks, default paths, linked/shared files, and concurrent writers.

## Host conversation bindings

```sh
gent integration config codex
gent integration config claude-code
```

These commands print JSON configuration fragments containing absolute Gent executable and state paths. They do not edit host settings. For Codex, translate the returned `mcp_servers.gent` fields into a `[mcp_servers.gent]` table in the host's `config.toml`. For Claude Code, merge `mcpServers.gent` into its MCP configuration and merge `settings.hooks.PreToolUse` into its settings. Preserve existing entries. Keep the MCP server name `gent`, which the generated Claude hook matches. The installer below applies these entries directly.

Both fragments launch the same stdio server with an explicit physical `--home` and `mcp serve --host codex` or `--host claude-code`. Host mode requires a pinned `--home` or `--cluster`; installed entries supply it. Do not combine `--host` with `--binding`. The host selects a persistent credential outside model-visible tool arguments. Gent stores credentials under the private `host-bindings` directory, scoped to node, cluster, host, and conversation. Reconnecting restores that chat's registration and inbox; a fork gets a different binding. Concurrent MCP processes cannot hold the same conversation binding. One MCP connection can hold up to 128 distinct bindings before it must reconnect.

Codex supplies `threadId` in each tool call's protocol metadata. Gent uses that field, which was observed in the tested CLI versions; it does not fall back to `sessionId`, since related threads can share a session tree. Calls without a valid thread ID fail. Existing explicit bindings remain available for hosts without verified metadata support.

Claude Code requires the generated `PreToolUse` hook for every Gent tool call. The hook receives the current session, optional subagent ID, and tool-use ID from Claude. It writes a private handoff containing hashes and a timestamp. The MCP server matches the tool-use ID and exact call contents before selecting the credential. Missing, expired, or conflicting handoffs fail without falling back to the previous chat. The hook does not grant permission or add model instructions. Disabling it makes Gent calls fail; another hook rewriting Gent's arguments can also invalidate the handoff.

Handoffs expire after ten minutes, with up to 4,096 retained per node/cluster/Claude scope. Expired records are pruned on later hook calls. They contain no plaintext message, file bytes, raw session ID, or credential. Binding credentials persist independently. Host labels and metadata are trusted only on this local, owner-configured stdio connection; they are not remote authentication. Agents with arbitrary filesystem access still share the trusted OS user's authority.

The same-connection protocol proof simulates session and subagent changes. Separate real-host proofs exercise concurrent CLI chats, resume, forks, queued images, interactive `/clear` and in-process `/resume`. The [child-agent proof](#real-child-agents) exercises native spawning and resumption. GUI surfaces still require separate tests. Claude's startup environment alone is insufficient for these transitions, so Gent uses the per-call hook even for CLI sessions.

```sh
python3 scripts/smoke_host_bindings.py target/debug/gent
python3 scripts/prove_host.py --host codex --automatic-binding
python3 scripts/prove_host.py --host claude-code --automatic-binding
```

The latter two consume model usage in synthetic conversations and retain private proof files. Add `--host-binary /absolute/path/to/host` when the executable is not on PATH. Codex's `--use-host-config` test option retains the machine's existing configured model access while disabling unrelated MCP servers and plugins for that invocation. No permanent host settings or existing conversations are edited.

## Install host integrations

With a configured Gent node, install either or both hosts:

```sh
gent integration install codex
gent integration install claude-code
gent integrations
gent integration status codex
gent integration uninstall claude-code
```

`gent integration remove` aliases `uninstall`. `status` without a host inspects both. Installation writes the common MCP server and, for Claude Code, its required identity hook. The daemon must be running when an agent calls Gent. Reopen the host session or restart its Gent MCP connection after changing installation. Shell setup is described above. Skills and automatic model wake/resume remain separate work.

Codex uses `$CODEX_HOME/config.toml`, defaulting to `~/.codex/config.toml`. Claude Code uses `~/.claude.json` for its user MCP entry and `~/.claude/settings.json` for its hook. When `CLAUDE_CONFIG_DIR` is set, both `.claude.json` and `settings.json` live inside that directory. `--config-dir PATH` on install, status, or uninstall selects an explicit host directory with those same override semantics. Use the same directory for subsequent operations. Gent state is independently selected by `--home` or `GENT_HOME`.

The installer preserves unrelated configuration values, TOML comments, and surrounding JSON text. Reinstalling is idempotent; running a new Gent executable updates its recorded command and hook paths. Existing file modes are retained, and new files are private. It refuses malformed documents, duplicate JSON keys, symlinked or hard-linked target files, shared write access, a foreign `gent` entry, or changes to a managed entry. Even an identical manually configured entry is unowned: preserve it elsewhere and remove it before using the installer. It does not add tool approvals or re-enable disabled Claude hooks. Project settings and managed policies can still override or block these user settings.

Each host directory contains a private `.gent-HOST.json` ownership/recovery record and `.gent-HOST.lock`. The record contains generated Gent paths and the previous/desired installation, without snapshots of account, model, or other host settings. Keep these sidecars while the integration is installed. A lock coordinates Gent installers, including different Gent homes targeting the same host. A second home must first uninstall through the recorded home. Uninstall retains Gent identities, bindings, inboxes, and host conversations; empty configuration containers and ownership sidecars may remain.

All target documents are checked before an update. Gent writes and syncs a pending record, then atomically replaces each configuration file. An interrupted multi-file edit reports `recovery_pending`; rerunning install or uninstall finishes it using the latest documents, preserving unrelated intervening edits. An altered managed entry stops recovery for manual resolution. Status never completes recovery or creates files. Gent detects changes before each file replacement, but host applications do not honor its lock: close other settings editors during installation, since their writes can still race the final rename.

Status reports `absent`, `configured`, `conflict`, `hooks_disabled`, or `recovery_pending`. A parsed status result exits 0; read/validation failures and failed mutations exit 1. The combined listing includes per-host read failures as `error`. `configured` means the recorded user entries match, not that the daemon, a project override, hook trust, or a GUI application has been verified. The output separately reports whether the recorded binary exists and whether the integration belongs to the selected Gent home.

Python 3.11 or newer drives the isolated installation and binding checks:

```sh
python3 scripts/smoke_install.py
python3 scripts/smoke_host_bindings.py target/debug/gent
python3 scripts/prove_host.py --host codex --installed-binding
python3 scripts/prove_host.py --host claude-code --installed-binding
```

The first script runs concurrent installers and checks discovery with each host's `mcp get gent`; use `--codex` and `--claude` for executable paths. The second launches installed server entries and the installed Claude hook through live MCP/RPC. The final two consume model usage. Claude loads the installed files through per-run flags; Codex reads the installed entry into per-run overrides, preserving its existing authentication location. Native config discovery is checked separately by the first script. These tests use temporary host configuration directories and leave real host settings unchanged. They do not establish GUI support.

The separate interactive proof uses a real pseudo-terminal and consumes model usage:

```sh
python3 scripts/prove_interactive.py --host codex
python3 scripts/prove_interactive.py --host claude-code
```

On Linux and macOS, `/clear` produces a separate agent with an empty directory and inbox. `/resume ORIGINAL_SESSION` restores the original identity and its pending image in the same CLI process; exact file bytes and the receipt are checked. Claude keeps one MCP process and changes session bindings through its per-call hook; Codex reconnects MCP during these transitions. The driver waits for tool discovery before submitting its first prompt. It retains synthetic evidence in a private temporary directory; the host may also retain the synthetic sessions and workspace-trust metadata. Existing conversations and saved MCP configuration remain unchanged.

Use `--host-binary PATH` for a nondefault CLI. Codex keeps the current provider configuration. A provider with its own configured `experimental_bearer_token` can use `--provider-token-auth` to bypass the TUI's separate ChatGPT login gate for this invocation, without changing saved authentication. The scripts reject dotted MCP/plugin names because Codex's CLI treats override path segments literally. Identity transfer, automatic wake-up, and GUI/web/mobile flows still need separate proofs.

## Real child agents

The opt-in proof consumes model usage through the installed hosts and requires Python 3.11 or newer:

```sh
python3 scripts/prove_subagents.py --host codex
python3 scripts/prove_subagents.py --host claude-code
```

Use `--host-binary PATH` for a nondefault CLI and `--binary PATH` for a different Gent build. The runner creates private temporary Gent state, uses the current host authentication/provider, disables unrelated tools, and leaves saved host settings unchanged. Codex uses medium reasoning. Claude uses low effort, a temporary `gent-worker` definition and Gent's generated identity hook. Every host turn has a five-minute timeout; Claude also has a $2 per-invocation budget. Synthetic conversations, transcripts and proof state remain for inspection; the daemon and fixture peer stop on exit.

Each real parent spawns two real children. All three register separate Gent identities and initially see empty directories. Only the parent and child-a receive permission to communicate with a fixture peer. The harness queues different private text markers with a PNG, restarts the daemon, and resumes the original parent and children in a new host process. Each permitted agent acknowledges and replies with its own exact text/files, using an ID allocated to its scope by `gent_request_ids`. Child-b's directory and inbox remain empty. Finally, child-a is revoked; its identity call fails while the parent and sibling retain their original identities.

The audit matches actual MCP traffic against native host records and rejects tools outside Gent and native child lifecycle operations. Codex's exact synthetic rollouts establish child ancestry and executed tool calls; Claude's native task events, per-call hooks and tool-use IDs establish the corresponding scopes. A final `report.json` says `passed` only after both protocol assertions and this audit succeed. Model summaries alone cannot pass the proof. It passes on Linux with Codex 0.167.2 and Claude Code 2.1.323, and on macOS with Codex 0.167.0 and Claude Code 2.1.311.

`--register-only` stops after registration. Continue that completed phase with `--root PATH`. After all protocol phases complete, `--root PATH --audit-only` rechecks retained evidence without starting a host or daemon. Preserve a failed partial turn and start a fresh proof; the runner refuses to overwrite its transcript or silently replay acknowledged messages.

This checks Gent identities, discovery and tool access. Native hosts can copy parent context into children and return child reports to parents, including message contents. Gent does not isolate that host-controlled context. These deliberately scheduled CLI turns also do not establish automatic wake-up, TUI-specific child controls, or GUI support.

## Grant communication as the local owner

After registering two clients, use `gent agents` to get their IDs. In the commands below, replace `AGENT_A_ID` and `AGENT_B_ID` with those IDs:

```sh
gent permission allow AGENT_A_ID AGENT_B_ID --permission enumerate send
gent permission allow AGENT_B_ID AGENT_A_ID --permission enumerate receive
gent providers list
```

A can now initiate an exchange with B. B can discover A, receive its message, and reply in that exchange without an unsolicited-send grant. Explicit denials take precedence. For example:

```sh
gent permission deny AGENT_B_ID AGENT_A_ID --permission receive
```

This blocks new messages and delivery of queued messages from A to B, as well as replies in the blocked relationship. Owner commands can inspect local and linked-node registrations; agent-facing discovery exposes only permitted peers. `last_seen` records local agent activity or receipt of a remote announcement and does not prove an active model turn or live connection.

Selectors support an agent ID, `'*'`, `same-node`, `node:UUID`, or `group:NAME`. Quote `'*'` in the shell. Groups and rules are stored under `[policy]` in `config.toml`. Edit the TOML to remove a rule, then run `gent config validate` and `gent config apply`. The active owner signs and commits accepted edits, including requests from authorized joined nodes. The newest accepted revision replaces the previous shared configuration; editing the file without applying it does not change active permissions. `gent agent revoke AGENT_ID` invalidates a registration hosted on the current node and publishes its tombstone to linked peers. Revoking an agent hosted on another node through administrative forwarding remains pending.

Signed authority and message queues share `state.sqlite3`. First daemon startup preserves existing local identities and creates a private `identity.key` for node and owner signing keys, separate from the RPC credential in `owner.key`. Keep both keys and the database private. Existing databases must have mode 0600; Gent rejects shared or symlink files. Missing signing keys for an initialized database cause an error instead of silently creating a different identity.

After a signed change commits, Gent projects the newest state into TOML while preserving unrelated local settings. If the filesystem write fails, the result reports `applied: true` and `config_saved: false`; the committed policy remains in effect and projection is retried. `applied_revision` identifies the revision represented by the file. Node renaming now uses this signed path and requires a running daemon.

`gent cluster` and `gent daemon status` show the active revision and lease status. The owner daemon renews its 24-hour configuration lease when six hours or less remain, checking at startup and every 15 minutes. Use `gent cluster renew` to renew immediately. Agent operations remain blocked if the lease expires before a renewal commits.

Encrypted configuration streams update this same live policy automatically when a development relay is configured. The same MCP operations send messages to permitted agents on directly paired nodes. `remote_ready` reports that at least one authorized data link and relay configuration exist; it does not prove current connectivity.

## Join another machine through SSH

The owner daemon must be running with a configured development relay, as described below. Obtain its cluster UUID with `gent cluster`. On the joining machine, use an existing trusted SSH destination for that owner's OS account:

```sh
gent --home ~/.gent-peer cluster join CLUSTER_UUID --via sam@owner-host --name laptop
gent --home ~/.gent-peer daemon run
```

Gent uses SSH's existing host-key trust with `StrictHostKeyChecking=yes`, noninteractive authentication, and no agent forwarding. It never accepts an unknown host key automatically. The remote login must be able to invoke Gent and read the owner's local RPC credential. Use `--remote-gent /absolute/path/to/gent` and `--remote-home /absolute/private/state` when the defaults do not match the owner machine.

The joining node generates and retains its own signing key. The owner approves its signed enrollment request through the authenticated SSH channel, then both sides establish an MLS configuration stream and two directional data streams. Bootstrap metadata, the stream grant, key package, and development relay credential travel inside SSH. The owner's signing key and local RPC credential never leave that machine. This enrolls a trusted daemon with full cluster-configuration access; agent messaging still follows its separate permission policy.

The command imports the owner's relay origin and shared development token into private local storage. `--relay-endpoint http://127.0.0.1:PORT` can override that origin when a development SSH tunnel exposes the relay at a different local address. Without an owner relay, joining stops before enrollment. The shared token is temporary development authorization, not a per-node production credential.

Interrupted joins retain their node key and progress in a private sibling directory, such as `~/.gent-peer.joining`. Rerun the same command and node name to resume. Gent installs the finished runtime atomically and refuses to overwrite another node or unrelated files. A completed retry reports `already_joined`. Rerunning the join command upgrades an older configuration-only node with data streams and owner-certified legacy agent IDs, preserving existing bindings. A stale unconsumed stream grant gets a fresh key package while preserving node identity; obsolete streams still need eventual pruning. Do not delete pending state to repair an interrupted join, since that would lose its identity.

`gent nodes` lists enrolled node IDs, names, the signed `can_configure` capability, and `data_link` for established encrypted peer links. Remote presence is currently `unknown`; a membership record or established link does not prove another daemon is online. Newly SSH-enrolled nodes receive configuration-management permission. Existing nodes keep their previous grant on join retry, so retrying cannot restore revoked administration. Nodes enrolled by older versions need an explicit owner grant. SSH pairing is implemented; service-backed enrollment and invite-based pairing are pending.

An opt-in proof creates temporary nodes on two machines, pairs through the real CLI, and checks encrypted configuration delivery through a local relay. It registers independent MCP clients, grants permissions from the joined node, transfers images in both directions, verifies scoped replies and recipient acknowledgments, then queues a reply while the receiving daemon is offline and retrieves it after restart. It also checks remote renaming, identical request retries, queued edits surviving owner downtime and source restart, and revoked administration. It needs Python 3.11 or newer, a running loopback development relay, a private token file, and an already trusted SSH host. It makes no model calls and removes its temporary nodes afterward:

```sh
python3 scripts/prove_pairing.py --owner sam@owner-host \
  --remote-binary /absolute/path/to/gent \
  --relay-token-file /absolute/private/relay.key
```

This proof passes with a Mac Studio owner and Linux joining node. Additional joined nodes automatically exchange bootstrap metadata through the owner and establish their own two-node encrypted streams. Agent discovery and delivery then use those direct links under the normal permissions. The owner forwards bootstrap records only; peer application messages travel through the relay without passing through the owner daemon. Initial setup needs the owner available, while established links continue through owner downtime until authority expires. `data_link: true` in `gent nodes` reports local setup completion.

To extend the proof to three daemons across the two machines, build `cargo build --locked -p gent-daemon --example join_local` on the owner machine and add `--remote-join-helper /absolute/path/to/target/debug/examples/join_local` to the command above. This test helper creates a second temporary Mac node through the owner's protected local RPC socket. Linux still uses the real SSH join command. The test exchanges MCP images, replies, and receipts directly between the two joined nodes while the owner daemon is stopped, restarts the Linux receiver, and checks that the owner database has no copy of those messages. The SSH relay tunnel stays open independently of the owner daemon. The three-node proof also checks that completed bootstrap bodies are empty, retry fingerprints persist through owner shutdown and joined-node restart, and history diagnostics report the job limits. All temporary nodes and processes are removed afterward.

## Real-agent visual iteration

`scripts/prove_visual.py` runs real Codex and Claude Code conversations on two machines through the same SSH enrollment and encrypted development relay. It requires Python 3.11 or newer on both machines, existing host authentication, and copies of the script and its companion `*_model_checks.py` modules in the remote scripts directory:

```sh
python3 scripts/prove_visual.py --owner sam@owner-host \
  --remote-binary /absolute/path/to/gent \
  --remote-script /absolute/path/to/scripts/prove_visual.py \
  --remote-python /absolute/path/to/python3 \
  --local-host codex --remote-host claude-code \
  --local-host-binary /absolute/path/to/codex \
  --remote-host-binary /absolute/path/to/claude \
  --relay-token-file /absolute/private/relay.key
```

Swap the host names and executable paths to exercise Claude locally and Codex remotely. Both combinations pass with Linux as builder and macOS as reviewer. The test consumes model usage, keeps synthetic state in private `/tmp/gent-visual-*` directories on both machines, and stops its daemons and SSH tunnel. Host authentication and saved MCP configuration stay in their usual locations; temporary installation settings are supplied per invocation.

The builder renders a small code-native status card and sends SVG source plus a PNG preview. The reviewer identifies the original dot's color and position, replies with a correction and reference files, then reviews and approves the builder's revision. Each message uses Gent, with only the builder permitted to initiate an exchange. Both daemons restart while visual feedback is pending. The test verifies session/agent continuity, four messages in one reply chain, exact attachment bytes at the receiving endpoint, and delivery receipts. Native compression libraries can produce different valid PNG encodings, so expected bytes come from the sender's renderer.

The harness schedules host turns and grants test permissions; it does not inject peer replies or attachments into prompts. Codex uses its read-only shell sandbox for the renderer; Claude permits the renderer command through a Bash prefix rule. Prompts restrict shell use to the renderer, and recorded commands match that restriction. Unrelated configured MCP servers and plugins are disabled. This proof uses a 160 x 100 graphic and inline base64. It establishes a small visual exchange, not arbitrary application editing, large attachments, automatic host wake-up, or persistent relay mode.

The bundled [agent guidance](../crates/gent-link/skills/gent/SKILL.md) is advertised through MCP server instructions. It covers returned agent IDs, retry IDs, receipt semantics, file bytes, polling, and the current relay limits. Messaging grants do not authorize policy changes or confer human authority.

## Local cluster profiles

`gent clusters` (also `gent cluster list`) lists local profiles without contacting a daemon or account service. Register an already initialized directory with `gent cluster add PATH`. This records its cluster ID, node ID and absolute directory; it neither joins a remote cluster nor copies state. For a separate local development cluster:

```sh
gent --home ~/.gent/clusters/scratch cluster new scratch --local
gent --home ~/.gent/clusters/scratch daemon install
gent cluster add ~/.gent/clusters/scratch
gent clusters
gent cluster switch scratch
gent --cluster CLUSTER_UUID agents
```

The primary directory must already be initialized. `gent cluster switch ID_OR_UNIQUE_NAME` changes the default for subsequent CLI commands. Without an argument it offers a numbered terminal picker; JSON and non-terminal invocations require the argument. `--cluster` selects one profile for a command without changing the default. Names follow each profile's current display label; ambiguous names require an ID. Missing, replaced, linked or mismatched selected state produces an error, without falling back to another cluster. Listing reports unavailable profiles so the user can select a remaining valid one.

Registration upgrades the primary `~/.gent/config.toml` to version 2 and stores the local registry under `[contexts]`. It retains the original cluster's `[node]`, `[cluster]` and policy at that path, with its original keys and database. Additional profiles keep their own config, keys, queues, account sessions and daemon service in their recorded directories. `gent config path` returns the selected profile's configuration path. The registry allows 128 profiles, including the original, and never enters encrypted cluster configuration sync. Configuration writes share `config.lock`; daemon projections preserve the latest selection even if they loaded an older file before a switch.

Switching leaves existing daemons, agents, inboxes, relay attachments and installed host entries in their original cluster. Each profile currently runs its own service. Installed service/MCP/hook commands pass an explicit physical `--home`; those runtime entry points keep interpreting it as that fixed directory. Ordinary CLI commands use that directory's selected context. Use `--cluster CLUSTER_UUID` to override selection explicitly, including for runtime commands. An unpinned new ephemeral MCP connection selects the default once at launch. Existing fixed bindings reject a reconnect into another cluster; installed Codex and Claude entries remain pinned across reconnects and daemon restarts.

Guided creation and enrollment of additional profiles from the primary directory remain unfinished. For now, initialize or enroll a separate `--home` directory with the existing setup commands, then register it with `cluster add`. Registration does not move credentials or share logins between profiles. A single daemon supervising several profiles and profile removal remain future work.

Run `python3 scripts/prove_contexts.py target/debug/gent` for the opt-in native-service proof. It creates two isolated systemd/launchd services, installs MCP entries in temporary host directories, switches contexts with a PNG queued, reconnects both synthetic host clients, checks binding isolation, restarts both services, and exercises the terminal picker. Cleanup removes its services and host entries. It makes no model calls and uses no account service or network relay.

## Configuration administration

The owner CLI and authorized joined-node CLIs can change policy, apply cluster and current-node names from TOML, rename the current node, and request lease renewal. MCP agent credentials cannot invoke these owner operations. Scoped administration through MCP remains planned.

On the owner node, use the stable node ID from `gent nodes`:

```sh
gent node admin grant NODE_UUID
gent node admin revoke NODE_UUID
```

These are independent examples. The grant authorizes configuration proposals; it does not export owner keys or permit enrollment or further delegation. The active owner retains signing authority regardless of its own `can_configure` flag. All proposals and results travel in encrypted node streams, and the owner rechecks the signed grant when accepting each edit.

Accepted changes immediately enter replication to the other nodes. Their signed revision orders changes, regardless of device clocks or when an editor first loaded the file. A later accepted policy replaces an earlier policy in full. The owner must be available for acceptance; while it is offline, authorized joined nodes persist requests and report `queued`. The queue survives restarts. Current policy remains in effect until a signed revision arrives, and normal communication still requires an unexpired lease.

For an exact retry, choose a UUID once and retain it with the proposed content:

```sh
gent --request-id 11111111-1111-4111-8111-111111111111 node name set laptop
gent config request 11111111-1111-4111-8111-111111111111
gent config requests
```

The CLI waits about five seconds before returning a still-queued request. Its eventual state is `applied` with a revision or `rejected` with a reason. An identical retry returns the original result; different content under the same UUID fails. A rejected request stays rejected even if the owner later restores its grant; submit new intent under a new UUID. Retrying `config apply` or a permission command requires the same complete proposal, including any policy loaded from TOML. Accepted incoming revisions can replace local TOML edits, so submit intended changes promptly and inspect the request status.

## Removing a node

On the signing owner, select the node ID from `gent nodes`:

```sh
gent node remove NODE_UUID
gent node removals
gent node removals --pending
```

Removal retires the node ID and signing key in the signed cluster configuration. The same database transaction records any service revocation still needed. Connected peers receive the signed update through configuration sync. The CLI then requests service revocation using the original account and service. The owner daemon retries pending service work at startup and every 30 seconds, in batches of at most 16. Keep it running to complete an offline removal.

`membership_removed: true` means the owner committed the signed removal. `service_status` is `pending`, `confirmed`, or `not_configured` for a node without an account service. A pending service step returns exit code 3 with its error and retry guidance. Run the same `gent node remove NODE_UUID` command again after a connection failure; it preserves the original revision, including when the service committed but its response was lost. Listing is read-only and returns up to 100 records, with a `next` cursor accepted by `--after`.

Service confirmation does not establish that every peer has received the signed update. Offline peers can retain old authority until sync or lease expiry, and removal cannot retract delivered history or plaintext. Already admitted service requests may finish. Shared-token development relays have no per-node service revocation. This command requires the local owner signing key; delegated configuration administrators and MCP agents cannot invoke it. Removing the owner itself requires an owner-transfer mechanism, which is not implemented.

## Development configuration relay

Adding a relay URL alone does not enroll a node or establish a stream. Use SSH pairing above, or the trusted Rust enrollment APIs in transport test fixtures. Joined nodes store their own signing key and verified bootstrap state in `identity.key`, without the owner's signing secret. Configuration proposals require a signed administration grant and established data streams to the owner.

For an already provisioned test node, add these machine-local settings to `config.toml` and restart the daemon:

```toml
[relay]
endpoint = "http://127.0.0.1:18787"
credential_file = "relay.key"
```

`relay.key` is a private mode-0600 file containing the development relay's 64-character hexadecimal credential. Relative paths resolve under the node's state directory; absolute paths are also accepted. Keep it out of model-visible arguments. Use an HTTPS origin outside loopback; URL credentials, paths, queries, fragments, and redirects are rejected. Relay settings are read at daemon startup and are never replicated.

Every committed owner edit or renewal wakes publication immediately. Connected receivers receive a WebSocket wake-up signal after ciphertext storage, fetch and apply verified revisions without an agent turn, and replace older shared settings. The signal contains no cluster configuration or message data. Healthy connections reconcile every 30 seconds to recover missed hints; disconnected push channels fall back to one-second polling while reconnecting. Stream errors retry with backoff up to 30 seconds. Offline nodes catch up from retained encrypted history. Relay acknowledgments prove neither receipt nor policy acceptance, so local history is retained after upload. See [the synchronization protocol and limits](security.md#automatic-configuration-sync). Production service authentication, notification scoping, and retention limits remain necessary before a hosted trial.

## Files, retries, and limits

For local CLI hosts, call `gent_file_paths`, copy the actual file into the returned `import_directory`, and call `gent_file_import` with its basename, media type, and a UUIDv7 from `gent_request_ids`. Use the returned file ID in `file_ids` on send/reply or relay tools. Each file can be up to 32 MiB. Gent seals fresh objects for every new message or forward; identical request retries retain their original IDs and bytes.

Received messages include descriptors in `attachments`. Call `gent_file_status` until ready during an authorized interaction, then `gent_file_export`. Use the returned path with the host's file or image tools. The path is local to the daemon machine. Files are verified before export; an existing file with different contents is never overwritten. Imported and exported handoff copies are temporary, with a `cleanup_after` timestamp in the tool result. Save lasting files elsewhere. Gent checks current file/message permissions on every access.

Small files can use `{ "name": "image.png", "media_type": "image/png", "data_base64": "..." }` in `files`, with a combined 1 MiB decoded limit. Supported inline images also produce MCP image blocks. Native attachment images require export before inspection. Files from agents remain untrusted input.

Call `gent_request_ids` for new agent mutations. It returns one UUIDv7 by default or up to 32 with `count`; generating IDs does not submit work. Use one ID per new operation within 24 hours. Keep it for identical retries; conflicting content is rejected. Retained results remain retryable after that window. An expired ID without a retained result is rejected: reconcile the original work and never substitute a new ID just to retry it. Owner CLI configuration IDs have a separate contract and continue to accept UUIDv4. Repeated inbox reads retain the same message IDs until acknowledgment. Acknowledge after accepting the message; Gent cannot guarantee a host will perform requested work exactly once after a crash.

Limits are 64 KiB of text, four files across `files` and `file_ids`, 32 messages per exchange, and a 24-hour exchange lifetime. Encrypted file storage reserves at most 128 objects and 256 MiB of ciphertext per node, including staged and sent copies; the development relay has a separate shared quota. Remote exchanges allocate 16 messages to each sender, including the initial message, so independently queued replies cannot exceed 32 when the nodes reconnect. Inbox responses are bounded; acknowledge retrieved messages before requesting the next batch. Message history and agent retry records have the limits described below. Plaintext handoff folders and encrypted transport histories remain outside those quotas.

Add `--file-objects` to `scripts/prove_pairing.py` to include a 2 MiB native-file round trip between physical Linux and Mac nodes, using the same authenticated MCP tools, file reads/writes, scoped reply, and both daemon restarts. The separate native large-file test uses two local nodes and actual Worker D1/R2 storage:

```sh
GENT_TEST_RELAY_URL=http://127.0.0.1:18787 \
GENT_TEST_RELAY_TOKEN_FILE=/absolute/private/relay.key \
cargo test -p gent-daemon --test remote --locked \
  wrangler_dispatches_agent_attachments_with_native_files_and_restart -- --ignored
```

## File storage and cleanup

These commands use local owner authority and do not start inference:

```sh
gent files
gent files status --json
gent files clean --dry-run
gent files clean
```

Status reports encrypted object counts, quota reservations, stored ciphertext bytes, tracked plaintext handoff copies, and files needing attention. Database status includes allocated and reusable pages, the 2 GiB configured ceiling, the effective ceiling, and oversized legacy state. Transaction journals, temporary files and handoff files need additional space. See [database allocation and journals](security.md#database-allocation-and-journals). Handoff sizes reflect recorded snapshots, not a filesystem-wide measurement. Changed and untracked files can consume additional space.

Gent records successfully imported/exported handoff copies and their file-expiry deadlines. Maintenance runs at startup and every 15 minutes, processing up to eight expired handoff copies and eight pending exports per pass. Imported sources normally expire after seven days; message-bound exports expire with their exchange. Reimporting the same unchanged source extends that copy's deadline to the latest import expiry. Cleanup also reaps expired/abandoned encrypted objects. `clean` runs one batch immediately; repeat it while `more_due` is nonzero. `--dry-run` previews the batch without removing files or changing retention records.

Cleanup compares file identity, size, timestamps, and content hash. It preserves changed or replaced files, refuses links and unsafe directories, and never traverses recursively. A stable `.gent-clean-UUID.tmp` recovery name allows the next pass to recover interrupted work. A new file at the original path is left alone. Status lists paths and possible recovery paths for preserved/blocked copies; inspect those locally before moving or removing them. They are retried after 15 minutes.

Files that predate this ledger, unimported outbox files, and old-version untracked exports require user/host cleanup. New exports reserve capacity before writing and retain a stable temporary path through interrupted tracking. Empty folders and abandoned old-version temporary files still remain. `gent files clean` only cleans file storage. Message/retry cleanup uses `gent history clean`; encrypted stream history remains retained. Neither cleanup guarantees physical erasure from SQLite, WAL, backups, or open file handles. The state directory still assumes a trusted OS user.

Run `python3 scripts/smoke_file_retention.py target/debug/gent` to exercise the real CLI, MCP tools, 2 MiB files, dry-run, cleanup, and startup recovery using temporary state. It advances only fixture deadlines and preserves the source outside Gent's handoff folders. The same proof passes on Linux and macOS without model calls or a relay.

## Message history and retries

```sh
gent history
gent history status --json
gent history clean --dry-run
gent history clean
```

These owner commands report message counts and payload bytes, exchanges, import retry records, relay selections, pending outbound events, sent-event retries and registration generation records. Cleanup retires whole exchanges seven days after their expiry, including replies, relay turns, file grants, and retry results. It preserves live exchanges. Expired relay selections can retire after seven days once their turns are gone. Import retry records retire only after the object is gone and their request ID can no longer be admitted.

Startup and 15-minute maintenance run one cleanup batch: up to eight exchanges, 256 import retry records, 256 expired sent-event retries, and 128 expired relay selections. `clean` runs one batch immediately. Use `--dry-run` to preview it; repeat cleanup while `more_exchanges_due` is nonzero or a retry/selection batch reaches its limit. New work is limited to 8,192 messages, 256 MiB of serialized message payloads, and 16,384 file import retry records per node. Existing exact retries do not consume these quotas. A full queue rejects new work atomically and can hold up remote message processing until capacity is available.

Message and receipt event retries expire seven days after their message expires. Registration announcements use one saved generation per agent/peer, limited to 65,536 pairs. Message/receipt traffic and configuration/setup traffic each reserve 16,384 queued events, 128 MiB of event bodies and 131,072 retry slots, counting both completed and pending work. Legacy records retain their original behavior and consume both reserves. Configuration and mesh event retries remain retained. See [the event retention rules](security.md#node-event-queues-and-deduplication).

Configuration edit retries have a separate 65,536-record / 64 MiB logical-byte cap, including 8 KiB reserved per pending result. New records keep compact status summaries, fingerprints and outcomes. Cleanup compacts at most eight legacy full inputs per pass without deleting retry records. See [configuration edit storage](security.md#configuration-edit-storage).

Peer setup jobs retain full inputs while pending and replace completed bodies with retry fingerprints. Per-node limits are 8,192 pending jobs, 65,536 total records and 128 MiB of logical fields, including 1 KiB reserved per pending error. Cleanup compacts at most eight legacy completed bodies per pass. Exact retries remain usable at capacity; their records never expire. See [peer setup job storage](security.md#peer-setup-job-storage).

The daemon persists a request-admission clock that cannot decrease after a committed transaction. New UUIDv7 IDs allow up to 60 seconds of future skew. Existing accepted legacy IDs preserve their retry results; unknown legacy IDs cannot start new local work. Upgrade all nodes together. For already queued remote legacy messages, each upgraded receiver allows at most 24 hours plus 60 seconds from its first upgrade; older exchange records wait until that grace ends before retirement. See [the replay rules and limitations](security.md#message-retention-and-replay-admission).

An old message may already have encrypted fragments in transit. Cleanup compacts its pending event into a cancellation that preserves its ID, destination, and fragment cursor. The receiver clears partial reconstruction when that cancellation arrives. A late receipt for an already retired message is ignored. Cleanup does not delete encrypted stream outboxes, replay/receipt history, configuration history, provider conversations, untracked files, or backups, and it does not bound the entire database.

Run `python3 scripts/smoke_history.py target/debug/gent` for an isolated CLI/MCP proof of ID generation, retained retries, native-file retry retirement, dry-run, cleanup, and restart maintenance. It advances only its temporary database's request clock; it does not change the system clock or use a model or relay.

## Encrypted transport storage

```sh
gent transport
gent transport status --json
gent transport clean --dry-run
gent transport clean
```

These owner commands report outgoing data/configuration packet usage, retry metadata, receiver checkpoints, legacy packet tombstones, redundant ciphertext copies, old replay evidence, and signed configuration history. Data packets have a 65,536-record / 512 MiB cap; configuration packets have an independent 65,536-record / 128 MiB reserve. Each class also admits up to 131,072 retry records, including legacy tombstones. New publication stops atomically when its class is full. Unconfirmed work stays queued and its exact retries still return the original packet. This does not bound the whole database or the relay.

Gent retains a stream's origin and the latest 128 position digests and corresponding wire receipts. Older signed packets are discarded before decryption without claiming they match the original. New ordered sends store ciphertext once. On upgrade, maintenance compacts redundant old copies in batches of eight and retires up to 256 old digests and 256 eligible receipt hashes per pass. Run `clean` again when a batch reaches its limit. Startup and 15-minute maintenance also run cleanup. Schema version 6 prevents older Gent binaries from opening compacted configuration history.

On two-node streams, the receiving daemon signs its committed position and digest. The sender verifies that checkpoint before retiring ciphertext or asking the relay to retire its copy. This confirms durable endpoint storage; agent acknowledgment and task completion remain separate. Each retirement batch processes at most 256 confirmed packets. Daemon-allocated requests lose their associated retry metadata; origins and legacy retry tombstones remain. Pending fragment/cancellation cursors protect the exact packet through interrupted writes. Unconfirmed packets stay available for offline catch-up. Exact agent retries retain their message results; a retired low-level transport request is rejected without re-encrypting it.

Confirmed positions also let the sender restore a lost relay's starting position. A receiver that loses or restores older endpoint state cannot fetch a retired prefix and requires endpoint recovery, which remains unfinished. Mesh peer associations, raw MLS groups, plaintext handoff folders, and total disk usage have separate retention needs. See [the storage and replay rules](security.md#ordered-transport-storage). Upgrade the development Worker with migration `0004_checkpoints.sql` alongside the daemons. Daemons now use schema version 13; older binaries refuse the upgraded database.

Full signed configurations have a separate 8,192-record / 256 MiB cap. Gent keeps the latest 64 full records and every revision still needed by an outgoing configuration stream or an interrupted join. Cleanup verifies and replaces up to eight older bodies with their accepted revision digests per pass. Those digests let delayed messages, configuration results, and duplicate streams still check their original authority. A full-history limit rejects an update atomically; queued publication or completing/revoking a stalled join can release capacity, subject to other peers' outstanding history needs. Accepted revisions have a separate lifetime cap of 1,048,576 per endpoint (32 MiB of digest payload). Legacy full records without digests reserve their eventual slots. Matching retries and compaction remain available at capacity, but new revisions, including renewals, fail atomically. Cleanup cannot free these permanent verification slots; reaching the limit can therefore lead to lease expiry. Authenticated archival or checkpoint transition beyond that limit remains future work.

An interrupted join retains its required suffix until its connected daemon confirms current configuration, or its node/key is revoked. Upgrading an older owner conservatively protects existing peers until that confirmation. Joined nodes do not serve enrollment and clear those migration-only join pins. `gent transport status` shows full-history bytes, digest counts, eligible records, and outstanding join pins. See [configuration history compaction](security.md#configuration-history-compaction) for the trust boundary and limits.

Add `--transport-storage` to `scripts/prove_pairing.py` to exercise 70 exchanges between physical nodes through the Worker, authenticated packet and retry-metadata retirement, replay-window cleanup, owner CLI preview/compaction, exact agent retry, and automatic startup cleanup of legacy duplicate copies. This uses disposable state and generic MCP clients without model calls.

Add `--event-storage` to finish that proof by advancing only the disposable request clocks, then checking sent-event cleanup, preserved control retries and registration generations, and startup cleanup on both machines. It runs after the other messaging checks and makes no further agent calls with the advanced clocks. Do not combine it with `--remote-join-helper`.

Use `--configuration-storage` to exercise 80 signed revisions, full-history compaction on both nodes, join-pin release, daemon restarts, human-readable diagnostics, and another remote configuration edit. It can be combined with `--file-objects`. The proof also checks accepted-revision counts, legacy reservations and the digest payload limit. `scripts/smoke_history.py` fills a disposable node with synthetic quota reservations to exercise CLI refusal, restart, exact retries and continued MCP messaging under existing authority. It removes only its synthetic reservations before testing recovery; real verification evidence is preserved.

Use `--edit-storage` to queue ten large policies while the owner is offline, restore their redundant legacy bodies in disposable state, and verify bounded preview/compaction, startup cleanup, eventual results on both machines, and exact retries. It can be combined with the other storage options. Only proof databases are altered; host clocks and real Gent state are unchanged. The bulk catch-up check allows five minutes and prints applied-result progress. The recorded debug-build run took 139 seconds for ten policies larger than 256 KiB; large-policy recovery latency still needs measurement and tuning before the daily-use trial. Failed runs preserve daemon logs in a private temporary diagnostics directory.

## Remaining integration work

Codex and Claude Code have explicit and host-metadata binding proofs on both OSes, including interactive clear/resume. The separate child-agent harness checks native spawning, resumption and isolated revocation. Authenticated import/export tools now pass native, generic MCP, and real-model proofs without putting large base64 payloads in model context. GUI/hosted file access remains to be tested. Daemon transport uses push signals; the agent-facing MCP inbox still requires a tool call. A common MCP connector does not guarantee that an idle host starts a model turn; optional wake/resume hooks require separate verification.

Private-file invitation pairing is implemented; its [enrollment notes](invitation-enrollment.md) distinguish the tested paths and remaining acceptance work. Hosted remote connectors remain unfinished. Account login passes the fixture proofs above; real GitHub consent and deployed service access remain unverified. SSH pairing, automatic peer links, configuration sync and edits from joined nodes, generic MCP messaging, real-model visual revision, and persistent relay turns have local development-relay proofs. Separate service-relay tests cover scoped credentials and native CLI enrollment. Shared agent guidance is bundled through MCP instructions. The [CLI design](cli.md) and [registration design](providers.md) describe the interfaces and remaining work.

## Real-agent relay proof

Add `--relay-turns` to the two-machine `scripts/prove_visual.py` command above to test a persistent intermediary and target. It passes with Linux Codex/Mac Claude and Linux Claude/Mac Codex, using each host's existing model access. Both Codex roles use medium reasoning. Shell tools and unrelated connectors are disabled; a transcript audit rejects non-Gent tool use. The test uses installed Gent entries, resumes the same host conversations, and keeps credentials outside model context.

The intermediary forwards exact user text and SVG/PNG bytes, checks pending status without resending, and recovers target progress after both daemons restart. It relays progress and final text without changes, retrieves the original files, submits a distinct follow-up, requests cancellation, detaches, and retrieves the target's final cancellation outcome without reattaching. Assertions inspect stored messages, actual tool responses, final answers, and recipient receipts. Logs and `report.json` remain under private `/tmp/gent-relay-host-*` directories; processes are stopped afterward.

The harness supplies the initial files as small JSON file objects in a synthetic user prompt. The following proof exercises larger native CLI files. GUI uploads, user-facing mobile attachment rendering, automatic background turns, and voice remain separate work. The test schedules host turns and does not prove exactly-once external execution or interruption of an executing task.

## Real-agent native files

Use `--native-files` instead of `--relay-turns` with the two-machine command above to exercise local files through the real hosts. Both Linux Codex/Mac Claude and Linux Claude/Mac Codex pass this workflow. A bounded helper writes a 1280 x 800 PNG (3,073,103 bytes) and SVG to disk. Each agent stages actual files in its Gent outbox and imports them through MCP. Messages carry `file_ids`; models never copy the file bytes as base64.

The reviewer exports and opens the PNG with its native image tool, requests a correction, and sends reference files. The builder exports and inspects that feedback, then imports and sends its revision. Both daemons restart during this exchange. After approval, the builder acts as an intermediary: it forwards exact user text and the revised files, then retrieves the target's response and unchanged files after another restart of both daemons. It exports and opens the returned PNG, gives exactly the target's private response text, acknowledges receipt, and detaches. Assertions compare plaintext hashes and lengths at both endpoints and require fresh encrypted object IDs on every send or forward.

Codex runs with workspace writes enabled for the fixture and Gent file folders. Claude permits only the fixture helper and exported PNG reads; absolute `Read` permissions use Claude's double-slash path syntax. Transcript audits permit Gent calls, literal fixture commands, and views of exported PNGs. Every exported PNG must be viewed, with actual image content in the tool result. Codex's exec JSON currently omits image-view events, so its audit also reads the exact synthetic session's own rollout under `CODEX_HOME/sessions`. It rejects an unavailable or ambiguous rollout. Unrelated sessions are not inspected.

Private logs, per-turn results, exported files, and `report.json` remain in each temporary proof directory. `protocol-report.json` preserves completed protocol assertions before transcript auditing, with an explicit audit-pending result; it is not a passing final report. To rerun a transcript audit without invoking a model, run `python3 scripts/prove_visual.py native-audit /absolute/proof/root` on that endpoint.

The proof schedules each turn and restricts rendering to a small fixture. Arbitrary application editing, GUI uploads, mobile rendering, background host wake-up, and voice remain separate work. Host OS access and inference-provider trust still apply.


## Database capacity and journal recovery

Run `python3 scripts/smoke_storage.py target/debug/gent` to verify the database policy through native CLI/MCP processes. It uses a disposable node, holds a read transaction until a send fails atomically, releases the reader and retries delivery, then restarts from a committed version-11 WAL left by an abruptly exited process. It checks exact retry, delivery status, schema upgrade, database integrity and the CLI page limit. It makes no model calls or permanent service changes.

Gent-owned databases now use rollback journaling and a 2 GiB page ceiling. Existing larger databases preserve their current pages and reject further allocation. Avoid long direct SQLite reads while Gent is running: readers can delay commits, which fail after the five-second busy timeout. Close other database users before upgrading from WAL; SQLite must acquire locks and preserve the committed WAL itself. Never remove journal or WAL files to force startup.

`gent files`, `gent files clean --dry-run`, `gent history clean --dry-run` and `gent transport clean --dry-run` expose usage and eligible cleanup. Cleanup requires journal space and may need database pages; these commands cannot guarantee recovery when the filesystem itself is full. Do not delete accepted hashes or retry evidence to make room. The page ceiling does not limit plaintext directories, temporary files, backups or writes from external programs, and does not automatically shrink the database file.


## Plaintext handoff limits and interrupted exports

`gent files` reports a shared budget of 4,096 records/reservations and 512 MiB for imported copies, completed exports and pending exports. Exact tracked retries still work at capacity. New admissions fail before Gent creates another plaintext export. Source files written directly by the host remain outside this admission control.

Retry an interrupted `gent_file_export` with the same file ID while source access is valid. Gent rechecks authorization at each committed step and resumes only a matching temporary prefix. Changed or unverified files remain visible with their final, temporary and quarantine paths in `gent files`. Inspect them before making manual changes. Expiry cleanup can retire verified unchanged files or missing paths; it preserves unverified or changed files and their reservations. Repeat cleanup while either handoff `more_due` or export `more_due` is nonzero.

Run `python3 scripts/smoke_handoffs.py target/debug/gent` to exercise this through real CLI/MCP processes. Add `--size-mib 32` to use the maximum file size instead of 2 MiB. It uses disposable state, injected storage failures, a process kill, a partial-file fixture, exact retry with the same inode, quota refusal, diagnostics, restart and expiry cleanup. The physical `prove_pairing.py --file-objects` proof also checks receiving-node export recovery after a failed ledger commit and both daemon restarts.
