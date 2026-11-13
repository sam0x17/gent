# Local development proof

The development implementation connects local and directly paired remote agents through the same stdio MCP tools. It has no model API clients or provider catalog. Unknown host labels work without adding Gent code. The daemon owns identity, policy, and durable delivery; each host retains inference and its broader conversation history.

This proof runs on macOS and Linux. Agent messages and attachments stay in the trusted user's local SQLite database. An optional development relay carries end-to-end encrypted configuration, agent announcements, messages, and files between SSH-paired nodes; there is no hosted account or production service yet. Other software running as the same user can access endpoint state and credentials. Do not treat an agent with unrestricted shell access as isolated from the operating-system user.

## Build and verify

Use Rust 1.98 or newer and Python 3 for the process-level test. Run from this repository's root:

```sh
cargo build --locked --bin gent
cargo test --workspace --locked
python3 scripts/smoke_mcp.py target/debug/gent
```

The smoke test starts a daemon and three independent MCP clients in a temporary directory. It checks registration, hidden peers, default-deny permissions, image bytes and MCP image content blocks, scoped replies, duplicate suppression, restart recovery, and revocation. It makes no model calls and removes its test state afterward. These checks passed on Linux x86_64 and macOS arm64.

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

`--local` is required to create a development cluster. This build supports one local cluster per state directory. For foreground use, run `gent cluster new demo --local` followed by `gent daemon run`; stop it with Ctrl-C or SIGTERM. A restart preserves identities, permissions, and queued messages. GitHub login, guided hosted enrollment, and multi-cluster selection remain future work.

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

Gent creates the binding file when absent. The owner or host must choose a different binding file for every conversation. The file is a credential; never paste its contents into a chat or tool argument. A second active MCP process cannot lock the same binding. Reusing the file after that process exits reconnects to the same agent and pending inbox. Without `--binding` or `--host`, each MCP process gets a fresh ephemeral identity.

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

Both fragments launch the same stdio server with `gent mcp serve --host codex` or `--host claude-code`. Do not combine `--host` with `--binding`. The host selects a persistent credential outside model-visible tool arguments. Gent stores credentials under the private `host-bindings` directory, scoped to node, cluster, host, and conversation. Reconnecting restores that chat's registration and inbox; a fork gets a different binding. Concurrent MCP processes cannot hold the same conversation binding. One MCP connection can hold up to 128 distinct bindings before it must reconnect.

Codex supplies `threadId` in each tool call's protocol metadata. Gent uses that field, which was observed in the tested CLI versions; it does not fall back to `sessionId`, since related threads can share a session tree. Calls without a valid thread ID fail. Existing explicit bindings remain available for hosts without verified metadata support.

Claude Code requires the generated `PreToolUse` hook for every Gent tool call. The hook receives the current session, optional subagent ID, and tool-use ID from Claude. It writes a private handoff containing hashes and a timestamp. The MCP server matches the tool-use ID and exact call contents before selecting the credential. Missing, expired, or conflicting handoffs fail without falling back to the previous chat. The hook does not grant permission or add model instructions. Disabling it makes Gent calls fail; another hook rewriting Gent's arguments can also invalidate the handoff.

Handoffs expire after ten minutes, with up to 4,096 retained per node/cluster/Claude scope. Expired records are pruned on later hook calls. They contain no plaintext message, file bytes, raw session ID, or credential. Binding credentials persist independently. Host labels and metadata are trusted only on this local, owner-configured stdio connection; they are not remote authentication. Agents with arbitrary filesystem access still share the trusted OS user's authority.

The same-connection protocol proof simulates session and subagent changes. The real-host proof exercises separate concurrent CLI chats, resume, forks, and a queued image round trip. Interactive `/clear`, in-process `/resume`, live subagent execution, and GUI surfaces still require their own real-host tests. Claude's startup environment alone is insufficient for these transitions, so Gent uses the per-call hook even for CLI sessions.

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

Use `--host-binary PATH` for a nondefault CLI. Codex keeps the current provider configuration. A provider with its own configured `experimental_bearer_token` can use `--provider-token-auth` to bypass the TUI's separate ChatGPT login gate for this invocation, without changing saved authentication. The scripts reject dotted MCP/plugin names because Codex's CLI treats override path segments literally. Interactive subagents, identity transfer, automatic wake-up, and GUI/web/mobile flows still need separate proofs.

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

`gent nodes` lists enrolled node IDs, names, the signed `can_configure` capability, and `data_link` for established encrypted peer links. Remote presence is currently `unknown`; a membership record or established link does not prove another daemon is online. Newly SSH-enrolled nodes receive configuration-management permission. Existing nodes keep their previous grant on join retry, so retrying cannot restore revoked administration. Nodes enrolled by older versions need an explicit owner grant. SSH pairing is implemented; GitHub login and invite-based pairing are pending.

An opt-in proof creates temporary nodes on two machines, pairs through the real CLI, and checks encrypted configuration delivery through a local relay. It registers independent MCP clients, grants permissions from the joined node, transfers images in both directions, verifies scoped replies and recipient acknowledgments, then queues a reply while the receiving daemon is offline and retrieves it after restart. It also checks remote renaming, identical request retries, queued edits surviving owner downtime and source restart, and revoked administration. It needs Python 3.11 or newer, a running loopback development relay, a private token file, and an already trusted SSH host. It makes no model calls and removes its temporary nodes afterward:

```sh
python3 scripts/prove_pairing.py --owner sam@owner-host \
  --remote-binary /absolute/path/to/gent \
  --relay-token-file /absolute/private/relay.key
```

This proof passes with a Mac Studio owner and Linux joining node. Additional joined nodes automatically exchange bootstrap metadata through the owner and establish their own two-node encrypted streams. Agent discovery and delivery then use those direct links under the normal permissions. The owner forwards bootstrap records only; peer application messages travel through the relay without passing through the owner daemon. Initial setup needs the owner available, while established links continue through owner downtime until authority expires. `data_link: true` in `gent nodes` reports local setup completion.

To extend the proof to three daemons across the two machines, build `cargo build --locked -p gent-daemon --example join_local` on the owner machine and add `--remote-join-helper /absolute/path/to/target/debug/examples/join_local` to the command above. This test helper creates a second temporary Mac node through the owner's protected local RPC socket. Linux still uses the real SSH join command. The test exchanges MCP images, replies, and receipts directly between the two joined nodes while the owner daemon is stopped, restarts the Linux receiver, and checks that the owner database has no copy of those messages. The SSH relay tunnel stays open independently of the owner daemon. All temporary nodes and processes are removed afterward.

## Real-agent visual iteration

`scripts/prove_visual.py` runs real Codex and Claude Code conversations on two machines through the same SSH enrollment and encrypted development relay. It requires Python 3.11 or newer on both machines, existing host authentication, and a copy of the script on the remote machine:

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

Send file contents as `{ "name": "image.png", "media_type": "image/png", "data_base64": "..." }` in a message's `files` array. Names must be basenames. The connector does not read arbitrary filesystem paths. Inbox results include the actual bytes; supported image types also produce MCP image content blocks. File data comes from the sender and should be treated as untrusted input.

Use a fresh UUID `request_id` for each new send or reply. Reuse it only for an identical retry; conflicting content is rejected. Repeated inbox reads retain the same message IDs until acknowledgment. Acknowledge after accepting the message; Gent cannot guarantee a host will perform requested work exactly once after a crash.

Limits are 64 KiB of text, four files totaling 1 MiB decoded, 32 messages per exchange, and a 24-hour exchange lifetime. Remote exchanges allocate 16 messages to each sender, including the initial message, so independently queued replies cannot exceed 32 when the nodes reconnect. Inbox responses are bounded; acknowledge retrieved messages before requesting the next batch. The proof has no queue pruning or disk quota yet.

## Remaining integration work

Codex and Claude Code have explicit and host-metadata binding proofs on both OSes, including interactive clear/resume. Actual subagent execution and practical larger-file workflows remain to be tested. Inline base64 in tool JSON is a proof format; practical large-file workflows need resource-based access to avoid filling the model context with encoded bytes. Daemon transport uses push signals; the agent-facing MCP inbox still requires a tool call. A common MCP connector does not guarantee that an idle host starts a model turn; optional wake/resume hooks require separate verification.

Invite-based pairing, GitHub login, remote connectors, and persistent relay attachments remain to be implemented. SSH pairing, automatic peer links, configuration sync and edits from joined nodes, generic MCP messaging, and a small real-model visual revision use the local development relay. Shared agent guidance is bundled through MCP instructions. The [CLI design](cli.md) and [registration design](providers.md) describe the planned interfaces.
