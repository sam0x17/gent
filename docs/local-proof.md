# Local development proof

The first implementation connects agents on one machine through the same stdio MCP tools. It has no model API clients or provider catalog. Unknown host labels work without adding Gent code. The daemon owns identity, policy, and durable delivery; each host retains inference and its broader conversation history.

This proof runs on macOS and Linux. It has no remote listener, E2EE protocol, hosted account, or production service. Messages and attachments are stored in the trusted user's local SQLite database. Other software running as that user can access that state and its credentials. Do not treat an agent with unrestricted shell access as isolated from the operating-system user.

## Build and verify

Use Rust 1.98 or newer and Python 3 for the process-level test. Run from this repository's root:

```sh
cargo build --locked --bin gent
cargo test --workspace --locked
python3 scripts/smoke_mcp.py target/debug/gent
```

The smoke test starts a daemon and three independent MCP clients in a temporary directory. It checks registration, hidden peers, default-deny permissions, image bytes and MCP image content blocks, scoped replies, duplicate suppression, restart recovery, and revocation. It makes no model calls and removes its test state afterward. These checks passed on Linux x86_64 and macOS arm64.

Separate real-host tests passed for Codex and Claude Code CLIs on both OSes using explicit per-conversation binding files. Each host registered a synthetic conversation, resumed that same conversation after a daemon restart, retrieved and identified an image, and replied with identical file bytes. These tests establish that workflow only; they do not establish automatic pairing, shared host configuration isolation, or idle wake/resume.

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
gent cluster new demo --local
gent daemon run
```

Keep the daemon running in that terminal. In another terminal, set the same `GENT_HOME` and inspect it:

```sh
export GENT_HOME="$HOME/.gent-dev"
gent daemon status
gent node name set workstation
gent node name
gent cluster
gent config path
```

`--local` is required to create a development cluster. This build supports one local cluster per state directory. `gent daemon run` runs in the foreground; stop it with Ctrl-C. A restart preserves identities, permissions, and queued messages. Service installation and multi-cluster enrollment are future work.

## Connect an MCP client

Configure the host to launch the following command, with absolute paths to the binary, state directory, and binding file:

```sh
gent --home /absolute/private/state mcp serve --binding /absolute/private/state/bindings/chat-a.key
```

Gent creates the binding file when absent. The owner or host must choose a different binding file for every conversation. The file is a credential; never paste its contents into a chat or tool argument. A second active MCP process cannot lock the same binding. Reusing the file after that process exits reconnects to the same agent and pending inbox. Without `--binding`, each MCP process gets a fresh ephemeral identity.

A host-wide MCP configuration may be shared by multiple chats. One binding in that shared configuration does not establish per-chat isolation. Automatic binding in Codex and Claude Code is still an integration proof; use explicit, separate configurations for each conversation as in the tested workflow. Merely supplying different agent names does not create separate identities on one authenticated connection.

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

This blocks new messages and delivery of queued messages from A to B, as well as replies in the blocked relationship. Owner commands can inspect all local registrations; agent-facing discovery exposes only permitted peers. `last_seen` records an agent's latest request and does not prove an active model turn or live connection.

Selectors support an agent ID, `'*'`, `same-node`, `node:UUID`, or `group:NAME`. Quote `'*'` in the shell. Groups and rules are stored under `[policy]` in `config.toml`. Edit the TOML to remove a rule, then run `gent config validate` and `gent config apply`. Applying a change signs and commits a new revision. The newest accepted revision replaces the previous shared configuration; editing the file without applying it does not change active permissions. `gent agent revoke AGENT_ID` invalidates that registration credential permanently in this proof.

Signed authority and message queues share `state.sqlite3`. First daemon startup preserves existing local identities and creates a private `identity.key` for node and owner signing keys, separate from the RPC credential in `owner.key`. Keep both keys and the database private. Existing databases must have mode 0600; Gent rejects shared or symlink files. Missing signing keys for an initialized database cause an error instead of silently creating a different identity.

After a signed change commits, Gent projects the newest state into TOML while preserving unrelated local settings. If the filesystem write fails, the result reports `applied: true` and `config_saved: false`; the committed policy remains in effect and projection is retried. `applied_revision` identifies the revision represented by the file. Node renaming now uses this signed path and requires a running daemon.

`gent cluster` and `gent daemon status` show the active revision and lease status. The owner daemon renews its 24-hour configuration lease when six hours or less remain, checking at startup and every 15 minutes. Use `gent cluster renew` to renew immediately. Agent operations remain blocked if the lease expires before a renewal commits.

Encrypted configuration streams can now update this same live policy through trusted library APIs. Automatic network distribution, remote edit requests, and protected node pairing are still pending; ordinary CLI/MCP messages remain local.

## Files, retries, and limits

Send file contents as `{ "name": "image.png", "media_type": "image/png", "data_base64": "..." }` in a message's `files` array. Names must be basenames. The connector does not read arbitrary filesystem paths. Inbox results include the actual bytes; supported image types also produce MCP image content blocks. File data comes from the sender and should be treated as untrusted input.

Use a fresh UUID `request_id` for each new send or reply. Reuse it only for an identical retry; conflicting content is rejected. Repeated inbox reads retain the same message IDs until acknowledgment. Acknowledge after accepting the message; Gent cannot guarantee a host will perform requested work exactly once after a crash.

Limits are 64 KiB of text, four files totaling 1 MiB decoded, 32 messages per exchange, and a 24-hour exchange lifetime. Inbox responses are bounded; acknowledge retrieved messages before requesting the next batch. The proof has no queue pruning or disk quota yet.

## Remaining integration work

Codex and Claude Code pass explicit pairing, session continuity, and a small image round trip on both OSes. Separate concurrent conversations in normal shared host configurations, automatic binding, and larger files remain to be tested. Inline base64 in tool JSON is a proof format; practical large-file workflows need resource-based access to avoid filling the model context with encoded bytes. The current transport is polling-only. A common MCP connector does not guarantee that an idle host starts a model turn; optional wake/resume hooks require separate verification.

Cross-machine transport, encryption and enrollment, signed configuration replication, GitHub login, remote connectors, daemon installers, host setup helpers, shell hooks, a Gent skill, and persistent relay attachments remain to be implemented. The [CLI design](cli.md) and [registration design](providers.md) describe those planned interfaces.
