# Gent

Gent will connect AI agents across providers and machines through a permissioned cluster. Each agent keeps its own context and tools while Gent handles discovery, messages, and replies. An agent is an existing host conversation or session that announces itself through Gent's MCP connector.

The planned client includes a persistent machine daemon, a CLI, shared MCP tools, host setup helpers, and skills. Turn-based relay mode will let the agent in any Gent-enabled chat forward messages to an authorized target agent and return its responses. CLI, desktop, web, and mobile chats can act as intermediaries, within or across providers and machines.

The first pass includes files, screenshots, and images in messages and replies, both directly between agents and through user relay mode. A CLI-based agent can send a visual result to another agent, receive feedback or an annotated image, and return a revision in the same exchange.

Rust is the default implementation language for the protocol, encryption, daemon, CLI, MCP integrations, and shared application logic. Use other languages where platform bindings or tooling require them.

The planned daemon and native-client transport requires end-to-end encryption for messages, files, discovery data, and replicated configuration. Gent's centralized relay will store and forward ciphertext without those endpoints' decryption keys. The service will retain minimal account and cluster administration records, and connection and traffic metadata can still be visible. Intended agents and their model providers see the content delivered to them.

Web agents may use a Gent-hosted bridge with an explicit warning that Gent and the chosen provider can read messages and files shared through it. The bridge receives only its agent's authorized access; unrelated encrypted exchanges and full cluster policy remain protected. A verified user-controlled gateway or encryption-capable host may preserve confidentiality from Gent. Security status follows the actual transport path. Mobile integration still needs a separate proof and must never silently inherit a web exception.

An initial local implementation runs on macOS and Linux: a Rust daemon, CLI, SQLite inbox, permission evaluator, and stdio MCP server. Independent MCP clients can register, exchange text and image bytes, reply, and recover queued work after a restart. Follow the [local proof guide](docs/local-proof.md) to build and try it.

Agent messaging uses a local Unix socket and encrypted streams between nodes. `gent cluster join CLUSTER_UUID --via user@owner-host --name laptop` pairs through authenticated SSH, preserving local keys and establishing configuration and bidirectional data streams. The owner must already have a configured development relay. Joined nodes automatically establish direct encrypted links with each other through [private bootstrap exchanges](docs/security.md#automatic-peer-mesh). Once established, these links carry messages through the relay while the owner is offline, subject to the signed configuration lease. Owner-signed relay grants and persistent target selection are available through the CLI and MCP. Ordered relay turns and hosted accounts remain unfinished; see [relay selection](docs/local-proof.md#persistent-relay-selection).

Codex and Claude Code CLI tests pass on Linux and macOS with explicit and [host-selected conversation bindings](docs/local-proof.md#host-conversation-bindings). Both hosts pass concurrent-chat isolation with shared connector configuration, resume, forks, interactive clear/resume, and an image-file round trip after daemon restart. Both provider pairings also pass a small [visual review and revision across machines](docs/local-proof.md#real-agent-visual-iteration), exchanging SVG/PNG files and recovering pending feedback after both daemons restart. `gent integration config codex|claude-code` prints setup fragments; the Claude mode requires a per-call identity hook. [Installation, status, and removal](docs/local-proof.md#install-host-integrations) manage user-scope entries and recover interrupted updates. Shared agent guidance is bundled through MCP server instructions. Actual subagent execution and desktop/web/mobile integration remain unfinished.

The daemon applies [signed cluster authority](docs/security.md#live-daemon-authority) inside its RPC permission and delivery transactions. Authorized joined nodes can submit configuration edits through the active owner. The newest accepted revision wins and is projected back to TOML. Each committed edit wakes the [configuration dispatcher](docs/security.md#automatic-configuration-sync). Paired peers receive encrypted updates automatically and catch up after outages. Connected daemons receive WebSocket wake-up signals after ciphertext storage and immediately fetch verified updates. Periodic reconciliation and polling fallback recover missed signals or unavailable push connections. SSH pairing, remote edits, offline owner recovery, and encrypted MCP images, scoped replies, receipts, and offline delivery pass between Linux and macOS through local Wrangler/D1. Invite-based pairing remains unfinished.

## Planned setup

Once released, the intended setup on a machine with Rust and Cargo installed is:

```sh
cargo install gent-link && gent daemon install
```

The Cargo package will be `gent-link` and the CLI binary will be `gent`. macOS and Linux are the first supported platforms. The daemon installer will guide GitHub login and cluster enrollment, offer shell-hook installation, and be safe to rerun. Package publication is still pending.

The development build now implements [daemon lifecycle commands](docs/local-proof.md#daemon-services) through systemd user services and macOS LaunchAgents. After installing from source, `gent daemon install --local demo` initializes a development cluster and starts its service. Existing or SSH-joined nodes use `gent daemon install`. Start, stop, restart, status, logs, and uninstall preserve node state; uninstall retains keys and queued messages. Guided GitHub setup is still pending. [Shell integration](docs/local-proof.md#shell-integration) now provides PATH setup and completion for Zsh, Bash, and Fish through `gent hooks install`, with status and removal commands.

Commands use a consistent noun-first structure:

```sh
gent auth
gent auth login
gent providers list
gent integration install codex
gent integration install claude-code
gent node name
gent node name set my-node
gent nodes
gent cluster
gent cluster new
gent cluster join my-cluster-id
gent cluster switch
gent daemon status
gent daemon install
gent daemon uninstall
gent hooks install
gent hooks uninstall
```

These are independent command examples. `gent hooks remove` aliases `gent hooks uninstall`. See [the CLI design](docs/cli.md) for command behavior, guided setup, and scripting conventions.

Cluster configuration uses TOML at `~/.gent/config.toml`, with local node settings, an active cluster selection, and separate profiles for joined clusters. Switching clusters changes the CLI context without moving running agents or pending work. Private keys stay in an OS credential store or protected local key store, outside the TOML file. Encrypt shared configuration before replication.

Agents register with the local daemon through the same MCP tools, or through an authorized remote connector for hosted chats. `gent providers list` summarizes the hosts announced by those agents. Setup helpers can detect Codex and Claude Code integration configuration; other MCP-capable hosts use the same server. Model settings, inference credentials, and conversation history stay with the host. Agents using LM Studio, llama.cpp, or other model backends participate through their MCP host without a dedicated Gent model integration. See [MCP hosts and agent registration](docs/providers.md).

## Development scope

- Shared Rust crates for the protocol, client libraries, encryption, and permission semantics.
- Machine daemon and command-line setup and diagnostics.
- Shared MCP registration and messaging tools, host setup helpers, and skills.
- Provider listing from agent registrations, with optional host lifecycle hooks where supported.
- Permissioned file, screenshot, and image transfer between agents and through relay mode.
- Documentation and tests that can run independently of the hosted service.

Codex and Claude Code have equal priority on macOS and Linux, with the same acceptance criteria for their CLIs. VS Code integrations and desktop applications are also targets, with separate tests for existing-session access and lifecycle behavior. ChatGPT and Claude mobile have equal priority, starting with iOS. Every supported chat surface will use the same relay operations; mobile and voice are applications of that shared capability.

The current MCP interface uses inbox polling and bounded exchanges. Automatic wake or resume will require a verified host mechanism; messages remain queued while an agent is busy or inactive. Gent must never interrupt automatically. The planned account model has one human owner, with separate identities and memberships to accommodate future multi-user clusters.

Mobile primarily lets the user send requests and retrieve replies. Occasional critical notifications invite the user to return; they do not automatically start a mobile agent turn. An optional coordinator can run on an available server, handle high-priority requests from other agents, and notify the user when human input is needed. Coordination can continue within its granted authority while the phone is asleep or offline.

## Visual identity

Gent's icon and logo will use a top hat motif. The exact design, colors, and typography remain open.

## Future native applications

Native Gent desktop and mobile apps are deferred beyond the first implementation pass. Planned capabilities include real-time voice communication with authorized agents using Kokoro for speech generation, display of their conversation context and history, native file-transfer controls, and rich image and artifact display, including images generated through Codex. These apps will reuse the Rust core and encrypted file transfer provided by the initial MCP and connector integrations. Their design, speech-recognition component, and schedule remain open.

A limited iOS companion investigation will explore encrypted push reception and supported handoff to provider apps. iOS permits notification extensions to decrypt eligible notifications, but does not provide a general-purpose persistent daemon. A companion's encrypted inbox alone does not secure a third-party provider's cloud connector calls. This investigation does not bring the full native app into the first pass.

A Steam-style game overlay is also planned as an optional desktop app feature for PC and Mac. It will aim to show agent notifications and offer a quick chat window without leaving the game, with voice support to follow. The overlay is outside the first pass; compatibility and implementation details remain to be established.

A public distribution license will be selected before publication.
