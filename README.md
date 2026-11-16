# Gent

Gent will connect AI agents across providers and machines through a permissioned cluster. Each agent keeps its own context and tools while Gent handles discovery, messages, and replies. An agent is an existing host conversation or session that announces itself through Gent's MCP connector.

The planned client includes a persistent machine daemon, a CLI, shared MCP tools, host setup helpers, and skills. Turn-based relay mode will let the agent in any Gent-enabled chat forward messages to an authorized target agent and return its responses. CLI, desktop, web, and mobile chats can act as intermediaries, within or across providers and machines.

The first pass includes files, screenshots, and images in messages and replies, both directly between agents and through user relay mode. A CLI-based agent can send a visual result to another agent, receive feedback or an annotated image, and return a revision in the same exchange.

Rust is the default implementation language for the protocol, encryption, daemon, CLI, MCP integrations, and shared application logic. Use other languages where platform bindings or tooling require them.

The planned daemon and native-client transport requires end-to-end encryption for messages, files, discovery data, and replicated configuration. Gent's centralized relay will store and forward ciphertext without those endpoints' decryption keys. The service will retain minimal account and cluster administration records, and connection and traffic metadata can still be visible. Intended agents and their model providers see the content delivered to them.

Web agents may use a Gent-hosted bridge with an explicit warning that Gent and the chosen provider can read messages and files shared through it. The bridge receives only its agent's authorized access; unrelated encrypted exchanges and full cluster policy remain protected. A verified user-controlled gateway or encryption-capable host may preserve confidentiality from Gent. Security status follows the actual transport path. Mobile integration still needs a separate proof and must never silently inherit a web exception.

An initial local implementation runs on macOS and Linux: a Rust daemon, CLI, SQLite inbox, permission evaluator, and stdio MCP server. Independent MCP clients can register, exchange text and image bytes, reply, and recover queued work after a restart. Follow the [local proof guide](docs/local-proof.md) to build and try it.

Run `scripts/check.sh` for [development checks](docs/testing.md), including formatting, strict Clippy, Rust tests and local CLI/MCP smoke checks. The GitHub workflow uses Linux; macOS testing remains deliberate.

The [local work journal](docs/work.md) records an agent's start before consequential host work and preserves uncertain attempts across restarts. `gent work` lists reports; owner-only `gent work reconcile` records reviewed outcomes or permits a subsequent attempt. It does not execute work, independently verify completion or restore old execution authority from an archive.

The [remote MCP gateway](docs/gateway.md) now serves the same agent tools on a user-controlled node, with direct TLS, expiring host credentials and persistent per-conversation bindings. It supports inline files/images, relay turns and [owner-approved OAuth](docs/gateway-oauth.md) with PKCE and rotating refresh tokens. Tests use synthetic trusted hosts; actual ChatGPT/Claude hosted connectors and mobile operation still need verification.

The [account login](docs/local-proof.md#account-login) supports GitHub browser/device login, service-session status and logout. Native tests pass on both OSes against a local provider fixture, including interrupted login and offline logout. The default `https://api.gent.link` service is deployed for an owner-only private trial; real GitHub device consent and first-owner setup pass. Actual browser callbacks remain unverified.

The [service-backed transport](docs/local-proof.md#service-backed-transport-proof) uses individual node credentials with cluster-scoped storage and notifications. Local proofs cover revocation and native encrypted transport on Linux and macOS. [First-owner setup](docs/service-setup.md) connects account login to `gent cluster new NAME` and recoverable relay provisioning. Additional nodes can [join through Gent](docs/service-setup.md#add-another-machine-through-gent) with `gent node add laptop` on an existing configuration-authorized node, then `gent cluster join CODE` on the new machine. The invitation supplies the name, and joining starts the daemon. A private one-time code authenticates encrypted invitation delivery. Trusted SSH and private-file invitations remain available. Each node gets its own relay credential.

Agent messaging uses a local Unix socket and encrypted streams between nodes. `gent cluster join CLUSTER_UUID --via user@owner-host --name laptop` pairs through authenticated SSH, preserving local keys and establishing configuration and bidirectional data streams. The owner must already have a configured relay. For service clusters, sign into the same account before joining; each machine keeps its own relay credential. Joined nodes automatically establish direct encrypted links with each other through [private bootstrap exchanges](docs/security.md#automatic-peer-mesh). Once established, these links carry messages through the relay while the owner is offline, subject to the signed configuration lease. Owner-signed relay grants, saved target selection, ordered turns, cancellation requests, and final outcomes are available through the CLI and MCP. These pass generic MCP proofs on both OSes and across Linux and the Mac Studio. Both real Codex/Claude intermediary-target pairings also pass exact text/files, pending checks, restart recovery, completion, cancellation, and detach. Authenticated MCP import/export now supports local files up to 32 MiB, with encrypted grants, automatic transfer, and fresh objects on forwarding. The private hosted trial passes code enrollment, encrypted messages, a 2 MiB file round trip, configuration edits and both daemon restarts between Linux and macOS. That check uses generic MCP clients and one existing real account session copied into isolated test homes; independent sign-in on the test Mac and hosted GUI/mobile connectors are separate checks. See [relay mode](docs/local-proof.md#persistent-relay-selection).

Codex and Claude Code CLI tests pass on Linux and macOS with explicit and [host-selected conversation bindings](docs/local-proof.md#host-conversation-bindings). Both hosts pass concurrent-chat isolation with shared connector configuration, resume, forks, interactive clear/resume, and an image-file round trip after daemon restart. A separate [real child-agent proof](docs/local-proof.md#real-child-agents) checks native spawning, resumption, Gent permission isolation and child revocation. Native parent/child context sharing remains controlled by the host. Both provider pairings also pass a small [visual review and revision across machines](docs/local-proof.md#real-agent-visual-iteration), exchanging SVG/PNG files and recovering pending feedback after both daemons restart. `gent integration config codex|claude-code` prints setup fragments; the Claude mode requires a per-call identity hook. [Installation, status, and removal](docs/local-proof.md#install-host-integrations) manage user-scope entries and recover interrupted updates. Shared agent guidance is bundled through MCP server instructions. Desktop/web/mobile integration remains unfinished.

The daemon applies [signed cluster authority](docs/security.md#live-daemon-authority) inside its RPC permission and delivery transactions. Authorized joined nodes can submit configuration edits through the active owner. The newest accepted revision wins and is projected back to TOML. Each committed edit wakes the [configuration dispatcher](docs/security.md#automatic-configuration-sync). Paired peers receive encrypted updates automatically and catch up after outages. Connected daemons receive WebSocket wake-up signals after ciphertext storage and immediately fetch verified updates. Periodic reconciliation and polling fallback recover missed signals or unavailable push connections. SSH pairing, remote edits, catch-up after owner downtime, and encrypted MCP images, scoped replies, receipts, and offline delivery pass between Linux and macOS through local Wrangler/D1. Private-file invitation pairing also passes across the two machines, including restart recovery and explicit continuation; see [the invitation workflow](docs/invitation-enrollment.md). Replacement of a lost signing owner remains unfinished. A planned transfer to an enrolled node uses [`gent cluster owner prepare`, `commit`, and `resume`](docs/owner-succession.md#local-owner-commands). Commitment permanently stops the source signer; the daemons retain delivery progress and activate the prepared successor after verifying the complete journal. A physical Mac-Linux proof passes the public commands, interrupted journal reception and source-offline activation.

## Planned setup

Source installation is available now: `cargo install --locked --path crates/gent-link` from this checkout. See [installation and upgrades](docs/installation.md) for prerequisites, local trials and private source archives.

Once released, the intended setup on a machine with Rust and Cargo installed is:

```sh
cargo install gent-link && gent daemon install
```

The Cargo package will be `gent-link` and the CLI binary will be `gent`. macOS and Linux are the first supported platforms. The daemon installer will guide GitHub login and cluster enrollment, offer shell-hook installation, and be safe to rerun. Package publication is still pending.

The development build implements [daemon lifecycle commands](docs/local-proof.md#daemon-services) through systemd user services and macOS LaunchAgents. After installing from source, `gent daemon install --local demo` initializes a development cluster and starts its service. Existing or joined nodes use `gent daemon install`. Start, stop, restart, status, logs, and uninstall preserve node state; uninstall retains keys and queued messages. Hosted installation guides login and owner/invitation enrollment, with explicit flags for noninteractive use. `gent cluster connect` resumes interrupted setup or replaces an invalid credential. [Shell integration](docs/local-proof.md#shell-integration) provides PATH setup and completion for Zsh, Bash, and Fish through `gent hooks install`, with status and removal commands.

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
gent node reset  # only when retiring local state for fresh enrollment
gent daemon status
gent daemon install
gent daemon uninstall
gent hooks install
gent hooks uninstall
```

These are independent command examples. `gent hooks remove` aliases `gent hooks uninstall`. See [the CLI design](docs/cli.md) for command behavior, guided setup, and scripting conventions.

Cluster configuration uses TOML at `~/.gent/config.toml`. A node belongs to one cluster, shared by every local chat and CLI command. Reset and re-enroll to replace that membership. Future multi-cluster support would use simultaneous memberships, with per-agent access.

Agents register with the local daemon through the same MCP tools, or through an authorized remote connector for hosted chats. `gent providers list` summarizes the hosts announced by those agents. Setup helpers can detect Codex and Claude Code integration configuration; other MCP-capable hosts use the same server. Model settings, inference credentials, and conversation history stay with the host. Agents using LM Studio, llama.cpp, or other model backends participate through their MCP host without a dedicated Gent model integration. See [MCP hosts and agent registration](docs/providers.md).

## Development scope

- Shared Rust crates for the protocol, client libraries, encryption, and permission semantics.
- Machine daemon and command-line setup and diagnostics.
- Shared MCP registration and messaging tools, host setup helpers, and skills.
- Provider listing from agent registrations, with optional host lifecycle hooks where supported.
- Permissioned file, screenshot, and image transfer between agents and through relay mode.
- Documentation and tests that can run independently of the hosted service.

Codex and Claude Code have equal priority on macOS and Linux, with the same acceptance criteria for their CLIs. VS Code integrations and desktop applications are also targets, with separate tests for existing-session access and lifecycle behavior. ChatGPT and Claude mobile have equal priority, starting with iOS. Every supported chat surface will use the same relay operations; mobile and voice are applications of that shared capability.

The MCP interface uses a durable inbox and bounded exchanges. Both CLI hosts can opt into [queued delivery](docs/wake.md) with `gent integration install <host> --wake`. `gent integration start codex` starts or reuses Codex's native background daemon; attach with `codex --remote unix://`, using the same Codex home. `gent integration status codex --live` checks endpoint connectivity. Saved attachments recover after MCP replacement, and native proofs retain automatic delivery after client disconnect and a planned Codex restart. Claude Code uses native plugin input and a retained command guard, with automatic delivery after resuming the same session. Both adapters leave busy queues and explicit interruption holds under host control. Codex and existing Claude background agents can separately opt into [automatic startup and idle recovery](docs/host-recovery.md); incomplete native work still needs owner review. OS-reboot recovery remains unverified. The planned account model has one human owner, with separate identities and memberships to accommodate future multi-user clusters.

Linux Claude Code in VS Code also passes native automatic delivery, busy/interruption boundaries, editor/daemon restart and opt-out using a loopback model. The tested Codex extension uses an embedded stdio server and retains manual inbox access; automatic IDE delivery is unfinished. See [VS Code delivery](docs/wake.md#vs-code-delivery) for versions and limits. Broader desktop, macOS IDE and real-model IDE wake acceptance remain ahead.

Mobile primarily lets the user send requests and retrieve replies. Occasional critical notifications invite the user to return; they do not automatically start a mobile agent turn. An optional coordinator can run on an available server, handle high-priority requests from other agents, and notify the user when human input is needed. Coordination can continue within its granted authority while the phone is asleep or offline.

## Visual identity

Gent's icon and logo will use a top hat motif. The exact design, colors, and typography remain open.

## Future native applications

Native Gent desktop and mobile apps are deferred beyond the first implementation pass. Planned capabilities include real-time voice communication with authorized agents using Kokoro for speech generation, display of their conversation context and history, native file-transfer controls, and rich image and artifact display, including images generated through Codex. These apps will reuse the Rust core and encrypted file transfer provided by the initial MCP and connector integrations. Their design, speech-recognition component, and schedule remain open.

A limited iOS companion investigation will explore encrypted push reception and supported handoff to provider apps. iOS permits notification extensions to decrypt eligible notifications, but does not provide a general-purpose persistent daemon. A companion's encrypted inbox alone does not secure a third-party provider's cloud connector calls. This investigation does not bring the full native app into the first pass.

A Steam-style game overlay is also planned as an optional desktop app feature for PC and Mac. It will aim to show agent notifications and offer a quick chat window without leaving the game, with voice support to follow. The overlay is outside the first pass; compatibility and implementation details remain to be established.

A public distribution license will be selected before publication.
