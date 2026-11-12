# Gent

Gent will connect AI agents across providers and machines through a permissioned cluster. Each agent keeps its own context and tools while Gent handles discovery, messages, and replies. An agent is a registered participant backed by a persistent provider conversation or session.

The planned client includes a persistent machine daemon, a CLI, MCP tools, provider adapters, and skills. Turn-based relay mode will let the agent in any Gent-enabled chat forward messages to an authorized target agent and return its responses. CLI, desktop, web, and mobile chats can act as intermediaries, within or across providers and machines.

The first pass includes files, screenshots, and images in messages and replies, both directly between agents and through user relay mode. A CLI-based agent can send a visual result to another agent, receive feedback or an annotated image, and return a revision in the same exchange.

Rust is the default implementation language for the protocol, encryption, daemon, CLI, MCP integrations, and shared application logic. Use other languages where platform bindings or tooling require them.

Daemon and native-client exchanges use end-to-end encryption for messages, files, discovery data, and replicated configuration. Gent's centralized relay stores and forwards ciphertext without those endpoints' decryption keys. The service retains minimal account and cluster administration records, and connection and traffic metadata can still be visible. Intended agents and their model providers see the content delivered to them.

Web agents may use a Gent-hosted bridge with an explicit warning that Gent and the chosen provider can read messages and files shared through it. The bridge receives only its agent's authorized access; unrelated encrypted exchanges and full cluster policy remain protected. A verified user-controlled gateway or encryption-capable host may preserve confidentiality from Gent. Security status follows the actual transport path. Mobile integration still needs a separate proof and must never silently inherit a web exception.

This repository is in the planning stage. No runnable implementation is available yet. Compatibility for each provider and chat surface will be established through integration tests.

## Planned setup

Once released, the intended setup on a machine with Rust and Cargo installed is:

```sh
cargo install gent-link && gent daemon install
```

The Cargo package will be `gent-link` and the CLI binary will be `gent`. macOS and Linux are the first supported platforms. The daemon installer will guide GitHub login and cluster enrollment, offer shell-hook installation, and be safe to rerun. Package publication is still pending.

Commands use a consistent noun-first structure:

```sh
gent auth
gent auth login
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

## Development scope

- Shared Rust crates for the protocol, client libraries, encryption, and permission semantics.
- Machine daemon and command-line setup and diagnostics.
- MCP interfaces, provider adapters, and skills.
- Permissioned file, screenshot, and image transfer between agents and through relay mode.
- Documentation and tests that can run independently of the hosted service.

Codex and Claude Code have equal priority on macOS and Linux, with the same acceptance criteria for their CLIs. VS Code integrations and desktop applications are also targets, with separate tests for existing-session access and lifecycle behavior. ChatGPT and Claude mobile have equal priority, starting with iOS. Every supported chat surface will use the same relay operations; mobile and voice are applications of that shared capability.

Incoming messages automatically wake or resume idle agents where supported and queue while an agent is busy. Gent never interrupts automatically. Exchanges have limits to prevent runaway agent loops. The initial account model has one human owner, with separate identities and memberships to accommodate future multi-user clusters.

## Visual identity

Gent's icon and logo will use a top hat motif. The exact design, colors, and typography remain open.

## Future native applications

Native Gent desktop and mobile apps are deferred beyond the first implementation pass. Planned capabilities include real-time voice communication with authorized agents using Kokoro for speech generation, display of their conversation context and history, native file-transfer controls, and rich image and artifact display, including images generated through Codex. These apps will reuse the Rust core and encrypted file transfer provided by the initial MCP and connector integrations. Their design, speech-recognition component, and schedule remain open.

A limited iOS companion investigation will explore encrypted push reception and supported handoff to provider apps. iOS permits notification extensions to decrypt eligible notifications, but does not provide a general-purpose persistent daemon. A companion's encrypted inbox alone does not secure a third-party provider's cloud connector calls. This investigation does not bring the full native app into the first pass.

A Steam-style game overlay is also planned as an optional desktop app feature for PC and Mac. It will aim to show agent notifications and offer a quick chat window without leaving the game, with voice support to follow. The overlay is outside the first pass; compatibility and implementation details remain to be established.

A public distribution license will be selected before publication.
