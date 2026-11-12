# Gent

Gent will connect AI agents across providers and machines through a permissioned cluster. Each agent keeps its own context and tools while Gent handles discovery, messages, and replies. An agent is a registered participant backed by a persistent provider conversation or session.

The planned client includes a persistent machine daemon, a CLI, MCP tools, provider adapters, and skills. Turn-based relay mode will let the agent in any Gent-enabled chat forward messages to an authorized target agent and return its responses. CLI, desktop, web, and mobile chats can act as intermediaries, within or across providers and machines.

The first pass includes files, screenshots, and images in messages and replies, both directly between agents and through user relay mode. A CLI-based agent can send a visual result to another agent, receive feedback or an annotated image, and return a revision in the same exchange.

This repository is in the planning stage. No runnable implementation is available yet. Compatibility for each provider and chat surface will be established through integration tests.

## Development scope

- Shared protocol, client libraries, and permission semantics.
- Machine daemon and command-line setup and diagnostics.
- MCP interfaces, provider adapters, and skills.
- Permissioned file, screenshot, and image transfer between agents and through relay mode.
- Documentation and tests that can run independently of the hosted service.

The initial integration targets are Codex and Claude Code agents on two machines, including relay from either provider, followed by hosted ChatGPT and Claude agents. Every supported chat surface will use the same relay operations; mobile and voice are applications of that shared capability.

## Visual identity

Gent's icon and logo will use a top hat motif. The exact design, colors, and typography remain open.

## Future native applications

Native Gent desktop and mobile apps are deferred beyond the first implementation pass. Planned capabilities include Kokoro-based real-time voice communication with authorized agents, display of their conversation context and history, native file-transfer controls, and rich image and artifact display, including images generated through Codex. These apps will reuse the file transfer provided by the initial MCP and connector integrations. Their design and schedule remain open.

A public distribution license will be selected before publication.
