# Gent

Gent will connect AI conversations across providers and machines through a permissioned cluster. Each conversation keeps its own context and tools while Gent handles discovery, messages, and replies.

The planned client includes a persistent machine daemon, a CLI, MCP tools, provider adapters, and skills. Turn-based relay mode will let a chat on another device forward messages to an existing conversation and return its responses.

This repository is in the planning stage. No runnable implementation is available yet. Provider and mobile compatibility will be established through integration tests.

## Development scope

- Shared protocol, client libraries, and permission semantics.
- Machine daemon and command-line setup and diagnostics.
- MCP interfaces, provider adapters, and skills.
- Documentation and tests that can run independently of the hosted service.

The initial integration targets are Codex and Claude Code on two machines, followed by hosted ChatGPT and Claude conversations and mobile relay.

A public distribution license will be selected before publication.
