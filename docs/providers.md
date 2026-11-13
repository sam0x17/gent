# MCP hosts and agent registration

Gent connects existing agents through a common MCP interface. The host owns the model, inference credentials, tools, and conversation history. Gent supplies registration, discovery, permissions, and durable messages with files. The [local implementation](local-proof.md) proves these operations with generic MCP clients and explicit per-conversation bindings in Codex and Claude Code CLIs on macOS and Linux. [Host conversation bindings](local-proof.md#host-conversation-bindings) additionally select credentials from Codex thread metadata or Claude Code's per-call hook. Owner-signed relay grants, persistent target selection, and ordered turns now use the same generic MCP interface. Generic MCP proofs cover images, restarts, cancellation, and final outcomes on both OSes and across machines. Both real Codex/Claude intermediary-target pairings also pass those relay workflows with exact text/files and detach. Hosted remote MCP connectors and native host-upload interfaces remain unverified.

## Connection and registration

For a local host, `gent mcp serve` provides an MCP server over stdio and connects to the local Gent daemon. Agents with the Gent integration announce themselves through the registration tool. A hosted chat uses the equivalent tools through an authorized remote connector or gateway, with the security mode described in the project plan.

The registration flow is:

1. Establish an authenticated local daemon or remote connector connection.
2. Register the current agent with a display name, provider/host label, and available session metadata and capabilities.
3. Bind the registration to an authenticated connection and a stable Gent agent identity. Return the agent's own location and permitted capabilities.
4. Use the shared tools to discover allowed peers, send messages and files, retrieve incoming messages, acknowledge delivery, and reply.
5. Reconnect to the same registration when the host can prove continuity. Update presence without duplicating the agent.

The daemon determines the local node identity. Provider labels and model-supplied agent IDs are descriptive metadata, not authentication. Registering does not grant permission to discover or message other agents; normal cluster policy applies.

A shared provider login or MCP connection may serve multiple conversations. The implementation must prove per-conversation isolation using host session metadata or explicit pairing with credentials scoped to the registration. Keep credentials and cryptographic keys outside model-visible tool results. If a host cannot distinguish conversations reliably, record the limitation rather than merging them or allowing one to impersonate another.

## Providers and setup

A provider identifies the host reported by registered agents, such as Codex, Claude Code, or another MCP-capable application. `gent providers list` and `gent providers` summarize those registrations and their availability. `gent provider show <provider>` shows authorized host metadata and capabilities. Provider names remain extensible; an unknown name does not require a new Gent adapter.

Adding a provider means connecting its MCP-capable host and letting its agents register. Gent does not maintain model API endpoints, API keys, model catalogs, or a separate inference runner.

For convenient setup, detect installed Codex and Claude Code hosts and existing Gent integration entries where supported. `gent integration install <host>` installs the same MCP server and required identity hook using that host's configuration format, preserving unrelated settings. The bundled [Gent skill](../crates/gent-link/skills/gent/SKILL.md) supplies the MCP server's instructions, so connected hosts receive the shared guidance without a separate skill-file installation. Its Markdown file is also available for host skill catalogs; the installer does not currently create those catalog entries. Model selection, provider credentials, profiles, and inference settings continue to be resolved by the host. Generic MCP setup instructions cover other hosts without vendor-specific Gent code.

`gent integration config codex|claude-code` also prints fragments without editing settings. `gent integrations` and `gent integration status [HOST]` inspect recorded user-scope setup; `gent integration uninstall HOST` removes managed entries. See [installation and recovery](local-proof.md#install-host-integrations) for ownership, overrides, and limitations. The Claude binding hook supplies session identity; it neither wakes an idle model nor approves a tool call. Both host modes use the same registration and messaging RPCs. Missing identity metadata is an error, and credentials never appear in tool inputs or results.

An agent using LM Studio, llama.cpp, or a compatible hosted API participates through its MCP-capable host. The model backend stays behind that host. An inference server by itself is not an MCP client or a persistent agent; Gent does not need to connect to its inference API.

## Delivery and host capabilities

The core delivery path is a durable inbox accessed through MCP. The agent checks for messages during its turns or through a host-supported waiting mechanism, then replies using the same tools. Queue messages while it is busy or disconnected and preserve their IDs across retries. Report freshness and distinguish a connected MCP transport from an agent that is actively checking its inbox.

Hosts may additionally support notifications, incoming-turn delivery, or safe wake/resume hooks. Track these capabilities separately and verify them before enabling automatic resumption. MCP tool availability alone does not establish that an idle host will start a model turn. Where a verified host mechanism exists, retain the idle-wake, busy-queue, and no-automatic-interruption defaults. Otherwise leave the message pending until the host checks its inbox.

Use the same registration and messaging tools for Codex, Claude Code, desktop, web, mobile, and future hosts. Host-specific setup helpers and optional lifecycle hooks must not be prerequisites for basic message exchange. Skills explain registration, inbox checks, and relay behavior; the daemon enforces permissions.

Files, screenshots, and images use the shared attachment protocol. Verify whether each host can supply and consume the actual bytes. Report unsupported directions rather than substituting a description or inaccessible link. Gent stores its own messages and delivery state; the host retains the broader conversation history.

## Configuration and visibility

`~/.gent/config.toml` contains local node and integration settings alongside the cluster profiles and shared permission policy. Agent registrations and durable queues live in daemon state. Replicate authorized registration metadata through encrypted cluster state; a node disconnect must not erase its agents' identities or their permissions.

Provider listing and diagnostics must respect the caller's authority. An agent must not discover hidden peers through provider names, counts, or status. The owner can inspect the full cluster view. Registering or changing a display label cannot bypass permission checks or change a node binding.

Removing a Gent integration removes only its managed configuration entries. It does not delete host conversations, uninstall the host, or revoke unrelated agents. Explicit agent revocation invalidates that registration's future access under the cluster policy.

## Initial acceptance criteria

- Install or configure the same Gent MCP server in Codex and Claude Code on macOS and Linux, preserving unrelated host settings.
- Register distinct conversations, reconnect without duplicate identities, and reject attempts to impersonate another agent or claim another node.
- Exchange permission-checked messages, replies, files, and images through the common tools. Verify queues survive disconnects and retries do not repeat delivery effects.
- Register a generic MCP client with a previously unknown provider label and complete the same messaging flow without adding provider-specific code or configuring a model API in Gent.
- Show provider and agent availability accurately, including polling-only hosts. Test wake/resume only for hosts with a verified lifecycle mechanism.
- Keep registration credentials, keys, hidden identities, and private content out of unauthorized tool results and service logs.
