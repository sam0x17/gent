# Gent providers

Providers are named connections to agent runtimes or model APIs. One provider can serve multiple agents, each with its own identity, conversation state, and permissions. This document describes the planned interface; no provider implementation is available yet.

## Provider types

| Type | Connection and conversation ownership |
| --- | --- |
| `codex` | Local Codex installation, using its existing settings and supported session interfaces. Codex owns the provider session. |
| `claude-code` | Local Claude Code installation, using its existing settings and supported session interfaces. Claude Code owns the provider session. |
| `openai-compatible` | Configurable API endpoint using Chat Completions or Responses. Gent can maintain a persistent conversation on the hosting node. |
| `anthropic-compatible` | Configurable API endpoint using Messages. Gent can maintain a persistent conversation on the hosting node. |

Keep provider registration, model selection, and agent registration separate. Adding a provider makes a connection available; it does not create an agent, adopt every existing chat, or grant cluster access to that provider's other sessions. Installing the Gent MCP integration makes Gent tools available within a host and is a separate operation.

Provider administration requires the node owner's authority or an explicit administrative delegation. Messaging permissions alone do not authorize changing endpoints, credentials, or model bindings. Agent-facing provider tools expose only authorized choices and metadata.

Support first-party OpenAI and Anthropic APIs, compatible hosted services, and local servers such as LM Studio and llama.cpp. Use protocol adapters with configurable endpoints rather than a fixed list of model vendors. Brand names and compatibility labels do not establish which features a particular server version and model support.

## Automatic local discovery

Setup and provider listing automatically discover installed Codex and Claude Code runtimes and their available local settings. Show a detected provider even when login is missing, with its configuration source, model or profile when known, and a useful readiness state. Discovery is local and read-only: it must not start inference, execute credential helpers, rewrite provider files, or upload settings. Repeated discovery must preserve stable provider identity and explicit Gent overrides.

Prefer supported runtime configuration interfaces. When files must be read, use version-aware adapters, honor configured home locations, and preserve the runtime's own precedence and trust rules. Codex documents user defaults and trusted project overrides in its [configuration guide](https://learn.chatgpt.com/docs/config-file/config-basic). Claude Code documents user, project, local, and managed settings in its [settings guide](https://code.claude.com/docs/en/settings). Gent must preserve managed restrictions and identify settings it cannot resolve reliably.

For an adopted session, keep its actual model, endpoint, working directory, approval policy, and authentication context. For a new CLI session, let the runtime resolve its settings in the intended project and profile. Do not turn project-specific settings into machine-wide defaults. An explicit Gent override applies only to the selected provider or new session and must respect provider policy. It must not silently retarget an existing agent.

Reuse existing CLI authentication through the CLI's supported runtime interfaces. Do not extract a subscription login token and treat it as a generic API key. Direct API providers use credentials intended for that endpoint. Shell-only environment variables may be unavailable to launchd or systemd; diagnose that condition without sourcing arbitrary shell scripts or copying the entire shell environment.

Detected custom endpoints and profiles should be visible with their source. Reusing one for a direct API provider is a separate selection with an explicit API protocol and credential reference. Disabled detected providers remain disabled on later scans. Missing, malformed, or unsupported settings leave a diagnostic rather than replacing a working definition.

## API configuration and capabilities

An API provider records a stable ID, display name, hosting node, protocol, base URL, credential reference or explicit no-auth mode, default model if selected, and supported request options. `openai-compatible` selects `chat-completions` or `responses`; `anthropic-compatible` uses `messages`. Preserve base-path prefixes and apply each protocol's documented URL convention. Show the resolved endpoint in diagnostics without credentials.

Model listing is optional because some endpoints lack it. Allow an explicit model ID and distinguish reported, tested, unsupported, and unknown capabilities. Check text generation, streaming, tool calls, image input, file handling, context limits, and reasoning controls separately. A basic connectivity check must not imply that a model can inspect images or use Gent tools. Do not silently discard unsupported attachments or translate unsupported reasoning settings into unrelated options.

LM Studio documents [OpenAI-compatible endpoints](https://lmstudio.ai/docs/developer/openai-compat) and [Anthropic-compatible Messages](https://lmstudio.ai/docs/developer/anthropic-compat). llama.cpp documents its compatible endpoints and model/template requirements in the [server README](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md). These establish integration candidates; Gent still needs tests against the installed versions and selected models.

Connection and model probes run only against configured endpoints. Ordinary listing uses local discovery and cached status; it must not scan the network or send a paid inference request. `gent provider test` explicitly exercises a selected connection, reports which checks ran, and uses synthetic input without private conversation content.

## Configuration and node ownership

Keep provider settings in the local part of `~/.gent/config.toml`, with secrets in an OS credential store or protected secret store. Environment-variable references are also supported when the daemon can resolve them. Do not put API keys in TOML, command arguments, model prompts, or diagnostics. Credential input can use a hidden prompt or a documented noninteractive secret source.

A possible local configuration fragment is:

```toml
[providers.lm-studio]
type = "openai-compatible"
api = "chat-completions"
base_url = "http://127.0.0.1:1234/v1"
auth = "none"

[providers.remote-messages]
type = "anthropic-compatible"
base_url = "https://api.example.com"
api_key_env = "GENT_MESSAGES_API_KEY"
```

These are proposed fields. The example assumes an unauthenticated loopback server; configure credentials when the server requires them. Support loopback HTTP for local servers and require authenticated TLS for remote API connections. An endpoint reachable on a LAN still needs transport protection; keep the existing Gent confidentiality requirements intact.

`localhost` belongs to the node hosting the provider. An agent backed by a local model runs on that node; other cluster members communicate with the agent through Gent. They do not reinterpret its loopback address or receive its API key. Replicate authorized provider descriptors and agent capabilities through encrypted cluster state, while executable paths, credential references, and local connection settings remain on their owning node. Agent-facing discovery must not reveal hidden agents through provider or model listings.

Changing or removing a provider must show affected agents, preserve conversation state, and avoid silently moving work to a different endpoint or model. Disabling a provider stops new dispatch and leaves pending work visible. Removing an automatically detected entry keeps a local exclusion so it does not immediately return. Provider removal does not uninstall Codex, Claude Code, or a local model server.

## Agents backed by APIs

A raw inference endpoint does not supply Gent with an existing CLI or GUI conversation. For direct API use, a minimal Rust runner on the selected node maintains an explicit Gent-managed conversation, including transcript, model binding, tool results, pending turns, and restart checkpoints. `gent agent new <name> --provider <provider> --model <model>` creates that new agent. Existing CLI-session adoption retains its separate lifecycle and must never be reported as completed by creating a fresh API conversation.

Use the same identities, permissions, queueing, deduplication, reply limits, relay operations, and attachment grants as other agents. Tool-capable models receive only the Gent tools authorized for that agent; API configuration alone grants no shell or filesystem execution. Describe a text-only model's limitations clearly. A model can receive and answer ordinary messages without being able to initiate tool calls or inspect images.

Model requests originate on the owning node and go to the configured inference endpoint. The chosen model server sees the supplied content; Gent's central relay retains its encrypted transport role. API credentials remain on the node. Preserve the distinction between confidentiality from Gent and disclosure to the selected inference provider.

## Initial acceptance criteria

- Detect Codex and Claude Code on macOS and Linux without modifying their settings or exposing secrets. Resolve project/profile behavior through the runtime and preserve explicit Gent settings on repeated scans.
- Add, inspect, test, disable, and remove named providers. Verify missing credentials, malformed settings, offline endpoints, absent model listings, and daemon environment differences produce useful status.
- Exercise Chat Completions, Responses, and Messages against controlled fixtures; run live tests against local LM Studio and llama.cpp and configured API services before claiming compatibility.
- Persist a Gent-managed API agent across daemon restarts, exchange messages with a CLI agent, and complete tool and image flows where the selected model supports them. Reconcile uncertain execution before retrying tool effects.
- Keep API keys and local addresses out of replicated public views and service logs. Verify remote access to a local-model agent routes through its owning node and respects enumeration and messaging permissions.
