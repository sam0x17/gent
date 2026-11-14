# User-controlled remote MCP gateway

`gent gateway run` serves the shared agent tools over authenticated Streamable HTTP on a user's node. It connects to that node's daemon and accepts static host credentials or [owner-approved OAuth clients](gateway-oauth.md). This is a transport for testing trusted MCP hosts; ChatGPT and Claude hosted connectors, desktop integrations and mobile operation still need separate acceptance tests.

## Local trial

Build `gent` from source and create a disposable local cluster. Use an absolute, physical node directory for all commands:

```sh
gent --home /private/path/gent-node cluster new gateway-trial --local
gent --home /private/path/gent-node gateway clients add test-host \
  --conversation-key test/conversation \
  --out /private/path/gent-node/test-host.json
gent --home /private/path/gent-node daemon run
```

In another terminal:

```sh
gent --home /private/path/gent-node gateway run --listen 127.0.0.1:8787
```

The endpoint is `http://127.0.0.1:8787/mcp`. Plain HTTP is restricted to loopback for local tests. `gateway run` requires explicit `--home` or `--cluster`; it runs in the foreground until interrupted. There is no gateway service installer yet.

Transfer the private export's `token` to the trusted host's credential store outside prompts and tool arguments. Send it as `Authorization: Bearer TOKEN` on every request, including initialization and tool discovery. Credentials are never printed by Gent. They expire after 720 hours by default; `--ttl-hours` accepts 1 through 8760. An identical `clients add` retry with the same export preserves its token.

The host must attach its own conversation identifier to every `tools/call` request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "gent_register",
    "arguments": {"name": "review", "provider": "test-host"},
    "_meta": {"test/conversation": "host-owned-conversation-id"}
  }
}
```

The metadata key is configured by the owner when issuing the host credential. Missing, non-string, empty, oversized or control-containing conversation identifiers are rejected. Initialization metadata, HTTP session IDs, provider labels and tool arguments cannot substitute for it. Stateless requests support older clients that initialize with MCP `2025-11-25`; the SDK also handles newer protocol versions. There is no persistent HTTP session to use as an agent identity.

A host credential authorizes a namespace containing several agents. Its holder can select any conversation in that namespace, so the host must supply conversation metadata outside model control. The gateway cannot prove that an arbitrary metadata string came from ChatGPT or Claude. Verify provenance and stability on each actual host before granting access. Separate host credentials isolate equal conversation identifiers from each other. Existing daemon permissions still determine discovery, messages, replies and relay grants; registration grants no communication permissions.

## Direct TLS

A reachable listener requires a certificate, private key and canonical HTTPS origin:

```sh
gent --home /private/path/gent-node gateway run \
  --listen 0.0.0.0:8787 \
  --origin https://agent.example.net:8787 \
  --tls-cert /private/path/gent-node/server.pem \
  --tls-key /private/path/gent-node/server.key
```

Use a hostname and TLS termination controlled by the user. The certificate must be trusted by the connecting host and cover that hostname. Gent reads regular, user-owned PEM files; the private key must have mode `0600`. Symlinks and shared writable files are refused. Certificate reload requires restarting the gateway. Certificate issuance and renewal are not implemented.

Connect directly or through a transport that preserves the TLS connection to this node. A Cloudflare HTTP proxy, Worker or tunnel that terminates this TLS connection would expose tool content at that service and would invalidate this route's security boundary. This implementation does not configure such a route. It rejects `Forwarded`, `X-Forwarded-*` and `X-Real-IP` headers, requires the exact configured `Host`, and accepts an `Origin` header only when it exactly matches the endpoint origin. MCP query strings, including query credentials, are rejected. Only the OAuth authorization and continuation endpoints accept query parameters. Browser cross-origin access is not enabled.

Plaintext tool calls are visible to the model provider and the user's node. Traffic from that node through Gent's central relay uses the existing encrypted daemon transport. This does not provide encryption against the model provider or prove a mobile connector's security. MCP instructions and registration, identity and relay-selection results disclose the user-controlled gateway route. No Gent-hosted plaintext bridge is implemented here.

## Files and relay mode

Agents use the existing messaging, receipt and relay tools. Inline files accept actual base64 bytes, up to 1 MiB each and four files per message. Received supported images also appear as MCP image blocks. The host still needs to expose real bytes to its tools; native hosted attachment handles are not supported.

Remote tool discovery excludes `gent_file_paths`, `gent_file_import` and `gent_file_export`, and calling those names directly fails. A remote chat cannot use Gent to browse the node's filesystem. Native 32 MiB file objects can be inspected with `gent_file_status`, but this gateway does not yet download their contents into a hosted chat. Use inline attachments for this trial.

The owner grants ordinary permissions and time-limited relay selection through the existing CLI. Target selection, pending turns, replies and receipts stay in the daemon database across gateway restarts. A timeout does not prove that a send failed: keep its original request ID for an identical retry, or inspect its status.

## State, revocation and limits

```sh
gent --home /private/path/gent-node gateway status
gent --home /private/path/gent-node gateway clients list
gent --home /private/path/gent-node gateway clients revoke CLIENT_UUID
```

Status and listing inspect configuration without probing the listener. Revocation rejects future host requests, including requests on an existing connection. The gateway rechecks the credential before resolving each tool call. Already accepted operations and agent data remain. Agent revocation through `gent agent revoke` also survives gateway reconnection; registration cannot create a replacement for that same binding.

Private `gateway/state.json` stores host token digests and persistent agent credentials indexed by hashed conversation IDs. A registry UUID in `config.toml` pins it to the node and cluster. Missing, corrupt or mismatched established state causes access to fail; restore a consistent backup instead of deleting the registry to repair it. Config version 3 protects the required local pin, and daemon projections preserve it. The highest observed authentication/binding timestamp is durable; a backward clock change blocks access until time catches up. The OS user and local backups are trusted.

The registry admits at most 32 host records, 256 conversations per host, and 4096 conversations total, with a 2 MiB state limit. Revoked and expired records retain their bindings and consume capacity. Host-grant lifetime extension and record retirement are future work; a replacement host grant needs a new name and export. OAuth access-token refresh works within the original grant lifetime. The server permits 64 simultaneous connections and 16 filesystem workers, with a 6 MiB request limit, 10-second TLS/header deadlines, 30-second request deadline and 60-second connection lifetime. Filesystem worker slots remain occupied if their requesting connection disappears. Clients reconnect and retry safely using operation IDs.

Changing the selected cluster cannot retarget a running gateway. An explicit physical `--home` also pins `gateway run` after restart. A `--cluster` selection is resolved once at startup. Administrative commands, including `clients add`, use the ordinary selected-profile rules, so use the intended profile consistently. Account logout does not revoke these independent local host grants; use `gateway clients revoke`. Service logout may separately prevent the daemon from using Gent's relay.

## Verification

```sh
cargo test -p gent-link gateway
cargo test -p gent-daemon --test config
cargo build -p gent-link
python3 scripts/prove_gateway.py --gent target/debug/gent
```

Tests cover separate conversations and host namespaces, absent and forged identity inputs, duplicate headers, wrong hosts/origins, proxy headers, credential expiry/revocation, registry recovery, concurrent allocation, bounded filesystem work and direct TLS trust. The HTTP/daemon test exchanges a PNG, reply and receipt, recovers a relay turn across both process layers restarting, and checks agent revocation. The CLI proof checks physical-node pinning across profile switches and restarts, live host revocation and clean foreground shutdown. All host calls in these tests are synthetic.
