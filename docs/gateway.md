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

Installed Codex CLI HTTP calls supply `threadId`; register its host grant with `--conversation-key threadId`. Gent accepts this specific unnamespaced field alongside namespaced host fields. Other unnamespaced fields, including `sessionId`, remain invalid. The real-host proof checks repeated calls, restart/resume and fork isolation. These are CLI observations, not evidence for Codex desktop, IDE or ChatGPT.

Claude Code HTTP calls supply `claudecode/toolUseId`, which changes for every call and cannot identify a conversation. Gent rejects that registration key. Claude Code should continue using the [local hooked integration](cli.md), which maps each tool-use ID to the actual conversation. OAuth login can succeed while agent tools correctly reject missing conversation metadata. Ordinary Claude web/mobile metadata needs a separate investigation.

A host credential authorizes a namespace containing several agents. Its holder can select any conversation in that namespace, so the host must supply conversation metadata outside model control. The gateway cannot prove that an arbitrary metadata string came from ChatGPT or Claude. Verify provenance and stability on each actual host before granting access. Separate host credentials isolate equal conversation identifiers from each other. Existing daemon permissions still determine discovery, messages, replies and relay grants; registration grants no communication permissions.

### Scope conversations to a host user

For an OAuth host that provides stable user metadata on every call, select that field when creating its namespace:

```sh
gent --home /private/path/gent-node gateway clients add scoped-host \
  --conversation-key test/conversation --subject-key test/subject \
  --oauth-resource https://agent.example.net/mcp \
  --redirect-uri https://host.example/callback \
  --out /private/path/gent-node/scoped-host.json
```

These are synthetic metadata names. The host must supply both values in per-call `_meta`; prompts, tool arguments and initialization metadata cannot substitute for them. `--subject-key` requires OAuth and a namespaced field distinct from the conversation key. It works with either secret or signed client authentication and optional mTLS. Setup retries cannot add, remove or change this policy on an existing namespace. Existing unscoped clients keep their bindings; moving one to scoped bindings requires a new namespace and new agents.

Each OAuth grant begins unbound. Its first call with valid identity metadata pins a hash of the reported user while allocating the agent credential in the same transaction. Later calls through that grant must report the same user, including after token refresh or gateway restart. A conflicting user is rejected before an agent is selected. Missing or malformed metadata and binding-capacity refusal leave an unbound grant unchanged. Agent identity includes the host namespace, user and conversation, so equal conversation IDs under different users remain separate. A newly approved grant reporting the same user and conversation recovers the original agent.

The pin depends on the trusted host's report; Gent does not independently verify the user's account. The first report must come from a host that keeps metadata and OAuth credentials outside model control. A compromised host can still impersonate its users. OpenAI's [reference](https://developers.openai.com/plugins/reference#_meta-fields-the-client-provides) documents `openai/subject` and `openai/session` as candidate user/conversation fields. Their provenance, stability and behavior across real accounts and devices still need verification; Gent does not automatically enable this policy for a provider label. CLI integrations do not require this optional field.

Only hashes of user and conversation identifiers enter the binding records; raw values are neither returned by status nor logged. Hashing does not protect low-entropy identifiers from guessing by someone with registry access. Scoped records use registry version 6 and export version 5; older readers reject them. Required policy markers and explicit unbound/bound grant records reject missing state instead of silently disabling user checks. The existing per-host conversation quota is shared across that host's users.

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

### Require a client certificate

A host grant can require a TLS client certificate in addition to its bearer or OAuth credentials. Pin one CA certificate and an exact lowercase DNS SAN when creating the grant:

```sh
gent --home /private/path/gent-node gateway clients add certificate-host \
  --conversation-key test/conversation \
  --tls-client-ca /private/path/client-ca.pem \
  --tls-client-name client.example \
  --out /private/path/gent-node/certificate-host.json
```

The CA file must contain one CA certificate, at most 16 KiB of PEM and 8 KiB of DER. Gent copies it into the private registry and export; changing or deleting the original file cannot change trust. `clients list` shows the CA's SHA-256 fingerprint and required DNS name. An identical setup retry retains the grant; omitting or changing either pin fails. Registries containing these grants use at least version 3, and their exports use at least version 2; [signed OAuth clients](gateway-oauth.md#register-a-client-that-signs-token-requests) require newer versions. A separate stored requirement marker prevents a missing policy field from silently disabling certificate checks.

Start the normal direct TLS listener after adding the grant. It loads the registered client CAs at startup, so adding another authority requires a gateway restart. Rustls checks the certificate chain and handshake proof of possession. Each authenticated HTTP request and agent tool call checks its own grant's CA, exact DNS SAN, explicit client-authentication usage and certificate validity, including the pinned CA's validity. A sibling intermediate under the same root cannot satisfy another grant. Wildcards, Common Names, HTTP headers and model arguments cannot substitute for the required identity.

Discovery and browser authorization/continuation remain accessible without a certificate. Certificate-bound grants require the certificate for OAuth code exchange, refresh and MCP access. Bearer grants without a certificate policy keep their existing behavior. Even if the listener is later started as loopback HTTP, a certificate-bound grant cannot authenticate. Revocation applies immediately to new requests and per-call checks on existing connections; already accepted work remains.

Leaf certificates may rotate under the pinned CA and DNS name without changing the agent namespace. CA/name changes currently require a new grant, which creates a new namespace; migration between grants is not implemented. There is no automatic CA download, CRL/OCSP checking, or live trust reload. The local owner selects the trust anchor and is responsible for its replacement or grant revocation. Gent logs no peer certificates or request content.

OpenAI's [mTLS guide](https://developers.openai.com/plugins/build/auth#mutual-tls-mtls) publishes a [Connectors intermediate CA](https://developers.openai.com/plugins/mtls/openai-connectors-mtls-ca.pem) and the DNS identity `mtls.prod.connectors.openai.com`. The published intermediate parses and registers with this implementation. This is a candidate ChatGPT configuration; actual provider certificate presentation at the MCP and token endpoints, hosted OAuth onboarding, and conversation stability still need acceptance tests. No provider CA is embedded in Gent. Claude's [remote connector requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) require publicly reachable HTTPS on port 443; the local CLI proofs on other ports do not establish that hosted route.

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

Private `gateway/state.json` stores host token digests and persistent agent credentials indexed by hashed conversation IDs, with user scope when configured. A registry UUID in `config.toml` pins it to the node and cluster. Missing, corrupt or mismatched established state causes access to fail; restore a consistent backup instead of deleting the registry to repair it. Config version 3 protects the required local pin, and daemon projections preserve it. The highest observed authentication/binding timestamp is durable; a backward clock change blocks access until time catches up. The OS user and local backups are trusted.

The registry admits at most 32 host records, 256 conversations per host, and 4096 conversations total, with a 2 MiB state limit. Revoked and expired records retain their bindings and consume capacity. Host-grant lifetime extension and record retirement are future work; a replacement host grant needs a new name and export. OAuth access-token refresh works within the original grant lifetime. The server permits 64 simultaneous connections and 16 filesystem workers, with a 6 MiB request limit, 10-second TLS/header deadlines, 30-second request deadline and 60-second connection lifetime. Filesystem worker slots remain occupied if their requesting connection disappears. Clients reconnect and retry safely using operation IDs.

Changing the selected cluster cannot retarget a running gateway. An explicit physical `--home` also pins `gateway run` after restart. A `--cluster` selection is resolved once at startup. Administrative commands, including `clients add`, use the ordinary selected-profile rules, so use the intended profile consistently. Account logout does not revoke these independent local host grants; use `gateway clients revoke`. Service logout may separately prevent the daemon from using Gent's relay.

## Verification

```sh
cargo test -p gent-link gateway
cargo test -p gent-daemon --test config
cargo build -p gent-link
python3 scripts/prove_gateway.py --gent target/debug/gent
python3 scripts/prove_gateway_mtls.py --gent target/debug/gent
```

Tests cover separate conversations and host namespaces, absent and forged identity inputs, duplicate headers, wrong hosts/origins, proxy headers, credential expiry/revocation, registry recovery, concurrent allocation, bounded filesystem work and direct TLS trust. The HTTP/daemon test exchanges a PNG, reply and receipt, recovers a relay turn across both process layers restarting, and checks agent revocation. The CLI proof checks physical-node pinning across profile switches and restarts, live host revocation and clean foreground shutdown. All host calls in these tests are synthetic.
