# User-controlled remote MCP gateway

`gent gateway run` serves the shared chat tools over authenticated Streamable HTTP on a user's node. It connects to that node's daemon and accepts static host credentials or [owner-approved OAuth clients](gateway-oauth.md). This is a transport for testing trusted MCP hosts; ChatGPT and Claude hosted connectors, desktop integrations and mobile operation still need separate acceptance tests.

For public HTTPS access without an inbound port, see the [hosted web/mobile gateway](hosted-mcp.md). That route has a separate plaintext disclosure and uses `--hosted`.

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

The endpoint is `http://127.0.0.1:8787/mcp`. Plain HTTP is restricted to loopback for local tests. `gateway run` uses this node in `~/.gent` and runs in the foreground until interrupted. For a persistent listener, use the [gateway service](#persistent-listener).

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

The metadata key is configured by the owner when issuing the host credential. Missing, non-string, empty, oversized or control-containing conversation identifiers are rejected. Initialization metadata, HTTP session IDs, provider labels and tool arguments cannot substitute for it. Stateless requests support older clients that initialize with MCP `2025-11-25`; the SDK also handles newer protocol versions. There is no persistent HTTP session to use as a chat identity.

Installed Codex CLI HTTP calls supply `threadId`; register its host grant with `--conversation-key threadId`. Gent accepts this specific unnamespaced field alongside namespaced host fields. Other unnamespaced fields, including `sessionId`, remain invalid. The real-host proof checks repeated calls, restart/resume and fork isolation. These are CLI observations, not evidence for Codex desktop, IDE or ChatGPT.

Claude Code HTTP calls supply `claudecode/toolUseId`, which changes for every call and cannot identify a conversation. Gent rejects that registration key. Claude Code should continue using the [local hooked integration](cli.md), which maps each tool-use ID to the actual conversation. OAuth login can succeed while chat tools correctly reject missing conversation metadata. Ordinary Claude web/mobile metadata needs a separate investigation.

A host credential authorizes a namespace containing several chats. Its holder can select any conversation in that namespace, so the host must supply conversation metadata outside model control. The gateway cannot prove that an arbitrary metadata string came from ChatGPT or Claude. Verify provenance and stability on each actual host before granting access. Separate host credentials isolate equal conversation identifiers from each other. Existing daemon permissions still determine discovery, messages, replies and relay selection; new clusters allow communication by default, subject to explicit restrictions.

### Hosts without conversation metadata

For a connector that does not supply a stable per-chat identifier, explicitly
select handles instead of `--conversation-key`:

```sh
gent gateway clients add phone-host --conversation-handles \
  --out /private/path/phone-host.json
```

The same option works with OAuth registration. Such a connector exposes
`gent_conversation_open`, which allocates a random handle without sending any
message. The chat retains the returned `conversation` and supplies it on every
subsequent tool call, beginning with `gent_register`. It reuses that handle after
reconnecting and for later relay turns. Opening again creates a separate
identity; it never recovers an uncertain send.

Handles require the authenticated connector on every call. With OAuth they are
also bound to the exact authorization grant: token refresh preserves them, but
a new authorization cannot use an older grant's handles. There is no handle
listing, and guessed, malformed or wrong-scope handles cannot allocate a chat.
Registry version 8 and export version 6 prevent older binaries from interpreting
this policy as ordinary metadata. Host metadata clients never silently fall back
to handles, and installation retries cannot switch a client's identity policy.

The provider/model must retain its own handle. This separates Gent conversation
state but cannot prove which provider chat is presenting a handle: a caller with
the same authorization and a copied handle can use it, and can create new
handles. Apply mandatory restrictions to the gateway node when the host cannot
enforce chat identity; restricting one handle cannot constrain every new handle.
This mode cannot be combined with `--subject-key`; OAuth grant scope supplies the
authorization boundary. Each connector retains the existing 256-conversation
limit, including handles whose initial response was lost.

`gent_relay_wait` reads an existing relay turn for up to 20 seconds, returning
when responses arrive or its state changes. It returns pending when no response
has arrived. Use `next_after` as `after_message_id` for later responses. A timeout,
disconnect or daemon error never repeats or cancels the send. Gateway
authorization and daemon permissions are checked again during waiting.

An owner can [recover a conversation on a replacement gateway](recovery.md#recover-a-gateway-conversation) with `gent chat recover --gateway-client CLIENT_UUID --conversation HOST_ID`. Recovery requires an unused binding, creates a fresh chat with selected archived history, and preserves host authentication and optional user scope. It cannot supply missing conversation metadata or restore provider-owned transcripts. Recovery records use registry version 7; existing host exports and ordinary bindings keep their formats.

### Scope conversations to a host user

For an OAuth host that provides stable user metadata on every call, select that field when creating its namespace:

```sh
gent --home /private/path/gent-node gateway clients add scoped-host \
  --conversation-key test/conversation --subject-key test/subject \
  --oauth-resource https://chat.example.net/mcp \
  --redirect-uri https://host.example/callback \
  --out /private/path/gent-node/scoped-host.json
```

These are synthetic metadata names. The host must supply both values in per-call `_meta`; prompts, tool arguments and initialization metadata cannot substitute for them. `--subject-key` requires OAuth and a namespaced field distinct from the conversation key. It works with either secret or signed client authentication and optional mTLS. Setup retries cannot add, remove or change this policy on an existing namespace. Existing unscoped clients keep their bindings; moving one to scoped bindings requires a new namespace and new chats.

Each OAuth grant begins unbound. Its first call with valid identity metadata pins a hash of the reported user while allocating the chat credential in the same transaction. Later calls through that grant must report the same user, including after token refresh or gateway restart. A conflicting user is rejected before a chat is selected. Missing or malformed metadata and binding-capacity refusal leave an unbound grant unchanged. Chat identity includes the host namespace, user and conversation, so equal conversation IDs under different users remain separate. A newly approved grant reporting the same user and conversation recovers the original chat.

The pin depends on the trusted host's report; Gent does not independently verify the user's account. The first report must come from a host that keeps metadata and OAuth credentials outside model control. A compromised host can still impersonate its users. OpenAI's [reference](https://developers.openai.com/plugins/reference#_meta-fields-the-client-provides) documents `openai/subject` and `openai/session` as candidate user/conversation fields. Their provenance, stability and behavior across real accounts and devices still need verification; Gent does not automatically enable this policy for a provider label. CLI integrations do not require this optional field.

Only hashes of user and conversation identifiers enter the binding records; raw values are neither returned by status nor logged. Hashing does not protect low-entropy identifiers from guessing by someone with registry access. Scoped records use registry version 6 and export version 5; older readers reject them. Required policy markers and explicit unbound/bound grant records reject missing state instead of silently disabling user checks. The existing per-host conversation quota is shared across that host's users.

## Direct TLS

A reachable listener requires a certificate, private key and canonical HTTPS origin:

```sh
gent --home /private/path/gent-node gateway run \
  --listen 0.0.0.0:8787 \
  --origin https://chat.example.net:8787 \
  --tls-cert /private/path/gent-node/server.pem \
  --tls-key /private/path/gent-node/server.key
```

Use a hostname and TLS termination controlled by the user. The certificate must be trusted by the connecting host and cover that hostname. Gent reads regular, user-owned PEM files; the private key must have mode `0600`. Symlinks and shared writable files are refused. Certificate reload requires restarting the gateway. Certificate issuance and renewal are not implemented.

Connect directly or through a transport that preserves the TLS connection to this node. A Cloudflare HTTP proxy, Worker or tunnel that terminates this TLS connection would expose tool content at that service and would invalidate this route's security boundary. This implementation does not configure such a route. It rejects `Forwarded`, `X-Forwarded-*` and `X-Real-IP` headers, requires the exact configured `Host`, and accepts an `Origin` header only when it exactly matches the endpoint origin. MCP query strings, including query credentials, are rejected. Only the OAuth authorization and continuation endpoints accept query parameters. Browser cross-origin access is not enabled.

Plaintext tool calls are visible to the model provider and the user's node. Traffic from that node through Gent's central relay uses the existing encrypted daemon transport. This does not provide encryption against the model provider or prove a mobile connector's security. MCP instructions and registration, identity and relay-selection results disclose the user-controlled gateway route. No Gent-hosted plaintext bridge is implemented here.

## Persistent listener

After creating the node and host registration, install the daemon and gateway as separate user services:

```sh
gent --home /private/path/gent-node daemon install
gent --home /private/path/gent-node gateway service install \
  --listen 0.0.0.0:8787 \
  --origin https://chat.example.net:8787 \
  --tls-cert /private/path/gent-node/server.pem \
  --tls-key /private/path/gent-node/server.key
gent --home /private/path/gent-node gateway service status
gent --home /private/path/gent-node gateway service logs --lines 50
```

Linux uses a systemd user service; macOS uses a LaunchAgent. The same login/session requirements as the [daemon service](local-proof.md#daemon-services) apply. `gateway service install` uses the same node and accepts the listener, TLS, metadata and file-capability options from `gateway run`. Use a fixed nonzero port. TLS paths are resolved to absolute paths; the private service file saves arguments and paths, never key or credential contents. The installed command and subsequent CLI service commands use the same node directory.

`gateway service` defaults to `status`. Use `start`, `stop`, `restart`, `logs`, and `uninstall` (`remove` is an alias) to manage the listener. An identical install or start preserves its PID. Changed install arguments replace the saved configuration and restart a running listener. Supply the complete intended options on every install; omitted capability flags are removed. Installation and start/restart validate the TLS material and selected host capabilities before replacing or stopping a working listener. Binding conflicts and later runtime failures can still prevent startup; inspect status and logs to diagnose them.

Status combines the service manager's PID with a private, same-user readiness socket at `gateway/control.sock`. `running` means the listener answered; `managed` means its PID matches the service manager. This does not establish daemon availability, public reachability, valid host credentials or provider compatibility. `--json` returns the same observations; status exits 3 when the listener is unavailable. The gateway uses its own service label and log, and stopping or uninstalling it leaves the daemon running. Uninstall preserves host grants, chat bindings, keys, messages and files. Stop/uninstall also work if a saved TLS file disappears. A ready foreground listener is refused by lifecycle mutations; its existing runtime lock prevents a second listener on the same node.

Native systemd and launchd proofs cover lifecycle operations, SIGKILL recovery, literal paths, invalid replacement settings, edited/shared/symlink service files, foreground ownership, independent daemon operation and queued PNG delivery after restarts. Run the opt-in proof with `python3 scripts/prove_gateway_service.py --gent target/debug/gent`; it creates and removes disposable user services. Reboot, certificate renewal and reachable hosted connectors still need acceptance testing.

## Require a client certificate

A host grant can require a TLS client certificate in addition to its bearer or OAuth credentials. Pin one CA certificate and an exact lowercase DNS SAN when creating the grant:

```sh
gent --home /private/path/gent-node gateway clients add certificate-host \
  --conversation-key test/conversation \
  --tls-client-ca /private/path/client-ca.pem \
  --tls-client-name client.example \
  --out /private/path/gent-node/certificate-host.json
```

The CA file must contain one CA certificate, at most 16 KiB of PEM and 8 KiB of DER. Gent copies it into the private registry and export; changing or deleting the original file cannot change trust. `clients list` shows the CA's SHA-256 fingerprint and required DNS name. An identical setup retry retains the grant; omitting or changing either pin fails. Registries containing these grants use at least version 3, and their exports use at least version 2; [signed OAuth clients](gateway-oauth.md#register-a-client-that-signs-token-requests) require newer versions. A separate stored requirement marker prevents a missing policy field from silently disabling certificate checks.

Start the normal direct TLS listener after adding the grant. It loads the registered client CAs at startup, so adding another authority requires a gateway restart. Rustls checks the certificate chain and handshake proof of possession. Each authenticated HTTP request and chat tool call checks its own grant's CA, exact DNS SAN, explicit client-authentication usage and certificate validity, including the pinned CA's validity. A sibling intermediate under the same root cannot satisfy another grant. Wildcards, Common Names, HTTP headers and model arguments cannot substitute for the required identity.

Discovery and browser authorization/continuation remain accessible without a certificate. Certificate-bound grants require the certificate for OAuth code exchange, refresh and MCP access. Bearer grants without a certificate policy keep their existing behavior. Even if the listener is later started as loopback HTTP, a certificate-bound grant cannot authenticate. Revocation applies immediately to new requests and per-call checks on existing connections; already accepted work remains.

Leaf certificates may rotate under the pinned CA and DNS name without changing the chat namespace. CA/name changes currently require a new grant, which creates a new namespace; migration between grants is not implemented. There is no automatic CA download, CRL/OCSP checking, or live trust reload. The local owner selects the trust anchor and is responsible for its replacement or grant revocation. Gent logs no peer certificates or request content.

OpenAI's [mTLS guide](https://developers.openai.com/plugins/build/auth#mutual-tls-mtls) publishes a [Connectors intermediate CA](https://developers.openai.com/plugins/mtls/openai-connectors-mtls-ca.pem) and the DNS identity `mtls.prod.connectors.openai.com`. The published intermediate parses and registers with this implementation. This is a candidate ChatGPT configuration; actual provider certificate presentation at the MCP and token endpoints, hosted OAuth onboarding, and conversation stability still need acceptance tests. No provider CA is embedded in Gent. Claude's [remote connector requirements](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) require publicly reachable HTTPS on port 443; the local CLI proofs on other ports do not establish that hosted route.

## Files and relay mode

Chats use the existing messaging, receipt and relay tools. Inline files accept actual base64 bytes, up to 1 MiB combined and four files per message across both attachment forms. Received supported inline images also appear as MCP image blocks. The host still needs to expose actual file inputs; the optional import path below accepts a host file ID and download URL.

Remote tool discovery excludes `gent_file_paths`, `gent_file_import` and `gent_file_export`, and calling those names directly fails. A remote chat cannot use Gent to browse the node's filesystem. Received `attachments` contain opaque file IDs. Check `gent_file_status` until ready, then retrieve their contents through the shared MCP tools:

- `gent_file_read {file_id, chunk_index}` returns at most 256 KiB decoded, with the file descriptor, chunk index, byte offset, chunk byte length, total chunk count and `next_chunk_index`. Start at zero and follow the next index until null. Empty files have one empty chunk. Decode `data_base64`, concatenate in order, and verify the complete descriptor's `byte_length` and `sha256`. Files retain the 32 MiB limit. Exact reads survive reconnect and restart while current access remains valid.
- `gent_file_view {file_id}` verifies a complete PNG, JPEG, WebP or GIF of at most 4 MiB, then returns descriptor text and an MCP image block with the original bytes. It does not resize or decode the image. The media type is supplied by the source. Host support determines whether the model can inspect the image; base64 text alone does not establish visual inspection. Use a local export or request a smaller preview when needed.

Reads require host-owned conversation metadata on every call and recheck current chat, message, relay and expiry rules. They create no filesystem exports or public download links and expose no file keys. `file_ids` can forward an authorized attachment directly in ordinary or relay messages. Bytes returned to a remote model cross the same provider/user-node trust boundary as text. Actual hosted rendering and native file upload/download acceptance remain unverified.

### Import host-provided files

Enable file inputs for an existing client by selecting each exact download origin when starting the gateway. Use origins from the host's actual documented file service; no provider origin is trusted by default:

```sh
gent --home /absolute/test-node gateway run \
  --file-origin CLIENT_UUID=https://files.example
```

Repeat `--file-origin` for additional origins. The runtime accepts at most 64 entries and eight origins per client, with no wildcards, paths, queries, IP literals or custom ports. Restart with the same flags to retain this capability. Existing host authentication and conversation/user binding remain required. Tool discovery exposes `gent_file_import_remote` when any origin is selected, but a call from an unselected host is refused before fetching.

The tool takes `request_id` from `gent_request_ids` and a `file` object with required `download_url` and `file_id` strings, plus optional `file_name` and `mime_type` strings. Its descriptor includes `openai/fileParams` according to [ChatGPT's published file-input schema](https://developers.openai.com/plugins/reference#file-apis). Any trusted MCP host able to provide that shape can use it. Actual ChatGPT/Claude attachment acceptance, URL origins and metadata provenance still need host tests.

The gateway fetches at most 32 MiB over canonical public HTTPS on port 443. It validates every DNS answer and pins those addresses for TLS. Redirects, proxies, compressed HTTP bodies, partial responses, private/reserved addresses and missing TLS trust are rejected. The fetch carries no Gent credentials, cookies or referrer. DNS and body retrieval share a ten-second deadline. There are two concurrent imports globally, one per host, and at most one new attempt per second per host. Cancellation releases the fetch; quota or network errors require retrying the same request ID.

Bytes stay in bounded memory until the daemon seals and commits the complete file, its chat binding and retry record together. A separate local binary exchange preserves the existing JSON frame limit and permits two bodies at a time. Disconnects, wrong lengths/hashes and revocation before commit create no partial file. No plaintext handoff file is written. Downloads recheck gateway authorization before transfer; the daemon checks current chat authority at commit. URLs and host file IDs are not stored in daemon state; it stores a hash of the host file ID/name/type and the content digest. Network failures omit URLs from their errors.

Keep the same request ID, host file ID, name and type on retries. A refreshed URL is allowed within approved origins. Completed imports return the original Gent descriptor without fetching again, even when the old URL is expired; they retain the original bytes if the external source later changes. Omitted metadata defaults to `attachment` and `application/octet-stream`. These defaults are part of the retry identity. Pending failures can be retried until the request's first-use window expires. Successful imports retain normal file expiry and object/retry quotas. Pass the returned Gent file ID in `file_ids` to send or relay it. This does not create outgoing provider file references or download links.

Relay selection follows ordinary messaging permissions and needs no separate grant. Target selection, pending turns, replies and receipts stay in the daemon database across gateway restarts. A timeout does not prove that a send failed: keep its original request ID for an identical retry, or inspect its status.

### Download links

Enable outgoing links for selected existing hosts at gateway startup:

```sh
gent --home /absolute/test-node gateway run --file-downloads CLIENT_UUID
```

Repeat the flag for more hosts, retaining it across restarts. Public access requires the direct TLS setup above. The option enables `gent_file_link {file_id}` for those hosts; unselected hosts cannot mint links even if discovery shows the tool. The call needs ordinary host authentication and conversation/user metadata, including mTLS when required by that host. The file must be ready and currently accessible to the issuing chat.

The result contains `file`, `download_url`, `expires_at` and `access: "bearer_url"`, plus an MCP `resource_link` with URI, filename, media type and byte length. Use this for a user-requested download. Anyone holding the URL can fetch that file without host credentials or mTLS until expiry, at most five minutes. Keep links private. Continue using `file_ids` for chat messaging. Actual ChatGPT/Claude display, file import and mobile handling of these links remain unverified; no provider-specific output metadata is assumed.

Links survive gateway/daemon restarts on the same origin while the host remains enabled. They bind to the registry, host, chat, file and, when used, the OAuth grant and its pinned user. Access-token refresh preserves them; host/grant revocation, chat/message permission changes, expired access, or disabling the option prevents later downloads. Their expiry cannot exceed the file, host or OAuth grant lifetime. Links do not permit listing files, reading another file or calling MCP tools. Revocation cannot retract an already admitted response or bytes copied by a recipient.

`GET` verifies every chunk and the full length/hash of files up to 32 MiB before sending any file bytes, then rechecks registry and file access. Two payloads may occupy memory at once; their slots remain held until the response bodies are released, including slow readers. Capacity refusal returns 503 with `Retry-After: 1`. `HEAD` checks current access and returns metadata without reading the file body. Ranges return 416; invalid, expired and unauthorized links return 404. Responses use attachment disposition, no-store, no-referrer, nosniff and a sandbox CSP. Cross-origin bearer downloads are allowed; MCP/OAuth retain their existing Origin restrictions. The gateway writes no plaintext handoff copies and logs no URLs. Browser, host and recipient copies remain outside Gent's control.

## State, revocation and limits

```sh
gent --home /private/path/gent-node gateway status
gent --home /private/path/gent-node gateway clients list
gent --home /private/path/gent-node gateway clients revoke CLIENT_UUID
```

Status and listing inspect configuration without probing the listener. Revocation rejects future host requests, including requests on an existing connection. The gateway rechecks the credential before resolving each tool call. Already accepted operations and chat data remain. Chat revocation through `gent chat revoke` also survives gateway reconnection; registration cannot create a replacement for that same binding.

Private `gateway/state.json` stores host token digests and persistent chat credentials indexed by hashed conversation IDs, with user scope when configured. A registry UUID in `config.toml` pins it to the node and cluster. Missing, corrupt or mismatched established state causes access to fail; restore a consistent backup instead of deleting the registry to repair it. Config version 3 protects the required local pin, and daemon projections preserve it. The highest observed authentication/binding timestamp is durable; a backward clock change blocks access until time catches up. The OS user and local backups are trusted.

The registry admits at most 32 host records, 256 conversations per host, and 4096 conversations total, with a 2 MiB state limit. Revoked and expired records retain their bindings and consume capacity. Host-grant lifetime extension and record retirement are future work; a replacement host grant needs a new name and export. OAuth access-token refresh works within the original grant lifetime. The server permits 64 simultaneous connections and 16 filesystem workers, with a 6 MiB request limit, 10-second TLS/header deadlines, 30-second request deadline and 60-second connection lifetime. Filesystem worker slots remain occupied if their requesting connection disappears. Clients reconnect and retry safely using operation IDs. File reads are bounded per call; repeated or concurrent reads have no separate bandwidth quota.

The gateway and its administration commands use the node’s sole cluster. Reset retires its managed service and archives its client grants. Account logout does not revoke these independent local host grants; use `gateway clients revoke`. Service logout may separately prevent the daemon from using Gent's relay.

## Verification

```sh
cargo test -p gent-link gateway
cargo test -p gent-daemon --test config
cargo build -p gent-link
python3 scripts/prove_gateway.py --gent target/debug/gent --files
python3 scripts/prove_gateway.py --gent target/debug/gent --host-files
python3 scripts/prove_gateway.py --gent target/debug/gent --downloads
python3 scripts/prove_gateway_mtls.py --gent target/debug/gent
```

Tests cover separate conversations and host namespaces, absent and forged identity inputs, duplicate headers, wrong hosts/origins, proxy headers, credential expiry/revocation, registry recovery, concurrent allocation, bounded filesystem work and direct TLS trust. The HTTP/daemon test exchanges a PNG, reply and receipt, recovers a relay turn across both process layers restarting, and checks chat revocation. The CLI proof checks second-cluster refusal and node identity across restarts, live host revocation and clean foreground shutdown. All host calls in these tests are synthetic.

With `--files`, the native proof additionally imports a 32 MiB file, an empty file and a generated PNG larger than 1 MiB through local stdio MCP, then retrieves them through HTTP after daemon/gateway restart. It verifies exact reassembly and image blocks, forwarding, missing or changed conversation metadata, malformed arguments, hidden local tools, message permission changes and chat revocation. Daemon tests cover image-view size limits, incomplete objects, tampered chunks, expiry and unauthorized IDs. This proves the MCP representation without a hosted provider or model rendering step.

With `--host-files`, the native proof fetches a public PNG from GitHub through the real HTTPS path, verifies its image bytes, and retries after restart using an intentionally unavailable URL. It also checks local binary ingress for a 32 MiB file, interrupted/oversized bodies, digest mismatches, ingress capacity, unchanged handoff usage and restart retries. Gateway tests exercise host isolation, failures and revocation during download; TLS fixtures check the download body limits and response policy. The public PNG is a synthetic host input, not a ChatGPT or Claude attachment.

With `--downloads`, the proof includes `--files` and additionally checks resource links, exact 32 MiB/PNG/empty downloads, response headers, HEAD/range behavior, surviving URLs after both process restarts, and permission revocation. Corrupting a later stored chunk returns 404 without releasing a verified prefix. Gateway tests also check OAuth refresh/revocation and user binding, minting through mTLS with certificate-free redemption, per-host selection, safe filenames, disabled options and capacity retained through cloned response bodies.
