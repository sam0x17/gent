# Gateway OAuth

The user-controlled gateway supports OAuth authorization-code exchange with S256 PKCE, rotating refresh tokens and discovery metadata. Clients are registered by the node owner. This version uses local CLI approval for consent and either `client_secret_post` or owner-pinned RS256 `private_key_jwt` authentication at the token endpoint. The owner can import published client metadata and opt selected hosts into runtime Client ID Metadata Document (CIMD) validation and key refresh. Automatic creation of host namespaces, dynamic registration, public clients and browser account login are not implemented. Hosted ChatGPT/Claude acceptance remains unverified.

## Register a client

Use the physical node directory, its exact reachable MCP URL and the exact callback supplied by the connecting host:

```sh
gent --home /private/path/gent-node gateway clients add hosted-client \
  --conversation-key test/conversation \
  --oauth-resource https://chat.example.net:8787/mcp \
  --redirect-uri https://host.example/callback \
  --out /private/path/gent-node/hosted-client.json
```

For an OAuth client, the private export's `client` is its client ID and `token` is its client secret. Configure both in the host's OAuth settings, outside prompts and tool arguments. The client secret cannot be used as an MCP bearer. The export also records the resource and allowed callbacks. Repeating the same command preserves the registration; changed callbacks, audience, mode or original options fail. Repeat `--redirect-uri` for up to eight callbacks, matched exactly. URLs must be canonical HTTPS, with numeric loopback HTTP allowed for local tests. Native callbacks also accept `http://localhost:PORT/callback` with an explicit nonzero port, as used by Claude Code. This exception applies only to callbacks; resource URLs and gateway listeners retain their existing rules. No hostname, port or path substitution is allowed. Wildcard matching is absent; this command fetches no metadata unless `--oauth-metadata` is supplied.

Start the daemon and [direct TLS gateway](gateway.md#direct-tls). The client discovers:

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource/mcp` | MCP resource, issuer and required `gent:chats` scope. Also served at the root protected-resource metadata path. |
| `/.well-known/oauth-authorization-server` | Issuer, authorization/token URLs, code/refresh grants, S256, `client_secret_post` and RS256 `private_key_jwt`. |
| `/oauth/authorize` | Validate a code request and show its pending owner approval. |
| `/oauth/continue` | Return the approved code or denial to the registered callback. |
| `/oauth/token` | Exchange a code or refresh token using a bounded form POST. |

Unauthenticated MCP requests receive a `401` challenge pointing to resource metadata. Authorization and token requests must include the exact `resource` URL. Codes bind the client, callback, audience and PKCE challenge. The callback preserves `state` and includes the exact `iss` value advertised in discovery. MCP access tokens work only at their resource audience; a gateway restart or URL change cannot repurpose them.

## Register a client that signs token requests

For a host using `private_key_jwt`, obtain its public JWKS through a trusted channel and pin it with the exact HTTPS client ID and callbacks:

```sh
gent --home /private/path/gent-node gateway clients add signed-host \
  --conversation-key test/conversation \
  --oauth-resource https://chat.example.net/mcp \
  --redirect-uri https://host.example/callback \
  --oauth-client-id https://host.example/oauth/client.json \
  --oauth-jwks /private/path/verified-host-jwks.json \
  --out /private/path/gent-node/signed-host.json
```

The HTTPS ID is an exact identifier; this command does not fetch its URL. Gent stores the public keys in the registry and private export. Changing or removing the source file does not change trust. The export has no shared secret or bearer token. Its local `client` UUID remains the identifier for inspection and revocation; `oauth.assertion.client_id` is the ID the host sends to OAuth. Repeating setup must match the current export and registration. A second namespace cannot reuse the same OAuth client ID on this node. Use the key update command below when the host changes its signing keys.

JWKS input is limited to 64 KiB and 1-8 public RSA keys, with unique `kid` values, 2048-4096 bit moduli and exponent 65537. If supplied, `alg`, `use` and `key_ops` must specify RS256 signature verification. Private key fields and unsupported fields are rejected. Gent verifies signatures with `ring`; it never follows JWT key URLs or trusts embedded keys. Only RS256 and an optional `typ` of `JWT` are accepted in assertion headers.

Token requests send `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, along with the normal code/PKCE or refresh parameters. Assertions require matching `iss` and `sub`, one exact audience naming this gateway's issuer or token endpoint, integer `iat`/`exp` and a nonempty `jti` of at most 128 printable ASCII bytes without spaces. Lifetimes are at most five minutes; `iat` allows thirty seconds of future clock skew, while expiry and any `nbf` are checked strictly. Assertions are limited to 4 KiB. Signed clients cannot fall back to a secret; secret clients reject assertion parameters. Assertions cannot be used as MCP bearer tokens or authorization grants.

The registry consumes each valid assertion ID atomically with token processing, including grant errors after client authentication. A retry needs a new assertion. Reusing an assertion rejects authentication without revoking an otherwise valid token family. Replaying a redeemed code or spent refresh token with a fresh valid assertion retains the existing family-revocation rule. Replay digests persist across restart until assertion expiry, with a limit of 1,024 active records. Capacity exhaustion returns `503` and `Retry-After`. An optional client-certificate policy remains an additional requirement for exchange, refresh and MCP.

This implements the signed token-authentication method described in [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html). OpenAI's [authentication guide](https://developers.openai.com/plugins/build/auth#client-registration) documents RS256 keys published through ChatGPT's metadata/JWKS route. Manual key pinning alone does not enable CIMD discovery or runtime refresh. Those require the opt-in gateway mode below; hosted consent and conversation-provenance acceptance remain separate.

### Update signing keys

Inspect the local client UUID, then replace its complete key set using a JWKS obtained through a trusted channel:

```sh
gent --home /private/path/gent-node gateway clients keys show CLIENT_UUID
gent --home /private/path/gent-node gateway clients keys set CLIENT_UUID \
  --jwks /private/path/verified-new-jwks.json --expect-revision 0
```

Use the `key_revision` returned by `keys show` as `--expect-revision`. Initial registrations have revision 0; each changed key set increments it. Concurrent conflicting updates and stale retries fail. Repeating the last successful command preserves its revision and keys. Reordering the same keys does not create a revision. The command requires an existing signed client and cannot change its OAuth ID, callbacks, resource, certificate policy, expiry or chat bindings.

For planned rotation, first supply a set containing both old and new keys, then supply only the retained keys once the host has switched. The current set is checked on each code exchange and refresh; no gateway restart is needed. Removing a key rejects subsequent assertions signed by it. Existing access tokens, refresh families, pending owner-approved codes and chats remain valid under their existing rules. Use host revocation to terminate that client's access after a compromise; a key update alone does not revoke previously issued grants.

Gent commits the keys and revision to the registry before updating the private export. An interruption after that commit can leave `export_pending: true` in `keys show` (`key_export_pending` in `clients list`). The committed keys are already in effect. Retry the same command and original expected revision to finish the export. Gent accepts the recorded previous export or the completed new export; it preserves changed files and requires missing files to be restored before retry. Finish a pending export before starting a different key update. An exact retry can finish this local export after host expiry or revocation without reactivating the host. An expired or revoked host cannot receive a new key set.

Updated registries use version 5 and exports use version 4, or versions 6 and 5 respectively when user-scoped bindings are configured. A per-client marker rejects missing revision records even when other clients retain newer schema versions. An updated export cannot recreate a missing registry client. Keep registry backups consistent; key-update retries are not a mechanism for rolling back registry state. Scheduled key refresh remains future work.

### Import published client metadata

If the host publishes its client ID as an HTTPS metadata URL, Gent can retrieve and validate its public keys during owner-initiated setup:

```sh
gent --home /private/path/gent-node gateway clients add published-host \
  --conversation-key test/conversation \
  --oauth-resource https://chat.example.net/mcp \
  --redirect-uri https://host.example/callback \
  --oauth-metadata https://host.example/oauth/client.json \
  --out /private/path/gent-node/published-host.json
```

Use the host's actual metadata URL and callback from its setup page. `test/conversation` is a synthetic example; the host's conversation metadata and its provenance need separate verification. `--oauth-metadata` replaces both `--oauth-client-id` and `--oauth-jwks`. The document's `client_id` must equal its exact URL, support RS256 `private_key_jwt` and publish every selected callback. Only the callbacks supplied on the command line enter the registration. A published callback list cannot expand the owner's selection. The resulting signed registration has no shared secret or static bearer fallback.

Metadata and `jwks_uri` must use canonical HTTPS URLs on port 443, with DNS hostnames and non-root paths, without credentials, queries or fragments. The JWKS must have the same origin as the metadata. Each fetch accepts at most 32 resolved addresses, rejects the entire set if any address is private or reserved, and pins the validated addresses for the TLS connection. Proxies, redirects and compression are disabled. Responses must be HTTP 200 with a JSON content type, and are limited to 64 KiB and ten seconds per fetch, including DNS and body reads. Other document URLs, including logos, are ignored. Inline JWKS is unsupported. TLS authenticates the selected publisher; choosing the intended host URL remains the owner's responsibility.

Refresh an existing signed client's keys using its exact OAuth client ID URL:

```sh
gent --home /private/path/gent-node gateway clients keys show CLIENT_UUID
gent --home /private/path/gent-node gateway clients keys refresh CLIENT_UUID \
  --expect-revision 0
```

Use the current revision from `keys show`. Refresh revalidates the document and the existing callback selection before applying a full key-set replacement with the update/recovery rules above. It can also refresh a manually pinned client whose ID is a supported metadata URL. It cannot change the resource, callbacks, chat bindings or other grant policy. Fetch or validation failure leaves the current keys in place. Repeating setup re-fetches metadata but cannot update an existing registration; use refresh after a published key change. If an export is pending and the publisher changes keys again, use `keys set` with the already committed key set and original expected revision to finish that export before applying another change.

By default, only these explicit owner commands fetch metadata. The gateway mode below permits bounded runtime fetching for selected hosts. JWT headers never choose key URLs, and Gent does not automatically create host namespaces. Importing ChatGPT's public metadata has been verified independently of actual hosted OAuth and conversation binding.

### Enable CIMD for selected hosts

After importing the host, start the gateway with its local UUID:

```sh
gent --home /private/path/gent-node gateway run \
  --listen 0.0.0.0:443 --origin https://chat.example.net \
  --tls-cert /private/path/server.pem --tls-key /private/path/server.key \
  --client-metadata CLIENT_UUID
```

This mode advertises `client_id_metadata_document_supported: true` so the host can identify itself by its published HTTPS URL without receiving a generated client ID or secret. Repeat `--client-metadata` for up to 32 existing signed hosts. Each must be active, have a supported metadata URL and use this gateway's resource. The [MCP trust-policy rules](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#trust-policies) permit allowlists. Gent's list contains exact identities selected by the owner; unknown clients are rejected without fetching their URLs. Existing preregistered clients continue to work.

The flag authorizes the publisher's validated key set to replace that host's pinned keys. Before authorization or token exchange, Gent retrieves metadata and JWKS when its previous validation has expired. It checks the exact identity and existing callbacks, then applies keys through the revision-checked update/export transaction. Callback scope, grants and chat bindings stay fixed. The consent page shows both the client URL and selected callback. Owner approval, PKCE, signed assertions and any client-certificate requirement still apply.

Successful validation can be reused for at most one minute. Shorter `max-age`, response age/date, `no-cache` and `no-store` reduce or disable reuse; ambiguous freshness headers require revalidation. Local key revisions invalidate reuse. Each host permits one in-flight refresh and at most two fetch attempts per second, with four simultaneous refreshes across the gateway. A failed or cancelled attempt imposes backoff until five seconds after it started. Busy or unavailable metadata returns `503` with `Retry-After`; expired validation never authorizes a new exchange. After revalidation, removed published callbacks block new exchanges. Failed fetches leave the last committed keys intact. Already issued access tokens keep their existing lifetime; revoke the host to terminate access immediately.

Cached validation exists only in memory. After restart, the first request re-fetches metadata. Include the flag on each start to retain this behavior; without it, the stored keys remain manually pinned and CIMD discovery is absent. While enabled, a later fetch may replace manual key edits with the publisher's current set. Stop this mode before switching back to manual pinning. No idle polling or scheduled refresh runs. Actual ChatGPT/Claude requests, conversation binding and hosted attachment interfaces still need acceptance tests.

## Approve a connection

Start the host's connection flow. Its browser authorization page displays the client, callback and request ID. On the node, inspect the pending request:

```sh
gent --home /private/path/gent-node gateway oauth requests
gent --home /private/path/gent-node gateway oauth approve REQUEST_UUID
# Or reject it:
gent --home /private/path/gent-node gateway oauth deny REQUEST_UUID
```

Approve only a connection you started, after matching its request ID and callback. Return to the browser page and select **Continue after approval**. The local OS identity supplies owner authorization; the public page and client secret alone cannot approve anything. This is an initial setup flow, not the final mobile onboarding experience. It requires access to the node's CLI.

Approval is limited to the named host namespace. Each chat call still requires host-owned conversation metadata, and daemon permissions still control discovery, sending, receiving and relay selection. OAuth neither proves that metadata's provenance nor grants permission to select an arbitrary existing chat. Choosing a provider label cannot authorize a request. The model provider and user-controlled node see tool plaintext, while Gent's central relay carries encrypted daemon traffic.

Optional [`--subject-key`](gateway.md#scope-conversations-to-a-host-user) requires host-owned user metadata too. Each grant pins the user reported on its first valid binding call and preserves that pin through refresh. Reauthorization creates a new unbound grant, while the same reported user/conversation recovers its existing chat. The owner must still verify the intended connection before approval; the subject pin does not authenticate the provider account independently.

An optional [client certificate policy](gateway.md#require-a-client-certificate) binds token exchange, refresh and MCP access to a pinned CA and exact client DNS identity. Browser consent pages and discovery remain accessible without that certificate. The certificate supplements OAuth and does not grant user consent or identify a conversation by itself.

Pending requests expire after ten minutes. An approved code lasts at most five minutes and cannot outlive its request. A decision cannot be reversed; revoke the host grant if an approved request must be disabled. Both an approval retry and a page reload preserve the original code until it expires or is redeemed.

## Refresh, reconnect and revoke

Access tokens last at most fifteen minutes. The client can exchange its refresh token for a new access/refresh pair without changing its chat namespace or existing bindings. Refresh does not extend the original authorization: the grant lasts at most thirty days and cannot outlive the host grant's expiry. Reauthorization uses another explicit owner approval and preserves the existing host's chat identities. Host-grant lifetime extension remains future work.

Code redemption and refresh rotation commit atomically before returning tokens. Reusing a valid redeemed code or a spent refresh token revokes that token family. Incorrect secrets, wrong PKCE values and invalid token guesses cannot revoke an unrelated family. Old access tokens stop working after a refresh. Clients must serialize refreshes; if a token response is lost, reauthorize instead of repeatedly replaying it. Reauthorization preserves the underlying chat bindings.

```sh
gent --home /private/path/gent-node gateway clients revoke CLIENT_UUID
```

Host revocation rejects all its codes, refreshes, new authorization requests and MCP access, including tool calls that already passed HTTP authentication but have not resolved a chat binding. Work accepted before revocation and chat data remain. `gent chat revoke` separately revokes a particular chat. Service account logout does not revoke these local OAuth grants.

## Stored state and limits

OAuth state shares `gateway/state.json` and its mutation lock with host revocation and chat bindings. OAuth registries use version 2, version 3 with client certificate policies, version 4 with signed-client policies and replay state, version 5 after a signing-key update, version 6 with user-scoped bindings, or version 7 with [owner-prepared conversation recovery](recovery.md#recover-a-gateway-conversation). Recovery leaves existing host exports, grants and ordinary bindings unchanged. Older gateway readers reject unsupported records. Signed-client exports use version 3 initially, version 4 after an update, or version 5 with user scope, and contain no secret. Secret-authenticated scoped clients also use export version 5 and retain their secret. Missing assertion policy, replay state, required subject policy or per-grant subject state fails validation. Existing static clients retain their original credentials and bindings. Store a consistent private backup; missing or corrupt established state causes access to fail. Rolling back a backup can also roll back revocations and token generations, so live-state rollback is not a supported recovery procedure.

The registry stores access-token and client-secret digests, pending code secrets until redemption or pruning of expired requests, and private refresh-family keys. Refresh tokens use HMAC-SHA256 over a domain, random family ID and generation; replay detection needs no unbounded list of spent tokens. These private keys remain on the user's node. Registry summaries exclude codes, tokens, PKCE values and browser state. HTTP responses disable caching, referrers and framing, and Gent logs no request content.

There are at most 64 retained authorization requests, four per client, and 128 token families. Expired OAuth records are pruned when a valid new authorization request arrives; pending records and code replay evidence occupy capacity until their request expires. OAuth parameter bodies are limited to 8 KiB and share the gateway's connection, worker and deadline bounds. An exhausted filesystem-worker pool returns `503` with `Retry-After`; it does not trigger another login. Busy tool calls ask the host to retry identical arguments with the original request ID. There is no IP-based rate limiter yet. Existing host/chat quotas and the 2 MiB registry limit still apply.

## Verification and provider follow-up

```sh
cargo test -p gent-link gateway
cargo build -p gent-link
python3 scripts/prove_gateway_oauth.py --gent target/debug/gent
python3 scripts/prove_gateway_oauth.py --gent target/debug/gent --private-key-jwt
# Optional host-user bindings, with either authentication mode:
python3 scripts/prove_gateway_oauth.py --gent target/debug/gent --subject-binding
python3 scripts/prove_gateway_oauth.py --gent target/debug/gent --subject-binding --private-key-jwt
# Opt-in public HTTPS metadata import; no listener or model calls:
python3 scripts/prove_gateway_metadata.py --gent target/debug/gent \
  --metadata https://chatgpt.com/oauth/client.json \
  --redirect-uri https://chatgpt.com/connector_platform_oauth_redirect
# Add --exercise-gateway for loopback CIMD authorization, denial and restart.
# Opt-in installed clients; no model calls:
python3 scripts/prove_gateway_clients.py --gent target/debug/gent
# Opt-in OAuth model lifecycle; six synthetic turns:
python3 scripts/prove_gateway_clients.py --gent target/debug/gent --exercise-models
# Two concurrent chats per host sharing a login; twelve synthetic turns:
python3 scripts/prove_gateway_clients.py --gent target/debug/gent --exercise-concurrent
# Opt-in static-bearer model identity proof; four synthetic turns:
python3 scripts/prove_gateway_hosts.py --gent target/debug/gent
```

The tests cover approval/denial, PKCE, exact callback/client/audience checks, expiry, replay and concurrent redemption, stable bindings through refresh/reconnect, host revocation, bounded malformed inputs and real HTTP discovery. The CLI proof runs separate native gateway and daemon processes and checks approval, callback issuer/state, restart, refresh, replay revocation, reconnect identity and private logs.

Signed-client tests also cover signature/key/algorithm substitution, exact claims, duplicate fields, replay capacity, concurrent assertion reuse, corrupted persistence, and combined mTLS/assertion requirements. Key-update tests cover concurrent conflicts, stale retries, simulated interruption at both export-write boundaries, modified/missing exports, retired-key rejection and preserved grants/chats. The TLS test verifies that key replacement retains the certificate requirement. The native proof generates disposable OpenSSL keys, exercises overlap and retirement while the gateway runs, deletes the JWKS sources and verifies identity after restart. All 48 gateway tests, strict Clippy, normal builds, both native OAuth modes and installed-client login pass on Linux and macOS. These checks make no signed hosted-provider acceptance claim.

Four user-binding tests cover equal conversation IDs under different users, conflicting concurrent first use, missing/malformed metadata, capacity refusal, setup-policy changes, lost or corrupt saved state, and continuity through refresh, reauthorization, key rotation and restart. The native OAuth proof's `--subject-binding` option exercises the same separation through actual HTTP tools in both authentication modes, including argument-injection rejection and absence of raw user IDs in saved state or logs. Actual provider user metadata remains unverified.

Four metadata tests cover URL/DNS restrictions, mixed public/private answers, exact identity and selected callbacks, supported authentication, same-origin keys and duplicate fields. A local TLS fixture checks trust/hostname validation, redirects, response types, compression, declared/chunked size limits, timeouts and refresh nonmutation. The public metadata CLI proof imports ChatGPT's published keys into a temporary cluster, repeats setup, refreshes unchanged keys and rejects a wrong revision without changing state. It passes on both OSes without starting a gateway, requesting provider consent or sending model traffic. This external-network proof is opt-in and is not part of automatic CI.

Five CIMD tests cover cache headers, owner selection, revision invalidation, revocation, cancellation, concurrent requests, fetch limits, failed refresh and conflicting local updates. The HTTP proof uses a local HTTPS metadata fixture, completes signed code exchange, replaces published keys, rejects the retired key, and preserves a chat through refresh and gateway restart. Removing an approved callback makes new exchanges fail without modifying stored grants. The public CLI proof's `--exercise-gateway` mode starts only a temporary loopback listener, accepts ChatGPT's actual published identity, denies the synthetic connection and repeats after restart. It never follows the provider callback or makes a model call. Both proof modes pass on Linux and macOS.

The installed-client proof, including both OAuth model lifecycle options, and the static-bearer model proof pass on Linux with Codex 0.167.2 / Claude Code 2.1.323 and on macOS with Codex 0.167.0 / Claude Code 2.1.311. These are tested versions, not minimum supported versions.

The installed-client proof drives each CLI's actual `mcp login --no-browser` flow, approves the request through Gent, checks S256/resource/callback/scope/state and confirms code redemption in Gent's registry. Claude's callback prompt runs in a temporary terminal. Codex uses a temporary profile and a unique file-store OAuth entry, removed with `mcp logout`; Claude uses isolated configuration and file credentials with Keychain commands disabled for that subprocess. Existing provider settings remain intact. Native Keychain behavior and hosted provider consent remain untested.

With `--exercise-models`, the proof uses normal model access for three turns per host: initial OAuth tool calls, resume after server-side access expiry and gateway restart, then resume after another gateway restart. It expires only the synthetic grant's access token while the server is stopped, leaving the client credential store unchanged. Both clients recover through refresh after HTTP 401. The proof checks rotation within the original token family, unchanged authorization lifetime and actual tool results. Codex preserves one chat throughout; Claude authenticates but consistently receives the missing-conversation rejection, with no chat allocated.

`--exercise-concurrent` runs the same lifecycle with two chats per host, each in its own working directory and sharing one OAuth credential entry. It starts both clients together and checks that their runs overlap. Codex retains two distinct chats across renewal and restart; Claude's two chats remain unbound. Both hosts pass on both OSes without token-family revocation. The observed renewal used one or two rotations per host, so callers must not assume one refresh per pair of chats. This proof does not force simultaneous HTTP requests or establish every refresh interleaving. Proactive expiry timers remain untested.

The separate model proof uses static host bearers and observes unchanged loopback HTTP tool calls. It checks Codex identity across repeated calls, a gateway/daemon restart, resume and fork, and checks Claude's missing-conversation rejection without allocating a chat. Both model proofs delete private test files on exit; provider-managed synthetic conversations remain. Neither establishes hosted or mobile integration.

For installed Codex, put the preregistered client ID/secret and callback URL in the server's `oauth` settings. Let resource discovery supply `resource`: Linux Codex 0.167.2 duplicated that parameter when `oauth_resource` was explicitly set to the discovered URL. Gent continues to reject duplicates. For Claude Code, `mcp add --client-id ID --client-secret --callback-port PORT` accepts the secret through `MCP_CLIENT_SECRET`; subsequent login reads the saved secret. Its callback uses `localhost`, matched exactly. See the [Codex configuration schema](https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json) and [Claude Code preregistration instructions](https://code.claude.com/docs/en/mcp#use-pre-configured-oauth-credentials). Successful Claude login still lacks a stable HTTP conversation identifier; use its existing local hook integration for chat traffic.

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) defines resource discovery and audience-bound bearer use. OpenAI's [authentication guide](https://developers.openai.com/plugins/build/auth) describes S256, resource parameters and issuer checks; use the callback shown in its management page. Anthropic's [custom connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) documents an option to supply your own OAuth client. These documents identify routes to test. They do not establish Gent compatibility, trustworthy per-conversation metadata, hosted file access or mobile E2EE.
