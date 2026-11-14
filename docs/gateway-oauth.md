# Gateway OAuth

The user-controlled gateway supports OAuth authorization-code exchange with S256 PKCE, rotating refresh tokens and discovery metadata. Clients are registered by the node owner. This version uses local CLI approval for consent and either `client_secret_post` or owner-pinned RS256 `private_key_jwt` authentication at the token endpoint. Dynamic registration, Client ID Metadata Document fetching, public clients and browser account login are not implemented. Hosted ChatGPT/Claude acceptance remains unverified.

## Register a client

Use the physical node directory, its exact reachable MCP URL and the exact callback supplied by the connecting host:

```sh
gent --home /private/path/gent-node gateway clients add hosted-client \
  --conversation-key test/conversation \
  --oauth-resource https://agent.example.net:8787/mcp \
  --redirect-uri https://host.example/callback \
  --out /private/path/gent-node/hosted-client.json
```

For an OAuth client, the private export's `client` is its client ID and `token` is its client secret. Configure both in the host's OAuth settings, outside prompts and tool arguments. The client secret cannot be used as an MCP bearer. The export also records the resource and allowed callbacks. Repeating the same command preserves the registration; changed callbacks, audience, mode or original options fail. Repeat `--redirect-uri` for up to eight callbacks, matched exactly. URLs must be canonical HTTPS, with numeric loopback HTTP allowed for local tests. Native callbacks also accept `http://localhost:PORT/callback` with an explicit nonzero port, as used by Claude Code. This exception applies only to callbacks; resource URLs and gateway listeners retain their existing rules. No hostname, port or path substitution is allowed. Wildcard matching and outbound metadata fetching are absent.

Start the daemon and [direct TLS gateway](gateway.md#direct-tls). The client discovers:

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/oauth-protected-resource/mcp` | MCP resource, issuer and required `gent:agents` scope. Also served at the root protected-resource metadata path. |
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
  --oauth-resource https://agent.example.net/mcp \
  --redirect-uri https://host.example/callback \
  --oauth-client-id https://host.example/oauth/client.json \
  --oauth-jwks /private/path/verified-host-jwks.json \
  --out /private/path/gent-node/signed-host.json
```

The HTTPS ID is an exact identifier; this command does not fetch its URL. Gent stores the public keys in the registry and private export. Changing or removing the source file does not change trust. The export has no shared secret or bearer token. Its local `client` UUID remains the identifier for inspection and revocation; `oauth.assertion.client_id` is the ID the host sends to OAuth. Repeating setup must preserve the original key set and options. A second namespace cannot reuse the same OAuth client ID on this node. Key-set updates are not implemented; a host may rotate among the keys already pinned.

JWKS input is limited to 64 KiB and 1-8 public RSA keys, with unique `kid` values, 2048-4096 bit moduli and exponent 65537. If supplied, `alg`, `use` and `key_ops` must specify RS256 signature verification. Private key fields and unsupported fields are rejected. Gent verifies signatures with `ring`; it never follows JWT key URLs or trusts embedded keys. Only RS256 and an optional `typ` of `JWT` are accepted in assertion headers.

Token requests send `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`, along with the normal code/PKCE or refresh parameters. Assertions require matching `iss` and `sub`, one exact audience naming this gateway's issuer or token endpoint, integer `iat`/`exp` and a nonempty `jti` of at most 128 printable ASCII bytes without spaces. Lifetimes are at most five minutes; `iat` allows thirty seconds of future clock skew, while expiry and any `nbf` are checked strictly. Assertions are limited to 4 KiB. Signed clients cannot fall back to a secret; secret clients reject assertion parameters. Assertions cannot be used as MCP bearer tokens or authorization grants.

The registry consumes each valid assertion ID atomically with token processing, including grant errors after client authentication. A retry needs a new assertion. Reusing an assertion rejects authentication without revoking an otherwise valid token family. Replaying a redeemed code or spent refresh token with a fresh valid assertion retains the existing family-revocation rule. Replay digests persist across restart until assertion expiry, with a limit of 1,024 active records. Capacity exhaustion returns `503` and `Retry-After`. An optional client-certificate policy remains an additional requirement for exchange, refresh and MCP.

This implements the signed token-authentication method described in [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523.html). OpenAI's [authentication guide](https://developers.openai.com/plugins/build/auth#client-registration) documents RS256 keys published through ChatGPT's metadata/JWKS route. Manual key pinning does not complete CIMD onboarding, automatic key refresh, hosted consent or conversation-provenance acceptance. Gent does not advertise `client_id_metadata_document_supported` yet.

## Approve a connection

Start the host's connection flow. Its browser authorization page displays the client, callback and request ID. On the node, inspect the pending request:

```sh
gent --home /private/path/gent-node gateway oauth requests
gent --home /private/path/gent-node gateway oauth approve REQUEST_UUID
# Or reject it:
gent --home /private/path/gent-node gateway oauth deny REQUEST_UUID
```

Approve only a connection you started, after matching its request ID and callback. Return to the browser page and select **Continue after approval**. The local OS identity supplies owner authorization; the public page and client secret alone cannot approve anything. This is an initial setup flow, not the final mobile onboarding experience. It requires access to the node's CLI.

Approval is limited to the named host namespace. Each agent call still requires host-owned conversation metadata, and daemon permissions still control discovery, sending, receiving and relay selection. OAuth neither proves that metadata's provenance nor grants permission to select an arbitrary existing agent. Choosing a provider label cannot authorize a request. The model provider and user-controlled node see tool plaintext, while Gent's central relay carries encrypted daemon traffic.

An optional [client certificate policy](gateway.md#require-a-client-certificate) binds token exchange, refresh and MCP access to a pinned CA and exact client DNS identity. Browser consent pages and discovery remain accessible without that certificate. The certificate supplements OAuth and does not grant user consent or identify a conversation by itself.

Pending requests expire after ten minutes. An approved code lasts at most five minutes and cannot outlive its request. A decision cannot be reversed; revoke the host grant if an approved request must be disabled. Both an approval retry and a page reload preserve the original code until it expires or is redeemed.

## Refresh, reconnect and revoke

Access tokens last at most fifteen minutes. The client can exchange its refresh token for a new access/refresh pair without changing its agent namespace or existing bindings. Refresh does not extend the original authorization: the grant lasts at most thirty days and cannot outlive the host grant's expiry. Reauthorization uses another explicit owner approval and preserves the existing host's agent identities. Host-grant lifetime extension remains future work.

Code redemption and refresh rotation commit atomically before returning tokens. Reusing a valid redeemed code or a spent refresh token revokes that token family. Incorrect secrets, wrong PKCE values and invalid token guesses cannot revoke an unrelated family. Old access tokens stop working after a refresh. Clients must serialize refreshes; if a token response is lost, reauthorize instead of repeatedly replaying it. Reauthorization preserves the underlying agent bindings.

```sh
gent --home /private/path/gent-node gateway clients revoke CLIENT_UUID
```

Host revocation rejects all its codes, refreshes, new authorization requests and MCP access, including tool calls that already passed HTTP authentication but have not resolved an agent binding. Work accepted before revocation and agent data remain. `gent agent revoke` separately revokes a particular agent. Service account logout does not revoke these local OAuth grants.

## Stored state and limits

OAuth state shares `gateway/state.json` and its mutation lock with host revocation and agent bindings. OAuth registries use version 2, version 3 with client certificate policies, or version 4 with signed-client policies and replay state; older gateway readers reject unsupported records. Signed-client exports use version 3 and contain no secret. Missing assertion policy or replay state fails validation; it cannot enable a secret fallback. Existing static clients retain their original credentials and bindings. Store a consistent private backup; missing or corrupt established state causes access to fail. Rolling back a backup can also roll back revocations and token generations, so live-state rollback is not a supported recovery procedure.

The registry stores access-token and client-secret digests, pending code secrets until redemption or pruning of expired requests, and private refresh-family keys. Refresh tokens use HMAC-SHA256 over a domain, random family ID and generation; replay detection needs no unbounded list of spent tokens. These private keys remain on the user's node. Registry summaries exclude codes, tokens, PKCE values and browser state. HTTP responses disable caching, referrers and framing, and Gent logs no request content.

There are at most 64 retained authorization requests, four per client, and 128 token families. Expired OAuth records are pruned when a valid new authorization request arrives; pending records and code replay evidence occupy capacity until their request expires. OAuth parameter bodies are limited to 8 KiB and share the gateway's connection, worker and deadline bounds. An exhausted filesystem-worker pool returns `503` with `Retry-After`; it does not trigger another login. Busy tool calls ask the host to retry identical arguments with the original request ID. There is no IP-based rate limiter yet. Existing host/agent quotas and the 2 MiB registry limit still apply.

## Verification and provider follow-up

```sh
cargo test -p gent-link gateway
cargo build -p gent-link
python3 scripts/prove_gateway_oauth.py --gent target/debug/gent
python3 scripts/prove_gateway_oauth.py --gent target/debug/gent --private-key-jwt
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

Signed-client tests also cover signature/key/algorithm substitution, exact claims, duplicate fields, replay capacity, concurrent assertion reuse, corrupted persistence, and combined mTLS/assertion requirements. The synthetic native proof generates a disposable RSA key with OpenSSL, imports the public JWKS, deletes its source file and exercises signed code exchange, refresh, restart, replay and revocation. All 30 gateway tests, strict Clippy, normal builds and both native OAuth modes pass on Linux and macOS. Installed-client login and native mTLS regressions pass on both. These checks make no signed hosted-provider acceptance claim.

The installed-client proof, including both OAuth model lifecycle options, and the static-bearer model proof pass on Linux with Codex 0.167.2 / Claude Code 2.1.323 and on macOS with Codex 0.167.0 / Claude Code 2.1.311. These are tested versions, not minimum supported versions.

The installed-client proof drives each CLI's actual `mcp login --no-browser` flow, approves the request through Gent, checks S256/resource/callback/scope/state and confirms code redemption in Gent's registry. Claude's callback prompt runs in a temporary terminal. Codex uses a temporary profile and a unique file-store OAuth entry, removed with `mcp logout`; Claude uses isolated configuration and file credentials with Keychain commands disabled for that subprocess. Existing provider settings remain intact. Native Keychain behavior and hosted provider consent remain untested.

With `--exercise-models`, the proof uses normal model access for three turns per host: initial OAuth tool calls, resume after server-side access expiry and gateway restart, then resume after another gateway restart. It expires only the synthetic grant's access token while the server is stopped, leaving the client credential store unchanged. Both clients recover through refresh after HTTP 401. The proof checks rotation within the original token family, unchanged authorization lifetime and actual tool results. Codex preserves one agent throughout; Claude authenticates but consistently receives the missing-conversation rejection, with no agent allocated.

`--exercise-concurrent` runs the same lifecycle with two chats per host, each in its own working directory and sharing one OAuth credential entry. It starts both clients together and checks that their runs overlap. Codex retains two distinct agents across renewal and restart; Claude's two chats remain unbound. Both hosts pass on both OSes without token-family revocation. The observed renewal used one or two rotations per host, so callers must not assume one refresh per pair of chats. This proof does not force simultaneous HTTP requests or establish every refresh interleaving. Proactive expiry timers remain untested.

The separate model proof uses static host bearers and observes unchanged loopback HTTP tool calls. It checks Codex identity across repeated calls, a gateway/daemon restart, resume and fork, and checks Claude's missing-conversation rejection without allocating an agent. Both model proofs delete private test files on exit; provider-managed synthetic conversations remain. Neither establishes hosted or mobile integration.

For installed Codex, put the preregistered client ID/secret and callback URL in the server's `oauth` settings. Let resource discovery supply `resource`: Linux Codex 0.167.2 duplicated that parameter when `oauth_resource` was explicitly set to the discovered URL. Gent continues to reject duplicates. For Claude Code, `mcp add --client-id ID --client-secret --callback-port PORT` accepts the secret through `MCP_CLIENT_SECRET`; subsequent login reads the saved secret. Its callback uses `localhost`, matched exactly. See the [Codex configuration schema](https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json) and [Claude Code preregistration instructions](https://code.claude.com/docs/en/mcp#use-pre-configured-oauth-credentials). Successful Claude login still lacks a stable HTTP conversation identifier; use its existing local hook integration for agent traffic.

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) defines resource discovery and audience-bound bearer use. OpenAI's [authentication guide](https://developers.openai.com/plugins/build/auth) describes S256, resource parameters and issuer checks; use the callback shown in its management page. Anthropic's [custom connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) documents an option to supply your own OAuth client. These documents identify routes to test. They do not establish Gent compatibility, trustworthy per-conversation metadata, hosted file access or mobile E2EE.
