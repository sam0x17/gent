# Gateway OAuth

The user-controlled gateway supports OAuth authorization-code exchange with S256 PKCE, rotating refresh tokens and discovery metadata. Clients are registered by the node owner. This version uses local CLI approval for consent and `client_secret_post` at the token endpoint. Dynamic registration, Client ID Metadata Documents, public clients, signed client assertions and browser account login are not implemented. Hosted ChatGPT/Claude acceptance remains unverified.

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
| `/.well-known/oauth-authorization-server` | Issuer, authorization/token URLs, code/refresh grants, S256 and `client_secret_post`. |
| `/oauth/authorize` | Validate a code request and show its pending owner approval. |
| `/oauth/continue` | Return the approved code or denial to the registered callback. |
| `/oauth/token` | Exchange a code or refresh token using a bounded form POST. |

Unauthenticated MCP requests receive a `401` challenge pointing to resource metadata. Authorization and token requests must include the exact `resource` URL. Codes bind the client, callback, audience and PKCE challenge. The callback preserves `state` and includes the exact `iss` value advertised in discovery. MCP access tokens work only at their resource audience; a gateway restart or URL change cannot repurpose them.

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

Pending requests expire after ten minutes. An approved code lasts at most five minutes and cannot outlive its request. A decision cannot be reversed; revoke the host grant if an approved request must be disabled. Both an approval retry and a page reload preserve the original code until it expires or is redeemed.

## Refresh, reconnect and revoke

Access tokens last at most fifteen minutes. The client can exchange its refresh token for a new access/refresh pair without changing its agent namespace or existing bindings. Refresh does not extend the original authorization: the grant lasts at most thirty days and cannot outlive the host grant's expiry. Reauthorization uses another explicit owner approval and preserves the existing host's agent identities. Host-grant lifetime extension remains future work.

Code redemption and refresh rotation commit atomically before returning tokens. Reusing a valid redeemed code or a spent refresh token revokes that token family. Incorrect secrets, wrong PKCE values and invalid token guesses cannot revoke an unrelated family. Old access tokens stop working after a refresh. Clients must serialize refreshes; if a token response is lost, reauthorize instead of repeatedly replaying it. Reauthorization preserves the underlying agent bindings.

```sh
gent --home /private/path/gent-node gateway clients revoke CLIENT_UUID
```

Host revocation rejects all its codes, refreshes, new authorization requests and MCP access, including tool calls that already passed HTTP authentication but have not resolved an agent binding. Work accepted before revocation and agent data remain. `gent agent revoke` separately revokes a particular agent. Service account logout does not revoke these local OAuth grants.

## Stored state and limits

OAuth state shares `gateway/state.json` and its mutation lock with host revocation and agent bindings. Registry version 2 prevents older gateway builds from accepting these records. Existing static clients retain their original credentials and bindings. Store a consistent private backup; missing or corrupt established state causes access to fail. Rolling back a backup can also roll back revocations and token generations, so live-state rollback is not a supported recovery procedure.

The registry stores access-token and client-secret digests, pending code secrets until redemption or pruning of expired requests, and private refresh-family keys. Refresh tokens use HMAC-SHA256 over a domain, random family ID and generation; replay detection needs no unbounded list of spent tokens. These private keys remain on the user's node. Registry summaries exclude codes, tokens, PKCE values and browser state. HTTP responses disable caching, referrers and framing, and Gent logs no request content.

There are at most 64 retained authorization requests, four per client, and 128 token families. Expired OAuth records are pruned when a valid new authorization request arrives; pending records and code replay evidence occupy capacity until their request expires. OAuth parameter bodies are limited to 8 KiB and share the gateway's connection, worker and deadline bounds. An exhausted filesystem-worker pool returns `503` with `Retry-After`; it does not trigger another login. Busy tool calls ask the host to retry identical arguments with the original request ID. There is no IP-based rate limiter yet. Existing host/agent quotas and the 2 MiB registry limit still apply.

## Verification and provider follow-up

```sh
cargo test -p gent-link gateway
cargo build -p gent-link
python3 scripts/prove_gateway_oauth.py --gent target/debug/gent
# Opt-in installed clients; no model calls:
python3 scripts/prove_gateway_clients.py --gent target/debug/gent
# Opt-in normal model access; four synthetic turns:
python3 scripts/prove_gateway_hosts.py --gent target/debug/gent
```

The tests cover approval/denial, PKCE, exact callback/client/audience checks, expiry, replay and concurrent redemption, stable bindings through refresh/reconnect, host revocation, bounded malformed inputs and real HTTP discovery. The CLI proof runs separate native gateway and daemon processes and checks approval, callback issuer/state, restart, refresh, replay revocation, reconnect identity and private logs.

Both opt-in proofs pass on Linux with Codex 0.167.2 / Claude Code 2.1.323 and on macOS with Codex 0.167.0 / Claude Code 2.1.311. These are tested versions, not minimum supported versions.

The installed-client proof drives each CLI's actual `mcp login --no-browser` flow, approves the request through Gent, checks S256/resource/callback/scope/state and confirms code redemption in Gent's registry. Claude's callback prompt runs in a temporary terminal. Codex uses a temporary profile and a unique file-store OAuth entry, removed with `mcp logout`; Claude uses isolated configuration and file credentials with Keychain commands disabled for that subprocess. Existing provider settings remain intact. This does not test native Keychain behavior, client-driven refresh or hosted provider consent.

The separate model proof uses static host bearers and observes unchanged loopback HTTP tool calls. It checks Codex identity across repeated calls, a gateway/daemon restart, resume and fork, and checks Claude's missing-conversation rejection without allocating an agent. It deletes private test files on exit; provider-managed synthetic conversations remain. These proofs establish OAuth login and metadata behavior separately, not a complete OAuth-authenticated model session or mobile integration.

For installed Codex, put the preregistered client ID/secret and callback URL in the server's `oauth` settings. Let resource discovery supply `resource`: Linux Codex 0.167.2 duplicated that parameter when `oauth_resource` was explicitly set to the discovered URL. Gent continues to reject duplicates. For Claude Code, `mcp add --client-id ID --client-secret --callback-port PORT` accepts the secret through `MCP_CLIENT_SECRET`; subsequent login reads the saved secret. Its callback uses `localhost`, matched exactly. See the [Codex configuration schema](https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json) and [Claude Code preregistration instructions](https://code.claude.com/docs/en/mcp#use-pre-configured-oauth-credentials). Successful Claude login still lacks a stable HTTP conversation identifier; use its existing local hook integration for agent traffic.

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) defines resource discovery and audience-bound bearer use. OpenAI's [authentication guide](https://developers.openai.com/plugins/build/auth) describes S256, resource parameters and issuer checks; use the callback shown in its management page. Anthropic's [custom connector guide](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) documents an option to supply your own OAuth client. These documents identify routes to test. They do not establish Gent compatibility, trustworthy per-conversation metadata, hosted file access or mobile E2EE.
