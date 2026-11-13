# Invitation enrollment design

Draft, November 13, 2026. This describes the next enrollment stage. The implemented join command still requires SSH; no invitation CLI, service route, or cryptographic channel is available yet.

An invitation admits one trusted daemon to an existing cluster. It must authenticate the owner independently of Gent's service, protect bootstrap metadata and keys, and preserve the same joining identity across interruptions. Initial enrollment requires the same human account on both machines. Hosted agents and future multi-user admission need separate, narrower capabilities.

## Trust and delivery

The owner creates an invitation through its local owner-authenticated CLI. The proposed first interface writes a private file, which the user transfers through an independently trusted channel:

```sh
# Proposed commands; not implemented.
gent cluster invite --output /private/path/laptop.gent-invite
gent cluster join --invite-file /private/path/laptop.gent-invite --name laptop
```

Output should show only the invitation ID and expiry. Secrets must stay out of command arguments, shell history, model tools, logs, and the ordinary TOML configuration. The joining CLI checks private, regular, nonlinked input and pins the invitation in its existing private staging area before network effects. A pasted web page or relay-supplied trust anchor cannot replace this transfer. A URL/QR interface can follow once its endpoint handling is proven; a URL fragment alone does not protect secrets from the page that reads it.

An owner-signed offer binds the protocol version, random invitation ID, cluster trust anchor, issuing owner node, account ID, canonical account and relay origins, per-invitation Noise responder public key, intended node privileges, issue time, and expiry. It also binds the digest of the invitation's routing credential. The owner signs a domain-separated canonical encoding. The recipient trusts the offer's anchor because of the protected transfer; verifying a signature against an anchor supplied by the service is insufficient.

The file includes a fresh, system-generated 256-bit Noise preshared key and an independent routing credential. It never includes the owner's signing key, account session, or normal node transport credential. The owner persists its draft, including the per-invitation responder private key, before registering the invitation with the service. A lost registration response must retry that draft rather than generate a new invitation.

## Separate service and endpoint checks

The routing credential grants temporary access only to the joining side of one invitation mailbox. The service stores its digest, opaque account/cluster/owner-node/invitation IDs, expiry, and transport status. It receives neither the Noise secret nor the signed offer, node display name, private policy, MLS packages, or grants in plaintext. Routing IDs, ciphertext sizes, timing, and account associations remain visible.

The owner CLI registers the mailbox under its account session. The owner daemon accesses the owner side with its existing node credential; it need not hold an account bearer. Service checks bind that credential to the designated owner node and cluster. The joining side requires its own current session for the same account as well as the invitation routing credential. Each side can write only its own direction and read only the corresponding reply direction. A routing credential cannot read normal cluster mailboxes, files, or other invitations.

The account bearer goes only to its previously pinned account origin. The CLI must compare the signed offer against that origin and account before enrollment, and check service ownership as the SSH flow does. Relay requests use scoped credentials. Service authorization is required for storage access, but only the native owner can approve a cryptographic member.

## Candidate encrypted channel

Use the established [Noise protocol](https://noiseprotocol.org/noise.html), with `Noise_NKpsk0_25519_ChaChaPoly_SHA256` as the candidate pattern. The joining endpoint knows the responder public key from the protected offer; both endpoints know the independent preshared key. Each connection attempt uses fresh ephemeral keys. The handshake prologue binds the complete signed offer and a fresh attempt ID, preventing cross-invitation, cross-service, or protocol substitution.

Both handshake payloads are empty. No node identity, snapshot, grant, or enrollment operation travels as early data. After the handshake, the initiator sends an encrypted, node-signed claim before the responder releases cluster metadata. This gives the responder confirmation of the completed channel and binds the new identity to that attempt. Record secrecy after later compromise of long-lived invitation material depends on fresh ephemeral keys and disposal of session secrets; it does not cover compromise of a running endpoint or retained secret-memory copies.

[Snow 0.10.0](https://docs.rs/snow/0.10.0/snow/) is a candidate Rust implementation, not an added dependency. Selection still needs native/Wasm build checks, standard-vector interoperability, low-order X25519 input tests, and review of secret lifetime and resolver features. Its default resolver contains raw key arrays; a successful handshake test would not establish zeroization. Use maintained primitives and protocol code rather than introducing Gent-specific key agreement.

Noise messages are at most 65,535 bytes, while the current pairing frame limit is 6 MiB. The adapter must authenticate fragment position and total length, enforce both limits before allocation, and assemble a complete operation before dispatch. Truncation, reordering, substitution, reflection, and malformed framing must fail without executing a partial request. Attempt lifetime and cumulative byte/message budgets must also be bounded.

Session keys and counters stay in memory. A process restart or uncertain session starts a fresh handshake; it never reconstructs an old session with reset counters. The transport can resend cached, byte-identical ciphertext within a live attempt, with exact duplicate handling outside Noise. Application retries across attempts use durable operation IDs and input digests. Authentication errors terminate the attempt; they do not fall back to plaintext or a development token.

## Single-use admission and restricted operations

The first encrypted request is a node-signed claim over the offer digest, invitation ID, completed handshake hash, node ID/public key, chosen name, and bounded validity period. The joining identity is generated and saved locally before this request. It cannot select owner authority or additional privileges.

The owner verifies the claim and atomically binds an unclaimed invitation to that node ID, key, and name before returning a snapshot or enrolling anything. A second claimant loses even if its cryptographic handshake succeeds. A reconnecting claimant must prove possession of the same node key in its new channel. SQL approval at the service cannot create, replace, or clear this native binding.

The current `Store::pair` API assumes owner authentication. Do not expose it directly to an invitation holder. A separate dispatcher must enforce the following scope before invoking existing pairing operations:

| Operation | Required restriction |
| --- | --- |
| Snapshot | An accepted claim for this invitation and cluster; service metadata only, without the owner's transport credential. |
| Enroll | The exact claimed node/key/name, signed request, offered anchor, fresh checkpoint and current owner-approved privileges. Existing membership still requires proof of the same key. |
| Configuration | The claimed peer and its verified MLS credential; durable request/input binding and recorded resulting group. |
| History | This cluster and the retained bootstrap checkpoint/history needed by this join, with bounded reads. |
| Data | The claimed peer, verified key package, and request/group bindings; no legacy-agent migration through a new-node invitation. |
| AcceptData | The claimed signer and roster, and the exact outgoing group created for this invitation. |
| Finish | The claimed node and completed bootstrap; an idempotent completion receipt. |

No other owner RPC is reachable through this dispatcher. Current SSH joins grant configuration-editing authority; invitation privileges must be explicitly bound in the offer and enforced when choosing the existing enrollment operation. An invitation grants no ability to mint another invitation or enroll a different node.

Native state progresses from draft to issued to claimed to complete. Revoked and expired records are terminal. Claiming permanently consumes the right to select a node; a claimed invitation may finish that same node before expiry. Completion permits only its bounded receipt retry, not further pairing operations. Each mutation checks current authority, native invitation state, and expiry. Revocation serializes with admission; it cannot undo an already committed membership or retract keys already delivered. Removing an admitted node requires the separate cryptographic and service revocation flow.

Persist operation identity and input digest before side effects. Existing pairing operations span more than one transaction, so a gateway journal alone does not make them atomic. Recover each operation through its existing exact-retry behavior, then persist the result before replying. Fault injection must cover a committed enrollment, MLS grant, or data link followed by a failed journal write. Bound grants and restart attempts so one invitation cannot allocate unbounded streams.

## Expiry and recovery

Start with a fixed 15-minute offer lifetime. Retries cannot extend it, and each endpoint uses its trusted local clock rather than a time supplied by the relay. Persist an admission-time watermark so ordinary clock rollback cannot reopen an expired invitation. Service cleanup must preserve the existing rule that an old ID/credential cannot be admitted again after its verifier is removed. Whole-endpoint backup rollback remains part of the separate recovery design.

An expired partial join retains its node key and staged state. A replacement invitation can explicitly authorize continuation of that exact node/key; it must not silently allocate another identity or revive a retired node. Define and test this continuation path before exposing invitation enrollment to users. Once the existing publication manifest is committed, local publication can finish without fresh owner pairing operations; normal account/transport checks still apply.

Preserve the current joining locks, account directory, service pin, immutable publication manifest, and `config.toml`-last installation. Provision the joined node's own transport credential under its account session. Failure cannot copy the owner's credential or publish a newly generated identity over partial state.

Service revocation stops transport; native revocation stops further cryptographic admission. Either check can deny a join. The service can withhold or reorder traffic, and an unavailable owner cannot finish enrollment. Completed nodes use their established encrypted streams independently of the invitation mailbox. Removing invitation secrets and ciphertext is cleanup, without a forensic-erasure guarantee.

## Implementation and acceptance order

1. Prove the channel and offer/claim validation in the crypto crate. Test wrong secrets/pins, every bound field, expired/future times, fresh sessions, handshake replay, transport replay/reflection/reordering, low-order keys, maximum frames, and an independent Noise implementation or standard vectors. Verify native and Wasm builds.
2. Add the owner's durable invitation journal and restricted dispatcher. Test competing claims, restart/rollback at every mutation boundary, changed inputs under an old request ID, cross-node/group access, expiry/revocation, resource limits, and continuation with the original key.
3. Add account and relay mailbox routes with per-direction credentials, quotas, expiry, logout/revocation, immutable retries, and fail-closed authorization. Test outage, delayed requests, storage rollback/restart, and captured SQL/logs for private values with injected-plaintext controls.
4. Connect the private-file CLI to the existing staged join. Prove Linux-to-Mac and Mac-to-Linux enrollment without an SSH pairing channel, independent transport credentials, encrypted configuration/messages/files, interrupted publication, both daemon restarts, and expiry continuation. SSH may orchestrate test machines and initial fixture delivery. Document that protected invitation transfer separately; all subsequent pairing RPCs must use the new channel, with no SSH fallback.

The exact wire encoding, fragmentation format, resource budgets, continuation CLI, and library resolver remain to be fixed by these proofs. This draft does not establish production security, hosted/mobile E2EE, or account/owner recovery.
