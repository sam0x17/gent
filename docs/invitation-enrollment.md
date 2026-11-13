# Invitation enrollment design

Draft, November 13, 2026. The offer, claim and encrypted channel are implemented as a crypto-library component. The implemented join command still requires SSH; the durable admission dispatcher, invitation CLI and service routes remain unfinished.

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

## Encrypted channel component

The `gent-crypto` crate's optional `invitation` feature implements the established [Noise protocol](https://noiseprotocol.org/noise.html), using `Noise_NKpsk0_25519_ChaChaPoly_SHA256`. The native daemon enables this feature; the relay Worker does not. The joining endpoint knows the responder public key from the protected offer; both endpoints know the independent preshared key. Each connection attempt uses fresh ephemeral keys. The handshake prologue binds the complete signed offer and a fresh UUIDv4 attempt ID, preventing cross-invitation, cross-service, or protocol substitution.

Both handshake payloads are empty. No node identity, snapshot, grant, or enrollment operation travels as early data. After the handshake, the initiator sends an encrypted, node-signed claim before the responder releases cluster metadata. This gives the responder confirmation of the completed channel and binds the new identity to that attempt. Record secrecy after later compromise of long-lived invitation material depends on fresh ephemeral keys and disposal of session secrets; it does not cover compromise of a running endpoint or retained secret-memory copies.

[Snow 0.10.0](https://docs.rs/snow/0.10.0/snow/) supplies the protocol state machine, SHA-256 and ChaChaPoly implementation. Thin resolver adapters use the workspace's system RNG and `x25519-dalek` 3 with contributory-DH checks and its zeroizing secret types. Snow requires its Curve25519 feature for the default hash/cipher resolver to compile, but Gent's resolver overrides DH. A published Cacophony vector checks the exact handshake ciphertexts, final hash and both transport directions; the fixture includes its provenance and license notices. Tests also reject low-order and zero-equivalent public points.

Invitation secrets, private-file encodings and decrypted messages use zeroizing buffers, and secret/channel types have no `Debug` or automatic serialization. Session counters and keys have no persistence API. Snow's cipher and handshake internals still contain raw key material without comprehensive zeroization; this component makes no claim that all secret-memory copies are erased. Endpoint-memory hardening and independent protocol review remain required before production use.

Noise messages are at most 65,535 bytes, while the current pairing frame limit is 6 MiB. Each encrypted fragment contains a one-byte version (`1`), a four-byte total plaintext length and four-byte offset, both big-endian, followed by at most 65,510 data bytes. A message uses exactly the required number of fragments, up to 97; even an empty message uses one authenticated fragment. The receiver checks ciphertext bounds before decryption, checks the authenticated total before allocating the message, and returns bytes only after every fragment passes. Truncation, reordering, substitution, reflection, and malformed framing close the channel without exposing a partial operation.

Each direction admits at most 4,096 messages and 64 MiB of plaintext, including the claim. A session expires after five minutes or at the offer deadline, whichever comes first. Trusted-clock rollback, expired sessions, exceeded budgets and cryptographic errors close the channel. A closed channel cannot be reopened by correcting the clock or resubmitting a packet.

Session keys and counters stay in memory. A process restart or uncertain session starts a fresh handshake; it never reconstructs an old session with reset counters. The transport can resend cached, byte-identical ciphertext within a live attempt, with exact duplicate handling outside Noise. Application retries across attempts use durable operation IDs and input digests. Authentication errors terminate the attempt; they do not fall back to plaintext or a development token.

## Single-use admission and restricted operations

The first encrypted request is a node-signed claim over the offer digest, invitation ID, completed handshake hash, node ID/public key, chosen name, and bounded validity period. The joining identity is generated and saved locally before this request. It cannot select owner authority or additional privileges.

The owner verifies the claim and atomically binds an unclaimed invitation to that node ID, key, and name before returning a snapshot or enrolling anything. A second claimant loses even if its cryptographic handshake succeeds. A reconnecting claimant must prove possession of the same node key in its new channel. SQL approval at the service cannot create, replace, or clear this native binding.

The library implements claim verification and requires an admission callback before exposing a response-capable owner channel. Claims last at most 60 seconds and cannot outlive their offer. Callback failure destroys the pending session. The callback's durable storage, competing-writer serialization and per-operation authorization are still to be implemented. The current test of repeated/competing identities uses an in-memory admission callback and does not establish crash-safe single-use enrollment.

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

## Wire records and remaining acceptance work

Offers and claims use RFC 8785 canonical JSON and domain-separated Ed25519 signatures. Unknown fields and noncanonical encodings are rejected. A signed offer is bounded to 8 KiB; the private joining/owner file encodings are bounded to 16 KiB and use distinct structures. The joining file contains the signed offer, PSK and routing secret. The owner record additionally contains the Noise responder private key. Decoding verifies the owner signature, responder-key shape and routing-secret SHA-256 binding; protected delivery supplies provenance, and the handshake verifies the PSK. The owner record also checks the private/public responder-key match. Private-file parse errors do not echo their input.

The prologue is `gent/invitation-channel/v1\0` followed by canonical JSON for `[signed_offer, attempt_id]`. Offer signing uses `gent/invitation-offer/v1\0` followed by the offer body; the claim's offer fingerprint hashes that same domain followed by the complete signed offer. Claim signing uses `gent/invitation-claim/v1\0`. The claim contains the invitation ID, offer fingerprint, completed Noise handshake hash, node ID/key/name and validity period. Neither handshake message may carry an application payload; each is exactly 48 bytes. Service envelope encoding and admission quotas remain separate work.

The library can issue an offer for a new node or for continuation of an existing enrolled node. Continuation pins the existing ID/key/name and preserves its configuration privileges; it cannot revive a retired node. This validates the authorization record only. Expired staged-join continuation still needs the daemon journal and CLI integration.

1. The channel and offer/claim component has tests for wrong secrets/pins, signed-field changes, expired/future times, fresh sessions, handshake replay, transport replay/reflection/reordering, low-order keys, malformed claims, maximum frames, directional budgets, admission failure and the independent Cacophony vector. Native/Wasm verification evidence is recorded in the private repository's progress notes. Physical-machine invitation enrollment and production security are not established by these component tests.
2. Add the owner's durable invitation journal and restricted dispatcher. Test competing claims, restart/rollback at every mutation boundary, changed inputs under an old request ID, cross-node/group access, expiry/revocation, resource limits, and continuation with the original key.
3. Add account and relay mailbox routes with per-direction credentials, quotas, expiry, logout/revocation, immutable retries, and fail-closed authorization. Test outage, delayed requests, storage rollback/restart, and captured SQL/logs for private values with injected-plaintext controls.
4. Connect the private-file CLI to the existing staged join. Prove Linux-to-Mac and Mac-to-Linux enrollment without an SSH pairing channel, independent transport credentials, encrypted configuration/messages/files, interrupted publication, both daemon restarts, and expiry continuation. SSH may orchestrate test machines and initial fixture delivery. Document that protected invitation transfer separately; all subsequent pairing RPCs must use the new channel, with no SSH fallback.

Service framing/quotas, persistent admission/retry records and the continuation CLI remain to be fixed by these proofs. This draft does not establish production security, hosted/mobile E2EE, or account/owner recovery.
