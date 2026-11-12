# Enrollment and configuration authority

The first security component is implemented in `gent-crypto`, with durable replica storage in `gent-daemon::replica`. It verifies owner-approved node identities and signed configuration history. It is a library component; the current local CLI/RPC proof does not use it yet. Remote delivery, content encryption, and encrypted configuration distribution remain disabled or unimplemented.

## Trust boundary

A trusted endpoint pins a cluster ID, owner verification key, and genesis-state digest. This `TrustAnchor` must arrive through an already trusted endpoint or a separately authenticated owner channel. Taking an anchor from the routing service would let that service substitute its own authority.

The owner signing key authorizes membership and policy. Each node has a separate signing key and stable node ID. The local MCP binding credential and owner RPC credential remain separate from both cryptographic identities. A provider label, GitHub login, database membership row, or model-supplied node ID cannot authorize a signed revision.

This version assumes one active configuration writer holding the cluster's owner key. Recovery copies must remain offline until the writer is deliberately replaced. Concurrent holders of that key can sign competing histories; receivers reject forks against their saved checkpoint, but this implementation does not provide distributed consensus between independent owner writers. Delegated administration and owner-key replacement need further design and tests.

The service must receive encrypted forms of these records. Signed states contain private node names, membership, and policy; signatures alone do not conceal them. The current implementation has no upload path. A future hosted bridge must receive only its agent's scoped credentials and grants, never this full configuration or the owner key.

## Keys and signed records

Owner and node keys use Ed25519 through `ed25519-dalek`, with system randomness and strict signature verification. Weak public keys are rejected. A node cannot use the owner key, share another active node's signing key, or reuse a retired key. Secret-bearing types have no `Debug` or serialization implementation. Explicit secret export returns a zeroizing buffer for protected endpoint storage.

Signed bodies use [RFC 8785 JSON canonicalization](https://www.rfc-editor.org/rfc/rfc8785.html) through `serde_jcs`. The signing inputs are:

```text
gent/cluster-state/v1<NUL> || JCS(ClusterState)
gent/enrollment-request/v1<NUL> || JCS(EnrollmentRequest)
```

The signature is Ed25519 over those bytes. State digests and enrollment fingerprints use SHA-256 over the corresponding signing input. Domain separation prevents a signature for one record type from authorizing another. Digests exclude the detached signature. Numeric counters and timestamps stay within JSON's exactly representable integer range.

Wire decoders require canonical JSON bytes, enforce size limits before parsing, reject unknown fields, and reject duplicate map entries through canonical re-encoding. A decoded record still needs signature and authority verification. The public signing/state types have explicit version fields; unsupported versions fail validation.

Current limits are:

| Record or collection | Limit |
| --- | --- |
| Signed configuration | 2 MiB |
| Enrollment request | 4 KiB |
| Active nodes | 1,024 |
| Retired node IDs / signing keys | 8,192 each |
| Policy rules / groups | 4,096 / 256 |
| Members per policy group | 4,096 |
| One history batch | 1,024 revisions and 16 MiB |

These are validation bounds for the prototype. History compaction and operational quotas remain future work.

## Node enrollment

1. The new node generates its own signing key and node ID locally.
2. It obtains the cluster's trusted anchor and current checkpoint through the pairing flow.
3. It signs an enrollment request containing that anchor, base revision/digest, its node ID and public key, display name, random request ID, and validity period.
4. The owner independently confirms the complete 32-byte request fingerprint. Echoing the fingerprint shown by an untrusted relay is insufficient. The eventual CLI must compare information from the new node or use an authenticated pairing channel.
5. The owner verifies proof of key possession, fingerprint, target cluster, exact current checkpoint, and expiry, then signs the next configuration revision.
6. The joining node verifies the owner's history against its pinned anchor before treating itself as enrolled.

Requests last 15 minutes. Any intervening configuration revision makes a request stale, so retrying requires a request for the new checkpoint and renewed approval. This intentionally favors explicit approval over concurrent invitations in the initial implementation. Replaying an accepted request cannot add a node again because its base checkpoint is no longer current.

The library implements request signing and verification, owner approval, and membership changes. It does not yet implement the invitation transport, pairing UI, GitHub service authorization, or `gent cluster join` command. No enrollment secret or private signing key belongs in a model-visible tool argument.

## Revisions, expiry, and revocation

Every state contains a revision number and the digest of its immediate predecessor. Receivers verify the owner signature, cluster/authority binding, contiguous revision, predecessor digest, nondecreasing issue time, and retained retirement history. An update chain is validated completely before changing the in-memory checkpoint. A signed record with a valid signature can still be rejected for a rollback, gap, or conflicting predecessor.

States currently last at most 24 hours. `authorize_node` requires a currently valid state and an exact match between the node ID and approved public key. Its result authenticates a node; agent discovery, messaging, and relay delegation still need their separate permission checks. Caller-supplied time must come from the trusted endpoint clock, never a model or relay field.

An expired state may be loaded to recover or synchronize. `advance_history` and `Replica::apply_history` accept verified history in bounded batches even when the latest batch is still expired. Node authorization remains unavailable until a fresh revision is reached. `apply_chain` and `Replica::apply` additionally require a fresh final revision. An owner with the correct signing key can renew expired state.

Under a partition or malicious relay, another endpoint may keep using its previously issued state until that state's validity ends. This implementation therefore has a revocation delay bounded by the remaining validity period, assuming a trustworthy clock. Local clock rollback and restoration of an older entire endpoint backup require additional recovery safeguards. The trial must choose an acceptable freshness interval and implement timely renewal before remote operation is enabled.

Node signing-key rotation keeps the node ID and permanently retires its previous key. Node removal retires both its ID and key. Retired entries cannot disappear from later revisions, and removed identities cannot reenroll under fresh signatures. Rejoining a removed endpoint currently requires a new logical node identity and key. Removing the last node is rejected. Rotation of content-encryption epochs remains a separate, unimplemented requirement.

## Durable endpoint state

`Replica` stores one cluster per private endpoint directory in `authority.sqlite3`. The database is mode 0600 beneath a mode-0700 directory. Symlinks, shared files, and unknown future schema versions are rejected. The SQLite database uses WAL and full synchronous commits.

The trust anchor, checkpoint, current signed state, and accepted revision history are retained locally. A write starts an immediate transaction, compares the caller's expected checkpoint with the stored checkpoint, validates every revision, inserts history, and advances current state and checkpoint together. The new verified state is returned only after commit. Concurrent stale writers must reload and reconcile their proposed changes.

Restoration verifies the exact state digest and revision against the saved checkpoint. An older signed state cannot replace a newer checkpoint. The trusted local checkpoint is part of the security boundary; a relay cannot supply a replacement checkpoint. Restoring the entire database from an old backup is outside this protection and must be addressed by the recovery procedure.

The database contains private configuration, but no node or owner private keys. OS-user access to endpoint files remains trusted. Integration with `~/.gent/config.toml`, encrypted network replication, key storage, and the live daemon policy transaction is still pending.

## Content-encryption protocol work

The plan requires forward secrecy, offline delivery, durable retries, endpoint removal, and recovery. The current signature layer does not supply these properties. Static-recipient encryption alone would leave recorded ciphertext exposed to later compromise of that recipient's long-term key.

[MLS, RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), is the next protocol candidate to prototype because it supports asynchronous key establishment and forward secrecy. Its credential authentication would need to bind to the approved node signing keys above. A possible layout is a configuration group for trusted daemons and separate messaging groups for the communicating endpoints. A limited hosted bridge must never join the full configuration group. Group membership does not replace per-agent policy checks.

[Noise](https://noiseprotocol.org/noise.html) is another candidate for authenticated live sessions, but a Noise-only design would still need to prove durable asynchronous delivery across both endpoints restarting. No custom ratchet or message-encryption construction has been added while that decision remains open.

The encryption proof must cover authenticated credentials, key-package substitution, replay and out-of-order delivery, fresh membership/policy, removed endpoints, protected file keys, erased historical secrets, and persistence of cryptographic state with the outbox/inbox. Only after that proof should the daemon acquire remote transport. Account recovery must never recreate decryption authority through a service database change.

## Verification

The authority tests exercise request-key and name substitution, wrong owner/genesis pins, policy tampering, replayed/stale/future/expired enrollment, conflicting revisions, gaps, rollback, key rotation, permanent retirement, canonical wire validation, and restart checkpoints. The replica tests exercise concurrent stale writers, restart/history recovery, expired-history catch-up, file permissions, symlinks, schema-version rejection, and an injected SQLite failure after history insertion but before checkpoint update.

Run from the public repository root:

```sh
cargo test -p gent-crypto -p gent-daemon --test authority --test replica --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p gent-crypto --target wasm32-unknown-unknown --locked
```

These tests establish the listed library and storage behavior. Independent protocol review, encrypted transport tests, real pairing UX, and recovery tests remain required before production use.
