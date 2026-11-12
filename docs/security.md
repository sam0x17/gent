# Security component proofs

`gent-crypto` verifies owner-approved node identities and signed configuration history, with durable replica storage in `gent-daemon::replica`. `gent-daemon::encrypted` adds a native MLS messaging and persistence proof. These are library components; the local CLI/RPC proof does not use them yet. Remote delivery and encrypted configuration distribution remain unimplemented.

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

Node signing-key rotation keeps the node ID and permanently retires its previous key. Node removal retires both its ID and key. Retired entries cannot disappear from later revisions, and removed identities cannot reenroll under fresh signatures. Rejoining a removed endpoint currently requires a new logical node identity and key. Removing the last node is rejected. The MLS proof below implements separate encryption-epoch changes, but orchestrating signing-key rotation across all affected groups remains unfinished.

## Durable endpoint state

`Replica` stores one cluster per private endpoint directory in `authority.sqlite3`. The database is mode 0600 beneath a mode-0700 directory. Symlinks, shared files, and unknown future schema versions are rejected. The SQLite database uses WAL and full synchronous commits.

The trust anchor, checkpoint, current signed state, and accepted revision history are retained locally. A write starts an immediate transaction, compares the caller's expected checkpoint with the stored checkpoint, validates every revision, inserts history, and advances current state and checkpoint together. The new verified state is returned only after commit. Concurrent stale writers must reload and reconcile their proposed changes.

Restoration verifies the exact state digest and revision against the saved checkpoint. An older signed state cannot replace a newer checkpoint. The trusted local checkpoint is part of the security boundary; a relay cannot supply a replacement checkpoint. Restoring the entire database from an old backup is outside this protection and must be addressed by the recovery procedure.

The database contains private configuration, but no node or owner private keys. OS-user access to endpoint files remains trusted. Integration with `~/.gent/config.toml`, encrypted network replication, key storage, and the live daemon policy transaction is still pending.

## MLS messaging proof

The native proof uses [MLS, RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), through OpenMLS 0.9.2, RustCrypto 0.6, and OpenMLS SQLite storage 0.3. The ciphersuite is `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Gent does not implement its own ratchet. The workspace uses rusqlite 0.37 to share the SQLite storage provider's native library version; the existing daemon and replica tests pass with that version on both OSes. No experimental MLS protocol features or secret-debug features are enabled by Gent.

`EncryptedEndpoint` takes a trusted node identity and a private directory. Initialization saves independently authenticated authority once. Each later operation restores that authority against its stored checkpoint and authorizes the local node. Updates must follow the signed chain; opening the database cannot replace its anchor or node key.

An MLS basic credential contains the protocol version, cluster UUID, and node UUID. Its Ed25519 signing key must exactly match fresh owner-approved membership. `NodeIdentity` implements the MLS signer interface without exporting another private-key copy. A valid MLS signature under an unapproved key cannot impersonate a node. Group creation also checks the expected identity of every key package. Joining requires an explicit local roster and verifies every member against both that roster and authority. Standalone proposals, external senders, public application/commit messages, and additions to existing groups are rejected in this proof.

Key packages allow an endpoint to join asynchronously. The joining endpoint commits consumption of its private package only after the Welcome and expected roster pass validation. A failed join rolls everything back. An exact Welcome retry is recognized after restart. Allocate a new package request ID for each invitation; retrying an allocation returns its original public bytes, even after its private material has been consumed. This does not make a package reusable for another group.

Current bounds are 16 members per group, 16 KiB per key package, 256 bytes per group ID, 1 MiB per decoded application payload, and 2 MiB per MLS wire message. The encrypted application envelope carries a version, UUID, and base64 payload. Payloads can contain arbitrary binary data. Independent attachment objects, file-key grants, MIME/filename handling, and agent-level file permissions still belong to the pending messaging integration. The current Worker proof accepts only 1 MiB per frame; transport sizing or chunking must be resolved before these components are connected.

### Persistence and retries

MLS secrets, the authority checkpoint, ciphertext outbox, plaintext endpoint inbox, and receipt hashes live in one private `mls.sqlite3` database. It uses WAL, full synchronous commits, and SQLite secure deletion. Owner and node signing secrets are not stored there. Its inbox and cryptographic state are plaintext within the trusted endpoint; this proof does not supply storage encryption or protection against a compromised OS user.

Each cryptographic operation starts an immediate transaction and loads fresh MLS state through the upstream SQLite provider on that transaction's connection. A send advances the ratchet and stores its ciphertext before commit. A receive advances the ratchet, stores the plaintext, and records its receipt before commit. Welcome processing and epoch commits use the same pattern. Results are returned only after commit. Failure drops the in-memory MLS object as well as rolling back storage, so the next attempt reloads the saved ratchet.

Request UUIDs bind to operation and input hashes. A send retry returns the exact committed ciphertext; conflicting reuse fails. Receipts suppress duplicate delivery, and MLS still rejects a consumed generation when Gent's receipt cache is removed in a test. Concurrent writers serialize through SQLite and reload state; they cannot independently advance from stale in-memory ratchets. Queue inspection is limited to trusted daemon code, in batches of at most 128 records. Queue acknowledgment, pruning, disk quotas, and authorization at actual agent delivery remain unfinished.

### Ordering, removal, and forward secrecy

The prototype retains no past epochs or resumption PSKs. It allows up to 32 skipped application generations within an epoch, with a maximum forward distance of 128. Encryption padding uses 256-byte blocks. These are proof parameters, not final operational settings.

The relay must deliver earlier application messages before the commit advancing their epoch. The tests demonstrate that an undelivered old-epoch message becomes undecryptable after that commit. Offline delivery works when the receiver resumes from its saved state and receives the backlog in this order. Ordering across independent senders, concurrent epoch commits, malicious relay forks, missing messages, and recovery from lost state need a delivery protocol before remote use. A malicious relay can always withhold traffic; it must not gain decryption authority through recovery.

Fresh owner authority is checked before application encryption and acceptance. An unapproved or removed credential in the group blocks application delivery. `remove_revoked` removes those credentials and commits a new epoch; surviving endpoints validate the resulting roster against their authority. A removed endpoint retaining its old authority and old keys cannot decrypt a new-epoch message. A signed revocation must reach a surviving endpoint before it can enforce it; the authority lease still bounds withholding as described above. Previously delivered plaintext and previously issued keys cannot be recalled.

The tests establish deletion of consumed key packages and loss of old-epoch decryption through the current logical MLS state. They do **not** establish forensic erasure from allocator memory, SQLite WAL history, filesystem snapshots, swap, or backups. `secure_delete` alone cannot provide that guarantee. Secret-storage design, backup exclusions, key retention, and recovery need review before claiming full endpoint-compromise forward secrecy in a deployed service.

### Boundaries still to implement

Key packages contain identity metadata and must travel inside an authenticated, encrypted enrollment or distribution channel. They must not become a plaintext public directory. MLS Welcome messages protect their group information, while ordinary MLS headers still expose opaque group IDs, epochs, sizes, and timing. The surrounding routing protocol must account for this metadata.

Node authentication does not authorize one agent to read another agent's messages. The proof has no model-facing API, and its raw inbox/outbox accessors are for trusted local code. Integration must bind authenticated agent envelopes, recheck policy at send and delivery, and atomically coordinate authority, agent permissions, and queues. The standalone `Replica` and this proof's authority checkpoint must be consolidated in that runtime path.

A likely layout remains a configuration group for trusted daemons and separate messaging groups for authorized endpoints. A limited hosted bridge must never join the configuration group. Encrypted policy distribution, file-key grants, periodic epoch refresh, pairing UX, signing-key replacement, lost-state recovery, hosted/mobile trust boundaries, and independent security review remain required before remote delivery is enabled.

## Verification

The authority tests exercise request-key and name substitution, wrong owner/genesis pins, policy tampering, replayed/stale/future/expired enrollment, conflicting revisions, gaps, rollback, key rotation, permanent retirement, canonical wire validation, and restart checkpoints. The replica tests exercise concurrent stale writers, restart/history recovery, expired-history catch-up, file permissions, symlinks, schema-version rejection, and an injected SQLite failure after history insertion but before checkpoint update.

Eleven MLS tests pass on Linux and macOS. They cover offline join/delivery and a 1 MiB binary reply, restart retries, validly signed key substitution, foreign clusters, Welcome roster mismatch, single-use join keys, malformed/tampered/cross-group messages, out-of-order delivery, MLS replay defense, concurrent writers, epoch changes, and node removal. SQLite triggers inject failures after cryptographic changes but before queue/receipt insertion, including Welcome and epoch commits, to verify rollback and retry. Expiry, authority rollback, wrong local identity, size limits, permissions, symlinks, and future schema versions are also checked. Tests reopen endpoint databases between operations; no running remote service is involved.

Run from the public repository root:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p gent-crypto --features mls --target wasm32-unknown-unknown --locked
```

The authority crate and its signer interface compile for Wasm; native SQLite MLS storage and MLS runtime behavior on Wasm are not covered by that check. The full Rust workspace has 38 passing tests on each native OS. Independent protocol review, encrypted transport tests, real pairing UX, and recovery tests remain required before production use.
