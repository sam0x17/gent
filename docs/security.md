# Security component proofs

`gent-crypto` verifies owner-approved node identities and signed configuration history. The live daemon uses that authority for RPC permission checks and owner configuration changes. `gent-daemon::encrypted` supplies MLS messaging and authenticated directional streams, including configuration recovery after authority expires. An optional background dispatcher synchronizes encrypted configuration through a development relay, updating the live database and its policy. Agent-message encryption and remote delivery remain unimplemented in the live RPC path; protected node pairing is also pending.

## Trust boundary

A trusted endpoint pins a cluster ID, owner verification key, and genesis-state digest. This `TrustAnchor` must arrive through an already trusted endpoint or a separately authenticated owner channel. Taking an anchor from the routing service would let that service substitute its own authority.

The owner signing key authorizes membership and policy. Each node has a separate signing key and stable node ID. The local MCP binding credential and owner RPC credential remain separate from both cryptographic identities. A provider label, GitHub login, database membership row, or model-supplied node ID cannot authorize a signed revision.

This version assumes one active configuration writer holding the cluster's owner key. Recovery copies must remain offline until the writer is deliberately replaced. Concurrent holders of that key can sign competing histories; receivers reject forks against their saved checkpoint, but this implementation does not provide distributed consensus between independent owner writers. Delegated administration and owner-key replacement need further design and tests.

Signed states contain private node names, membership, and policy; signatures alone do not conceal them. The configuration dispatcher encrypts these records in established MLS streams before upload. Initial grants and key packages still require protected pairing and have no network publication path. A future hosted bridge must receive only its agent's scoped credentials and grants, never this full configuration or the owner key.

## Keys and signed records

Owner and node keys use Ed25519 through `ed25519-dalek`, with system randomness and strict signature verification. Weak public keys are rejected. A node cannot use the owner key, share another active node's signing key, or reuse a retired key. Secret-bearing types have no `Debug` or serialization implementation. Explicit secret export returns a zeroizing buffer for protected endpoint storage.

Signed bodies use [RFC 8785 JSON canonicalization](https://www.rfc-editor.org/rfc/rfc8785.html) through `serde_jcs`. The signing inputs are:

```text
gent/cluster-state/v1<NUL> || JCS(ClusterState)
gent/enrollment-request/v1<NUL> || JCS(EnrollmentRequest)
gent/configuration-grant/v1<NUL> || JCS(ConfigurationGrant)
```

The signature is Ed25519 over those bytes. State digests and enrollment fingerprints use SHA-256 over the corresponding signing input. Domain separation prevents a signature for one record type from authorizing another. Digests exclude the detached signature. Numeric counters and timestamps stay within JSON's exactly representable integer range.

Wire decoders require canonical JSON bytes, enforce size limits before parsing, reject unknown fields, and reject duplicate map entries through canonical re-encoding. A decoded record still needs signature and authority verification. The public signing/state types have explicit version fields; unsupported versions fail validation.

Current limits are:

| Record or collection | Limit |
| --- | --- |
| Signed configuration | 2 MiB |
| Enrollment request | 4 KiB |
| Configuration stream grant | 8 KiB |
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

The standalone replica database contains private configuration, but no node or owner private keys. OS-user access to endpoint files remains trusted. The live runtime uses the shared authority schema described below instead of running a second `Replica` checkpoint alongside its queues.

## Live daemon authority

The local runtime stores authority, accepted history, MLS tables, registrations, exchanges, and message queues in one private `state.sqlite3`. Each RPC starts an immediate transaction, verifies the saved state and local node identity, and uses that state's policy for discovery, send, reply, inbox, and acknowledgment. Agent requests require fresh authority. A previously opened daemon handle reloads authority for every request; it cannot keep using an earlier policy from memory. Registration activity and message/exchange writes commit together.

First startup creates separate owner and node Ed25519 keys and pins genesis in `identity.key`, a mode-0600 file under the private state directory. The original `owner.key` remains the distinct local RPC credential. The owner file's `GENTKEY1` header precedes the two private keys and bootstrap records; it has no model-facing accessor. Key buffers are zeroized on drop. This is protected local storage, without OS keychain encryption or forensic-erasure guarantees.

`Store::install_joined` installs an already enrolled node using its own signing key and independently verified authority. Its `GENTKEY2` file contains that node's private key, trust anchor, checkpoint, and signed state, with no owner signing secret. It creates a separate local RPC credential and atomically installs the initialized directory, refusing to overwrite an existing configuration. This is a trusted Rust API, unavailable through RPC, MCP, or the relay. Its caller must have completed authenticated pairing; the actual pairing transport and CLI remain pending. Joined nodes reject signing operations until edit forwarding to the active owner is implemented.

Bootstrap preserves existing local node and cluster IDs, registrations, and messages. An interrupted bootstrap reuses the same saved keys and genesis. Missing keys for an initialized database, mismatched identities, symlink/shared key files, or an authority anchor that differs from the separate key-file pin fail closed. The database must also be a private regular file. Restoring the entire key file and database from an older backup remains outside rollback protection.

Owner configuration changes create a signed revision, persist history/checkpoint, and queue a TOML projection in one transaction. Accepted changes are ordered by signed revision: the newest change replaces the previous shared configuration. Later authorized edits can replace an earlier policy without a merge, including edits begun from an older view. Invalid revisions, stale replay, and forks still fail verification. The commit immediately wakes the configuration dispatcher, with history available to each stream's publication cursor. Routing remote edit requests to the active owner writer remains pending.

After commit, Gent writes the newest signed settings to `config.toml` atomically, preserving unrelated local settings. The file's `applied_revision` records that projection. A filesystem failure leaves committed authority in force and a durable retry marker; the RPC reports `applied: true` with `config_saved: false`. Restart, subsequent successful RPCs, and maintenance retry the latest state, never a saved older projection. Editing TOML alone does not change active authority: `gent config apply` authorizes and signs the edit. `gent node name set` also goes through the daemon and requires it to be running.

The owner daemon checks renewal at startup and every 15 minutes, renewing when at most six hours remain in the 24-hour lease. `gent cluster renew` requests an immediate owner renewal. Agent requests do not renew authority themselves. Expired authority blocks them until a renewal commits; failed renewal storage leaves them blocked. Joined nodes receive signed renewals through their configuration streams and never self-renew. Owner replacement remains unfinished.

`OrderedEndpoint::open_runtime` attaches trusted daemon code to this database. Receiving a complete configuration revision advances the same checkpoint used by live RPC permission checks and queues the same TOML projection. Runtime tests pass encrypted packets directly between peers, including a newer denial that blocks an already queued message. Separate dispatcher tests exercise network synchronization through a local relay.

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

MLS must process earlier application messages before the commit advancing their epoch. The low-level tests demonstrate that an undelivered old-epoch message becomes undecryptable after that commit. The directional stream layer below enforces this order and buffers packets that arrive early, including commits. It no longer depends on a relay supplying the correct order. A missing packet stalls that stream until retransmission; the relay can always withhold traffic. Lost-state recovery must not grant it decryption authority.

Fresh owner authority is checked before application encryption and acceptance. An unapproved or removed credential in the group blocks new application sends. `remove_revoked` removes those credentials and commits a new epoch; surviving endpoints validate the resulting roster against their authority. A removed endpoint retaining its old authority and old keys cannot decrypt a new-epoch message. A signed revocation must reach a surviving endpoint before it can enforce it; the authority lease still bounds withholding as described above. Previously delivered plaintext and previously issued keys cannot be recalled.

The tests establish deletion of consumed key packages and loss of old-epoch decryption through the current logical MLS state. They do **not** establish forensic erasure from allocator memory, SQLite WAL history, filesystem snapshots, swap, or backups. `secure_delete` alone cannot provide that guarantee. Secret-storage design, backup exclusions, key retention, and recovery need review before claiming full endpoint-compromise forward secrecy in a deployed service.

## Directional encrypted streams

`gent-daemon::encrypted::ordered::OrderedEndpoint` supplies the delivery primitive intended for daemon integration. Each stream has one pinned sending node and an explicit recipient roster. A reply uses a separate stream in the opposite direction. Two peers can therefore send and refresh keys concurrently without competing to commit the same MLS group. Broadcast to several approved nodes uses the same single-writer rule. This is a transport role; it does not require a coordinator agent or constrain which agents may talk to each other.

The originating node creates an MLS group and publishes its Welcome as sequence zero. The receiving node independently approves the writer and roster, checks the outer packet signature, and verifies that the MLS Welcome was authored by that same writer. The stream saves the writer's node ID and approved signing key, origin digest, original-roster digest, and current sequence/digest locally. These identities and roster records do not appear in the outer packet.

Every packet signs this exact binary input with the node's Ed25519 key:

```text
gent/stream-packet/v1<NUL>
|| version:u8
|| group_id_length:u16be || group_id
|| sequence:u64be
|| previous_packet_digest:[32]
|| SHA256(mls_ciphertext):[32]
```

The packet digest is SHA-256 of that signing input, excluding the detached signature. Sequence zero has an all-zero predecessor; later positions require a nonzero predecessor. Counters are bounded to JSON-safe integers. Wire records use canonical JSON with base64 ciphertext, group ID, and signature, and reject duplicate/unknown fields or noncanonical encodings. Packet size is bounded to 3 MiB around a maximum 2 MiB MLS message. This signature authenticates ordering; MLS remains the encryption protocol.

Opaque group IDs, counters, predecessor hashes, ciphertext lengths, signatures, and timing remain visible to transport. Agent names, node IDs, public keys, request IDs, message bodies, and private configuration are absent from this outer framing. Key-package distribution still requires its encrypted channel.

### Durable ordering and backpressure

Sending, MLS epoch changes, signed packet insertion, and advancement of the stream checkpoint commit together. Repeating a request ID returns its original packet. Concurrent operations on one node reload state under SQLite's immediate transaction lock. Only the pinned writer may send or change that stream's epochs; the general MLS proof APIs reject mutations and receives on ordered groups so callers cannot accidentally bypass sequencing.

`stage` checks current authority and the writer's signature before saving a packet. It recognizes exact repeats and rejects conflicting accepted or buffered sequence slots. Packets may be at most 128 positions ahead of the saved head. Pending application ciphertext is limited to 16 MiB across the endpoint database. Future packets can occupy at most 13 MiB, reserving 3 MiB for a missing immediate predecessor. Once a ready prefix occupies that reserve, callers must drain it before staging more data. Configuration traffic has a separate quota, described below.

`drain` applies only the next sequence with the expected predecessor digest. Each packet gets a separate transaction covering MLS state, inbox/receipt insertion, stream checkpoint, accepted digest, and pending-row deletion. A later failure cannot undo an earlier committed prefix. Authority is rechecked when applying previously buffered data. The sender inside MLS must equal the pinned outer writer, including for epoch commits. Status exposes the next needed sequence, and the signed outbox supports bounded retransmission from that position.

Schema version 3 retains stream metadata, signed outbox records, accepted digests, and pending ciphertext, and adds stream purpose, authority history, configuration grants, publication cursors, and partial records. Existing version-1 and version-2 proof databases upgrade without replacing their MLS state or queued ciphertext. Migrated authority history starts at the saved current checkpoint; it cannot reconstruct earlier revisions. A previously used unsequenced group cannot be adopted into an ordered stream. The proof retains both its original MLS outbox and signed packet outbox; runtime storage consolidation, acknowledgment, retention, and total disk quotas remain unfinished.

### Revocation and conflicting history

An offline recipient can encounter older traffic before the commit removing another member. For directional backlog, the writer and local receiving node must still be authorized. Historical refreshes may preserve an existing credential or remove a now-revoked credential; they cannot add a member, replace a signing identity, or remove a currently authorized node. This lets the recipient reach the removal commit without reviving the revoked node or retaining old epochs indefinitely. Earlier ciphertext may already be known to the removed recipient; revocation cannot undo that exposure. New sends remain blocked until revoked members are removed, and final agent delivery still needs a current policy check.

A writer's revocation or signing-key replacement disables its existing streams. Applying that authority update also removes its pending ciphertext in the same transaction, freeing the receive quota while preserving other writers' queues. Revocation of the local endpoint clears its entire pending queue. Replacement stream enrollment and key-recovery UX remain to be implemented. A receiver cannot take over an offline writer's stream; it can continue sending through its own direction while the other stream waits.

The relay cannot create a valid alternative sequence or skip a predecessor without the writer's signing key. An observed signed fork is rejected against saved accepted or pending history. This does not provide global consensus between cloned copies of a node key: a malicious writer can maintain separate histories until endpoints compare them, or sign invalid MLS data. Such a packet remains pending and stops the stream for diagnosis; the receiver never silently skips it. Recovery from a compromised writer, rollback of an entire endpoint backup, key loss, and selective withholding remain separate work.

## Encrypted configuration recovery

`ordered::configuration` gives each trusted receiving daemon its own two-node configuration stream. An owner-signed grant binds the cluster anchor, exact initial checkpoint, group and origin digest, and both node IDs and signing keys. Provisioning requires fresh authority at both ends. The grant, like a key package, contains private identity metadata and must travel through protected pairing; that transport is still pending. A hosted bridge must never receive a configuration grant.

Only an established configuration stream may receive or retransmit with expired authority. Its saved grant and both endpoint keys must still match known membership. Revocation or signing-key replacement disables it. Fresh authority is required to create a stream, publish a new fragment, or refresh encryption keys. Ordinary data APIs reject configuration streams, and configuration APIs reject data streams. Configuration records never enter the application inbox.

The writer first accepts owner-signed revisions into its local authority history. `next_configuration` then publishes them in order, tracking a separate cursor for each recipient. Each signed record is split into fragments of at most 256 KiB, with its revision, digest, total size, and offset inside MLS encryption. Committed requests return the same packet on retry. A return value of `None` means there is no new history and does not reserve the request ID. Current fragment packets fit the Worker proof's 1 MiB frame limit; larger application messages still need transport sizing or chunking.

The receiver verifies fragment continuity and the complete record's owner signature, predecessor, and revision before changing authority. Known revisions must match retained verified history; conflicting owner-signed forks are rejected. A complete expired revision can advance the checkpoint, but ordinary messaging stays blocked until a fresh revision is reached. Partial records cannot change authority. The final fragment commits authority, history, MLS state, receipts, stream checkpoint, and fragment cleanup in one transaction. An MLS epoch refresh may change encryption keys while preserving both signing identities and membership.

Configuration ciphertext has a separate 8 MiB pending quota, with 3 MiB reserved for a missing predecessor. A full application queue cannot consume that space. Partial records reserve their entire declared size from a separate 8 MiB reconstruction budget when admitted, allowing them to finish even when that budget is full. Completed records release the reservation; retiring a writer removes its pending packets and partial records. Malformed authenticated traffic stalls its stream, and a compromised approved writer can still withhold updates or consume its available quota.

This recovers an expired node that retains its keys, checkpoint, and established stream. It does not recover lost keys or roll back an endpoint backup safely. The sender needs a contiguous retained history after each recipient's initial checkpoint. Retention, stream replacement, and protected distribution of initial grants and key packages remain required for live operation.

## Automatic configuration sync

An explicit machine-local `[relay]` setting starts the daemon's background configuration task. It needs established, owner-authorized configuration streams and no agent turn. Successful signed edits and lease renewals notify the task after commit. Publication persists each encrypted packet before upload; reception verifies the packet, MLS sender, and signed history before changing live policy. A saved pending packet is drained before contacting the relay, so it can finish applying after a restart even while the network is unavailable.

The development HTTP protocol uses a base64url-encoded opaque group ID as its mailbox address:

| Request | Response |
| --- | --- |
| `GET /v1/mailboxes/{group}` | JSON `{"next": N}`, an untrusted next-storage-position hint. |
| `PUT /v1/mailboxes/{group}/{sequence}` with the encoded packet as its body | JSON `{"stored": true, "sequence": N}` on success. |
| `GET /v1/mailboxes/{group}/{sequence}` | Exact encoded packet, or HTTP 404 if unavailable. |

Uploads are limited to 1 MiB, and JSON metadata responses to 1 KiB. The client bounds streamed responses, disables redirects, and sets connection/request timeouts. HTTPS is required except for loopback development origins. The credential comes from a private local file, separate from node/owner keys. The proof relay uses a shared synthetic bearer token; it does not implement account or per-node service authorization. That token authorizes storage only. Possession does not authorize a signed revision or decrypt a packet.

The local Worker persists opaque packets in D1. Its insertion triggers enforce contiguous storage and advance the mailbox head atomically. Exact retries succeed, conflicting bytes and gaps fail. Neither a relay position nor a storage acknowledgment proves recipient acceptance. The sender rejects a position beyond its local history and retains all ciphertext/history after upload, allowing retransmission after relay storage loss. Endpoints verify the requested group and sequence and never use a relay timestamp to order policy changes. The service still sees opaque routing IDs, traffic sizes, and timing.

The dispatcher rotates through batches of up to 32 streams with four concurrent transfers and never holds the RPC store mutex during network requests. It scans at most 4,096 established streams, excluding known revoked or replaced peers. Idle receivers poll once per second; progressing transfers continue after 10 ms, and errors back off per stream from one to 30 seconds. These are development parameters, not a latency guarantee. Publication wakes immediately, but remote application still waits for polling, transfer, and verification. Push/WebSocket notification transport is needed to meet the intended immediate-sync behavior and reduce polling cost before a hosted trial.

This path handles configuration only. Normal enrollment, edits from joined nodes, encrypted agent traffic, authenticated recipient acknowledgments, queue pruning, service quotas, and retention limits remain unfinished. The test fixture establishes trusted enrollment in-process and does not prove a user-facing pairing flow or a two-physical-machine agent workflow. Local endpoint and relay histories currently grow without pruning.

## Boundaries still to implement

Key packages contain identity metadata and must travel inside an authenticated, encrypted enrollment or distribution channel. They must not become a plaintext public directory. MLS Welcome messages protect their group information, while ordinary MLS headers still expose opaque group IDs, epochs, sizes, and timing. The surrounding routing protocol must account for this metadata.

Node authentication does not authorize one agent to read another agent's messages. MLS inbox/outbox accessors are for trusted local code. Local RPC now checks signed policy inside its queue transaction, and configuration reception shares that authority. Remote message integration still must bind authenticated agent envelopes, enforce registration ownership, recheck policy before encryption and after decryption, and commit cryptographic state with the corresponding agent queue changes.

Configuration streams belong only to trusted daemons; messaging groups serve separately authorized endpoints. Remote agent-message transport, file-key grants, periodic epoch refresh scheduling, pairing UX, signing-key replacement, lost-state recovery, hosted/mobile trust boundaries, and independent security review remain required before remote agent delivery is enabled.

## Verification

The authority tests exercise request-key and name substitution, wrong owner/genesis pins, policy tampering, replayed/stale/future/expired enrollment, conflicting revisions, gaps, rollback, key rotation, permanent retirement, canonical wire validation, and restart checkpoints. The replica tests exercise concurrent stale writers, restart/history recovery, expired-history catch-up, file permissions, symlinks, schema-version rejection, and an injected SQLite failure after history insertion but before checkpoint update.

Eleven MLS tests pass on Linux and macOS. They cover offline join/delivery and a 1 MiB binary reply, restart retries, validly signed key substitution, foreign clusters, Welcome roster mismatch, single-use join keys, malformed/tampered/cross-group messages, out-of-order delivery, MLS replay defense, concurrent writers, epoch changes, and node removal. SQLite triggers inject failures after cryptographic changes but before queue/receipt insertion, including Welcome and epoch commits, to verify rollback and retry. Expiry, authority rollback, wrong local identity, size limits, permissions, symlinks, and future schema versions are also checked. Tests reopen endpoint databases between operations; no running remote service is involved.

Two packet-format tests and ten ordered-stream tests cover signature binding, canonical framing, reordered epochs, simultaneous opposite-direction traffic, concurrent refreshes/retries, writer and Welcome-creator substitution, MLS sender substitution, fork rejection, pending quotas with predecessor reserve, authority changes while buffered, revocation catch-up, partial-prefix durability, and version-1 database migration. Injected ordering-table failures verify that MLS state and stream checkpoints cannot commit separately.

Two configuration-grant tests and eleven configuration-stream tests cover owner/key/group binding, purpose isolation, expired-history recovery, forged policy from an approved writer, large-record reassembly across restart and epoch refresh, conflicting owner history, revocation, separate queue limits, partial-record reservations, and version-2 migration. A valid MLS removal cannot change configuration-stream membership. Injected failures verify that grants, publication cursors, authority history, and cryptographic state roll back together.

Nine runtime tests cover the newest accepted policy across existing handles and restarts, failed policy/message transactions, retryable TOML projection, encrypted updates affecting live inbox access, key-file protections, interrupted bootstrap, expiry/renewal failure, and preservation of legacy registrations and messages. The existing delivery and MCP smoke tests now exercise the signed runtime path.

Five dispatcher tests pass on Linux and macOS. They cover automatic newest-revision replacement, outages, peer restart, complete relay storage loss, corrupted packets and false positions, fragmented large configurations without an agent turn, safe endpoint/credential setup, and applying already-buffered traffic while the relay is offline. Fixtures also verify joined nodes receive no owner signing secret. An additional opt-in test passes through the real local Wrangler/D1 Worker on Linux, including offline catch-up. It is ignored by the default suite and uses the same trusted enrollment fixture.

Run from the public repository root:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p gent-crypto --features mls --target wasm32-unknown-unknown --locked
```

The native workspace has 77 passing default tests on Linux and macOS, plus the opt-in Worker test described above. The authority crate, configuration grants, packet format, and signer interface compile for Wasm; native SQLite MLS storage and MLS runtime behavior on Wasm are not covered by that check. Independent protocol review, production transport and authentication tests, real pairing UX, and lost-state recovery tests remain required before production use.
