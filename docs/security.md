# Security component proofs

`gent-crypto` verifies owner-approved node identities and signed configuration history. The live daemon uses that authority for RPC permission checks and owner configuration changes. `gent-daemon::encrypted` supplies MLS messaging and authenticated directional streams, including configuration recovery after authority expires. An optional background dispatcher synchronizes encrypted configuration through a development relay, updating the live database and its policy. Node pairing is available through authenticated SSH. The same dispatcher now carries encrypted agent registrations, messages, files, and recipient receipts between directly paired nodes.

## Trust boundary

A trusted endpoint pins a cluster ID, owner verification key, and genesis-state digest. This `TrustAnchor` must arrive through an already trusted endpoint or a separately authenticated owner channel. Taking an anchor from the routing service would let that service substitute its own authority.

The owner signing key authorizes membership and policy. Each node has a separate signing key and stable node ID. The local MCP binding credential and owner RPC credential remain separate from both cryptographic identities. A provider label, GitHub login, database membership row, or model-supplied node ID cannot authorize a signed revision.

This version assumes one active configuration writer holding the cluster's owner key. Recovery copies must remain offline until the writer is deliberately replaced. Concurrent holders of that key can sign competing histories; receivers reject forks against their saved checkpoint, but this implementation does not provide distributed consensus between independent owner writers. Delegated administration and owner-key replacement need further design and tests.

Signed states contain private node names, membership, and policy; signatures alone do not conceal them. The configuration dispatcher encrypts these records in established MLS streams before upload. Initial grants and key packages travel through authenticated SSH pairing and are never published to the relay in plaintext. A future hosted bridge must receive only its agent's scoped credentials and grants, never this full configuration or the owner key.

## Keys and signed records

Owner and node keys use Ed25519 through `ed25519-dalek`, with system randomness and strict signature verification. Weak public keys are rejected. A node cannot use the owner key, share another active node's signing key, or reuse a retired key. Owner and node signing-key types have no `Debug` or serialization implementation. Explicit secret export returns a zeroizing buffer for protected endpoint storage.

Signed bodies use [RFC 8785 JSON canonicalization](https://www.rfc-editor.org/rfc/rfc8785.html) through `serde_jcs`. The signing inputs are:

```text
gent/cluster-state/v1<NUL> || JCS(ClusterState)
gent/enrollment-request/v1<NUL> || JCS(EnrollmentRequest)
gent/configuration-grant/v1<NUL> || JCS(ConfigurationGrant)
gent/legacy-agent-binding/v1<NUL> || JCS(LegacyAgentBinding)
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
4. The owner authenticates the complete request through the protected pairing channel or independently confirms its complete 32-byte fingerprint. Echoing the fingerprint shown by an untrusted relay is insufficient. The current CLI uses an authenticated SSH channel.
5. The owner verifies proof of key possession, fingerprint, target cluster, exact current checkpoint, and expiry, then signs the next configuration revision.
6. The joining node obtains a verified checkpoint directly from the trusted owner endpoint, or verifies the owner's history against its independently pinned anchor. Once installed, its authority advances only through verified history.

Requests last 15 minutes. An intervening configuration revision makes an unaccepted request stale; retrying requires a request for the new checkpoint and owner authorization. A protected SSH retry for an already approved node/key returns current bootstrap state without enrolling another node or issuing another revision. A different key, retired node, or different authority is rejected.

`gent cluster join CLUSTER_UUID --via user@owner-host --name laptop` implements this flow through the owner's existing SSH login and local RPC credential. It requires trusted SSH host keys, disables interactive authentication and agent forwarding, bounds protocol frames, and invokes only a dedicated pairing protocol on the remote machine. Remote command paths are shell-quoted; target names cannot inject SSH options or commands. Owner-only pairing RPCs are separate from MCP agent operations. No enrollment secret or private signing key belongs in a model-visible tool argument.

The joining machine saves its own key, the authenticated owner pin, and request IDs in a private sibling staging directory. The owner approves enrollment, then signs a two-node configuration-stream grant using the joining node's fresh MLS key package. A joining runtime receives no owner signing secret. Interrupted retries preserve identity and reuse committed operations; a stale unconsumed grant gets a fresh package and stream. Once its runtime is installed, it verifies bounded history batches through its saved checkpoint before accepting a grant at that exact revision. New joins publish their staged runtime atomically after configuration and both directional data streams are ready. Existing configuration-only nodes can rerun joining to add data streams without replacing their identity or agent credentials. Old unused streams and abandoned joins currently require future retention/revocation work; local temporary-file deletion does not promise forensic erasure.

The owner must have a configured development relay before enrollment. Pairing copies its shared synthetic relay credential over SSH into a separate private file; it never exports the owner signing key or local RPC credential. This token still lacks production account and per-node scope. First bootstrap trusts the SSH-authenticated endpoint's verified snapshot; subsequent installed state cannot be replaced by a new snapshot. A replaced owner pin is rejected on resume. GitHub authorization, invitation-based pairing, owner-key replacement, and recovery from an old whole-endpoint backup remain separate work.

## Revisions, expiry, and revocation

Every state contains a revision number and the digest of its immediate predecessor. Receivers verify the owner signature, cluster/authority binding, contiguous revision, predecessor digest, nondecreasing issue time, and retained retirement history. An update chain is validated completely before changing the in-memory checkpoint. A signed record with a valid signature can still be rejected for a rollback, gap, or conflicting predecessor.

States currently last at most 24 hours. `authorize_node` requires a currently valid state and an exact match between the node ID and approved public key. Its result authenticates a node; agent discovery, messaging, and relay delegation still need their separate permission checks. Caller-supplied time must come from the trusted endpoint clock, never a model or relay field.

An expired state may be loaded to recover or synchronize. `advance_history` and `Replica::apply_history` accept verified history in bounded batches even when the latest batch is still expired. Node authorization remains unavailable until a fresh revision is reached. `apply_chain` and `Replica::apply` additionally require a fresh final revision. An owner with the correct signing key can renew expired state.

Under a partition or malicious relay, another endpoint may keep using its previously issued state until that state's validity ends. This implementation therefore has a revocation delay bounded by the remaining validity period, assuming a trustworthy clock. Local clock rollback and restoration of an older entire endpoint backup require additional recovery safeguards. The hosted trial must choose an acceptable freshness interval; the owner daemon now schedules renewals and distributes them over configuration streams.

Node signing-key rotation keeps the node ID and permanently retires its previous key. Node removal retires both its ID and key. Retired entries cannot disappear from later revisions, and removed identities cannot reenroll under fresh signatures. Rejoining a removed endpoint currently requires a new logical node identity and key. Removing the last node is rejected. The MLS proof below implements separate encryption-epoch changes, but orchestrating signing-key rotation across all affected groups remains unfinished.

## Durable endpoint state

`Replica` stores one cluster per private endpoint directory in `authority.sqlite3`. The database is mode 0600 beneath a mode-0700 directory. Symlinks, shared files, and unknown future schema versions are rejected. The SQLite database uses WAL and full synchronous commits.

The trust anchor, checkpoint, current signed state, and accepted revision history are retained locally. A write starts an immediate transaction, compares the caller's expected checkpoint with the stored checkpoint, validates every revision, inserts history, and advances current state and checkpoint together. The new verified state is returned only after commit. Concurrent stale writers must reload and reconcile their proposed changes.

Restoration verifies the exact state digest and revision against the saved checkpoint. An older signed state cannot replace a newer checkpoint. The trusted local checkpoint is part of the security boundary; a relay cannot supply a replacement checkpoint. Restoring the entire database from an old backup is outside this protection and must be addressed by the recovery procedure.

The standalone replica database contains private configuration, but no node or owner private keys. OS-user access to endpoint files remains trusted. The live runtime uses the shared authority schema described below instead of running a second `Replica` checkpoint alongside its queues.

## Live daemon authority

The local runtime stores authority, accepted history, MLS tables, registrations, exchanges, and message queues in one private `state.sqlite3`. Each RPC starts an immediate transaction, verifies the saved state and local node identity, and uses that state's policy for discovery, send, reply, inbox, and acknowledgment. Agent requests require fresh authority. A previously opened daemon handle reloads authority for every request; it cannot keep using an earlier policy from memory. Registration activity and message/exchange writes commit together.

First startup creates separate owner and node Ed25519 keys and pins genesis in `identity.key`, a mode-0600 file under the private state directory. The original `owner.key` remains the distinct local RPC credential. The owner file's `GENTKEY1` header precedes the two private keys and bootstrap records; it has no model-facing accessor. Key buffers are zeroized on drop. This is protected local storage, without OS keychain encryption or forensic-erasure guarantees.

`Store::install_joined` installs an already enrolled node using its own signing key and independently verified authority. Its `GENTKEY2` file contains that node's private key, trust anchor, checkpoint, and signed state, with no owner signing secret. It creates a separate local RPC credential and atomically installs the initialized directory, refusing to overwrite an existing configuration. This remains a trusted Rust API; the SSH CLI calls it after authenticated enrollment. A relay or MCP agent cannot invoke it. Joined nodes reject signing and owner-pairing operations until the corresponding delegation or forwarding is implemented.

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

Current bounds are 16 members per group, 16 KiB per key package, 256 bytes per group ID, 1 MiB per decoded application payload, and 2 MiB per MLS wire message. The encrypted application envelope carries a version, UUID, and base64 payload. Payloads can contain arbitrary binary data. Agent records validate filenames and content sizes, enforce message permissions, and carry inline files. Their 256 KiB fragments fit the Worker's 1 MiB frame limit after encoding. Independent attachment objects and file-key grants remain pending.

### Persistence and retries

MLS secrets, the authority checkpoint, ciphertext outbox, plaintext endpoint inbox, and receipt hashes live in one private `mls.sqlite3` database. It uses WAL, full synchronous commits, and SQLite secure deletion. Owner and node signing secrets are not stored there. Its inbox and cryptographic state are plaintext within the trusted endpoint; this proof does not supply storage encryption or protection against a compromised OS user.

Each cryptographic operation starts an immediate transaction and loads fresh MLS state through the upstream SQLite provider on that transaction's connection. A send advances the ratchet and stores its ciphertext before commit. A receive advances the ratchet, stores the plaintext, and records its receipt before commit. Welcome processing and epoch commits use the same pattern. Results are returned only after commit. Failure drops the in-memory MLS object as well as rolling back storage, so the next attempt reloads the saved ratchet.

Request UUIDs bind to operation and input hashes. A send retry returns the exact committed ciphertext; conflicting reuse fails. Receipts suppress duplicate delivery, and MLS still rejects a consumed generation when Gent's receipt cache is removed in a test. Concurrent writers serialize through SQLite and reload state; they cannot independently advance from stale in-memory ratchets. Queue inspection is limited to trusted daemon code, in batches of at most 128 records. The runtime integration below adds permission checks at actual agent delivery and authenticated acknowledgment. Queue pruning and disk quotas remain unfinished.

### Ordering, removal, and forward secrecy

The prototype retains no past epochs or resumption PSKs. It allows up to 32 skipped application generations within an epoch, with a maximum forward distance of 128. Encryption padding uses 256-byte blocks. These are proof parameters, not final operational settings.

MLS must process earlier application messages before the commit advancing their epoch. The low-level tests demonstrate that an undelivered old-epoch message becomes undecryptable after that commit. The directional stream layer below enforces this order and buffers packets that arrive early, including commits. It no longer depends on a relay supplying the correct order. A missing packet stalls that stream until retransmission; the relay can always withhold traffic. Lost-state recovery must not grant it decryption authority.

Fresh owner authority is checked before application encryption and acceptance. An unapproved or removed credential in the group blocks new application sends. `remove_revoked` removes those credentials and commits a new epoch; surviving endpoints validate the resulting roster against their authority. A removed endpoint retaining its old authority and old keys cannot decrypt a new-epoch message. A signed revocation must reach a surviving endpoint before it can enforce it; the authority lease still bounds withholding as described above. Previously delivered plaintext and previously issued keys cannot be recalled.

The tests establish deletion of consumed key packages and loss of old-epoch decryption through the current logical MLS state. They do **not** establish forensic erasure from allocator memory, SQLite WAL history, filesystem snapshots, swap, or backups. `secure_delete` alone cannot provide that guarantee. Secret-storage design, backup exclusions, key retention, and recovery need review before claiming full endpoint-compromise forward secrecy in a deployed service.

## Directional encrypted streams

`gent-daemon::encrypted::ordered::OrderedEndpoint` supplies the delivery primitive used by the daemon. Each stream has one pinned sending node and an explicit recipient roster. A reply uses a separate stream in the opposite direction. Two peers can therefore send and refresh keys concurrently without competing to commit the same MLS group. Broadcast to several approved nodes uses the same single-writer rule. This is a transport role; it does not require a coordinator agent or constrain which agents may talk to each other.

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

`ordered::configuration` gives each trusted receiving daemon its own two-node configuration stream. An owner-signed grant binds the cluster anchor, exact initial checkpoint, group and origin digest, and both node IDs and signing keys. Provisioning requires fresh authority at both ends. The grant and key package contain private identity metadata and travel through authenticated SSH pairing. A hosted bridge must never receive a configuration grant.

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

The dispatcher rotates through batches of up to 32 streams with four concurrent transfers and never holds the RPC store mutex during network requests. It scans at most 4,096 configuration streams plus two data streams per linked peer (up to 1,024 peers), excluding known revoked or replaced peers. Local commits and relay push signals wake it immediately. Progressing transfers continue after 10 ms; errors back off per stream from one to 30 seconds. Retry deadlines remain active while push is connected. Network, storage, verification, and backlog still determine application latency.

The dispatcher also carries agent records over separate data streams. Invitation-based enrollment, edits from joined nodes, automatic links between joined peers, queue pruning, service quotas, and retention limits remain unfinished. Local endpoint and relay histories currently grow without pruning.

### Push notifications and recovery

Each configured daemon connects to `GET /v1/watch` over WebSocket, using the same origin and private authorization header as HTTP. HTTPS maps to WSS; loopback development origins may use WS. The client does not follow redirects, limits frames/messages to 1 KiB, and bounds handshake and write time. No token is placed in a URL. Browser smoke clients use the existing synthetic-token subprotocol instead.

The development Worker routes successful mailbox writes through a hibernating Durable Object. After D1 storage succeeds, it broadcasts `{"version":1,"event":"changed"}`. New connections first receive `{"version":1,"event":"ready"}`; that signal triggers reconciliation after subscription so a write during connection setup cannot be missed. These untrusted hints carry no group ID, node name, configuration, or message contents. They cannot advance a checkpoint or mark a message delivered. Existing encrypted packet and signed-authority checks remain mandatory.

The client coalesces bursts into at most one wake-up per 50 ms. A healthy channel reconciles every 30 seconds, covering lost signals. It sends `gent-ping-v1` every 15 seconds and requires `gent-pong-v1` within 45 seconds; the Worker responds through its hibernation auto-response API. Invalid frames, socket closure, missing readiness, or heartbeat expiry cause reconnection with backoff from one to 30 seconds. Without a ready push connection the dispatcher falls back to one-second polling. Stopping the dispatcher also stops its notification task.

This proof has one shared-token notification realm and broadcasts to all its connections, capped at 2,048. Participants can observe that some relay traffic occurred, beyond their own stream activity. Production must scope notification realms to authenticated service membership and enforce connection revocation, rate limits, and resource quotas. The local tests exercise the hibernation API but do not prove Cloudflare production eviction behavior, scale, or cost. Mobile OS push and agent wake/resume remain separate integrations.

## Encrypted agent delivery

SSH pairing establishes two exact-roster data streams between the owner and a joining node. Each stream has one authenticated writer. Current topology is owner-to-peer; automatic peer-to-peer mesh establishment is pending. A remote directory entry never carries a usable MCP credential.

New agent IDs are domain-separated hashes of their hosting node UUID and a random nonce, encoded as UUIDv8. An enrolled malicious node cannot claim another node's unknown agent ID using its own nonce. Legacy random IDs retain their credentials and require an owner-signed cluster/agent/node binding; the owner persists unique assignments and rejects conflicting ownership. Directory updates have monotonic generations, immutable origins, and permanent revocation tombstones. Enumeration policy still filters the agent-facing directory.

Records carry an authority checkpoint, sender registration, and stable sender-scoped message ID. Receivers verify hosting-node ownership, content limits, participants, lifetime, and reply parent. A reply must refer to a locally accepted message with the same exchange and expiry. A record ahead of local signed authority waits for configuration recovery. Current policy governs import and each later inbox read. Remote exchanges allocate 16 messages per sender, 32 total, to bound simultaneous offline replies without a shared counter.

RPC acceptance commits the local message and outbound event together. The dispatcher commits each MLS ratchet step with its ciphertext and stable request ID, then advances the event's fragment cursor. If that cursor write fails, retry retrieves the same ciphertext without another ratchet step. Reception commits the MLS ratchet with a bounded decrypted-frame inbox. A second transaction reassembles the record, imports its queue entries or receipt, and removes consumed frames together. Failed imports preserve the encrypted/decrypted recovery state for retry.

A queued message is checked against current permission inside the encryption transaction. Revocation persists cancellation and sends an encrypted cancellation frame, clearing a partly received record. A cancelled send remains marked revoked if permissions are later restored. Already committed ciphertext remains retained; later revocation cannot retract plaintext previously delivered to an endpoint. Message expiry and current policy still govern inbox access. Only an authenticated receipt from the recipient's hosting node changes delivery status; relay storage acknowledgments never claim agent receipt or completion of work.

Records are limited to 2 MiB and split into 256 KiB fragments, keeping encoded packets within the relay's 1 MiB limit. Inline files remain limited to 1 MiB decoded per message. Pending decrypted frames have a 16 MiB bound; reconstruction reserves at most 8 MiB across partial records. Malformed authenticated records stall their stream. Queue pruning, storage quotas, and repair after lost state remain unfinished.

Six runtime tests inject enqueue, fragment-cursor, and recipient-import failures, cancel partial files, reject foreign agent claims and forged replies/receipts, delay messages until configuration catches up, and bound replies queued by both nodes. Two automatic relay tests cover a 1 MiB file, scoped replies, restart, authenticated acknowledgment, outage, policy changes, and directory tombstones. Two authority tests check ID scoping and legacy-certificate substitution.

## Boundaries still to implement

Key packages contain identity metadata and must travel inside an authenticated, encrypted enrollment or distribution channel. They must not become a plaintext public directory. MLS Welcome messages protect their group information, while ordinary MLS headers still expose opaque group IDs, epochs, sizes, and timing. The surrounding routing protocol must account for this metadata.

Node authentication does not authorize one agent to read another agent's messages. MLS inbox/outbox accessors are for trusted local code. The live RPC path and remote import check signed policy and bind each registration to its authenticated hosting node. Trusted daemons can read records addressed to their node; MCP callers receive only their permitted directory and inbox.

Configuration streams belong only to trusted daemons; messaging streams serve separately authenticated endpoints. Automatic mesh establishment, larger-file storage and grants, periodic epoch refresh scheduling, invitation pairing, signing-key replacement, lost-state recovery, hosted/mobile trust boundaries, and independent security review remain required before production use.

## Verification

The authority tests exercise request-key and name substitution, wrong owner/genesis pins, policy tampering, replayed/stale/future/expired enrollment, conflicting revisions, gaps, rollback, key rotation, permanent retirement, canonical wire validation, and restart checkpoints. The replica tests exercise concurrent stale writers, restart/history recovery, expired-history catch-up, file permissions, symlinks, schema-version rejection, and an injected SQLite failure after history insertion but before checkpoint update.

Eleven MLS tests pass on Linux and macOS. They cover offline join/delivery and a 1 MiB binary reply, restart retries, validly signed key substitution, foreign clusters, Welcome roster mismatch, single-use join keys, malformed/tampered/cross-group messages, out-of-order delivery, MLS replay defense, concurrent writers, epoch changes, and node removal. SQLite triggers inject failures after cryptographic changes but before queue/receipt insertion, including Welcome and epoch commits, to verify rollback and retry. Expiry, authority rollback, wrong local identity, size limits, permissions, symlinks, and future schema versions are also checked. Tests reopen endpoint databases between operations; no running remote service is involved.

Two packet-format tests and ten ordered-stream tests cover signature binding, canonical framing, reordered epochs, simultaneous opposite-direction traffic, concurrent refreshes/retries, writer and Welcome-creator substitution, MLS sender substitution, fork rejection, pending quotas with predecessor reserve, authority changes while buffered, revocation catch-up, partial-prefix durability, and version-1 database migration. Injected ordering-table failures verify that MLS state and stream checkpoints cannot commit separately.

Two configuration-grant tests and eleven configuration-stream tests cover owner/key/group binding, purpose isolation, expired-history recovery, forged policy from an approved writer, large-record reassembly across restart and epoch refresh, conflicting owner history, revocation, separate queue limits, partial-record reservations, and version-2 migration. A valid MLS removal cannot change configuration-stream membership. Injected failures verify that grants, publication cursors, authority history, and cryptographic state roll back together.

Nine runtime tests cover the newest accepted policy across existing handles and restarts, failed policy/message transactions, retryable TOML projection, encrypted updates affecting live inbox access, key-file protections, interrupted bootstrap, expiry/renewal failure, and preservation of legacy registrations and messages. The existing delivery and MCP smoke tests now exercise the signed runtime path.

Eight dispatcher tests pass on Linux and macOS. They cover automatic newest-revision replacement, outages, peer restart, complete relay storage loss, corrupted packets and false positions, fragmented large configurations without an agent turn, safe endpoint/credential setup, and applying already-buffered traffic while the relay is offline. They also verify updates arrive without idle mailbox polling, reconnect recovers lost hints, malformed/oversized notifications cannot change authority, polling fallback works, and dispatcher shutdown closes its socket. Fixtures verify joined nodes receive no owner signing secret. An additional opt-in test passes through the real local Wrangler/D1 Worker on Linux, including offline catch-up. It is ignored by the default suite and uses the same trusted enrollment fixture.

Ten pairing tests cover identity/credential separation, legacy agent migration, lost replies at eight protocol boundaries, stale requests and grants, concurrent owner edits, replacement owner keys, tampered grants, private/missing key files, refusal to overwrite unrelated state, owner-only access, exact cluster/checkpoint checks, and rejecting enrollment without a configuration transport. Two CLI tests check SSH argument handling and bounded frames. These tests pass on Linux and macOS.

The opt-in `scripts/prove_pairing.py` also passes with a Mac Studio owner and Linux joining node. It invokes the real SSH CLI, checks idempotent join and node-only keys, observes signed node metadata changes through local Wrangler/D1, and runs two independent MCP clients. The clients exchange actual PNG bytes and MCP image blocks in both directions, reject unsolicited reverse sends, receive authenticated delivery receipts, and retrieve a queued reply after restarting the receiver. Temporary nodes and processes are removed afterward. Hosted account authorization, real model iteration across machines, and invite-based pairing remain untested.

Run from the public repository root:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets -- -D warnings
cargo check -p gent-crypto --features mls --target wasm32-unknown-unknown --locked
```

The native workspace has 102 passing default tests on Linux and macOS, plus the opt-in integration proofs described above. The authority crate, configuration grants, packet format, and signer interface compile for Wasm; native SQLite MLS storage and MLS runtime behavior on Wasm are not covered by that check. Independent protocol review, production transport and authentication tests, invitation pairing, and lost-state recovery tests remain required before production use.
