# Backup and recovery

Gent can create encrypted backups of a stopped node, verify every payload, extract the archive into a guarded offline directory, and export retained Gent history with recovered files. The owner can assign one archived agent's history to a current local agent. A lost joined node can be replaced through authenticated SSH or a scoped private invitation using a fresh identity and fresh encrypted streams. Migrating agent identities, bindings or pending work, and replacing a lost cluster owner remain unfinished.

## Commands

Keep the recovery key outside node state and separately from the archives. Its private file contains one age X25519 secret string, optionally surrounded by whitespace; Gent never prints the secret. Losing it makes these archives unreadable. Anyone holding it can decrypt archives and create authenticated archives with the same key.

```sh
mkdir -m 700 ~/gent-backups
gent backup keygen --output ~/gent-recovery.key
gent daemon stop
gent backup create ~/gent-backups/node.age --identity ~/gent-recovery.key
gent daemon start
gent backup verify ~/gent-backups/node.age --identity ~/gent-recovery.key
gent backup inspect ~/gent-backups/node.age --identity ~/gent-recovery.key --files
gent backup extract ~/gent-backups/node.age --identity ~/gent-recovery.key --output ~/gent-recovered
gent backup history ~/gent-backups/node.age --identity ~/gent-recovery.key --output ~/gent-history
```

Close MCP connections using bindings inside the selected node directory before creating an archive. Busy locks or database readers make creation fail without publishing an archive. Gent does not stop or restart services itself. `create` honors the selected cluster and `--cluster`; all other backup commands work without initialized node state and reject `--cluster`. All commands support `--json`.

Archive, key and extraction destinations must be new paths with existing parent directories owned by the current user and not writable by others. Creation refuses keys or archives inside the selected node directory. It never overwrites an existing archive or key. Extraction never overwrites an existing path, including an empty directory, and performs no service, provider or enrollment requests.

## Why a database copy cannot resume a node

The live database contains MLS sending state, receive checkpoints, retained retries, pending messages, and signed configuration history. Restoring an older copy can reuse a sending key or generation, forget already accepted traffic, or attempt to replay history that a peer has retired. A second active copy also shares the original node's identity. An owner copy can sign a competing configuration history.

Successful decryption and valid signatures establish the archive's integrity and historical authority. They do not establish that it is the newest copy or that the original node has stopped. GitHub login authenticates an account; it supplies neither missing encryption keys nor authority to replace a cluster owner. Ordinary daemon restart uses the current committed state and remains supported.

## Implemented offline boundary

The reserved `recovery-required.json` entry marks a directory as offline recovery material. Its contents are informational. Any entry at that path, including an empty file, malformed JSON, directory or dangling symlink, blocks operational access. Errors checking the marker also block access.

Checks cover the supplied path and its resolved ancestors, including nested cluster profiles, missing child directories and filesystem aliases. The CLI checks the original home before reading its profile registry, then checks the selected home. An archived registry therefore cannot redirect a command to an external live node. Configuration reads and mutations, daemon startup, local RPC/file requests, runtime storage, standalone MLS storage and authority replicas check the same boundary. Shell setup, help and completion generation do not use node state.

The guard is an activation check, not a way to stop an already running daemon. Extraction must use a new directory and create the marker before writing any saved state. There is no command to clear the marker or activate that directory. Removing it manually is not a recovery procedure. The trusted OS user can remove markers, copy individual files, or run an older binary that lacks these checks; the guard cannot protect against those actions.

## Archive scope and capture

An archive covers one selected node profile: configuration, signing/RPC keys, databases, local account/gateway records, included conversation bindings, file objects and handoff copies. The manifest lists omitted lock/socket/profile paths and configured external profile, account-store and relay-credential references. External references are not followed. Provider conversation histories and caller-selected external MCP bindings remain outside this scope; Gent cannot inventory all host-owned files. This is not a cluster-wide or provider-chat backup.

Creation holds service, daemon, configuration, invitation and discovered mutation locks. It refuses busy conversation credentials. SQLite recovers hot journals and checkpoints legacy WAL itself, then exclusive transactions and integrity checks protect the database files during capture. Gent never deletes database journals manually or opens the runtime Store to create a backup. Journal recovery can change the source database before capture. Other file contents are not changed; missing persistent lock files may be created.

Sorted inventories record inode, device, size, permissions, ownership and modification/change times. Files are hashed before encryption and checked again during streaming; a final inventory check detects changes and new paths. Symlinks, hard links, special files other than the omitted daemon socket, and state writable by other users are refused. Capturing files concurrently changed by an uncooperative process is unsupported; the trusted OS user can bypass local locks and checks.

Limits are 65,536 inventory entries, 4 GiB per file, 64 GiB of payload, a 16 MiB manifest, 1,024-byte relative paths and 64 path components. Creation also bounds configuration parsing at 16 MiB and held mutation locks at 1,024. These are archive limits, not new live-node storage quotas. Oversized input fails without publishing a partial archive.

## Encryption and format

Archives are standard binary age files encrypted to one X25519 recipient. The implementation uses the age 0.11 line, whose X25519 stream format is unchanged in 0.12; 0.12's additional ML-KEM dependency currently conflicts with the MLS stack's stable KEM API. No external age executable is needed. Creation writes only ciphertext to its temporary archive file and publishes without overwriting. Plaintext payloads use bounded streaming buffers.

The decrypted version-1 container consists of `GENTBK01`, a four-byte big-endian manifest length, canonical JCS JSON, a 32-byte HMAC-SHA256 tag, then each file's raw bytes in manifest order. Directories have no payload. The manifest binds archive/node/cluster IDs, capture time, source path, exclusions, and sorted relative paths with types, lengths and SHA-256 file hashes.

The MAC key is `SHA256("gent-backup-manifest-key-v1\0" || identity)`, where `identity` is the canonical uppercase age secret string without a newline. The MAC covers `"gent-backup-manifest-v1\0" || manifest_bytes`. This authenticates creation by a holder of the private recovery key; public recipient encryption alone would allow forged archives. Manifest authentication precedes parsing and extraction of its paths.

Verification checks the complete authenticated age stream, canonical manifest, every payload hash and exact end of input. It rejects wrong keys, corrupted or truncated data, extra plaintext/ciphertext, duplicate or unsafe paths, unsupported versions and oversized metadata. The unauthenticated age header is capped at 16 KiB. `inspect` performs the same full verification before returning metadata. A successful result proves archive integrity, not current cluster authority or the operational health of an arbitrary saved configuration.

Extraction writes into a new private staging directory with the recovery guard present before the first payload file. After complete verification and file/directory synchronization, an atomic rename publishes it without replacing another path. A filesystem lacking the required no-replace operation causes failure. Directories use mode `0700`; files use `0600`, regardless of original executable or other mode bits. Failed extraction removes only its own staging files. Interrupted processes may leave a guarded staging directory for manual inspection/removal.

The extracted copy retains historical keys and credentials. It must remain offline. Message/file expiry and deletion on live nodes do not remove historical archive copies; archive retention and recovery-key custody remain the user's responsibility.

## Export offline history

`gent backup history ARCHIVE --identity KEY --output NEW_DIRECTORY` creates a private plaintext export of the Gent records retained in that archive. It verifies the complete authenticated archive, including payloads it does not extract. Only `state.sqlite3` is materialized in a guarded temporary directory. The reader opens it with SQLite's read-only, immutable mode, disables SQLite's trusted-schema setting, and performs no runtime initialization, migration, expiry cleanup, network call or queue processing. It removes that temporary database before publishing the export.

The output contains:

- `history.json`: format version, archive/cluster/node IDs, capture time, source database digest, JSONL hashes/counts and file outcomes.
- `agents.jsonl`: historical agent IDs, node IDs, names, providers, activity times and revocation flags. No credentials or credential hashes.
- `messages.jsonl`: original message IDs, participants, exchange/reply/relay references, text, timestamps, inline file contents and attachment descriptors. The saved acknowledgment column supplies the historical acknowledgment flag. Each record also lists recovered file paths and outcomes.
- `files/`: inline files and complete native attachments, named with generated identity-based paths. Original filenames and media types remain in the JSON records. Native files pass chunk authentication and whole-file SHA-256 verification before publication.
- `recovery-required.json`: the offline activation guard. The export is historical data and has no command that activates it as node state.

The export includes expired or revoked historical records still present in the archive. It does not renew their authorization, resubmit messages, issue reply rights, or recreate bindings. A missing native object is marked `missing`; an object saved as unfinished is marked `incomplete`, with no partial plaintext exported. An object marked complete but missing chunks, corrupt ciphertext, mismatched descriptors or wrong message binding makes the entire export fail. The reader does not retrieve absent files from peers or the service. Files that were imported but never attached to a retained message are outside this history export.

Signing keys, local RPC credentials, account/gateway secrets, file decryption grants, MLS state, policy and live queue records are excluded. Provider-owned conversation transcripts remain outside the node archive and this export. Source IDs and hashes establish which authenticated archive the exporter read; the resulting plaintext files are not independently signed and do not prove current cluster authority or independently authenticate each historical sender.

The destination must be new, with the same parent ownership/permission requirements as extraction. Directories use `0700` and files `0600`; publication refuses an existing destination, including races. Limits are 65,536 agents, 65,536 messages, 6 MiB per stored message and 1 GiB of exported JSONL/file content. Known message/file types and table layouts are checked; unsupported schemas or inconsistent records fail without publishing partial output. Interrupted processes may leave guarded temporary directories.

## Assign history to a current agent

Start or enroll a fresh node normally and register its replacement agent through MCP. Use `agents.jsonl` from an offline export to identify the original agent and `gent agents` on the current node to identify the recipient. With the current daemon running, assign the selected history:

```sh
gent history import ~/gent-backups/node.age --identity ~/gent-recovery.key \
  --from-agent OLD_AGENT_UUID --agent CURRENT_AGENT_UUID
gent history imports
gent history status
```

The command authenticates the entire archive and creates a private temporary history export. An owner-authenticated local request pins its manifest digest and selects exactly one archived agent and one current, nonrevoked local agent. The daemon validates JSONL counts and hashes, historical references, selected file lengths and hashes, ownership and private permissions before committing. Failure rolls back records, access and quota together. The temporary export is removed when the command exits normally; a killed process may leave guarded plaintext staging files.

Only messages sent or received by the selected historical agent are assigned, along with their historical participant labels and file outcomes. Other archived conversations remain inaccessible. The recipient reads these records through `gent_history_imports` and `gent_history_messages`; pages contain at most 20 messages and 1 MiB of serialized records. Follow `next_after` while `has_more` is true. `gent_history_file_read` returns ready files in 256 KiB chunks; `gent_history_file_view` returns verified PNG, JPEG, WebP or GIF bytes up to 4 MiB as an MCP image. Missing and incomplete files remain labelled and cannot be read.

The assignment is a separate read grant. It includes retained expired messages and historical labels that the recipient may lack permission to enumerate as live agents. Original message IDs, acknowledgments, timestamps and archive provenance remain attached to the records. They establish historical context only: the old agent, exchange, relay and file IDs confer no live routing or reply rights. Records never enter the current inbox or transport queues. No keys, old credentials, permissions, conversation bindings or pending work are restored. Repeating an old action requires checking current host state; the archive cannot prove that the action never ran.

Imported content stays in separate tables in the current node's private SQLite database. It is plaintext at that trusted endpoint, like current Gent messages, and is not replicated to other nodes or uploaded to the relay. The selected agent can read it through either local MCP or its configured remote gateway; the existing provider/gateway trust boundary applies. Revoking that agent immediately prevents further reads. Another agent needs its own owner-issued import assignment.

### Remove or restore an assignment

`gent history imports` lists current and retired assignments for the owner, including their revisions. An exact repeat of the same archive/source/recipient import is a no-op. To remove revision 1:

```sh
gent history remove IMPORT_UUID --expect-revision 1
```

Removal deletes the imported message/file rows and advances the receipt to revision 2. It stops further reads and frees the content quota; it does not erase copies already read or guarantee forensic removal from storage. A small receipt remains so an old import retry cannot restore access. Explicit restoration uses the same archive/source/recipient and the current retired revision:

```sh
gent history import ~/gent-backups/node.age --identity ~/gent-recovery.key \
  --from-agent OLD_AGENT_UUID --agent CURRENT_AGENT_UUID --restore-revision 2
```

That restoration advances the revision to 3. Exact removal/restoration retries are safe; stale revisions are refused. Recreating an archive produces a different import identity, so overlapping archives can contain the same historical messages. Use source cluster/archive provenance and original message IDs when comparing them.

Each node permits 256 import receipts, including retired ones, 8,192 imported messages and 256 MiB of imported record/file content. `gent history status` reports usage. Receipt compaction is not implemented. Ordinary history expiry/cleanup leaves these explicit assignments in place until the owner removes them.

**Keep the original source archives and recovery keys.** A full backup includes the imported SQLite tables, but `gent backup history` currently exports only the original live message tables. It cannot re-export previously imported history from a later backup. Restoring a raw database to recover those rows is unsafe and remains blocked by the activation guard.

## Replace a lost joined node

On the current owner, use `gent nodes` to identify the lost node. From a fresh node directory on the replacement machine:

```sh
gent --home ~/.gent-replacement cluster join CLUSTER_UUID \
  --via user@owner-host --name laptop --replace-node OLD_NODE_UUID
gent --home ~/.gent-replacement daemon install
```

The owner daemon and its configured relay must be available. SSH uses strict host-key verification and the existing owner's local authority. The usual `--remote-gent`, `--remote-home`, and development-only `--relay-endpoint` options apply. Service-backed clusters require login to the same account/service before joining. The active signing owner cannot be replaced by this command. Ordinary invitation files do not authorize replacement; the scoped invitation flow below does.

One signed revision retires the old node ID and signing key and enrolls the fresh identity. A durable removal record commits in the same database transaction and binds the old ID/key to the replacement ID/key. A retry after a lost reply reuses that identity; another fresh directory cannot replace the same retired node. Configuration administration is preserved only if the old node had it. Old node-specific rules, agent IDs, message history, pending sends, reply grants and conversation bindings are not transferred. Existing blanket and same-node rules apply normally to newly registered agents. Configure any new explicit permissions deliberately.

If joining is interrupted, rerun the identical command with the same home, name and `--replace-node` value. Keep the sibling `.joining` directory: it contains the new private identity, trusted old-key pin and retry records. A committed retirement is not rolled back if later stream or service setup fails. Losing the pending identity after that commit needs separate recovery; starting another directory is refused. Completed installations retain `node-replacement.json` and its hash in local TOML; missing or changed records are refused. These files are local recovery evidence, not cluster permission rules.

Signed revocation applies as peers receive current configuration. Offline peers can retain stale authority until synchronization or lease expiry. Service credential removal follows the existing owner maintenance journal and may remain pending during service downtime. On the owner, `gent node removals` reports the old node, replacement identity and cleanup status; service confirmation does not prove that every peer has caught up. The development relay uses a shared credential and has no per-node service revocation.

The new node never opens the archived runtime, resumes an old MLS ratchet or clears the recovery guard. Keep extracted archives offline. Use the separate history assignment above to grant a new agent read access to selected archived exchanges. Pending work, agent bindings and peer permissions still need deliberate migration rules; archived requests must not silently become new sends. Replacing a node cannot remove historical data already held by it or its backups.

## Replace through a private invitation

On the current owner, create an invitation for the exact lost node. Transfer the file privately to the replacement machine, then join from a fresh directory signed into the same account and service:

```sh
# Current owner
gent cluster invite --replace-node OLD_NODE_UUID --out /private/replacement.gent-invite

# Replacement machine, after private transfer and login
gent --home ~/.gent-replacement cluster join \
  --invite-file /private/replacement.gent-invite --name laptop
```

The signed offer pins the old ID and signing key. Claiming it selects one fresh identity; enrollment retires the old member and records the replacement in the same transaction used by SSH. Issuing or claiming the offer alone does not remove the old node. The default preserves the old node's configuration rights; `--no-configure` can restrict the replacement further. Neither a normal invitation nor an altered enrollment request can retire a node. A changed target key, loss of configuration rights needed by the offer, competing replacement or retired replacement identity stops admission.

Interrupted joins reuse the same private file and directory. If the offer expires or is revoked after enrollment committed, the owner issues `gent cluster invite --continue-node NEW_NODE_UUID --out NEW_FILE`, adding `--no-configure` when the enrolled replacement is restricted. This continuation includes the original retirement target from the durable removal record. Transfer it and rerun joining with `--continue`, the same name and the same directory. Before enrollment, a new `--replace-node OLD_NODE_UUID` offer can continue the saved fresh identity instead. The joining journal refuses any offer that drops or changes the original replacement scope.

Gent enrollment uses the invitation's encrypted Noise mailbox; SSH is unnecessary for that path. File transfer still needs an independently trusted private channel. Replacement and continuation offers expire after 15 minutes. Account authentication and service-node credentials remain separate from native replacement authority. Upgrade both endpoints before using replacement invitations; older builds reject the new signed field. Ordinary offers keep their original signed encoding.

## Remaining recovery work

Owner replacement additionally needs current authenticated cluster checkpoints, retirement of the previous writer, and a policy for unavailable or conflicting peers. An old owner's key and backup cannot establish the newest history by themselves. If no trustworthy current authority remains, a new cluster can receive selected archived history through the assignment commands above, without recovering the old cluster's authority. Agent bindings, peer permissions, pending-work reconciliation and recovery of previously imported history remain unfinished. Multi-user recovery authority remains future work.

## Validation

Recovery tests cover marker forms, nested and aliased paths, missing directories, configuration mutation, database entry points, and refusal before local socket access. Archive tests additionally cover encryption and origin authentication, strict parsing, corruption, truncation, unsafe paths, file changes, busy locks/databases, private extraction, exclusions, cleanup and publication races. History-export tests cover expired content, acknowledgment state, omitted secrets, selective extraction, missing/incomplete files, corrupt content and unsupported layouts. The native backup proof captures real MCP text/image/native-file state, exports exact historical PNG/native-file bytes, recovers crash-left WAL and hot journals, checks guarded extraction, and restarts only the original node. Its optional `--peer` mode independently exports the same archive on the peer and compares every output file byte for byte:

```sh
cargo test -p gent-daemon --test recovery
cargo test -p gent-link recovery_guard
cargo test -p gent-link backup::
python3 scripts/prove_recovery_guard.py --gent target/debug/gent
python3 scripts/prove_backup.py --gent target/debug/gent
```

History-assignment tests cover recipient isolation, pagination, exact file bytes, restart persistence, removal/restoration revisions, revocation, transaction rollback, quotas and changed content. The native CLI/MCP proof creates an encrypted archive, imports selected history into an independent fresh cluster, reads the original PNG and 2 MiB file, and checks restart, removal/restoration and unchanged live identity/inbox state:

```sh
cargo test -p gent-daemon --test recovered
python3 scripts/prove_history_import.py --gent target/debug/gent
```

Replacement tests cover lost replies at every pairing step, owner/competing-target refusal, atomic rollback, durable key pins, interrupted publication, schema migration, invitation scope and retries after later revocation. The optional physical-machine proof adds a replacement to the existing SSH workflow:

```sh
python3 scripts/prove_pairing.py --owner user@owner-host \
  --remote-binary /absolute/path/to/gent --relay-token-file /private/relay.key \
  --node-replacement
```

This uses temporary nodes and a local development relay, checks fresh keys/streams and preserved administration limits, exchanges MCP images and a 2 MiB native file after both daemon restarts, and keeps the old archive guarded. It does not prove deployed service cleanup, archive import or owner replacement.

A separate service-backed physical proof passes replacement and scoped continuation in both Linux/Mac directions through local account/relay Workers. It verifies independent transport credentials, automatic old-node service revocation through outages and lost replies, retained privilege limits, PNG delivery, relay turns and exact 2 MiB file bytes across restarts. This uses synthetic GitHub login; it does not establish live consent or deployed service behavior.
