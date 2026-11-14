# Backup and recovery

Gent can create encrypted backups of a stopped node, verify every payload, and extract the archive into a guarded offline directory. Activating a restored node, migrating its agents or pending work, and replacing a lost cluster owner remain unfinished.

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

## Planned return to service

For a lost joined node, use a fresh node identity and authenticated enrollment with the current owner. Retire the old node's authority and establish fresh streams. Any import of saved history or pending work needs explicit provenance and duplicate handling; archived requests must not silently become new sends. Agent bindings and peer permissions need deliberate migration rules.

Owner replacement additionally needs current authenticated cluster checkpoints, retirement of the previous writer, and a policy for unavailable or conflicting peers. An old owner's key and backup cannot establish the newest history by themselves. If no trustworthy current authority remains, creating a new cluster and separately importing historical data is the fallback to design. Multi-user recovery authority remains future work.

## Validation

Recovery tests cover marker forms, nested and aliased paths, missing directories, configuration mutation, database entry points, and refusal before local socket access. Archive tests additionally cover encryption and origin authentication, strict parsing, corruption, truncation, unsafe paths, file changes, busy locks/databases, private extraction, exclusions, cleanup and publication races. The native backup proof captures real MCP text/image/native-file state, recovers crash-left WAL and hot journals, verifies exact bytes, checks guarded extraction, and restarts only the original node:

```sh
cargo test -p gent-daemon --test recovery
cargo test -p gent-link recovery_guard
cargo test -p gent-link backup::
python3 scripts/prove_recovery_guard.py --gent target/debug/gent
python3 scripts/prove_backup.py --gent target/debug/gent
```

These checks cover offline archives and the activation boundary. Restored-node enrollment and owner replacement remain unimplemented.
