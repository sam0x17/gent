# Backup and recovery

Gent does not yet provide a supported backup archive or a procedure for activating a restored node. The implemented recovery boundary keeps marked offline copies from being used by the CLI, daemon, or encrypted storage APIs. Archive creation, verification, extraction and recovery enrollment are the next work.

## Why a database copy cannot resume a node

The live database contains MLS sending state, receive checkpoints, retained retries, pending messages, and signed configuration history. Restoring an older copy can reuse a sending key or generation, forget already accepted traffic, or attempt to replay history that a peer has retired. A second active copy also shares the original node's identity. An owner copy can sign a competing configuration history.

Successful decryption and valid signatures establish the archive's integrity and historical authority. They do not establish that it is the newest copy or that the original node has stopped. GitHub login authenticates an account; it supplies neither missing encryption keys nor authority to replace a cluster owner. Ordinary daemon restart uses the current committed state and remains supported.

## Implemented offline boundary

The reserved `recovery-required.json` entry marks a directory as offline recovery material. Its contents are informational. Any entry at that path, including an empty file, malformed JSON, directory or dangling symlink, blocks operational access. Errors checking the marker also block access.

Checks cover the supplied path and its resolved ancestors, including nested cluster profiles, missing child directories and filesystem aliases. The CLI checks the original home before reading its profile registry, then checks the selected home. An archived registry therefore cannot redirect a command to an external live node. Configuration reads and mutations, daemon startup, local RPC/file requests, runtime storage, standalone MLS storage and authority replicas check the same boundary. Shell setup, help and completion generation do not use node state.

The guard is an activation check, not a way to stop an already running daemon. Extraction must use a new directory and create the marker before writing any saved state. There is no command to clear the marker or activate that directory. Removing it manually is not a recovery procedure. The trusted OS user can remove markers, copy individual files, or run an older binary that lacks these checks; the guard cannot protect against those actions.

## Planned archive contract

The first archive stage will cover one selected node profile. It must list exclusions explicitly, including other profiles, external account stores, external MCP bindings, host-provider conversation histories and credentials referenced outside the selected directory. A node archive must not claim to back up an entire cluster or its provider-hosted chats.

Creation will require the daemon to be stopped, hold the relevant service/configuration/credential locks, and obtain consistent SQLite state through SQLite's own recovery and locking rules. Raw copies of live database files and manual deletion of journals are unsuitable. Concurrent changes or unsupported files must abort creation. Archives must reject links, sockets and special files, bound entry counts and sizes, and avoid plaintext staging files.

Use a standard streaming encrypted format with a separately stored recovery secret. Authenticate the manifest and payloads as originating from a holder of that secret. Recipient encryption alone does not authenticate who created an archive. Verification must check the entire authenticated stream, manifest, payload hashes and exact end of input before reporting success. It must reject truncation, extra data, duplicate or unsafe paths, unsupported formats and oversized metadata.

Extraction must verify into a new private staging directory, with the guard present before the first payload file. It must preserve the existing destination on every failure and publish without overwriting another directory. Directories use mode `0700`; files use `0600`. Failed extraction removes only its own staging files. Extraction performs no account, relay, provider or enrollment requests.

The archive format and commands remain unimplemented. Candidate commands are `gent backup keygen`, `create`, `verify`, `inspect` and `extract`; none imply activation.

## Planned return to service

For a lost joined node, use a fresh node identity and authenticated enrollment with the current owner. Retire the old node's authority and establish fresh streams. Any import of saved history or pending work needs explicit provenance and duplicate handling; archived requests must not silently become new sends. Agent bindings and peer permissions need deliberate migration rules.

Owner replacement additionally needs current authenticated cluster checkpoints, retirement of the previous writer, and a policy for unavailable or conflicting peers. An old owner's key and backup cannot establish the newest history by themselves. If no trustworthy current authority remains, creating a new cluster and separately importing historical data is the fallback to design. Multi-user recovery authority remains future work.

## Validation

Recovery tests cover marker forms, nested and aliased paths, missing directories, configuration mutation, database entry points, and refusal before local socket access. The native process proof creates real MCP text/image state, takes a disposable offline copy, and checks that CLI, daemon, MCP, diagnostics and profile commands refuse it without modifying keys, databases, external bindings or the referenced peer:

```sh
cargo test -p gent-daemon --test recovery
cargo test -p gent-link recovery_guard
python3 scripts/prove_recovery_guard.py --gent target/debug/gent
```

These checks establish the activation boundary. They do not test archive encryption, verification or restored-node enrollment.
