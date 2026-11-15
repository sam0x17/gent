# Host dispatch journal

Gent records a local host adapter's attempt to submit incoming-message input before that submission can begin. A lost daemon response or restart cannot grant a second submission for the same message. An optional Codex adapter now uses this journal to queue an inbox notification for a loaded conversation through its existing local app-server socket.

The tested Codex queue creates a new entry when the same client message ID is submitted again. Gent therefore cannot treat a repeated queue call as harmless. Claude's tested channel mechanism can deliver during an active turn. Its native plugin adapter also has an unresolved unload race, so automatic Claude delivery remains disabled in default builds. Generic MCP inbox access remains available on both hosts.

## Enable Codex queued delivery

Use Codex's default local app-server socket:

```sh
gent integration install codex --wake
```

Gent selects the Codex configuration directory from `--config-dir`, then `CODEX_HOME`, then `~/.codex`. It pins `<directory>/app-server-control/app-server-control.sock` in the MCP entry, so later environment changes cannot retarget that entry. Installation and `gent integration status codex` report the recorded `wake_socket` without probing the host. `gent integration config codex --wake [--config-dir PATH]` prints the equivalent fragment without editing settings.

For a custom server, provide its absolute advertised socket path:

```sh
gent integration install codex --wake-socket /absolute/path/to/codex.sock
```

Use either `--wake` or `--wake-socket`, then restart the host's Gent MCP connection to load the setting. `gent integration config codex --wake-socket PATH` prints a custom fragment. Direct setups can use `gent --home PATH mcp serve --host codex --wake-socket PATH`.

Gent does not start the Codex server. It resolves Codex's socket alias, requires a private socket and directory owned by the current OS user, and verifies the connected peer's user ID. The socket must serve the conversation that is using Gent. A standalone embedded host without that socket continues to use its inbox normally.

For a manual default-server setup, run `codex app-server --listen unix://` in one terminal, then `codex --remote unix://` in another. Use the same Codex configuration directory for the server and CLI. The server must remain running and the conversation must stay loaded for automatic delivery. These commands create a new host connection; Gent does not move an existing embedded conversation to that server.

After a conversation calls a Gent tool, its host-supplied thread ID selects the registration credential and saves an attachment for the configured socket. One watcher per node, cluster and socket checks loaded conversations against those attachments, visiting up to 128 thread IDs per sweep and waiting five seconds between sweeps. Before claiming a pending message, it reads that exact thread's metadata and requires a loaded idle or active thread that accepts direct input. It then uses `thread/queue/add`; it never calls turn start, steering, resume, queue start or interruption. Busy queues and explicit interruption holds remain controlled by Codex.

The queue receives a fixed instruction to check Gent's inbox, with no message content, file bytes or peer identity. The inbox rechecks current permissions when the model retrieves messages. Host model settings and approval rules remain unchanged. Gent does not answer approval or other server-initiated requests. Owners must configure ordinary host tool access separately.

The adapter lives with the MCP process. A replacement or another opted-in MCP process can recover saved attachments without a new registration, model turn or Gent tool call. An OS lock elects the watcher and releases ownership when its process exits. Recovery reads existing credentials and their scope records without taking ownership away from live MCP connections or creating missing keys. All adapters stop when their MCP processes exit; Gent does not launch a replacement or load stopped conversations.

Unloaded threads, missing sockets, unsupported host APIs and unavailable registrations leave messages pending. A lost response after a claim leaves an uncertain journal record and never triggers a repeated submission. Other attached conversations remain eligible when one fails.

To disable queued delivery, run `gent integration install codex` without either wake option, then reconnect the host's Gent MCP connections so the old watchers exit. This removes the managed socket option while preserving the ordinary MCP integration. Each conversation's next Gent call through a connection without that option also disables its saved attachment. Other still-running opted-in connections can continue watching saved attachments until they exit or those attachments are disabled. No Codex service or model setting is changed.

Daemon identity still reports `delivery: polling` for its durable inbox. That field does not describe this optional adapter's live connection status; inspect `gent wake` for dispatch evidence. Live connection diagnostics, discovery of custom endpoints, automatic server startup, cold resume and GUI acceptance remain unfinished.

## Claude native adapter investigation

The `experimental-claude-wake` Cargo feature enables a development adapter for isolated native-host tests. It currently fails the plugin-unload acceptance check and is not ready for ordinary use. Default builds reject both installation with `gent integration install claude-code --wake` and the hidden runtime bridge, leaving existing MCP setup available.

The candidate installer manages a native plugin under the host configuration directory's `skills/gent-wake`. It records the installed module bytes, an installation ID, node and cluster, and checks ownership before upgrading or removing files. Interrupted updates accept the recorded before/after versions; edited files are preserved. A pending update, disabled identity hook, old installation ID or changed binding prevents the Rust bridge from granting a usable response.

The module polls every five seconds, using a bounded JSON subprocess interface with argument vectors. Rust reads the exact session's existing Gent credential and pinned scope without creating missing keys or taking live MCP credential locks. It claims before returning a fixed inbox notification. Credentials, message content and files never enter that subprocess response or notification. One notification remains outstanding per module.

Native `prompt.submit` controls completed-turn queuing and interruption holds. A separate `classic.UserPromptSubmit` hook rechecks the target session and current claim eligibility at delivery. This hook does not infer turn completion from classic Stop events. The adapter correlates a guarded notification with a native `turn.start` UUID for its receipt; its generated attempt ID is not a host acceptance ID. Dropped or lost submissions remain uncertain and are never retried automatically.

Linux and Mac native tests demonstrate idle delivery, busy boundaries, interruption/rearm, isolation when a claim response is delayed across `/clear`, restored binding after `/resume`, and no repeated submission after a lost claim response and daemon restart. They also expose the release blocker: Claude's file watcher can unload the validation hook after uninstall while retaining the plugin's queued input. That input can subsequently start a model turn without the guard. A shorter test initially passed because delivery reached the old guard before unload; the expanded test holds delivery until the watcher has actually unloaded the module. Session replacement, host restart, unload and real-model acceptance require further work before enabling this feature by default.

## Owner inspection

Run these commands on the recipient's node, selecting its cluster profile if needed:

```sh
gent wake
gent wake list --after MESSAGE_UUID
gent wake show MESSAGE_UUID
```

Lists return 50 records per page in message-ID order, with `has_more` and `next_after`. These commands inspect evidence; they do not start a host, retry a submission or reconcile an uncertain attempt.

| Evidence | Meaning |
| --- | --- |
| `state: uncertain` | Gent committed a claim. The host might never have received input, or might have accepted it before its response was lost. |
| `state: submitted` | The adapter reported a host submission ID for the exact claim. Gent has not independently verified execution. |
| `inbox_seen_at` | An ordinary inbox call returned the message after the claim. This does not identify the turn or explain why it fetched the inbox. |
| Message acknowledgment | The recipient separately acknowledged receipt through the messaging protocol. |
| Work journal | The recipient or owner separately reported task progress and outcomes. See [interrupted work](work.md). |

Inbox observation does not resolve an uncertain dispatch. A submission report neither acknowledges the message nor records work completion. A claim grants no authority to perform the requested task.

## Adapter contract

Four local agent RPCs support adapters. They use the registration credential and are absent from the model-callable MCP tools:

1. `wake_pending` returns up to 50 currently accessible, unacknowledged, unexpired message IDs and expiry times with no existing claim. It includes no message text or files.
2. `wake_claim` accepts a message ID, unique attempt ID and target. Only the first committed claim returns `may_submit: true`. An exact retry returns the saved record with `may_submit: false`, including after restart. Changing the attempt or target for a claimed message fails.
3. `wake_check` checks an existing claim against its agent, attempt and host conversation. Its `eligible` result also requires an uncertain claim and a currently accessible, unacknowledged, unexpired message visible in the relay queue. It creates no record, changes no evidence, and grants no submission permission. Only an adapter still holding the original successful claim response may use it before submitting; it cannot authorize recovery of an uncertain submission.
4. `wake_submitted` records the host submission ID against the exact attempt. Repeating that report preserves the result; conflicting IDs fail. It can record an already attempted submission after peer permissions change, but still requires the authorized, unrevoked local registration and node.

New claims recheck message permissions and relay queue visibility. All journal transitions use the existing immediate SQLite transaction. Adapter RPCs do not update agent `last_seen`, so background polling does not make the model appear active.

Targets identify either a Codex thread UUID or a Claude Code session UUID. Host type is part of the target: identical UUID text under different hosts does not identify the same dispatch. The journal itself trusts the adapter's target report. The Codex adapter obtains its UUID from the same host metadata used to select the agent credential, then checks the connected server's thread identity and capability before claiming. The Claude bridge reads the existing session binding and its pinned scope. Adapters must preserve this binding and the host's busy queues and interruption holds. A process crash between claim and submission can leave an unused claim permanently uncertain. Never blindly retry an external submission after a lost response.

## Storage and recovery

Each opted-in Codex binding keeps a private, versioned `.key.wake.json` sidecar beside its existing credential. It contains the node, cluster, canonical thread ID, a credential hash and the advertised socket path. It contains no credential or message content. Recovery requires the existing key, matching scope and current daemon authorization. Corrupt, oversized, linked, unsupported-version or substituted records are refused without repair. Offline backup guards apply before host connection and credential recovery.

Attachments are scoped to the advertised socket name, preserving Codex's rendezvous alias across server restarts. Parent aliases such as macOS `/tmp` and `/private/tmp` normalize to the same endpoint. The next Gent call through an explicitly configured different socket updates that conversation's attachment. Ordinary bindings created without queued delivery are never adopted automatically.

Dispatch records live in the selected node database's `wake_dispatches` table, with an independent schema marker. Missing versioned storage, an unversioned existing table or an unsupported version fails startup. Reading a malformed or inconsistent record fails without granting a new submission.

Each database admits 16,384 records of at most 2,048 payload bytes each. New claims are limited to 12 per agent per hour and 120 per database per hour, with at least five seconds between an agent's claims. These limits use the persisted request clock. Admission failure leaves the message pending; exact claim retries grant no additional submission. The limits do not bound a host's inference cost or external actions.

Records survive message cleanup and revocation. They contain local agent, message, attempt and host-thread identifiers plus timestamps and submission evidence. They do not copy message content and are not replicated or sent to the centralized service by these operations. The existing trusted-OS-user boundary applies.

There is no pruning, reset, retry approval or automatic reconciliation. Preserve evidence at capacity. Deleting records, changing message IDs or rolling back a backup can forget earlier attempts and must not be used to repeat uncertain work. Offline backup guards remain required; see [recovery](recovery.md). Lost-node migration and verified host reconciliation remain unfinished.

## Verification

```sh
cargo test -p gent-daemon --test wake --locked
cargo build -p gent-link --locked
python3 scripts/prove_wake_journal.py --gent target/debug/gent
```

Ten journal tests cover restart, exact retries, conflicting attempts, concurrent claims, failed writes, permissions, expiry, revocation, storage and rate limits, and independent message/work state. They also cover read-only claim checks, Claude session IDs and cross-host target substitution. The journal process proof drops a committed claim response, restarts the daemon and verifies that the retry grants no new submission. It also checks MCP tool exclusion, inbox observation and synthetic submission reporting without invoking a host queue or model.

`cargo test -p gent-link wake --locked` additionally covers thread identity and capability gates, exact queue response binding, private socket requirements, refusal to answer host approval requests, installation upgrades/removal, saved attachment validation, watcher election, endpoint isolation, opt-out and bounded loaded-thread pages. Native installed-Codex proofs separately exercise actual metadata, queues, MCP calls, interrupted holds, lost queue responses and delivery after actual MCP process replacement. Real-model acceptance uses fresh synthetic conversations and normal host model access; its restart check covers the Gent daemon. Those proofs do not establish GUI support or exactly-once host execution across a Codex crash; Gent's journal controls its own submissions.
