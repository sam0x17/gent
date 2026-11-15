# Host dispatch journal

Gent records a local host adapter's attempt to submit incoming-message input before that submission can begin. A lost daemon response or restart cannot grant a second submission for the same message. An optional Codex adapter now uses this journal to queue an inbox notification for a loaded conversation through its existing local app-server socket.

The tested Codex queue creates a new entry when the same client message ID is submitted again. Gent therefore cannot treat a repeated queue call as harmless. Claude's tested channel mechanism can deliver during an active turn and is not enabled. Generic MCP inbox access remains available on both hosts.

## Enable Codex queued delivery

Provide the absolute path of an existing Codex app-server Unix socket:

```sh
gent integration install codex --wake-socket /absolute/path/to/codex.sock
```

Restart the host's Gent MCP connection to load the setting. Use `--config-dir` when managing a separate Codex configuration directory. `gent integration config codex --wake-socket PATH` prints the equivalent fragment. Direct setups can use `gent --home PATH mcp serve --host codex --wake-socket PATH`.

Gent does not start the Codex server. It resolves Codex's socket alias, requires a private socket and directory owned by the current OS user, and verifies the connected peer's user ID. The socket must serve the conversation that is using Gent. A standalone embedded host without that socket continues to use its inbox normally.

After a conversation calls a Gent tool, its host-supplied thread ID selects the registration credential and saves an attachment for the configured socket. One watcher per node, cluster and socket checks loaded conversations against those attachments, visiting up to 128 thread IDs per sweep and waiting five seconds between sweeps. Before claiming a pending message, it reads that exact thread's metadata and requires a loaded idle or active thread that accepts direct input. It then uses `thread/queue/add`; it never calls turn start, steering, resume, queue start or interruption. Busy queues and explicit interruption holds remain controlled by Codex.

The queue receives a fixed instruction to check Gent's inbox, with no message content, file bytes or peer identity. The inbox rechecks current permissions when the model retrieves messages. Host model settings and approval rules remain unchanged. Gent does not answer approval or other server-initiated requests. Owners must configure ordinary host tool access separately.

The adapter lives with the MCP process. A replacement or another opted-in MCP process can recover saved attachments without a new registration, model turn or Gent tool call. An OS lock elects the watcher and releases ownership when its process exits. Recovery reads existing credentials and their scope records without taking ownership away from live MCP connections or creating missing keys. All adapters stop when their MCP processes exit; Gent does not launch a replacement or load stopped conversations.

Unloaded threads, missing sockets, unsupported host APIs and unavailable registrations leave messages pending. A lost response after a claim leaves an uncertain journal record and never triggers a repeated submission. Other attached conversations remain eligible when one fails.

To disable queued delivery, run `gent integration install codex` without `--wake-socket`, then reconnect the host's Gent MCP connections so the old watchers exit. This removes the managed socket option while preserving the ordinary MCP integration. Each conversation's next Gent call through a connection without that option also disables its saved attachment. Other still-running opted-in connections can continue watching saved attachments until they exit or those attachments are disabled. No Codex service or model setting is changed.

Daemon identity still reports `delivery: polling` for its durable inbox. That field does not describe this optional adapter's live connection status; inspect `gent wake` for dispatch evidence. Richer connection diagnostics, automatic socket discovery, cold resume and GUI acceptance remain unfinished.

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

Three local agent RPCs support adapters. They use the registration credential and are absent from the model-callable MCP tools:

1. `wake_pending` returns up to 50 currently accessible, unacknowledged, unexpired message IDs and expiry times with no existing claim. It includes no message text or files.
2. `wake_claim` accepts a message ID, unique attempt ID and target. Only the first committed claim returns `may_submit: true`. An exact retry returns the saved record with `may_submit: false`, including after restart. Changing the attempt or target for a claimed message fails.
3. `wake_submitted` records the host submission ID against the exact attempt. Repeating that report preserves the result; conflicting IDs fail. It can record an already attempted submission after peer permissions change, but still requires the authorized, unrevoked local registration and node.

New claims recheck message permissions and relay queue visibility. All journal transitions use the existing immediate SQLite transaction. Adapter RPCs do not update agent `last_seen`, so background polling does not make the model appear active.

The current target format supports a Codex thread UUID. The journal itself trusts the adapter's target report. The bundled adapter obtains that UUID from the same host metadata used to select the agent credential, then checks the connected server's thread identity and capability before claiming. Future adapters must preserve this binding and the host's busy queues and interruption holds. A process crash between claim and submission can leave an unused claim permanently uncertain. Never blindly retry an external submission after a lost response.

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

Seven journal tests cover restart, exact retries, conflicting attempts, concurrent claims, failed writes, permissions, expiry, revocation, storage and rate limits, and independent message/work state. The journal process proof drops a committed claim response, restarts the daemon and verifies that the retry grants no new submission. It also checks MCP tool exclusion, inbox observation and synthetic submission reporting without invoking a host queue or model.

`cargo test -p gent-link wake --locked` additionally covers thread identity and capability gates, exact queue response binding, private socket requirements, refusal to answer host approval requests, installation upgrades/removal, saved attachment validation, watcher election, endpoint isolation, opt-out and bounded loaded-thread pages. Native installed-Codex proofs separately exercise actual metadata, queues, MCP calls, interrupted holds, lost queue responses and delivery after actual MCP process replacement. Real-model acceptance uses fresh synthetic conversations and normal host model access; its restart check covers the Gent daemon. Those proofs do not establish GUI support or exactly-once host execution across a Codex crash; Gent's journal controls its own submissions.
