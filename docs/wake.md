# Host dispatch journal

Gent records a local host adapter's attempt to submit incoming-message input before that submission can begin. A lost daemon response or restart cannot grant a second submission for the same message. This is preparation for automatic delivery: no host runner or attachment mechanism is enabled, and agents still report `delivery: polling`.

The tested Codex queue creates a new entry when the same client message ID is submitted again. Gent therefore cannot treat a repeated queue call as harmless. Claude's tested channel mechanism can deliver during an active turn and is not enabled. Generic MCP inbox access remains available on both hosts.

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

Three local agent RPCs exist for future adapters. They use the registration credential and are absent from the model-callable MCP tools:

1. `wake_pending` returns up to 50 currently accessible, unacknowledged, unexpired message IDs and expiry times with no existing claim. It includes no message text or files.
2. `wake_claim` accepts a message ID, unique attempt ID and target. Only the first committed claim returns `may_submit: true`. An exact retry returns the saved record with `may_submit: false`, including after restart. Changing the attempt or target for a claimed message fails.
3. `wake_submitted` records the host submission ID against the exact attempt. Repeating that report preserves the result; conflicting IDs fail. It can record an already attempted submission after peer permissions change, but still requires the authorized, unrevoked local registration and node.

New claims recheck message permissions and relay queue visibility. All journal transitions use the existing immediate SQLite transaction. Adapter RPCs do not update agent `last_seen`, so background polling does not make the model appear active.

The current target format supports a Codex thread UUID. The adapter supplies it; the journal does not establish that the thread belongs to the authenticated Gent agent. A future adapter must verify conversation identity before claiming and preserve host settings, busy queues and interruption holds. A process crash between claim and submission can leave an unused claim permanently uncertain. Never blindly retry an external submission after a lost response.

## Storage and recovery

Records live in the selected node database's `wake_dispatches` table, with an independent schema marker. Missing versioned storage, an unversioned existing table or an unsupported version fails startup. Reading a malformed or inconsistent record fails without granting a new submission.

Each database admits 16,384 records of at most 2,048 payload bytes each. New claims are limited to 12 per agent per hour and 120 per database per hour, with at least five seconds between an agent's claims. These limits use the persisted request clock. Admission failure leaves the message pending; exact claim retries grant no additional submission. The limits do not bound a host's inference cost or external actions.

Records survive message cleanup and revocation. They contain local agent, message, attempt and host-thread identifiers plus timestamps and submission evidence. They do not copy message content and are not replicated or sent to the centralized service by these operations. The existing trusted-OS-user boundary applies.

There is no pruning, reset, retry approval or automatic reconciliation. Preserve evidence at capacity. Deleting records, changing message IDs or rolling back a backup can forget earlier attempts and must not be used to repeat uncertain work. Offline backup guards remain required; see [recovery](recovery.md). Lost-node migration and verified host reconciliation remain unfinished.

## Verification

```sh
cargo test -p gent-daemon --test wake --locked
cargo build -p gent-link --locked
python3 scripts/prove_wake_journal.py --gent target/debug/gent
```

Seven Rust tests cover restart, exact retries, conflicting attempts, concurrent claims, failed writes, permissions, expiry, revocation, storage and rate limits, and independent message/work state. The process proof drops a committed claim response, restarts the daemon and verifies that the retry grants no new submission. It also checks MCP tool exclusion, inbox observation, synthetic submission reporting and unchanged polling delivery. Both use synthetic host IDs and invoke no host queue or model; actual host attachment and automatic delivery require separate acceptance.
