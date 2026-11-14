# Interrupted agent work

Gent can preserve a recipient's local report of work on an incoming message. Recording a start before acting helps a cooperating agent avoid repeating an uncertain task after a crash or lost response. Gent neither runs the task nor verifies external side effects. A host that ignores the journal can still repeat work.

The journal is opt-in, with one record per incoming message. It complements message delivery and relay outcomes. Acknowledgment, a recorded work outcome and a relay's final response remain separate operations.

## Agent workflow

1. Read `gent_work_status {message_id}` when resuming work. An absent record means unknown execution history, including work performed before journaling existed. Resolve any existing uncertainty with the user and actual host state.
2. Before authorized consequential work, call `gent_work_begin {message_id, expect_revision: 0, description}`. Descriptions are nonblank and at most 1,024 UTF-8 bytes. Keep the original arguments. Proceed only on `started_now: true`, subject to the user's authorization and normal host approvals.
3. An identical begin retry returns `started_now: false` while its start remains current. Other conflicting or superseded attempts fail. Neither result authorizes repeating the work. A lost first response can therefore require review even when no external action began.
4. Check the actual outcome, then call `gent_work_complete {message_id, expect_revision, note}` with the started revision and a nonblank outcome note of at most 2,048 UTF-8 bytes. Identical completion retries preserve the result. `execution_verified: false` identifies an agent or owner report that Gent has not independently verified.
5. Send the ordinary reply or `gent_relay_respond` separately. Journal operations do not send messages, acknowledge receipt, advance the relay queue or wake a host.

Agent operations require the original recipient, current signed node authority and current message access. Acknowledging the message does not change its journal identity. A new relay attempt also requires the current queue head and no cancellation request. An existing attempt can report its checked outcome after a cancellation request; cancellation alone proves neither interruption nor completion.

## Owner review

Run these commands on the recipient's node, selecting its cluster profile if necessary:

```sh
gent work
gent work list --after MESSAGE_UUID
gent work show MESSAGE_UUID
gent work reconcile MESSAGE_UUID --expect-revision 1 \
  --decision completed --note 'Checked the output and confirmed the requested change'
```

Inspect the host's real state before choosing a resolution:

| Decision | Meaning |
| --- | --- |
| `completed` | The owner reports the work complete after review. |
| `abandoned` | The owner records that this work will not proceed. |
| `retry-approved` | The owner permits one subsequent recorded attempt after reconciling uncertainty. |

Every reconciliation requires the exact current revision and a review note. An identical immediate retry returns the saved outcome; changed or stale requests fail. A retry approval requires current source access and node authority and cannot revive cancelled or finished relay work. The recipient starts it with the original message ID and description, using the approved revision as `expect_revision`. Gent still checks authorization on that call. Owner approval itself executes nothing.

The owner can revise a prior reported outcome within the journal's revision limit. The full event history remains visible. A local owner credential is required; there is no MCP tool for owner reconciliation. Messaging or permission-edit delegations do not grant this authority. An agent must not use filesystem or shell access to bypass that boundary.

## Persistence and limits

The record and transition event commit together in the recipient's SQLite transaction before `started_now: true` returns. Separate Store connections cannot both receive a successful new start. Reads and mutations validate contiguous event history and its consistency with the current record. Startup refuses an unsupported journal version, missing versioned tables or tables whose version marker is missing.

Records retain the source message ID, sender/recipient IDs, a message digest, description, attempts, revisions, timestamps and review notes. They survive message cleanup and agent revocation. After source expiry or loss of permissions, the agent cannot read or change the journal; the local owner can inspect it and record an outcome, but cannot approve another attempt. Retained descriptions and notes are local plaintext under the existing trusted-OS-user boundary. They are never sent to the central relay by these operations.

Limits are 4,096 records, 65,536 events, 64 revisions per record and 128 MiB of accounted record/event storage per node database. Each record reserves 8 KiB; events use actual encoded bytes plus 16 KiB for each reserved future event. A start reserves completion space, and a retry approval reserves space for both the start and completion. Admission failure rolls back the whole operation. These reservations do not guarantee free filesystem space or bypass the database page ceiling. Owner listings return 50 records per page in message-ID order.

There is no journal deletion or automatic pruning. At capacity, preserve the evidence and stop admitting journaled work until a reviewed archival/migration procedure exists. Never delete records, resend with new IDs or move to a fresh node merely to repeat uncertain work.

This journal is local and is not replicated to peers. Full offline backups include its database, but historical exports and fresh-agent recovery do not assign these records or restore execution authority. Backup rollback can forget later attempts; extracted backups remain guarded offline. Lost-node work migration, owner-key replacement and automated reconciliation remain unfinished. See [backup and recovery](recovery.md).

## Verification

Run `cargo test -p gent-daemon --test work` for restart/retry, concurrent writers, recipient and policy checks, cancellation, expiry cleanup, atomic rollback, schema corruption, paging and capacity coverage. Run the native process proof with:

```sh
cargo build -p gent-link
python3 scripts/prove_work.py --gent target/debug/gent
```

The proof drops a begin response, kills and restarts the daemon, performs explicit owner reconciliation, writes one disposable host output, crashes again, checks that a repeated begin cannot start it again, and records completion before sending a separate reply. It uses isolated state and synthetic MCP clients, with no model calls. Real-model adherence to the workflow and interruption of arbitrary external tools remain unverified.
