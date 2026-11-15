# Selected native agent recovery

The Gent daemon can reopen selected Codex and Claude Code agents when they have unclaimed pending messages. This is off by default on Linux and macOS. Ordinary [queued delivery](wake.md) remains responsible for notifying the agent after it is loaded.

## Select a Codex agent

Install queued delivery and start the native host:

```sh
gent integration install codex --wake
gent integration start codex
codex --remote unix://
```

Open the conversation and use a Gent tool so its existing registration is attached to that host. While it is loaded, enable recovery from a terminal on the same node:

```sh
gent integration recovery enable codex THREAD_ID
gent integration recovery list
```

`THREAD_ID` is the native Codex conversation UUID. Enabling returns its Gent agent ID. Repeating the same selection preserves it. The command requires an intact managed installation using the default socket and an existing local registration; it never creates a new agent or credential. Custom Codex sockets are unsupported.

Use `--config-dir PATH` with enable when selecting a nondefault Codex home, matching the installation. `--host-binary PATH` selects the executable for startup; Gent records its absolute path. Host authentication, models, tool approvals and native updates remain controlled by Codex. Configure durable tool access in the host so recovery can proceed without a disconnected approval UI.

## Codex recovery conditions

The daemon checks selections every five seconds, visiting at most four per pass. It validates the installation and saved credential binding, then asks Gent for currently eligible messages without a dispatch claim. With no such work, it does not start or resume a host. An already loaded conversation needs no recovery.

For a missing host, Gent uses the same bounded native startup as `gent integration start codex`. Before calling `thread/resume`, it requires that the exact conversation is unloaded, its latest saved turn completed without an error, and its native queue is empty. An interrupted or unfinished turn, retained queue entry, malformed response or unavailable binding prevents automatic resume. Inspect the native history and queue, then resume explicitly when appropriate.

Resume supplies only the thread ID and `excludeTurns: true`. It does not override the saved model, reasoning, approvals, sandbox, working directory, instructions or history. Native settings probes pass on Linux Codex 0.167.2 and macOS 0.167.0. Existing MCP delivery then claims and queues the fixed inbox notification. Previously uncertain Gent submissions remain uncertain and cannot trigger a new submission.

Host startup occurs before Gent can inspect unloaded history. Codex controls its own startup restoration: a planned native restart can restore previously loaded conversations. The selected-agent isolation proof covers an abrupt crash on the tested versions; selection is not a restriction on Codex's own restoration or on delivery to agents already loaded by the owner.

## Select a Claude background agent

Install `gent integration install claude-code --wake`, register the conversation through Gent, and adopt it with Claude's native background controls. While that background agent is running, select its full native session UUID:

```sh
gent integration recovery enable claude-code SESSION_ID
gent integration recovery inspect AGENT_ID
```

Enabling requires an intact current wake installation, a local Gent binding, and the exact native background session. Use the installation's `--config-dir PATH` for a custom profile, and `--host-binary PATH` if needed. Gent records the profile, executable, session, working directory and credential hash. It never adopts an interactive-only conversation or creates a replacement agent. Repeating the same selection preserves its ID.

Automatic attachment uses the recorded profile and a small OS environment, excluding transient provider variables from the shell that launched Gent. Save custom API endpoints and provider credentials in Claude's own supported profile configuration before enabling recovery; shell-only provider settings are not retained by Gent. Native model, authentication and tool-approval settings remain Claude's responsibility. Explicit owner startup continues to use the invoking environment.

Before attaching an inactive agent, Gent checks its native job and transcript. The job must identify that session and working directory and report no tasks, queued input, monitors or children. History must stay inside the selected profile, remain unchanged during inspection, and finish with an assistant `end_turn` followed by its matching turn-duration record. Gent rejects unresolved branches, duplicate identities, partial records, error endings and unmatched native queue entries. Transcript contents are never returned in diagnostics or copied into Gent's configuration.

Compacted histories, unknown native record types, unsupported queue operations and missing job fields require owner review. Some native planned-stop records omit the in-flight summary and therefore require explicit owner startup even after a completed turn. Historical unmatched enqueue records can continue to block automatic recovery even after Claude itself continues a turn. These checks deliberately do not infer completion from the native `done` label or discard old queue evidence. Inspection is bounded to 256 MiB, 8 MiB per line and 200,000 records.

Eligible recovery uses the same exact-session, closed-stdin `claude attach SHORT_ID` path as [owner startup](wake.md#reopen-a-claude-background-agent), with its reconciliation interval, bounded retries and 30-second deadline. It rechecks pending work, installation, binding and stable history before attachment. A loaded worker is left running; Gent's ordinary wake plugin handles delivery. Previously claimed messages cannot cause another Gent submission.

## Shared limits

Each selection has a minimum 60-second retry interval and at most six attempts per hour. The node has a shared limit of 24 attempts per hour. Attempts are saved before startup/resume, survive Gent restart and remain charged when the clock moves backward. These limits bound recovery attempts, not inference cost or external work. Maintenance bounds each attempt to 90 seconds and advances between selections so an unavailable host cannot permanently starve others.

## Inspect or disable

```sh
gent integration recovery list
gent integration recovery inspect AGENT_ID
gent integration recovery disable AGENT_ID
```

List reports selections and the persisted retry budget without contacting a native host. Inspect validates an existing selection and queries native readiness without starting it. Claude results include a reason when history requires review. The daemon logs changed failures and owner-review conditions. Disable removes the selection without stopping a native host, unloading a conversation or disabling its ordinary MCP delivery. It serializes with an in-progress recovery operation; retry if the command reports that recovery is busy. Removing the managed wake installation or revoking the bound agent also prevents further recovery.

Selections live in the node-local `host_recovery` table in `~/.gent/config.toml` (or the selected cluster profile). They are not replicated cluster policy. The table pins the node, cluster, native session, configuration directory, executable and credential hash; Claude selections also pin their working directory, with at most 32 selections. It contains no credential or message content. Version 1 Codex selections keep their original encoding; adding Claude upgrades the recovery table to version 2. Config projections preserve the latest selection, including an empty table after disabling the last agent. Older binaries that do not understand this local feature refuse the configuration.

The private `host-recovery-budget.json` file stores attempt timestamps and agent IDs. Missing, corrupt or foreign budget state prevents recovery; restore the node's state rather than deleting the file to reset limits. Disabling selections still works when the budget is damaged. Existing offline-backup and trusted-OS-user boundaries apply.

## Tested scope

Native loopback proofs on both OSes crash Codex and Gent, then observe startup, selected resume, inbox retrieval and acknowledgment without an owner resume. An unselected sibling remains unloaded. No selected pending work and explicit opt-out both prevent startup. An active-turn crash leaves retained native input and the new Gent message waiting for owner review, with no extra inference or dispatch claim.

Claude native proofs crash an idle selected worker and Gent, then recover one pending delivery while a registered sibling remains stopped. No selected work and opt-out prevent startup. A planned stop during a held model stream leaves unfinished history and existing claims untouched, and fresh work awaits owner review. The planned stop distinguishes Gent behavior from Claude’s own busy-worker crash continuation.

Both host proofs also pass with Gent installed as a systemd user service on Linux and a LaunchAgent on macOS. After Gent is killed, the OS manager restarts it without a test-issued start/restart command. Saved selections still govern host recovery, and the same no-work, opt-out and unfinished-history checks apply. Native evidence matches the process identity, manager restart counter, unchanged service definition and original agent delivery receipts. These runs use isolated native profiles and synthetic loopback models; they verify the service environment without using provider credentials.

These checks do not establish OS-reboot recovery, general compatibility across host versions or atomic completion of external side effects. Review the [work journal](work.md) before repeating consequential work. Mac GUI, standalone desktop and hosted/mobile recovery still need acceptance work. Claude supports [explicit owner startup](wake.md#reopen-a-claude-background-agent) for an existing background agent. Its native background service can also continue an unfinished turn automatically, independently of Gent's recovery selections and submission journal.
