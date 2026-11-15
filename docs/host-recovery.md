# Automatic Codex recovery

The Gent daemon can start native Codex and resume selected agents when they have unclaimed pending messages. This is off by default and currently supports Codex on Linux and macOS. Ordinary [queued delivery](wake.md) remains responsible for notifying the agent after it is loaded.

## Select an agent

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

`THREAD_ID` is the native Codex conversation UUID. Enabling returns its Gent agent ID. Repeating the same selection preserves it. The command requires an intact managed installation using the default socket and an existing local registration; it never creates a new agent or credential. Custom sockets and Claude Code automatic startup are unsupported.

Use `--config-dir PATH` with enable when selecting a nondefault Codex home, matching the installation. `--host-binary PATH` selects the executable for startup; Gent records its absolute path. Host authentication, models, tool approvals and native updates remain controlled by Codex. Configure durable tool access in the host so recovery can proceed without a disconnected approval UI.

## Recovery conditions

The daemon checks selections every five seconds, visiting at most four per pass. It validates the installation and saved credential binding, then asks Gent for currently eligible messages without a dispatch claim. With no such work, it does not start or resume a host. An already loaded conversation needs no recovery.

For a missing host, Gent uses the same bounded native startup as `gent integration start codex`. Before calling `thread/resume`, it requires that the exact conversation is unloaded, its latest saved turn completed without an error, and its native queue is empty. An interrupted or unfinished turn, retained queue entry, malformed response or unavailable binding prevents automatic resume. Inspect the native history and queue, then resume explicitly when appropriate.

Resume supplies only the thread ID and `excludeTurns: true`. It does not override the saved model, reasoning, approvals, sandbox, working directory, instructions or history. Native settings probes pass on Linux Codex 0.167.2 and macOS 0.167.0. Existing MCP delivery then claims and queues the fixed inbox notification. Previously uncertain Gent submissions remain uncertain and cannot trigger a new submission.

Host startup occurs before Gent can inspect unloaded history. Codex controls its own startup restoration: a planned native restart can restore previously loaded conversations. The selected-agent isolation proof covers an abrupt crash on the tested versions; selection is not a restriction on Codex's own restoration or on delivery to agents already loaded by the owner.

Each selection has a minimum 60-second retry interval and at most six attempts per hour. The node has a shared limit of 24 attempts per hour. Attempts are saved before startup/resume, survive Gent restart and remain charged when the clock moves backward. These limits bound recovery attempts, not inference cost or external work. Maintenance bounds each attempt to 90 seconds and advances between selections so an unavailable host cannot permanently starve others.

## Inspect or disable

```sh
gent integration recovery list
gent integration recovery disable AGENT_ID
```

List reports selections and the persisted retry budget. The daemon logs changed failures and owner-review conditions. Disable removes the selection without stopping a native host, unloading a conversation or disabling its ordinary MCP delivery. It serializes with an in-progress recovery operation; retry if the command reports that recovery is busy. Removing the managed wake installation or revoking the bound agent also prevents further recovery.

Selections live in the node-local `host_recovery` table in `~/.gent/config.toml` (or the selected cluster profile). They are not replicated cluster policy. The table pins the node, cluster, native thread, configuration directory, executable and credential hash, with at most 32 selections. It contains no credential or message content. Config projections preserve the latest selection, including an empty table after disabling the last agent. Older binaries that do not understand this local feature refuse the configuration.

The private `host-recovery-budget.json` file stores attempt timestamps and agent IDs. Missing, corrupt or foreign budget state prevents recovery; restore the node's state rather than deleting the file to reset limits. Disabling selections still works when the budget is damaged. Existing offline-backup and trusted-OS-user boundaries apply.

## Tested scope

Native loopback proofs on both OSes crash Codex and Gent, then observe startup, selected resume, inbox retrieval and acknowledgment without an owner resume. An unselected sibling remains unloaded. No selected pending work and explicit opt-out both prevent startup. An active-turn crash leaves retained native input and the new Gent message waiting for owner review, with no extra inference or dispatch claim.

These checks do not establish OS-reboot recovery, general compatibility across host versions or atomic completion of external side effects. Review the [work journal](work.md) before repeating consequential work. Gent-managed Claude startup, Mac GUI, standalone desktop and hosted/mobile recovery still need acceptance work. Claude's own [background service](wake.md#native-claude-background-sessions) has separate crash behavior: it can continue an unfinished turn automatically, independently of Gent's recovery selections and submission journal.
