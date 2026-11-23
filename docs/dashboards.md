# Chat dashboards and goal recovery

## Publish a dashboard

Each registered chat can publish one dashboard. Open **Dashboard** in Gent Desktop on any participating node. Nodes exchange dashboard data over Gent wire protocol 9. The tab refreshes from the local daemon while open.

For a new board, call `gent_dashboard_define` with an initial revision of zero.

```json
{
  "expected_revision": 0,
  "board": {
    "title": "Training run",
    "widgets": [
      {"id": "loss", "kind": "graph", "label": "Validation loss", "value": [0.9, 0.71, 0.64]},
      {"id": "epochs", "kind": "progress", "label": "Epochs completed", "max": 20, "value": 4},
      {"id": "inspect", "kind": "button", "label": "Check latest checkpoint", "value": "Report the latest checkpoint and its validation loss."}
    ]
  }
}
```

The call returns the committed revision. To record epoch 5, call `gent_dashboard_update` with that revision and the values you want to replace.

```json
{"expected_revision": 1, "values": {"epochs": 5, "loss": [0.9, 0.71, 0.64, 0.59]}}
```

Supply the whole series for a graph and the whole list of strings for an event feed. A board can contain up to 32 widgets and 32 KiB of serialized data. Each graph can show 256 samples and each event feed can show 64 entries. Gauge and progress ranges default to 0 through 100. Use a text widget for a status line or paragraph.

Clicking a button sends its instruction as a waking message from **Gent Desktop** to the chat that published it. The chat handles the action under its existing permissions. If the board changed since the window displayed it, refresh before clicking again.

To change the layout, define the complete board again. To remove it, call `gent_dashboard_delete` with its current revision. On a revision conflict, call `gent_dashboard_get` for the latest board and revision, including after deletion. An identical retry of the most recent successful change returns the saved revision.

## Automatic goal recovery

Babysitting starts enabled for chats connected to Gent's managed Codex and Claude Code integrations. In **Settings**, toggle **Resume goals after provider failures** for this machine. Within a registered chat, use `gent_babysit({"enabled": false})` or `gent_babysit({"enabled": true})`. Call `gent_babysit({})` to read the effective setting. The machine setting takes precedence.

Gent checks the host's failed turn and its current goal. Recognized failures include model overload, rate limits, interrupted provider streams, invalid tool types, and the provider error “Invalid request payload.” An unrecognized failure stays available for human review. Web MCP chats can publish dashboards. Automatic resume needs the turn and goal information exposed by the managed native integrations.

The Gent daemon checks loaded Codex chats using their managed connections, including chats that have kept an older Gent MCP process open across an update. For a blocked goal, Gent checks the failed turn and its local Codex history for a deliberate block or a later user decision. A command or subagent from an earlier turn can report completion after the failure. Gent checks which turn owns that report. It rechecks the current goal and turn immediately before calling Codex's native resume operation, which preserves the objective and token budget. Codex can still accept a concurrent user edit between that check and the resume operation.

Claude Code receives the user-input continuation “Continue working on the current goal.” Its `/goal` command treats the following text as a new goal condition.

The first eligible failure can resume on the next host check. If the same goal fails again within five minutes of a recovery attempt, the delays are 15, 30, 60 and 120 seconds, then double up to one hour. A later failure outside that window starts over. The daemon saves the delay and attempt ID across restarts. If the host may already have received input, Gent leaves that attempt for review.

## Account notifications

A confirmed goal resume and a completed automatic update each create a typed event for the Gent account. An enrolled service node uses its configured account. A local-only node uses the account signed in at the time of the event. Signed-out local-only nodes have no account inbox. Desktop receives notifications while the companion is running, including in the tray. Enable OS notifications for your graphical session.

The account inbox returns the latest 512 events from the past seven days. New publications prune older rows. Receivers open an authenticated WebSocket at `/v1/notifications/watch`, then fetch `GET /v1/notifications` with their own bearer and `X-Gent-After` cursor. Each page contains up to 64 ordered events. On a `changed` hint, or after reconnecting, fetch from the last processed sequence. Each device keeps its own cursor. The event ID identifies a publication across retries. Future clients can consume the same inbox. Mobile push delivery requires a mobile receiver.

## Dashboard implementation plan

1. Bind publication to the existing MCP conversation credential on stdio and hosted connectors. A chat owns one optional dashboard. Define replaces its title, widgets and initial values. Update replaces values by widget key. Delete retains a revision tombstone. All three operations compare the expected revision, with identical retries recognized. An inspect operation returns the current revision after reconnect.
2. Accept bounded plain text, events, numeric series, progress, gauges and named buttons. Validate the complete resulting document before committing it. Button definitions carry a human-readable instruction for the publishing chat. Gent renders data natively and delivers the instruction only after a user click.
3. Store the current snapshot transactionally in SQLite. Replicate changes through authenticated node records to compatible peers. Retain a per-peer cursor and send current snapshots on capability refresh for newly joined or returning peers. Authenticate the chat's hosting node, preserve tombstones across restarts, and include hosted dashboards in portable checkpoints.
4. Add a Dashboard tab on GTK and AppKit. While visible it refreshes from the local daemon. Use a grid on wide windows and full-width cards on narrow ones. Show the chat, dashboard title, latest values and active buttons. Send clicks with an ordinary Gent Desktop registration so the chat sees their source and normal delivery policy applies.
5. Verify schema validation, revision conflicts and replay, cross-node state and deletion, callback routing, hosted compatibility and both native renderers with disposable state.

## Babysitter implementation plan

1. Observe managed host adapters' own turn failures and goal lifecycle. Classify known capacity, rate-limit, connection and tool-schema provider errors deterministically. Ignore arbitrary chat text, tool failures, human pauses, cancellation, approval prompts and finished goals. Require fresh matching goal and failed-turn evidence before submission.
2. Default to enabled and expose a global setting and per-chat control. Deduplicate by chat, goal and failure identity. Record a durable claim before native input. Resume the first eligible failure immediately. For subsequent failures within five minutes of the previous attempt, delay 15, 30, 60, 120 seconds, doubling to one hour. Persist the schedule across restarts and cancel obsolete work.
3. Use native goal controls or the provider's user-input mechanism for the exact conversation. Record a notification only when the host accepts resumption. Keep uncertain submissions deduplicated and respect newer user activity.
4. Store typed notification events by authenticated Gent account with a stable event ID. Keep provider diagnostics and conversation content local. Desktop delivery and a future mobile receiver share the account event identity. Verify account isolation, duplicate handling, host-specific behavior and timer boundaries with fixtures.
