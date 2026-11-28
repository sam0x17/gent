# Chat dashboards and goal recovery

## Publish a dashboard

Each registered chat can publish one dashboard. Open **Dashboard** in Gent Desktop on any participating node. A single board fills the pane. Multiple boards share it and wrap into fewer columns as the window narrows. The page scrolls vertically when the boards need more room. The tab refreshes from the local daemon while open.

Ask a Gent-connected chat to build a dashboard in plain language. For example, “Make a Gent dashboard for this test run. Show how many tests have passed and list any failures.” To keep it current, tell the same chat, “Update my dashboard after each test batch.” The chat publishes the values it observes as it works. Publishing dashboards requires Gent Pro. [Dashboard examples](https://gent.link/dashboards)

For a new board, call `gent_dashboard_define` with an initial revision of zero.

```json
{
  "expected_revision": 0,
  "board": {
    "title": "Training run",
    "widgets": [
      {"id": "loss", "kind": "graph", "label": "Validation loss", "value": [0.9, 0.71, 0.64]},
      {"id": "epochs", "kind": "progress", "label": "Epochs completed", "max": 20, "value": 4},
      {"id": "results", "kind": "link", "label": "Open run results", "value": "https://example.org/runs/42"},
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

### Private static HTML

Starting with Gent 0.1.8, a chat can attach a private HTML view to its dashboard. Keep the native widgets as the fallback. Import a UTF-8 file of 1 to 65,536 bytes with media type `text/html` through the chat’s usual Gent file tools. Read the current board revision, then call `gent_dashboard_attach_html` with the file ID and that revision.

```json
{"expected_revision":1,"file_id":"a2355007-c576-424a-b587-7b792af2853c"}
```

An identical retry returns the saved revision. A different write against a stale revision fails. An update, redefinition or deletion clears the attachment. To replace the HTML, import the revised file and attach its ID against the current revision.

Desktop reads the attachment locally or requests the exact board revision from the publishing carrier over Gent’s authenticated QUIC connection. Both nodes need Pro, direct transport enabled and a current advertised endpoint reachable by IP or a configured Iroh relay. The nodes must agree on the signed cluster configuration. Each read checks the chat’s current file access, expiry, UTF-8 and the complete content digest. For an unchanged document the viewer supplies its digest and the carrier returns a confirmation without the body.

The visible Dashboard tab checks every 15 seconds. An unavailable carrier or file, a helper-only or mailbox-only route, and older clients show the native widgets. The widgets, board revision and deletion still replicate through the ordinary board stream. Hosted failover retains that native board. Attach the file against its current revision on the new carrier to enable the HTML view there.

### Status lanes and paired event feeds

Use consecutive `events` widgets with `unit: "gent:lane:v1"` to show parallel work. Give each slot a permanent ID and label. The first string in its value is a tone, a colon, a space and a written state. Choose `neutral`, `info`, `success`, `warning` or `critical` for the tone. Follow the state with up to three detail strings. Keep the state and each detail on a single line. Desktop wraps long text to fit the card.

```json
[
  {"id":"lane_1","kind":"events","unit":"gent:lane:v1","label":"Lane 1",
   "value":["warning: Waiting for checkpoint","Epoch 42","Replay · slot 7","ETA 13:40 UTC"]},
  {"id":"lane_2","kind":"events","unit":"gent:lane:v1","label":"Lane 2","value":[]},
  {"id":"landed","kind":"events","unit":"gent:feed-pair:v1","label":"Landed (UTC)",
   "value":["Epoch 40 · 11:28","Epoch 41 · 12:31"]},
  {"id":"estimated","kind":"events","unit":"gent:feed-pair:v1","label":"Estimated (UTC)",
   "value":["Epoch 42 · 13:40","Epoch 43 · 14:53"]}
]
```

An empty lane value (`[]`) reserves the ID and takes up no space on a supporting Desktop. Fill or clear it with a values-only update. For example, send `{"expected_revision":1,"values":{"lane_2":["info: Starting","Epoch 43"]}}` to activate the second slot at revision 1. An unrecognized tone or malformed card displays as an ordinary event list.

Mark both feeds with `gent:feed-pair:v1` and put them next to each other in the widget array. Desktop pairs consecutive marked feeds in twos and displays an odd final feed on its own. When the board has room, the two feeds sit side by side. If three columns fit and the second feed has at least four entries and at least twice as many as the first, its entries flow down the middle column and continue at the top of the right column. On a narrow board, the feeds stack in document order. The page scrolls through every entry. In GTK, right-click either half of a split feed and choose **Select feed text…** to select across the column break, or **Copy entire feed** to copy all its entries.

For an existing board, call `gent_dashboard_get`, then `gent_dashboard_define` once with the complete board and its current revision to add the markers. Continue updating values by widget ID. Gent Desktop 0.1.7 reads these widgets as ordinary event lists, including the labels of reserved slots. Its GTK presenter also prints the unit marker after the event text.

### Metrics, charts and images

A `metric` displays the field name in bold followed by the number and its optional unit, for example **GPU temperature:** 64 °C.

```json
{"id":"temperature","kind":"metric","label":"GPU temperature","unit":"°C","value":64}
```

| Kind | Example value | How it reads |
| --- | --- | --- |
| `graph` | `[18, 24, 21, 30]` | Gent numbers samples from 1, labels the value axis with the unit, and draws a smooth spline through the samples. |
| `scatter` | `[[0.5, 18], [1.5, 19], [5, 30]]` | Each pair supplies its own x and y coordinates. Set `x_unit` for the horizontal axis and `unit` for the vertical axis. |
| `bar` | `[{"label":"Read","value":42},{"label":"Write","value":-7}]` | Compare values across categories, including values below zero. |
| `pie` | `[{"label":"GPU","value":8},{"label":"CPU","value":2}]` | Show shares of a positive total. Values can be counts or other nonnegative quantities. |
| `radar` | `[{"label":"GPU","value":80},{"label":"CPU","value":36},{"label":"RAM","value":60}]` | Compare at least three nonnegative values on a common scale, with one spoke per category. |

Scatter plots accept up to 256 points. Bar, pie and radar charts accept up to 16 categories. Use the same unit for all values in a series. For example, a scatter with `"x_unit":"s","unit":"MiB"` plots memory usage against elapsed seconds.

For an `image`, put a PNG or JPEG data URI in `value` and describe the picture in `label`. To build the value from a PNG thumbnail in Python, encode its bytes in base64.

```python
import base64
from pathlib import Path

value = "data:image/png;base64," + base64.b64encode(Path("preview.png").read_bytes()).decode("ascii")
```

The preview travels with the dashboard and counts toward the 32 KiB board limit, including base64 overhead. Use a still image up to 2,048 pixels per side and 1,048,576 pixels in total. For a larger original, place a `link` widget alongside the preview.

### Links and buttons

Use a `link` widget for a web page. Give it a label and an absolute HTTP or HTTPS URL. Clicking the label opens the page in the viewer's default browser. To point it at a different run, update the value by widget ID. Older Gent desktops show the destination as text.

If a hosted chat moves to an older carrier whose MCP schema lacks `link`, use `"kind": "text", "unit": "↗ web link"` with the same URL. This is the stored form of a link. It also lets you retry the original definition with the same expected revision after a carrier change.

Clicking a button sends its instruction as a waking message from **Gent Desktop** to the chat that published it. The recipient is the publisher’s Gent chat ID. If a replacement chat registers under the same name with a new ID, it can publish its own board. Buttons on the earlier board keep addressing the original ID. The chat handles the action under its existing permissions. If the board changed since the window displayed it, refresh before clicking again.

To change the layout, define the complete board again. To remove it, call `gent_dashboard_delete` with its current revision. On a revision conflict, call `gent_dashboard_get` for the latest board and revision, including after deletion. An identical retry of the most recent successful change returns the saved revision.

## Automatic goal recovery

Free and Pro include Babysitter on Stable and Beta. Goal recovery starts enabled for chats connected to the managed Codex and Claude Code integrations. In **Settings**, toggle **Resume goals after provider failures** for this machine. To opt a registered chat out of both goal and ordinary chat recovery, call `gent_babysit({"enabled": false})` in that chat. Use `gent_babysit({"enabled": true})` to opt back in. Each kind of recovery still needs its own machine setting enabled. Call `gent_babysit({})` to read the effective goal recovery setting. [Babysitter guide](https://gent.link/babysitter)

Gent checks the host's failed turn and its current goal. Recognized failures include model overload, rate limits, interrupted provider streams, request payload errors, and parameter validation errors such as “Unknown parameter” and “Invalid value.” The provider can identify any field or omit the parameter. Babysitter also recognizes a Codex turn that failed because the response reached its output token limit (`max_output_tokens`). An unrecognized failure stays available for human review. Web MCP chats can publish dashboards. Automatic resume needs the turn and goal information exposed by the managed native integrations.

The Gent daemon checks loaded Codex chats using their managed connections, including chats that have kept an older Gent MCP process open across an update. Codex can finish queued messages while the goal itself stays blocked. Once the queue drains, Gent can trace the block back to a provider failure even when a later queued turn succeeded. It checks the turn history for a newer user decision, including a pause or a new foreground turn. A late completion from a command or subagent is attributed to its original turn.

Routine recovery considers provider failures from the past two hours. After an update or reconnect, the local Codex supervisor can recover a still-blocked goal for up to 24 hours after the most recent eligible provider failure. It must verify the native turn that blocked the goal and account for every intervening turn. A later Gent delivery counts only when its completed native turn matches the retained dispatch receipt by client input ID and input hash. If Codex finishes queued work after the block, Babysitter checks those turns too. When a Gent relay request arrived during a queued turn, its delivery receipt and completed reply must match. That delivery does not restart the 24-hour clock. If the history is incomplete or the reason for the block is ambiguous, the goal stays available for manual resume. Gent rechecks the goal and turn history immediately before asking Codex to resume the same objective and token budget. Codex can still accept a concurrent user edit between that check and the resume operation.

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
