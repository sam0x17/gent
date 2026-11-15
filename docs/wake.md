# Host dispatch journal

Gent records a local host adapter's attempt to submit incoming-message input before that submission can begin. A lost daemon response or restart cannot grant a second submission for the same message. Optional Codex and Claude Code adapters use this journal to queue inbox notifications for loaded conversations.

The tested Codex queue creates a new entry when the same client message ID is submitted again. Gent therefore cannot treat a repeated queue call as harmless. Claude's adapter uses native plugin input to wait for completed turns and respect explicit interruption. Generic MCP inbox access remains available on both hosts.

## Enable Codex queued delivery

Use Codex's default local app-server socket:

```sh
gent integration install codex --wake
gent integration start codex
codex --remote unix://
```

Gent selects the Codex configuration directory from `--config-dir`, then `CODEX_HOME`, then `~/.codex`. It pins `<directory>/app-server-control/app-server-control.sock` in the MCP entry, so later environment changes cannot retarget that entry. Installation and `gent integration status codex` report the recorded `wake_socket` without probing the host. `gent integration config codex --wake [--config-dir PATH]` prints the equivalent fragment without editing settings.

For a custom server, provide its absolute advertised socket path:

```sh
gent integration install codex --wake-socket /absolute/path/to/codex.sock
```

Use either `--wake` or `--wake-socket`, then restart the host's Gent MCP connection to load the setting. `gent integration config codex --wake-socket PATH` prints a custom fragment. Direct setups can use `gent --home PATH mcp serve --host codex --wake-socket PATH`.

These socket configurations also expose the [native pasted-image tools](providers.md): `gent_host_attachments` lists embedded images from the caller's authenticated conversation, and `gent_file_import_host` imports selected bytes for normal Gent messaging. Host tool approvals still apply. Disabling the socket removes both automatic delivery and these native attachment tools after MCP reconnect.

`gent integration start codex` starts or reuses Codex's native background daemon. It requires an intact managed `--wake` installation belonging to the selected Gent home and using the default socket. It probes the endpoint first; only a missing or refused connection permits launching `codex app-server daemon start`. An unsafe socket, unsupported response, timeout, conflicting installation or custom socket fails without launching a replacement. Gent resolves Codex's socket alias, requires a private socket and directory owned by the current OS user, and verifies the connected peer's user ID.

Use the same `--config-dir PATH` for install, start and status when selecting a nondefault Codex home. Startup also accepts `--host-binary PATH`. Its result supplies the command and `CODEX_HOME` for attaching with `--remote unix://`. Codex manages its own package and background process, including any native updater policy. Gent neither registers another service nor changes that policy. Startup has a 60-second limit and bounds native output. A timeout can leave the native daemon running; inspect live status before retrying.

`gent integration status codex --live` validates the managed installation and probes its default or recorded custom endpoint without starting a host or model turn. It returns `runtime.connected`, a loaded-thread count for one page of at most 128 entries, and `has_more`, or a diagnostic error. It does not expose thread IDs or prove that a particular agent is ready. Ordinary status and `gent doctor` retain their file-only integration checks. Claude live status and startup are currently unsupported.

For a foreground server, run `codex app-server --listen unix://` in one terminal, then `codex --remote unix://` in another. Use the same Codex configuration directory for the server and CLI. The socket must serve the conversation using Gent, and that conversation must stay loaded for automatic delivery. Resume it explicitly if needed; Gent does not move an existing embedded conversation or cold-resume it. A standalone embedded host without that socket continues to use its inbox normally.

After a conversation calls a Gent tool, its host-supplied thread ID selects the registration credential and saves an attachment for the configured socket. One watcher per node, cluster and socket checks loaded conversations against those attachments, visiting up to 128 thread IDs per sweep and waiting five seconds between sweeps. Before claiming a pending message, it reads that exact thread's metadata and requires a loaded idle or active thread that accepts direct input. It then uses `thread/queue/add`; it never calls turn start, steering, resume, queue start or interruption. Busy queues and explicit interruption holds remain controlled by Codex.

The queue receives a fixed instruction to check Gent's inbox, with no message content, file bytes or peer identity. The inbox rechecks current permissions when the model retrieves messages. Host model settings and approval rules remain unchanged. Gent does not answer approval or other server-initiated requests. Owners must configure ordinary host tool access separately.

The adapter lives with the MCP process. A replacement or another opted-in MCP process can recover saved attachments without a new registration, model turn or Gent tool call. An OS lock elects the watcher and releases ownership when its process exits. Recovery reads existing credentials and their scope records without taking ownership away from live MCP connections or creating missing keys. All adapters stop when their MCP processes exit. The explicit startup command is separate from the adapter; incoming messages never launch a stopped host or load conversations.

Native background-daemon proofs on Linux Codex 0.167.2 and macOS 0.167.0 retain a loaded conversation after its client disconnects. A planned `codex app-server daemon restart` also restores that conversation and automatic inbox/acknowledgment calls with the same Gent identity. These checks use a loopback model and owner-approved Gent tools saved in a trusted project's Codex configuration. Per-thread approval overrides did not survive native restart; configure durable tool access through the host. The proofs do not establish recovery after a crash or operating-system restart.

Unloaded threads, missing sockets, unsupported host APIs and unavailable registrations leave messages pending. A lost response after a claim leaves an uncertain journal record and never triggers a repeated submission. Other attached conversations remain eligible when one fails.

To disable queued delivery, run `gent integration install codex` without either wake option, then reconnect the host's Gent MCP connections so the old watchers exit. This removes the managed socket option while preserving the ordinary MCP integration. Each conversation's next Gent call through a connection without that option also disables its saved attachment. Other still-running opted-in connections can continue watching saved attachments until they exit or those attachments are disabled. No Codex service or model setting is changed.

Daemon identity still reports `delivery: polling` for its durable inbox. That field does not describe this optional adapter's live connection status; inspect `gent wake` for dispatch evidence and `gent integration status codex --live` for endpoint connectivity. Discovery of custom endpoints, unattended host startup, cold resume and GUI delivery acceptance remain unfinished.

## Enable Claude Code queued delivery

Use the managed installer, then start or restart Claude Code and register the conversation with Gent:

```sh
gent integration install claude-code --wake
```

This option is available in ordinary builds. Plain installation keeps inbox polling. Gent selects the Claude configuration directory from `--config-dir`, then `CLAUDE_CONFIG_DIR`, then `~/.claude`. `gent integration status claude-code` reports the recorded `claude_wake` installation ID, not live host connectivity. `gent integration config claude-code --wake` cannot produce this managed installation; use `install` instead. The adapter requires Claude's native function hooks and plugin-input API, tested on Linux Claude 2.1.323 and macOS Claude 2.1.311. It does not start a stopped host or load another conversation.

The installer manages a native plugin under the host configuration directory's `skills/gent-wake` and a separate `UserPromptSubmit` command hook in user settings. Version 3 installation records require both and set the command hook's `onFailure` to `block`. Version 1 and 2 records can be upgraded or removed, but cannot dispatch through the new bridge. The installer records the installed module bytes, an installation ID, node and cluster, and checks ownership before upgrading or removing files. Interrupted updates accept the recorded before/after versions; edited files and unrelated hooks are preserved. A pending update, disabled hook, old installation ID or changed binding prevents the Rust bridge from granting a usable response.

The module polls every five seconds, using a bounded JSON subprocess interface with argument vectors. Rust reads the exact session's existing Gent credential and pinned scope without creating missing keys or taking live MCP credential locks. It claims before returning a fixed inbox notification. Credentials, message content and files never enter that subprocess response or notification. One notification remains outstanding per module.

Native `prompt.submit` controls completed-turn queuing and interruption holds. A separate `classic.UserPromptSubmit` hook rechecks the target session and current claim eligibility at delivery. This hook does not infer turn completion from classic Stop events. The adapter correlates a guarded notification with a native `turn.start` UUID for its receipt; its generated attempt ID is not a host acceptance ID. Dropped or lost submissions remain uncertain and are never retried automatically.

The command guard runs independently of the native module. Its fixed notification format includes installation, message and attempt IDs, which are references to existing claims, never credentials or submission grants. It checks the event's exact session against the existing binding and claim, current permissions and the complete installation. Invalid or stale notifications return a blocking hook decision. Ordinary human input returns an explicit allow without reading Gent state, including after uninstall. The shell wrapper returns Claude's blocking exit status if the executable fails or is missing. The host's `onFailure` policy also blocks a timeout or an invalid structured verdict. Claude accepts an empty object or plain text as successful command-hook output; Gent emits explicit JSON results. Restart Claude after uninstall before removing the executable, because a retained hook with no executable cannot distinguish a human prompt from a stale notification.

Linux and Mac native tests demonstrate idle delivery, busy boundaries, interruption/rearm, isolation when a claim response is delayed across `/clear`, restored binding after `/resume`, and no repeated submission after a lost claim response and daemon restart. The earlier module-only adapter allowed queued input to run after its guard unloaded. With the command guard, holding delivery until actual watcher unload now produces no extra model request, even though uninstall removed the guard's only settings entry. A probe adding that entry after the host's initial human turn also passes. Uninstall during a busy turn likewise prevents an extra turn; those runs retain the module through the delivery check and therefore prove a different boundary.

Direct module reload drops a held notification, and restoring the installed bytes restores automatic polling without a human prompt. Two actual host restarts exercise a held Rust claim response and a notification already queued by Claude. Resuming the exact session processes a fresh message without registration or a human model turn, while the old claim stays uncertain.

Actual installer replacement with a different executable path creates a new installation ID, blocks old queued input and restores fresh delivery without restarting the host. Reinstalling without `--wake` removes the plugin and command guard while retaining ordinary MCP access and the same agent identity. Re-enabling creates another installation ID and delivers an unclaimed message that arrived while disabled; previously claimed input remains uncertain without replay. The tested host retains the old executable for its existing MCP process and hooks. Restart Claude before removing that executable.

Native stream observation also confirms that Escape during a partial text response aborts that exact turn. Both an already queued notification and a new arrival cause no further model request. Explicit human input rearms delivery, and a fresh notification runs without replaying either old attempt. These lifecycle proofs use isolated native hosts and a loopback model.

Separate real-model checks on both OSes use one initial registration turn and three automatic reply/acknowledgment exchanges. They cover initial delivery, a Gent daemon restart, and an actual Claude restart into the same synthetic session. Agent identity and native submission receipts remain exact, and resumed delivery needs no registration or human model turn. Those checks do not establish arbitrary crash recovery, operating-system restart or GUI delivery.

## VS Code delivery

Linux VS Code 1.146.0 with Claude Code extension 2.1.325 now passes automatic inbox/acknowledgment delivery through the installed user-scope `--wake` integration. The actual UI shows the plugin prompt and completed response. A notification waits through a held model stream; clicking Stop holds both queued and new notifications. Explicit human input permits fresh delivery without replaying old claims. Editor reload plus Gent daemon restart preserves the session and agent, and another message runs without registration or human input. Reinstalling without `--wake` stops automatic delivery while retaining ordinary MCP access.

These lifecycle checks use an isolated profile, owner-approved Gent tools and a loopback model. Separate real-model checks with Sonnet 4.6 now pass three automatic exact replies and acknowledgments: initial delivery, after a Gent daemon restart, and after editor reload. All three retain the same session and agent, with one initial registration and no additional human model turn. Native transcripts and stored message results agree; the final exchange also has an independently matched native submission receipt. macOS IDE wake and standalone desktop wake still need acceptance checks.

The tested Codex extension, `openai.chatgpt` 26.1111.21308 with bundled Codex 0.169.0-alpha.11.1, launches an embedded stdio app server without Gent's required Unix endpoint. Its managed `--wake` installation remains disconnected and messages stay pending. Reopening the original chat and asking it to check its inbox retrieves and acknowledges the message after editor/daemon restart. `gent integration start codex` starts a separate native background server; it does not move an embedded IDE chat to that server.

A separate experimental Rust route now connects a fresh IDE chat to the native background server through the extension's development-only executable override:

```sh
gent integration install codex --wake --vscode
gent integration start codex
```

Reload VS Code, then open or explicitly resume a conversation. Installation preserves unrelated settings and JSON comments, refuses existing executable overrides, and records enough information to recover an interrupted update. It installs a small private shell launcher that invokes Gent's Rust transport. `--vscode-settings PATH` selects another VS Code user-settings file; the default is stable Code's user configuration on Linux or macOS. For the default socket with a custom `--config-dir`, start both the server and VS Code with that `CODEX_HOME`. The editor's home must match the managed launcher. An explicit `--wake-socket PATH` can select a separately configured foreground server.

Linux VS Code 1.146.0, extension 26.1111.21308 and packaged Codex 0.167.2 pass registration and three automatic inbox/acknowledgment turns, including editor/Gent restart and delivery after a held busy request. Clicking the actual Stop button leaves queued and new messages paused without starting another model request during the observation. Protocol and installer process checks pass on Linux and macOS, including forwarding approval requests unchanged, waiting for the client's response, rejecting stale installations and exiting on server disconnect. The Mac checks do not establish Mac GUI behavior.

Further Linux checks interrupt the actual UI after a partial text response appears. Queued and newly arriving notifications remain paused without another model request. Clicking Codex's Resume button processes the retained queue entries, and a fresh message then delivers automatically. The first resumed inbox call can retrieve both waiting messages; the next queued notification then finds an empty inbox. Gent preserves the original submission attempts throughout. Scroll to the latest response when inspecting a long chat, because the editor can omit offscreen turns from its rendered document.

A separate synthetic chat requires native approval for `gent_inbox`. Its automatic notification displays Codex's Allow/Deny prompt and leaves the inbox unseen until the test cancels the turn with Stop. Gent supplies no approval response. These checks use a loopback model and do not establish real-model decisions or approval acceptance.

Real-model checks through the managed route now pass on the same Linux pairing, using `gpt-6-astra` at low reasoning. One registration is followed by three automatic exact replies and acknowledgments: initial delivery, after Gent daemon restart and after editor reload. The original agent and thread are retained, with no additional human prompt. The editor displays each response. The test uses a foreground native server with its ordinary authentication and a custom socket; no credential files are copied and saved host configuration remains unchanged. This does not establish a native server restart with a real model.

The shared server controls model, tools, approvals and feature flags. Gent recognizes the tested IDE launch arguments without applying their `-c` overrides to the running server. Unknown invocation patterns fail with an extension-version diagnostic. Version compatibility beyond this tested pairing and Mac GUI acceptance remain unverified. Keep the route experimental until those checks pass.

Run `gent integration install codex --wake` without `--vscode` to remove the IDE route while retaining ordinary MCP and CLI wake. `gent integration uninstall codex` removes both managed integrations. Reload the editor after either change; Gent leaves the native server's lifecycle under Codex control.

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

`cargo test -p gent-link integration::runtime --locked` covers startup refusal for invalid or custom installations, reuse without launching another executable, invalid host responses, literal argument/environment passing and bounded subprocess output. Separate native background-daemon proofs cover startup, read-only live status, client disconnect and planned Codex restart on both OSes.
