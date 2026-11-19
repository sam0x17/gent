# Automatic incoming-message delivery

Gent records a local host adapter's attempt to submit incoming-message input before that submission can begin. A lost daemon response or restart cannot grant a second submission for the same message. Managed Codex and Claude Code installations enable adapters by default and use this journal to submit the actual message to loaded conversations.

Native input submission is not assumed idempotent. Gent never repeats a submission after an uncertain response. Claude's adapter uses native plugin input to wait for completed turns and respect explicit interruption. Generic MCP inbox access remains available on both hosts.

For remote use, leave the receiving machine awake and the intended conversation loaded. Installing a connector or seeing a node connection marked ready does not verify automatic input to that conversation. Installation reports `delivery.state: configured_unverified`; `status codex --live` checks the host endpoint, not a particular chat. Verify one authorized message and reply in the intended chat before relying on unattended delivery. Codex receives ordinary new-message input during active work without an interrupt command. Claude retains native plugin-input scheduling. [Selected recovery](host-recovery.md) can separately reopen eligible stopped conversations.

Repeated installation preserves an existing Codex custom socket and VS Code route. Use `--wake` to explicitly select the default socket or `--no-vscode` to remove only the IDE route. Old `--wake` commands remain accepted.

## Enable Codex queued delivery

Use Codex's default local app-server socket:

```sh
gent integration install codex
gent integration start codex
codex --remote unix://
```

Gent selects the Codex configuration directory from `--config-dir`, then `CODEX_HOME`, then `~/.codex`. It pins `<directory>/app-server-control/app-server-control.sock` in the MCP entry, so later environment changes cannot retarget that entry. Installation and `gent integration status codex` report the recorded `wake_socket` without probing the host. `gent integration config codex --wake [--config-dir PATH]` prints the equivalent fragment without editing settings.

For a custom server, provide its absolute advertised socket path:

```sh
gent integration install codex --wake-socket /absolute/path/to/codex.sock
```

The default uses Codex’s standard socket; `--wake-socket` selects a custom endpoint. Restart the host's Gent MCP connection to load the setting. `gent integration config codex --wake-socket PATH` prints a custom fragment. Direct setups can use `gent --home PATH mcp serve --host codex --wake-socket PATH`.

These socket configurations also expose the [native pasted-image tools](providers.md): `gent_host_attachments` lists embedded images from the caller's authenticated conversation, and `gent_file_import_host` imports selected bytes for normal Gent messaging. Host tool approvals still apply. Disabling the socket removes both automatic delivery and these native attachment tools after MCP reconnect.

`gent integration start codex` starts or reuses Codex's native background daemon. It requires an intact managed `--wake` installation belonging to the selected Gent home and using the default socket. It probes the endpoint first; only a missing or refused connection permits launching `codex app-server daemon start`. An unsafe socket, unsupported response, timeout, conflicting installation or custom socket fails without launching a replacement. Gent resolves Codex's socket alias, requires a private socket and directory owned by the current OS user, and verifies the connected peer's user ID.

Use the same `--config-dir PATH` for install, start and status when selecting a nondefault Codex home. Startup also accepts `--host-binary PATH`. Its result supplies the command and `CODEX_HOME` for attaching with `--remote unix://`. Codex manages its own package and background process, including any native updater policy. Gent neither registers another service nor changes that policy. Startup has a 60-second limit and bounds native output. A timeout can leave the native daemon running; inspect live status before retrying.

`gent integration status codex --live` validates the managed installation and probes its default or recorded custom endpoint without starting a host or model turn. It returns `runtime.connected`, a loaded-thread count for one page of at most 128 entries, and `has_more`, or a diagnostic error. It does not expose thread IDs or prove that a particular chat is ready. Ordinary status and `gent doctor` retain their file-only integration checks.

For a foreground server, run `codex app-server --listen unix://` in one terminal, then `codex --remote unix://` in another. Use the same Codex configuration directory for the server and CLI. The socket must serve the conversation using Gent, and that conversation must stay loaded for automatic delivery. Resume it explicitly if needed, or select [automatic recovery](host-recovery.md) for a managed default-socket installation. Gent does not move an existing embedded conversation. A standalone embedded host without that socket continues to use its inbox normally.

After a conversation calls a Gent tool, its host-supplied thread ID selects the registration credential and saves an attachment for the configured socket. One watcher per node, cluster and socket checks loaded conversations against those attachments, visiting up to 128 thread IDs per sweep and waiting five seconds between sweeps. Before claiming a pending message, it reads that exact thread's metadata and requires a loaded idle or active thread that accepts direct input. It submits `turn/start` with only the exact thread ID, client message ID and text. The native host starts an idle turn or accepts the message into active work. Gent does not call `turn/interrupt`, force queue execution, or override host execution settings. A timeout leaves the original claim uncertain; it never falls back to a second submission.

The host receives the message text, a quoted sender label and a message reference. Relay requests say to answer normally: Gent returns the native final answer automatically. If a Codex turn contains multiple user messages, Gent records the exact input identity but does not automatically forward its mixed final answer. The recipient uses `gent_relay_next` and `gent_relay_respond` to return the requested response separately. Permissions are checked immediately before submission; a later revocation cannot retract text already copied into the native host. Attachment descriptors are included, while file bytes remain available through Gent's permission-checked file tools. Host model settings and approval rules remain unchanged. Gent does not answer approval or other server-initiated requests. Owners must configure ordinary host tool access separately.

The adapter lives with the MCP process. A replacement or another opted-in MCP process can recover saved attachments without a new registration, model turn or Gent tool call. An OS lock elects the watcher and releases ownership when its process exits. Recovery reads existing credentials and their scope records without taking ownership away from live MCP connections or creating missing keys. All adapters stop when their MCP processes exit. By default, incoming messages cannot launch a stopped host or load conversations. The Gent daemon can do that for explicitly selected Codex chats through [automatic recovery](host-recovery.md).

Native background-daemon proofs on Linux Codex 0.167.2 and macOS 0.167.0 retain a loaded conversation after its client disconnects. A planned `codex app-server daemon restart` also restores that conversation and automatic inbox/acknowledgment calls with the same Gent identity. These checks use a loopback model and owner-approved Gent tools saved in a trusted project's Codex configuration. Per-thread approval overrides did not survive native restart; configure durable tool access through the host.

Without selected recovery, an abrupt host crash leaves the conversation unloaded after native startup on both tested versions. A message arriving while Codex is down survives a separate Gent daemon crash, but remains pending until the owner resumes the original conversation. Explicit native resume then restores automatic inbox/acknowledgment with the same Gent identity and no new registration. Starting the background server alone is insufficient.

For manual recovery at the default managed endpoint, start the host with `gent integration start codex`, then select the original conversation with `codex resume --remote unix:// THREAD_ID`. Use the same Codex configuration directory for both commands. Alternatively, enable automatic recovery while the conversation is loaded with `gent integration recovery enable codex THREAD_ID`. Incomplete turns and retained native queue entries still require owner review. OS-restart recovery remains unverified.

A separate native check loses a successful queue response, retrieves the message without acknowledging it, then kills both daemons. After explicit startup and resume, the same uncertain journal entry prevents another queue submission. Fresh work still runs. This covers an idle host with durable intake evidence; it does not establish atomic recovery for a crash during model execution or an external side effect.

Unloaded threads, missing sockets, unsupported host APIs and unavailable registrations leave messages pending. A lost response after a claim leaves an uncertain journal record and never triggers a repeated submission. Other attached conversations remain eligible when one fails.

Incoming messages always queue a normal host turn. `gent_send_non_blocking` skips waiting for the reply; it still wakes the recipient. Busy hosts retain queued input, and Gent never forces an active-turn interruption. Web providers without a wake API still require a user turn to retrieve incoming messages.

`gent_identity` reports `delivery: host_dependent` and an `inbox_delivery` snapshot: waiting for host submission, submitted without observed intake, uncertain, and the latest dispatch. `gent wake` distinguishes `submitted_not_seen`, `submission_uncertain` and `seen`. None of these claims live host availability or completed work. Use `gent integration status codex --live` for endpoint connectivity. Discovery of custom endpoints, OS-restart recovery and broader GUI delivery acceptance remain unfinished.

## Enable Claude Code queued delivery

Use the managed installer, then start or restart Claude Code and register the conversation with Gent:

```sh
gent integration install claude-code
```

This adapter is enabled by default in ordinary builds. Gent selects the Claude configuration directory from `--config-dir`, then `CLAUDE_CONFIG_DIR`, then `~/.claude`. `gent integration status claude-code` reports the recorded `claude_wake` installation ID, not live host connectivity. `gent integration config claude-code --wake` cannot produce this managed installation; use `install` instead. The adapter requires Claude's native function hooks and plugin-input API, tested on Linux Claude 2.1.323 and macOS Claude 2.1.311. It does not start a stopped host or load another conversation.

The installer manages a native plugin under the host configuration directory's `skills/gent-wake` and a separate `UserPromptSubmit` command hook in user settings. Version 3 installation records require both and set the command hook's `onFailure` to `block`. Version 1 and 2 records can be upgraded or removed, but cannot dispatch through the new bridge. The installer records the installed module bytes, an installation ID, node and cluster, and checks ownership before upgrading or removing files. Interrupted updates accept the recorded before/after versions; edited files and unrelated hooks are preserved. A pending update, disabled hook, old installation ID or changed binding prevents the Rust bridge from granting a usable response.

Claude can replace its configuration file while Gent validates the installation. These read-only checks allow up to three attempts, with a 10 ms delay between attempts, only when a snapshot changes. Each attempt rereads and validates the complete installation. Changed authorization, unsafe files, malformed configuration and persistent contention still refuse delivery. The initial and final installation checks use this retry policy independently; credential checks, RPCs, claims and native submissions are never retried by it.

The module polls every five seconds, using a bounded JSON subprocess interface with argument vectors. Rust reads the exact session's existing Gent credential and pinned scope without creating missing keys or taking live MCP credential locks. It claims before returning the message text and routing references. Credentials and file bytes never enter that subprocess response. One input remains outstanding per module.

Native `prompt.submit` controls completed-turn queuing and interruption holds. A separate `classic.UserPromptSubmit` hook rechecks the target session and current claim eligibility at delivery. This hook does not infer turn completion from classic Stop events. The adapter correlates a guarded notification with a native `turn.start` UUID for its receipt; its generated attempt ID is not a host acceptance ID. Dropped or lost submissions remain uncertain and are never retried automatically.

The command guard runs independently of the native module. Its delivery footer includes installation, message and attempt IDs, which are references to existing claims, never credentials or submission grants. It checks the event's exact session against the existing binding and claim, current permissions and the complete installation. Invalid or stale notifications return a blocking hook decision. Ordinary human input returns an explicit allow without reading Gent state, including after uninstall. The shell wrapper returns Claude's blocking exit status if the executable fails or is missing. The host's `onFailure` policy also blocks a timeout or an invalid structured verdict. Claude accepts an empty object or plain text as successful command-hook output; Gent emits explicit JSON results. Restart Claude after uninstall before removing the executable, because a retained hook with no executable cannot distinguish a human prompt from a stale notification.

Linux and Mac native tests demonstrate idle delivery, busy boundaries, interruption/rearm, isolation when a claim response is delayed across `/clear`, restored binding after `/resume`, and no repeated submission after a lost claim response and daemon restart. The earlier module-only adapter allowed queued input to run after its guard unloaded. With the command guard, holding delivery until actual watcher unload now produces no extra model request, even though uninstall removed the guard's only settings entry. A probe adding that entry after the host's initial human turn also passes. Uninstall during a busy turn likewise prevents an extra turn; those runs retain the module through the delivery check and therefore prove a different boundary.

Direct module reload drops a held notification, and restoring the installed bytes restores automatic polling without a human prompt. Two actual host restarts exercise a held Rust claim response and a notification already queued by Claude. Resuming the exact session processes a fresh message without registration or a human model turn, while the old claim stays uncertain.

Actual installer replacement with a different executable path creates a new installation ID, blocks old queued input and restores fresh delivery without restarting the host. The tested host retains the old executable for its existing MCP process and hooks. Restart Claude before removing that executable.

Native stream observation also confirms that Escape during a partial text response aborts that exact turn. Both an already queued notification and a new arrival cause no further model request. Explicit human input rearms delivery, and a fresh notification runs without replaying either old attempt. These lifecycle proofs use isolated native hosts and a loopback model.

Separate real-model checks on both OSes use one initial registration turn and three automatic reply/acknowledgment exchanges. They cover initial delivery, a Gent daemon restart, and an actual Claude restart into the same synthetic session. Chat identity and native submission receipts remain exact, and resumed delivery needs no registration or human model turn. Those checks do not establish arbitrary crash recovery, operating-system restart or GUI delivery.

### Claude live status

```sh
gent integration status claude-code --live
```

Use the same `--config-dir PATH` as installation for a nondefault profile. `--host-binary PATH` selects the Claude executable; the default is `claude`. Gent validates the managed installation before and after running `claude agents --json --all` in that profile. Both ordinary MCP and wake installations are supported. A pending update, conflicting files, disabled hooks or changed node/cluster refuses inspection. The command has a 15-second limit, bounds each output stream to 1 MiB and accepts at most 1,024 sessions.

The result includes `runtime.inspected`, `reported_running`, `session_count` and `sessions`. Each row preserves the native kind, working directory, reported PID, status/state and available session identifiers. Interactive sessions can lack the short `native_id`; Gent leaves it null. Titles and conversation content are omitted. An inspection failure returns `inspected: false` and an error without native stderr.

Rows with a reported PID become `reported_idle`, `reported_busy` or `reported_running`. Rows without one become `inactive_complete` for native `done`, `inactive_incomplete` for native `working`, `blocked` or `waiting`, and `inactive_unknown` otherwise. Stopping a completed session can retain `done` or produce `stopped`. These are native observations: an incomplete record does not prove recovery is underway, and a completion marker does not establish successful external work.

`gent_bindings_checked` is false: the inventory does not authenticate Gent chat bindings or prove a chat can receive messages. Gent does not register chats, edit configuration, or start/resume sessions during inspection. The native Claude CLI can maintain its own profile cache.

### Native Claude background sessions

Claude can keep an existing conversation in its own background service. After using Gent in that conversation and stopping its interactive host, run Claude from the conversation's working directory with its native session UUID:

```sh
claude --bg --resume SESSION_ID
```

Use the same Claude configuration directory and configure any required Gent tool approvals in the saved host settings. Gent does not change the model or approval policy. On the tested Linux/macOS versions, explicit background resume retains the Gent chat, and messages survive Gent restart and native stop/resume.

Native background crash recovery depends on the session's state. In isolated SIGKILL tests, an idle session remained unloaded during a 20-second observation and delivered its queued message after explicit resume. For a crash during a streamed response, Claude's own background service restored the session and continued its unfinished turn without a new user prompt or Gent submission. Gent retained the old dispatch claims and unacknowledged messages, then delivered fresh work normally.

Inspect `claude agents --json --all` and use `claude attach ID` for an already running session. An explicit resume while the session is running or recovering can create a copy. Opt-in [selected recovery](host-recovery.md#select-a-claude-background-chat) can reopen an eligible saved background chat. Its single-use dispatch claims govern Gent submissions; they do not prevent native recovery from continuing saved work. Check `gent_work_status` before repeating consequential operations. These tests do not establish OS-reboot recovery or atomic external actions.

### Reopen a Claude background chat

After the original conversation has registered with Gent and entered Claude's native background service, its owner can reopen it with:

```sh
gent integration start claude-code SESSION_ID
```

Supply its full native session UUID, available from live status. Use the same `--config-dir PATH` as installation; `--host-binary PATH` selects the Claude executable. Gent requires its daemon, a current intact `--wake` installation and an existing local binding. An absent session, interactive-only session, unknown binding or mismatched native ID fails before attachment. Initial adoption into Claude's background service still uses Claude's own controls.

Gent selects the session's exact short native ID from the inventory and invokes `claude attach` with closed stdin. It supplies no model input or settings overrides. A reported live worker is reused. For an inactive session, Gent first allows three seconds for the native supervisor to reconcile a recent exit, then makes at most three attachment attempts with two seconds between observations. The complete operation has a 30-second limit; command output is bounded and is not copied into the result. An exit code alone cannot establish success: Gent checks the installation, saved binding, native identity and reported worker before returning.

The result contains the selected Gent chat, session metadata, `native_attach_attempts`, and `action: already_running` or `attached`. `gent_binding_checked: true` refers to the saved binding confirmed by Gent's daemon; `reported_running` comes from Claude's native inventory. This does not establish model availability or completion of pending work. On an error or timeout, inspect live status before retrying because the native service may have acted.

Native Linux/macOS checks retain the original chat through live reuse, concurrent starts after a planned stop, and an idle worker crash plus Gent restart. Ordinary wake delivery retrieves and acknowledges pending messages afterward. This command does not enable [automatic recovery](host-recovery.md#select-a-claude-background-chat); select that separately. Explicit attachment can let Claude continue its own saved work; review unfinished actions through the work journal before reopening an interrupted session. OS reboot and loss of Claude's background service remain unverified.

## VS Code delivery

Linux VS Code 1.146.0 with Claude Code extension 2.1.325 now passes automatic inbox/acknowledgment delivery through the installed user-scope `--wake` integration. The actual UI shows the plugin prompt and completed response. A notification waits through a held model stream; clicking Stop holds both queued and new notifications. Explicit human input permits fresh delivery without replaying old claims. Editor reload plus Gent daemon restart preserves the session and chat, and another message runs without registration or human input. Managed installations always include automatic delivery.

These lifecycle checks use an isolated profile, owner-approved Gent tools and a loopback model. Separate real-model checks with Sonnet 4.6 now pass three automatic exact replies and acknowledgments: initial delivery, after a Gent daemon restart, and after editor reload. All three retain the same session and chat, with one initial registration and no additional human model turn. Native transcripts and stored message results agree; the final exchange also has an independently matched native submission receipt. macOS IDE wake and standalone desktop wake still need acceptance checks.

The tested Codex extension, `openai.chatgpt` 26.1111.21308 with bundled Codex 0.169.0-alpha.11.1, launches an embedded stdio app server without Gent's required Unix endpoint. Its managed `--wake` installation remains disconnected and messages stay pending. Reopening the original chat and asking it to check its inbox retrieves and acknowledges the message after editor/daemon restart. `gent integration start codex` starts a separate native background server; it does not move an embedded IDE chat to that server.

A separate experimental Rust route now connects a fresh IDE chat to the native background server through the extension's development-only executable override:

```sh
gent integration install codex --vscode
gent integration start codex
```

Reload VS Code, then open or explicitly resume a conversation. Installation preserves unrelated settings and JSON comments, refuses unknown executable overrides, and records enough information to recover an interrupted update. It installs a small private shell launcher that invokes Gent's Rust transport. `--vscode-settings PATH` selects another VS Code user-settings file; the default is stable Code's user configuration on Linux or macOS. For the default socket with a custom `--config-dir`, start both the server and VS Code with that `CODEX_HOME`. The editor's home must match the managed launcher. An explicit `--wake-socket PATH` can select a separately configured foreground server.

### AI Provider Switcher

AI Provider Switcher manages `chatgpt.cliExecutable`. With its app-server-wrapper compatible version (0.2.1), Gent preserves that setting and uses `aiProviderSwitcher.codex.appServerWrapper` instead. Upgrade the switcher, run **AI Provider Switcher: Refresh Models**, then run:

```sh
gent integration install codex --vscode
```

Run **AI Provider Switcher: Refresh Models** again so it picks up the wrapper, then reload the window and reopen the original chat. Ask it to call `gent_identity` or check its Gent inbox to attach its existing chat to this window. Each window starts its own native Codex server with a private socket. This route needs no `gent integration start codex` command. Keep the editor and receiving computer running for unattended delivery.

The switcher retains provider credentials, model choices and routing. Gent preserves its native invocation and overrides only Gent's MCP command/arguments and the app-server transport. It does not save provider settings in its installation journal. Closing the window stops the native process it started. Reopening a chat requires a Gent tool call to attach its saved identity to the new socket; no new registration or enrollment is needed. Automatic recovery of a closed editor window is not supported.

`gent integration status codex --live` reports this route as `per_window`, with connectivity unverified. Probing the separate CLI socket cannot establish editor connectivity. Verify an actual message and reply in the intended chat; use `gent wake` to inspect delivery attempts. The ordinary CLI integration retains its separately configured socket.

The installer requires the switcher's capability marker and refuses older or unknown executable overrides with an upgrade diagnostic. It can recover interrupted wrapper installation and removal. Uninstall removes Gent's wrapper setting and launcher while preserving the switcher's CLI setting and provider configuration.

### Shared-server route validation

Linux VS Code 1.146.0, extension 26.1111.21308 and packaged Codex 0.167.2 pass registration and three automatic inbox/acknowledgment turns, including editor/Gent restart and delivery after a held busy request. Clicking the actual Stop button leaves queued and new messages paused without starting another model request during the observation. Protocol and installer process checks pass on Linux and macOS, including forwarding approval requests unchanged, waiting for the client's response, rejecting stale installations and exiting on server disconnect. The Mac checks do not establish Mac GUI behavior.

Further Linux checks interrupt the actual UI after a partial text response appears. Queued and newly arriving notifications remain paused without another model request. Clicking Codex's Resume button processes the retained queue entries, and a fresh message then delivers automatically. The first resumed inbox call can retrieve both waiting messages; the next queued notification then finds an empty inbox. Gent preserves the original submission attempts throughout. Scroll to the latest response when inspecting a long chat, because the editor can omit offscreen turns from its rendered document.

A separate synthetic chat requires native approval for `gent_inbox`. Its automatic notification displays Codex's Allow/Deny prompt and leaves the inbox unseen until the test cancels the turn with Stop. Gent supplies no approval response. These checks use a loopback model and do not establish real-model decisions or approval acceptance.

Real-model checks through the managed route now pass on the same Linux pairing, using `gpt-6-astra` at low reasoning. One registration is followed by three automatic exact replies and acknowledgments: initial delivery, after Gent daemon restart and after editor reload. The original chat and thread are retained, with no additional human prompt. The editor displays each response. The test uses a foreground native server with its ordinary authentication and a custom socket; no credential files are copied and saved host configuration remains unchanged. This does not establish a native server restart with a real model.

The shared server controls model, tools, approvals and feature flags. Gent recognizes the tested IDE launch arguments without applying their `-c` overrides to the running server. Unknown invocation patterns fail with an extension-version diagnostic. Version compatibility beyond this tested pairing and Mac GUI acceptance remain unverified. Keep the route experimental until those checks pass.

Run `gent integration install codex --no-vscode` to remove the IDE route while retaining ordinary MCP and CLI wake. `gent integration uninstall codex` removes both managed integrations. Reload the editor after either change; Gent leaves the native server's lifecycle under Codex control.

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
| `inbox_seen_at` | An inbox call returned the message or the native adapter confirmed its intake. Direct records separately identify the native turn. |
| Message acknowledgment | The recipient separately acknowledged receipt through the messaging protocol. |
| Work journal | The recipient or owner separately reported task progress and outcomes. See [interrupted work](work.md). |

Inbox observation does not resolve an uncertain dispatch. A submission report neither acknowledges the message nor records work completion. A claim grants no authority to perform the requested task.

## Adapter contract

The original four local chat RPCs remain available to already-loaded legacy adapters. They use the registration credential and are absent from the model-callable MCP tools:

1. `wake_pending` returns up to 50 currently accessible, unacknowledged, unexpired message IDs and expiry times with no existing claim. It includes no message text or files.
2. `wake_claim` accepts a message ID, unique attempt ID and target. Only the first committed claim returns `may_submit: true`. An exact retry returns the saved record with `may_submit: false`, including after restart. Changing the attempt or target for a claimed message fails.
3. `wake_check` checks an existing claim against its chat, attempt and host conversation. Its `eligible` result also requires an uncertain claim and a currently accessible, unacknowledged, unexpired message visible in the relay queue. It creates no record, changes no evidence, and grants no submission permission. Only an adapter still holding the original successful claim response may use it before submitting; it cannot authorize recovery of an uncertain submission.
4. `wake_submitted` records the host submission ID against the exact attempt. Repeating that report preserves the result; conflicting IDs fail. It can record an already attempted submission after peer permissions change, but still requires the authorized, unrevoked local registration and node.

New claims recheck message permissions and relay queue visibility. All journal transitions use the existing immediate SQLite transaction. Adapter RPCs do not update chat `last_seen`, so background polling does not make the model appear active.

Targets identify either a Codex thread UUID or a Claude Code session UUID. Host type is part of the target: identical UUID text under different hosts does not identify the same dispatch. The journal itself trusts the adapter's target report. The Codex adapter obtains its UUID from the same host metadata used to select the chat credential, then checks the connected server's thread identity and capability before claiming. The Claude bridge reads the existing session binding and its pinned scope. Adapters must preserve this binding and the host's busy queues and interruption holds. A process crash between claim and submission can leave an unused claim permanently uncertain. Never blindly retry an external submission after a lost response.

## Direct messages and automatic replies

A relay target receives a short label followed by the original message, for example:

> User relay via Gent ("coordinator"). Answer normally; your final response is returned automatically.

The adapter returns the final text from that exact native turn through the existing encrypted relay. It never forwards the latest unrelated assistant output. Codex matches the saved client input ID and original prompt hash in native turn history; multiple user inputs in one turn are not eligible for automatic capture. Claude binds its validated plugin input to `turn.start`, persists the route in native plugin storage, and captures the matching `turn.complete` result. Child-chat turns are excluded. An interrupted or failed turn reports that outcome without replaying the input.

The recipient need not call inbox or relay tools for a plain-text answer. Ordinary chat messages still use normal Gent reply tools. Relay replies arriving at an intermediary are delivered directly for verbatim presentation; they do not generate another automatic reply. Messages remain attributed to their sending chat. A relay label is not proof of human authorship or permission for host actions. Consequential work still follows the work journal and the host's approval rules.

The direct RPCs (`wake_direct_claim`, `wake_direct_read`, `wake_direct_pending`, `wake_direct_observe`, `wake_direct_complete`) are adapter-only and absent from MCP's model tools. They persist the input hash, native turn binding, reply request ID and final response hash. Committing the response and finishing the journal record is one transaction. An identical completion retry returns the same response; a changed native turn or answer is refused. A manual final relay response, including one carrying files, suppresses automatic duplication.

Attachments continue through Gent file tools. Inline-file messages stay in the inbox until retrieved/acknowledged or the relay completes. Native file links, images and generated artifacts are not automatically converted into Gent attachments; use an explicit file-bearing relay response for those.

Codex can recover completed native text from retained turn history after an MCP or daemon restart. Claude saves captured results in native plugin storage and retries delivery after a daemon outage. A replacement module can drain an older generation’s captured results for the same session and exact native turn; the daemon revalidates the existing attempt and current permissions. A crash before Claude captures the result can leave an uncertain turn requiring inspection. Neither adapter resubmits uncertain input. Revocation and expiry can prevent returning an already-produced answer.

Updates automatically refresh managed integration files after the new daemon is healthy. Claude can pick up its module through native file watching. Reconnect Gent's Codex MCP process to load new adapter code if the host has not already done so. An already-running old adapter continues its legacy inbox notification behavior until replaced. Use `gent integration refresh` to inspect/retry a blocked refresh.

## Storage and recovery

Each opted-in Codex binding keeps a private, versioned `.key.wake.json` sidecar beside its existing credential. It contains the node, cluster, canonical thread ID, a credential hash and the advertised socket path. It contains no credential or message content. Recovery requires the existing key, matching scope and current daemon authorization. Corrupt, oversized, linked, unsupported-version or substituted records are refused without repair. Offline backup guards apply before host connection and credential recovery.

Attachments are scoped to the advertised socket name, preserving Codex's rendezvous alias across server restarts. Parent aliases such as macOS `/tmp` and `/private/tmp` normalize to the same endpoint. The next Gent call through an explicitly configured different socket updates that conversation's attachment. Ordinary bindings created without queued delivery are never adopted automatically.

Dispatch records live in the selected node database's `wake_dispatches` table, with an independent schema marker. Missing versioned storage, an unversioned existing table or an unsupported version fails startup. Reading a malformed or inconsistent record fails without granting a new submission.

Each database admits 16,384 records of at most 2,048 payload bytes each. New claims are limited to 720 per chat per hour and 7,200 per database per hour, with at least five seconds between a chat's claims. At most 512 unresolved direct deliveries per chat are admitted; observed ordinary input releases that capacity. These limits use the persisted request clock. Admission failure leaves the message pending; exact claim retries grant no additional submission. The limits do not bound a host's inference cost or external actions.

Records contain local chat, message, attempt and host-thread identifiers plus timestamps and submission evidence. They do not copy message content and are not replicated or sent to the centralized service by these operations. The existing trusted-OS-user boundary applies.

Inspect and clean the selected node's journal with owner commands:

```sh
gent wake status
gent wake clean --dry-run
gent wake clean
```

Cleanup removes at most 128 records per call, ordered by claim time and message ID. A record is eligible only when it reports a native submission, has an inbox observation or confirmed native intake, its source message has been removed by history retention, and at least seven days have passed since its last update. Legacy request admission must also have ended. A late submission report starts a fresh seven-day retention period. Submission and inbox evidence establish delivery, not completion of external work; the separate work journal is unchanged.

The daemon runs the same cleanup after message-history maintenance at startup and every 15 minutes. `gent history clean` only retires message history; a subsequent `gent wake clean` can then retire eligible dispatches. Status reports capacity, uncertain records, unobserved submissions and cleanup eligibility. Preview validates the same records and changes no journal entries. Malformed evidence or a failed deletion aborts cleanup, rolling back all deletions in that batch.

Uncertain attempts and submissions without an inbox observation survive cleanup and revocation. They can still exhaust the journal; cleanup does not guarantee space under sustained load. The retention delay exceeds the maximum request/message replay window, including both clock-skew allowances, and uses the persisted monotonic clock. A retired message cannot receive another claim, even after restart or timestamp rewriting. Old reports fail once their record has retired. Attempt identifiers are unique among retained records; adapters must continue generating fresh IDs for new messages.

There is no reset, retry approval or automatic reconciliation. Preserve uncertain evidence at capacity. Manually deleting records, changing message IDs or rolling back a backup must not be used to repeat uncertain work. Offline backup guards remain required; see [recovery](recovery.md). Lost-node migration and verified host reconciliation remain unfinished.

## Verification

```sh
cargo test -p gent-daemon --test wake --locked
cargo test -p gent-daemon --lib retired_wake_claim --locked
cargo build -p gent-link --locked
python3 scripts/prove_wake_journal.py --gent target/debug/gent
```

Twenty-two journal tests cover restart, exact retries, conflicting attempts, concurrent claims, failed writes, permissions, expiry, revocation, storage and rate limits, and independent message/work state. They also cover read-only claim checks, Claude session IDs, cross-host target substitution, retention boundaries, legacy admission, bounded cleanup, malformed evidence and transaction rollback. Direct-delivery cases add native turn binding, response retries, atomic rollback, current permission checks, cancellation, manual reply suppression, rename recovery and inline-file availability. A separate network test retires a delivered claim and rejects both original and timestamp-rewritten remote replays after restart. The journal process proof drops a committed claim response, restarts the daemon and verifies that the retry grants no new submission. It also checks MCP tool exclusion, inbox observation, owner preview/cleanup, replay rejection and startup maintenance using synthetic submission reports and a disposable admission clock. It invokes no host queue or model.

`cargo test -p gent-link wake --locked` additionally covers thread identity and capability gates, exact queue response binding, private socket requirements, refusal to answer host approval requests, installation upgrades/removal, saved attachment validation, watcher election, endpoint isolation, opt-out and bounded loaded-thread pages. Native installed-Codex proofs separately exercise actual metadata, queues, MCP calls, interrupted holds, lost queue responses and delivery after actual MCP process replacement. Real-model acceptance uses fresh synthetic conversations and normal host model access; its restart check covers the Gent daemon. Those proofs do not establish GUI support or exactly-once host execution across a Codex crash; Gent's journal controls its own submissions.

`cargo test -p gent-link integration::runtime --locked` covers startup refusal for invalid or custom installations, reuse without launching another executable, invalid host responses, literal argument/environment passing and bounded subprocess output. Separate native background-daemon proofs cover startup, read-only live status, client disconnect and planned Codex restart on both OSes.
