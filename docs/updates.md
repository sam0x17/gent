# Updates and CLI output

With automatic updates enabled, a running Gent daemon checks its cluster’s selected release every five minutes in `sam0x17/gent`. Existing clusters default to stable. Stable resolves `refs/tags/stable` and peels annotated tags. Beta resolves the branch `refs/heads/beta`. Both channels resolve their refs directly through Git. A clean installed executable whose embedded commit matches the selected SHA skips the build.

Use `gent cluster channel get --json` to inspect the selection. Run `gent cluster channel set beta` to follow beta or `gent cluster channel set stable` to return to stable. Channel-aware nodes follow the selected commit even when it is older than their installed build. Upgrade each node to a channel-aware stable build before the cluster’s first switch to beta. Earlier daemons only follow the stable tag and cannot read the signed beta selection.

Install the first updater-capable release once on each machine:

```sh
cargo install --git ssh://git@github.com/sam0x17/gent.git --tag stable --locked --force gent-link
gent daemon restart
```

Git, Cargo, a native compiler and noninteractive access to the GitHub repository must be available to the daemon. Gent first tries HTTPS with the configured Git credential helper, then SSH. Both routes use the same repository and exact commit. A login shell's temporary SSH agent may be unavailable to a background service; saved HTTPS credentials also work. An authentication or build failure leaves the installed binary running and is reported by `gent update status`.

```sh
gent version                 # exact build revision
gent update status           # local state and build-log path
gent update check            # check the selected channel without installing
gent update                  # check and install now
gent update disable          # pause routine updates on this node
gent update enable           # resume following new commits on the selected channel
```

If an update is already running, `gent update` waits for it with a progress indicator, then rechecks the installed release. Ctrl-C during the wait leaves the existing updater running. Scheduled checks skip an update that is already in progress. `gent update status` reports whether an updater currently holds the lock, alongside the saved phase and build-log path; JSON includes `update_in_progress`. A leftover lock file alone does not mean an update is running. The lock is released when its owning process exits; do not delete it to bypass a running updater.

`gent update check --json` resolves the ref live and returns its `channel`, `release_ref` and `blessed_commit`. `gent update status` reads local state. Its top-level channel and ref describe the current selection, while `update.blessed_commit` and `update.phase` describe the last updater run. After a channel switch the saved revision can still belong to the prior channel. On managed installations, `applied_channel` is the last channel the node activated or verified at the same installed SHA. Existing installations start with stable as their applied channel.

Update status distinguishes the calling CLI (`cli`), executable on disk (`installed`), and authenticated daemon's loaded build (`running`). Older daemons that do not report build metadata leave `running` null; their version is never inferred from the CLI. `daemon.reachable` reports whether the status probe succeeded. Pending activation also reports `activation_home` and `activation_starting`.

A manually installed binary can differ from the version already loaded by the daemon. That does not prevent activation of the next verified update. If startup encounters a busy update lock, the daemon keeps serving and retries acknowledgement after authenticated readiness. On older affected versions, a persistent `awaiting activation` whose pending record has `starting: false` can be completed with `gent daemon restart`, followed by `gent update`. A true starting flag requires inspecting daemon status before restarting, because startup recovery may roll back an unacknowledged build.

Automatic updates default to enabled. These commands edit the node-local setting in `~/.gent/config.toml`:

```toml
[updates]
enabled = false
```

Direct TOML edits also take effect without `gent config apply`. This setting is preserved when shared cluster configuration arrives. Disabling routine updates during compilation prevents that routine build from being installed. An installation already published proceeds through activation. Explicit `gent update` still works while paused.

A signed cluster channel switch applies once on each managed node, including nodes with routine updates paused. The daemon checks its local channel on startup and every ten seconds. After an offline node reconnects, it compares the latest signed selection with its last applied channel. A paused node that missed intermediate switches stays pinned if those channels already match. If both refs point to the installed SHA, the node records the switch without running Cargo. After activation, a paused node stays on that commit until another channel switch, a manual update or `gent update enable`.

If a switch fails, the node keeps its previous applied channel and retries on its regular five-minute schedule. A failed startup restores the previous executable and suppresses automatic retries of that SHA. The channel receipt is private to the Gent home and Cargo installation. Older releases can still read the activation journal.

## Installation and restart

The updater operates on the standard `CARGO_HOME/bin/gent` installation (`~/.cargo/bin/gent` by default). Automatic updates skip binaries built from modified source and executables launched from a development checkout. `gent update status` explains unsupported installations.

Cargo builds each exact revision using a dependency cache shared by both channels and a separate staging installation while the existing daemon continues handling messages. The cache lives at `CARGO_HOME/.gent-updates/target/shared/`; the first update using it adopts the installed revision's old cache when available. Gent invalidates its own workspace crates before each build to prevent stale path dependencies across Git checkouts. Cargo reuses compatible third-party artifacts and rebuilds them when dependency versions, compiler versions, targets or flags change. No cache configuration or additional tool is required. The older updater still performs a full build to install the release that introduces this cache; subsequent updates can reuse it.

Gent validates the candidate's package, commit, target and update protocol, then resolves the same ref again and rechecks the selected channel and the existing executable. If channel lookup fails, the ref disappears or moves to another commit, the selection changes during the build, or validation fails, the updater leaves the installed executable in place. A missing beta branch produces an error even when the stable tag is available.

Builds use a lower CPU priority through the system `nice` utility when available. Linux also requests idle I/O through `ionice`, and macOS uses `taskpolicy` background scheduling, when those system utilities are present. These priorities apply to Cargo and its children, not the daemon. They reduce competition with messaging and other foreground work, but cannot eliminate delays caused by unrelated disk load. The default remains two build jobs unless `CARGO_BUILD_JOBS` is set.

Gent saves the previous binary, writes a durable activation record, and replaces the executable with a rename on the same filesystem. The daemon stops accepting new connections, finishes accepted requests and database work, then executes the new binary with the same PID. Inbox and transport queues remain in SQLite; remote nodes can retain messages during the short reconnect window. Ordinary local requests and file uploads wait up to ten seconds for a missing or refused socket before sending any request bytes. Status probes report a stopped daemon immediately. Requests whose outcomes are uncertain after transmission still need an explicit retry with the original request ID; Gent does not blindly replay them. An update cannot promise uninterrupted access to every RPC.

After the new daemon reports authenticated readiness, it refreshes installed Gent integration files through the existing ownership journal. It preserves custom host directories, socket paths, VS Code routing and unrelated settings. Legacy manual-inbox installations gain automatic delivery. Removed integrations stay removed. Entries owned by another node or pinned to another Gent executable are skipped. User-edited Gent fragments are preserved and reported as blocked; this does not roll back a healthy daemon or stop messaging. Refresh retries every five minutes, including when automatic release checks are disabled.

`gent update status` includes integration refresh status. Use `gent integration refresh --json` to inspect/retry individual conflicts. Installs remember custom locations in the node's private `integration-targets.json`; existing default locations are discovered on upgrade. A custom location installed before this registry must be recorded once by rerunning its original install command. Refresh results are stored separately in `integration-refresh.json`.

Existing chat hosts and MCP processes stay open. Claude's native module can reload through its file watcher; captured replies survive a module-generation change using their existing session, attempt and native-turn bindings. Already-running Codex MCP processes keep their loaded code until the host reconnects them. Updating configuration does not prove that a live MCP process has reloaded. Gent does not force a host restart or submit a model turn.

A failed startup before authenticated readiness restores the previous binary. Gent also recovers interrupted publication and startup records. Automatic checks suppress the failed commit on either channel until a check resolves a different commit. Use `gent update install` to retry the selected revision explicitly. Future releases must preserve backward compatibility of stored state for this binary rollback to remain usable.

Update state, the saved binary, compilation cache and bounded build log live in `CARGO_HOME/.gent-updates/`. After a successful build, cache cleanup keeps the shared dependency cache and removes obsolete caches left by older updater versions. The executable's embedded metadata is authoritative. Cargo's installation inventory can continue to show the original manually installed revision after an automatic replacement; use `gent version` for the running command and `gent update status` for activation state.

The Git discovery/build backend is separate from publication and activation so a future crates.io backend can reuse the same installation procedure.

## Desktop notifications

Gent requests one native system notification after an automatic update has been installed and the new daemon has reported readiness. Unchanged versions, failed builds, rollbacks and manual updates do not generate an update notification.

Gent Desktop uses its Inkling icon for update and goal-resumed notifications. On macOS, allow notifications from **Gent** when prompted. To change that choice later, open **Notifications** in System Settings and select **Gent**. On Linux, Gent passes its icon and desktop entry to `notify-send`. Banners require a graphical session and follow the desktop’s notification and Focus settings.

Automatic activation and successful Babysitter resumes from Codex or Claude Code enqueue account events. The daemon publishes them, and each signed-in desktop reads the inbox using its own cursor. On macOS the running menu-bar app submits the notice to Notification Center, including when its window is closed. Quitting the app pauses delivery. The device advances its cursor for a supported event only after the app confirms native acceptance. If permission was just granted, the next read rechecks the account before delivery.

## Terminal output

Ordinary commands show readable status, tables and labeled results. Interactive operations use a pulsing block of dots on stderr while waiting. Animation is disabled for redirected output, `TERM=dumb`, `--json`, `--verbose`, foreground servers, MCP and host hooks. `NO_COLOR` disables color.

```sh
gent daemon status
gent nodes
gent integration status codex
gent update status --verbose   # full formatted JSON response
gent nodes --json              # compact JSON for scripts
```

`--json` takes precedence over `--verbose`. Machine-facing host hooks and `gent integration config` retain their JSON format. Completion scripts remain shell code. Node-name and config-path queries remain plain values by default.
