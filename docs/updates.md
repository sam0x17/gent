# Updates and CLI output

A running Gent daemon checks the `stable` tag in `sam0x17/gent` every five minutes. The tag resolves to a full commit SHA, including annotated tags. Gent compares that SHA with the installed executable's embedded build metadata and runs Cargo only when they differ. There is no update Worker.

Install the first updater-capable release once on each machine:

```sh
cargo install --git ssh://git@github.com/sam0x17/gent.git --tag stable --locked --force gent-link
gent daemon restart
```

Git, Cargo, a native compiler and noninteractive access to the GitHub repository must be available to the daemon. Gent first tries HTTPS with the configured Git credential helper, then SSH. Both routes use the same repository and exact commit. A login shell's temporary SSH agent may be unavailable to a background service; saved HTTPS credentials also work. An authentication or build failure leaves the installed binary running and is reported by `gent update status`.

```sh
gent version                 # exact build revision
gent update status           # local state and build-log path
gent update check            # check stable without installing
gent update                  # check and install now
gent update disable          # stop automatic checks on this node
gent update enable           # resume automatic checks
```

Automatic updates default to enabled. These commands edit the node-local setting in `~/.gent/config.toml`:

```toml
[updates]
enabled = false
```

Direct TOML edits also take effect without `gent config apply`. This setting is preserved when shared cluster configuration arrives. Disabling updates during compilation prevents that build from being installed; it does not cancel an installation already published. Explicit `gent update` still works while automatic checks are disabled.

## Installation and restart

The updater operates on the standard `CARGO_HOME/bin/gent` installation (`~/.cargo/bin/gent` by default). Automatic updates skip binaries built from modified source and executables launched from a development checkout. `gent update status` explains unsupported installations.

Cargo builds each exact revision in its own compilation directory and a separate staging installation while the existing daemon continues handling messages. Gent validates the candidate's package, commit, target and update protocol, then rechecks the stable tag and the existing executable. A changed tag, a changed installation or an invalid candidate cancels publication.

Gent saves the previous binary, writes a durable activation record, and replaces the executable with a rename on the same filesystem. The daemon stops accepting new connections, finishes accepted requests and database work, then executes the new binary with the same PID. Inbox and transport queues remain in SQLite; remote nodes can retain messages during the short reconnect window. A new local request during that window may need a retry with its original request ID. An update cannot promise uninterrupted access to every RPC.

Existing chat hosts and MCP processes stay open. Already-running MCP processes keep their loaded code until they reconnect; Gent does not silently restart the chat host or submit a model turn.

A failed startup before authenticated readiness restores the previous binary. Gent also recovers interrupted publication and startup records. A rolled-back revision is suppressed until the stable tag changes or `gent update install` explicitly retries it. Future releases must preserve backward compatibility of stored state for this binary rollback to remain usable.

Update state, the saved binary, compilation cache and bounded build log live in `CARGO_HOME/.gent-updates/`. After a successful build, cache cleanup retains the installed and candidate revisions and removes older release caches. The executable's embedded metadata is authoritative. Cargo's installation inventory can continue to show the original manually installed revision after an automatic replacement; use `gent version` for the running command and `gent update status` for activation state.

The Git discovery/build backend is separate from publication and activation so a future crates.io backend can reuse the same installation procedure.

## Desktop notifications

Gent requests one native system notification after an automatic update has been installed and the new daemon has reported readiness. Unchanged versions, failed builds, rollbacks and manual updates do not generate an update notification.

macOS uses Notification Center through the system `osascript` command. Linux uses `notify-send` and the current desktop notification service. Notifications need a graphical user session and the relevant OS notification permissions; a headless server or a system-level service may have neither. A notification failure is logged and does not undo a successful update. Delivery is best effort: OS settings, Focus/Do Not Disturb and a crash after activation can prevent the notification from appearing.

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
