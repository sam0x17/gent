# Install from source

Gent currently supports source installation on Linux and macOS. The crate is not published yet. Use the future-public `gent` checkout, which contains the four Rust crates and its own `Cargo.lock`:

```sh
cargo install --locked --path crates/gent-link
gent --version
gent daemon install
```

The package is `gent-link`; its executable is `gent`. Cargo normally installs it under `~/.cargo/bin`. Rust 1.98 or newer and a working native C compiler/linker are required. On macOS, install the Xcode command-line tools. On Linux, install your distribution's C build tools. SQLite is bundled; HTTPS uses Rustls. Building requires access to the locked crates.io dependencies or a populated Cargo cache.

For access to the private GitHub source, install or upgrade directly:

```sh
cargo install --locked --git ssh://git@github.com/sam0x17/gent.git gent-link --force
```

`gent daemon install` guides GitHub login and cluster creation or pairing, then installs a user service. The default account and relay services are deployed for the owner-only private trial. See [service setup](service-setup.md#add-another-machine-through-gent) to join an existing cluster through Gent. For an independent local trial:

```sh
gent daemon install --local demo
gent integration install codex
gent integration install claude-code
gent hooks install --shell zsh
gent doctor
```

Linux uses systemd user services; macOS uses LaunchAgents. This setup needs a working user service session. Headless systems without one can run `gent daemon run` in the foreground. Shell setup also supports `--shell bash` and `--shell fish`. Integration installation preserves unrelated host settings. New clusters allow registered chats to discover and message each other by default; [explicit restrictions](permissions.md) still apply.

Installing the daemon also registers Gent Desktop for graphical login. Open it with `gent desktop`. Linux desktop users need GTK 3 and the system Python bindings. [Desktop requirements and login options](desktop.md)

Host installation enables [automatic incoming-message delivery](wake.md) by default for Codex and Claude Code. Codex also needs `gent integration start codex` and a conversation attached with `codex --remote unix://`. For its experimental [VS Code route](wake.md#vs-code-delivery), install with `--vscode`, start the server, then reload the editor and open or explicitly resume the original chat. Claude Code needs a host restart to load its plugin. Reinstalling preserves an existing custom socket and VS Code route; automatic delivery is always enabled. Verify a message and reply in the intended chat before leaving it unattended.

For a separate install prefix, add `--root /absolute/install/prefix` to `cargo install`, then use its `bin/gent`. The daemon records the installed executable's absolute path. Keep that executable available while its service or connector entries are installed. Use `--home /absolute/state/path` to isolate Gent state for a trial. The hidden `--cluster` option only asserts that the selected node belongs to that cluster; it never selects a profile.

## Private source archives

A prepared source archive contains one committed version of this repository, including `Cargo.lock`, the embedded Gent skill, tests and documentation. It has no Git metadata or private service implementation. Verify its independently supplied manifest/digest before extracting it, enter its `gent-VERSION` directory, and run the same `cargo install --locked --path crates/gent-link` command. The archive includes the [client license](../LICENSE) and [notices](../NOTICE.md).

Keep the commit and archive manifest with the installed version. A successful source-install proof establishes that this archive supplies the binary and its embedded resources; it does not establish that the hosted service is deployed, that GUI/mobile connectors work, or that the build ran on a pristine operating system.

## Upgrade and remove

Stop the selected daemon before replacing its executable, retain an encrypted backup when upgrading persistent state, then install the reviewed source version:

```sh
gent daemon stop
cargo install --locked --path crates/gent-link --force
gent daemon install
gent integration install codex
gent integration install claude-code
gent doctor
```

Use the same install prefix and Gent home as before. Rerunning integration installation updates Gent's managed entries. Database upgrades can be one-way; copying an old database back into a live node is not a rollback procedure. Follow [backup and recovery](recovery.md) for archived state.

To remove the integration and executable:

```sh
gent integration uninstall codex
gent integration uninstall claude-code
gent hooks uninstall --shell zsh
gent daemon uninstall
cargo uninstall gent-link
```

Remove any Bash/Fish hooks you installed as well. For a custom Cargo prefix, pass the same `--root` to `cargo uninstall`. Daemon uninstallation preserves Gent keys, configuration and queued messages. Host conversations remain with their provider.

After an explicit public-release decision and Cargo publication, the intended setup is `cargo install gent-link && gent daemon install`.
