# Development checks

Run the client checks from this checkout:

```sh
scripts/check.sh
```

Install a native C compiler/linker, Python 3.11 or newer, Bash, Zsh and Fish first. The active Rust toolchain needs `rustfmt`, Clippy and the `wasm32-unknown-unknown` target. CI pins Rust 1.100.0; use the same version to reproduce its checks:

```sh
rustup toolchain install 1.100.0 --profile minimal \
  --component rustfmt --component clippy --target wasm32-unknown-unknown
RUSTUP_TOOLCHAIN=1.100.0 scripts/check.sh
```

The script stops on failure and runs:

| Check | Coverage |
| --- | --- |
| `cargo fmt --all -- --check` | Formatting across the four client crates. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Native library, binary, test and example targets. |
| Wasm Clippy with all features | Protocol and crypto libraries, independent of the private service repository. |
| `cargo test --workspace --locked` | Default unit, integration and documentation tests, at optimization level 1 with debug assertions and overflow checks enabled. |
| Native binary build | The `gent-link` package's `gent` executable. |
| CLI smoke | Readable results, JSON/verbose equivalence, terminal animation, pipes and color controls. |
| MCP smoke | Registration, permission isolation, text/images, replies, retries, restart recovery and ordered relay turns. |
| Host binding smoke | Synthetic Codex/Claude metadata and hooks, distinct conversations, reconnects and revocation. |
| Config editor smoke | Terminal editing, private drafts, concurrent writes, profile selection and explicit publication. |
| Shell smoke | Bash, Zsh and Fish startup/completion, literal paths, concurrent installers and preservation of unrelated edits. |

Rust commands keep `Cargo.lock` fixed. The smoke checks use disposable state and foreground processes; they need no accounts, model credentials or installed provider CLIs. They do not install a real OS service. Tests execute temporary fixtures, so `/tmp` and any custom `TMPDIR` must permit execution. The driver uses Cargo metadata to find the binary, so `CARGO_TARGET_DIR` is supported.

Four tests that require local account/relay Workers remain explicitly ignored in the default suite. Run those through the service fixtures in the private parent. Default CI also does not establish native systemd/launchd lifecycle, real provider behavior, hosted OAuth, remote storage, GUI/mobile support or release installation. Those have separate acceptance checks.

## Goal recovery

With Codex 0.170.0 on `PATH`, run the following from the client checkout. The tests launch isolated app-servers and loopback providers. They exercise quota recovery, continuation of an idle goal, a user interruption, and an explicit user block after a provider failure.

```sh
cargo test --locked -p gent-link installed_codex_ -- --ignored
```

With Node.js on `PATH`, run the Claude Code adapter proof. A synthetic host loads the installed plugin and drives its hooks through the native Gent bridge and a disposable daemon.

```sh
cargo test --locked -p gent-link babysitter_installed_plugin_and_native_transcript -- --ignored
```

The private parent also includes a live Claude Code test. From the parent checkout, run `python3 scripts/prove_claude_babysitter.py --gent gent/target/debug/gent` with Claude Code on `PATH`. It creates a disposable goal, returns a provider error over loopback, and checks Claude's transcript for the resumed turn and completed goal.

## GitHub Actions

The `Linux checks` workflow runs on pushes to `main`, pull requests and manual dispatch. It uses one Ubuntu 24.04 job with a 30-minute timeout and cancels superseded runs on the same ref. It validates the workflow with checksum-pinned actionlint and the driver with ShellCheck before running `scripts/check.sh`.

Checkout and dependency-cache actions use commit pins. The job has read-only repository permissions, does not persist checkout credentials and needs no repository secrets. It caches downloaded Cargo dependencies; compiled targets are rebuilt. Native debug information and incremental compilation are disabled to limit runner disk use. Update the toolchain/action pins deliberately, then run the checks before committing.

This repository has no macOS Actions job. Test on a Mac deliberately over SSH. Any future macOS workflow must use only `workflow_dispatch`, without push, pull-request, schedule or automatic workflow chaining. The shared check script defaults to two Rust test threads because parallel fixtures open many independent node databases in one process. For direct Cargo tests, use `RUST_TEST_THREADS=2 cargo test --workspace --locked`. No raised file-descriptor limit is required. Developers can override the thread count when their environment supports more concurrent fixtures.

The private parent has separate Worker and native-tool workspaces; this client workflow does not check them or fetch the parent. Their formatting, strict Clippy and service tests remain separate checks.

## Desktop companion

Linux CI also runs the GTK companion in an isolated D-Bus session, Xvfb display and Openbox window manager. With the desktop dependencies, AT-SPI and its system Python bindings (`python3-pyatspi`), `gio`, Xvfb, Xauth, xdotool and Openbox installed, run the same smoke test after building the binary.

```sh
dbus-run-session -- xvfb-run -a sh -c 'openbox >/dev/null 2>&1 & exec /usr/bin/python3 scripts/smoke_desktop_linux.py target/debug/gent'
```

The test creates its own node and login directories, opens the real tray menu, and checks the status of its foreground daemon after the GUI quits. On a logged-in Mac, the standalone AppKit test exercises the native menu bar and window with a synthetic status snapshot.

```sh
fixture=$(mktemp -d)
xcrun --sdk macosx swiftc -swift-version 5 crates/gent-link/src/desktop/macos.swift \
    crates/gent-link/src/desktop/macos_tabs.swift \
    crates/gent-link/src/desktop/management.swift \
    crates/gent-link/src/desktop/dashboard.swift \
    scripts/desktop-macos/main.swift -o "$fixture/GentDesktopSmoke"
"$fixture/GentDesktopSmoke" assets/branding/inkling-512.png
rm "$fixture/GentDesktopSmoke" && rmdir "$fixture"
```

## Automatic update acceptance

Run `python3 scripts/prove_updates.py --cache /absolute/path/to/disposable-cache`
on Linux or deliberately on a Mac. This builds real Git revisions with Cargo
in an isolated installation and uses two persistent MCP clients. It checks
unchanged/disabled versions, build failure, disabling during compilation,
moving the stable tag during a build, atomic activation, image/message/reply
continuity, startup rollback, explicit retry and notification eligibility.
It also changes daemon code between revisions to check dependency rebuilding.

The `test-updates` feature permits only a local `file:///` release repository
and an isolated installation root. Production builds reject these candidates.
Notification delivery is recorded in the fixture instead of displaying test
notifications. The proof never changes the live cluster or the real stable tag.
The default Rust suite separately verifies accepted-request draining, binary
replacement, journal recovery, file ownership and bounded subprocesses.
