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
| MCP smoke | Registration, permission isolation, text/images, replies, retries, restart recovery and ordered relay turns. |
| Host binding smoke | Synthetic Codex/Claude metadata and hooks, distinct conversations, reconnects and revocation. |
| Config editor smoke | Terminal editing, private drafts, concurrent writes, profile selection and explicit publication. |
| Shell smoke | Bash, Zsh and Fish startup/completion, literal paths, concurrent installers and preservation of unrelated edits. |

Rust commands keep `Cargo.lock` fixed. The smoke checks use disposable state and foreground processes; they need no accounts, model credentials or installed provider CLIs. They do not install a real OS service. Tests execute temporary fixtures, so `/tmp` and any custom `TMPDIR` must permit execution. The driver uses Cargo metadata to find the binary, so `CARGO_TARGET_DIR` is supported.

Four tests that require local account/relay Workers remain explicitly ignored in the default suite. Run those through the service fixtures in the private parent. Default CI also does not establish native systemd/launchd lifecycle, real provider behavior, hosted OAuth, remote storage, GUI/mobile support or release installation. Those have separate acceptance checks.

## GitHub Actions

The `Linux checks` workflow runs on pushes to `main`, pull requests and manual dispatch. It uses one Ubuntu 24.04 job with a 30-minute timeout and cancels superseded runs on the same ref. It validates the workflow with checksum-pinned actionlint and the driver with ShellCheck before running `scripts/check.sh`.

Checkout and dependency-cache actions use commit pins. The job has read-only repository permissions, does not persist checkout credentials and needs no repository secrets. It caches downloaded Cargo dependencies; compiled targets are rebuilt. Native debug information and incremental compilation are disabled to limit runner disk use. Update the toolchain/action pins deliberately, then run the checks before committing.

This repository has no macOS Actions job. Test on a Mac deliberately over SSH. Any future macOS workflow must use only `workflow_dispatch`, without push, pull-request, schedule or automatic workflow chaining. On the trial Mac, raise the shell's file-descriptor limit with `ulimit -n 4096` before the Rust suite.

The private parent has separate Worker and native-tool workspaces; this client workflow does not check them or fetch the parent. Their formatting, strict Clippy and service tests remain separate checks.
