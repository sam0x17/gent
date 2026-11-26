# Publishing Gent

The four crates share a workspace version. A version tag such as `v0.1.0` starts the Linux **Publish Gent** workflow. The tagged commit must be reachable from public `main` or `stable`. The workflow builds and tests the locked workspace, packages all four crates, publishes missing versions in dependency order, installs `gent-link` from crates.io, and verifies the installed binary’s version and Git commit before creating the GitHub Release. SemVer prereleases such as `v0.2.0-rc.1` get GitHub prereleases.

## One-time setup and first publication

Create the GitHub environment `crates-io` with a deployment rule allowing release **tags** matching `v*`. Limit who may create or update those tags. Configure each crate’s trusted publisher for repository `sam0x17/gent`, workflow filename `release.yml` and environment `crates-io`. crates.io requires a first publication before an owner can add the trusted publisher. Future releases use the official auth action’s short-lived token. [crates.io trusted publishing](https://crates.io/docs/trusted-publishing)

For the first publication, use a clean Linux checkout of the final release commit and Cargo 1.100.0, matching the workflow. Use the maintainer’s credentials locally. From the workspace root, run:

```sh
export RUSTUP_TOOLCHAIN=1.100.0
cargo test --workspace --locked
cargo package --workspace --locked
python3 scripts/release.py bootstrap-check
```

The check prints the commit, archive SHA-256, and registry status for each crate. For each **missing** crate, in the order shown below, run `cargo publish --locked --registry crates-io -p NAME`. Wait for the command to finish, then rerun `bootstrap-check` to verify its published bytes before continuing.

1. `gent-protocol`
2. `gent-crypto`
3. `gent-daemon`
4. `gent-link` (installs the `gent` binary)

Push the version tag at that **same commit** after all four versions verify. The workflow skips token exchange and publication when the matching packages already exist. It still performs the registry install and creates the release.

## Subsequent versions and retries

Update the workspace version, exact companion dependency versions, and lockfile together. Land the intended source, then push its matching version tag. To retry, rerun the workflow or use `gh workflow run release.yml --ref v0.1.0`, substituting the original tag. Manual dispatch requires the workflow to exist on the default branch.

A retry accepts an existing version only when its index checksum and downloaded archive match the package from the tagged checkout. The package must carry that commit and crate path in Cargo’s VCS metadata. An accepted upload may take time to appear in the sparse index. If propagation times out or an upload returns an uncertain result, retry the same tag after it settles. A yanked version, conflicting bytes, moved tag, published dependent with a missing dependency, or conflicting GitHub Release stops the workflow. Inspect the conflict before continuing. A source correction after publication requires a new version. [Cargo publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
