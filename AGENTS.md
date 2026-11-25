# Cluster operations

Expose cluster resources from every enrolled machine with the required permissions.
Resolve the resource through the cluster directory. When a conversation needs its
native host, route the request there on the caller's behalf.

# Completing work and releases

- Land completed client changes on the remote `main` branch and verify that it contains the finished commit.
- Before reporting a client release complete, verify that remote `main` contains the released commit. Maintainers working across both repositories must also land and verify the corresponding client submodule update and release work on the parent repository’s remote `main`.

# CI

- macOS CI must be manual-only. Put macOS jobs in workflows triggered solely by `workflow_dispatch`; do not trigger them through pushes, pull requests, schedules, or automatic workflow chaining.
- Use Linux for automatic CI. GitHub-hosted macOS runners consume the owner's monthly minutes too quickly.
- Manual testing on an available Mac is independent of GitHub Actions and remains supported.

# Code quality

- Keep modules focused, with shared behavior behind explicit interfaces.
- For Rust changes, run `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`, plus tests appropriate to the change.
- Keep the lockfile current. Do not suppress warnings or skip failing checks to obtain a passing result.
