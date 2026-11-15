# CI

- macOS CI must be manual-only. Put macOS jobs in workflows triggered solely by `workflow_dispatch`; do not trigger them through pushes, pull requests, schedules, or automatic workflow chaining.
- Use Linux for automatic CI. GitHub-hosted macOS runners consume the owner's monthly minutes too quickly.
- Manual testing on an available Mac is independent of GitHub Actions and remains supported.

# Code quality

- Keep modules focused, with shared behavior behind explicit interfaces.
- For Rust changes, run `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings`, plus tests appropriate to the change.
- Keep the lockfile current. Do not suppress warnings or skip failing checks to obtain a passing result.
