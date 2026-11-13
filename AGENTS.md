# CI

- macOS CI must be manual-only. Put macOS jobs in workflows triggered solely by `workflow_dispatch`; do not trigger them through pushes, pull requests, schedules, or automatic workflow chaining.
- Use Linux for automatic CI. GitHub-hosted macOS runners consume the owner's monthly minutes too quickly.
- Manual testing on an available Mac is independent of GitHub Actions and remains supported.
