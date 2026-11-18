# Diagnose a Gent installation

Run `gent doctor` to inspect this node, daemon, account state, gateway, MCP installations and shell hooks. It reports problems and suggested commands without starting a model or changing setup.

```sh
gent doctor
gent --json doctor
gent --cluster CLUSTER_UUID doctor --online
```

The default performs local reads, a bounded owner-authenticated daemon probe and service-manager queries. `--online` additionally checks a saved account session at its saved Gent service origin, after checking any cluster service/account pins. It sends that session's credential only to the saved origin, refuses redirects and has a five-second request deadline. It does not sign in, renew, log out or save returned account data. The daemon may already be communicating independently in the background.

Exit codes are 0 when the available checks pass, 3 when a check warns or fails, and 2 for invalid command syntax. Optional absent integrations and checks without applicable state are marked `skip`. A successful report does not prove hosted-provider compatibility, GUI configuration, remote chat availability or end-to-end delivery. Read the individual results, including skipped checks.

## Checks

| Check | Evidence and limits |
| --- | --- |
| Configuration | Validates the node's identity/routing and editable names/policy. Invalid local policy edits can be diagnosed while the daemon continues using signed state. A failed cluster identity assertion never selects another node. |
| Local state | Checks owner credential format and protected key/database paths. It does not open or migrate an offline database. After initialization, a missing key or database is a failure. |
| Daemon | Probes an owned, private Unix socket with the owner credential. The response must match the selected node, cluster and diagnostic version. The deadline is two seconds. Older binaries without this operation need upgrading. |
| Authority | The live daemon verifies signed state and reports revision, expiry, membership and a request-clock watermark ahead of wall time. Reconnecting cannot override removal. |
| Config projection | Reports committed configuration waiting for its TOML file write without retrying that write. No pending projection does not mean an unapplied local edit has been signed. |
| Relay | Shows process-local ordered-sync observations: last successful contact, failure time, retrying streams, local errors and notification connection state. A pass requires recent contact/observations with no pending stream failures. Observations older than 90 seconds warn. File transfers and peer delivery require separate evidence. |
| Service | Inspects systemd/launchd registration, enablement, PID and binary availability. A running managed service must match the authenticated daemon PID. Queries have a three-second deadline. Foreground daemons need no managed service. |
| Account | Distinguishes cached, expired, pending-login, pending-logout and remotely verified state. An unexpired cache alone does not establish current service authorization. Shared account-source pins are checked. |
| Gateway | Validates registry/node/cluster pins, clock watermark and active host grants without creating a lock or listener. It does not prove endpoint reachability or provider metadata. |
| Codex and Claude Code | Inspects Gent-managed user-scope entries, required hooks and binary availability. Entries pointing to an obsolete directory are warnings requiring reset and reinstallation. Effective project, GUI and managed-policy settings remain host-specific. |
| Shell | Inspects the managed block and referenced binary. It does not source the startup file or test the current shell. |

Components are observed separately, so this is not an atomic snapshot of the installation. The daemon probe uses a read-only transaction: it does not advance request clocks, project configuration, initialize state, wake synchronization or run maintenance. Existing daemon work can proceed independently. Relay observations reset on daemon restart and never authorize delivery.

## Nondefault installations

Normal host configuration discovery applies. Override a location when diagnosing an installation outside those defaults:

```sh
gent doctor --codex-config-dir /private/codex --claude-config-dir /private/claude
gent doctor --shell zsh --rc-file /private/zsh/.zshrc
gent doctor --shell bash --rc-file /private/bashrc
gent doctor --shell fish --rc-file /private/fish/config.fish
```

Suggested commands retain the selected cluster. Host and shell inspection suggestions retain their corresponding explicit paths. They are advice only. Gent does not execute repairs, launch inference, install services or recreate credentials during diagnosis. For unresolved pins, missing keys or inconsistent database state, preserve the directory and investigate before restarting. Restoring an old database can restore obsolete authority and cryptographic state; safe owner/key-loss recovery remains separate work.

## Structured output and privacy

`--json` returns `version: 1`, resolved `home` and `cluster_id` when available, the online-check choice, and ordered `checks`. Each check has a stable `id`, `status` (`pass`, `warn`, `fail`, `skip`), fixed `summary`, whitelisted `evidence` and optional `next`. Advice contains a message and an optional command as an argument array. Commands for unrepresentable or control-character paths are omitted.

The report includes local paths, node/cluster IDs, process IDs, grant counts and timestamps. It excludes credentials, account names, chat/message content, full policies, raw parser/configuration errors, host output and daemon logs. The separate suggested commands may expose more detail to the local owner. Gent writes no report file automatically.

## Verification

```sh
cargo test -p gent-link doctor
cargo test -p gent-link diagnostic_account
cargo test -p gent-daemon --lib diagnostics
cargo test -p gent-daemon --lib sync::health
cargo test -p gent-daemon --test remote diagnostics
cargo build -p gent-link
python3 scripts/prove_doctor.py --gent target/debug/gent
python3 scripts/prove_service.py target/debug/gent
```

The native proof uses a private disposable node and host configuration. It checks missing setup, both installed MCP hosts, a live daemon, byte/mode/inventory preservation, gateway inspection without lock creation, pending projection, an advanced clock watermark, second-cluster refusal, host-error redaction and an unresponsive socket. Rust tests also verify authentication, unchanged database/config bytes, optional account requests, service/account pins and relay outage/recovery. These checks do not establish backup restoration or lost-key recovery.

The separate service proof creates and removes a temporary service through the real user service manager. It also checks doctor's PID correlation, stopped-service warning, preservation of an edited registration, and foreground-process distinction. It retains its temporary files if cleanup fails.
