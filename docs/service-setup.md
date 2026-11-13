# Service cluster setup

The source build can provision an owner and join additional nodes through private-file invitations or a trusted SSH channel against a configured Gent account service. The public account and messaging services are not deployed yet. Real GitHub consent remains unverified.

The [invitation enrollment guide](invitation-enrollment.md) documents the implemented commands, protected file transfer, expiry and interrupted-join recovery.

For a configured service, run the guided installer in a terminal:

```sh
gent daemon install
```

On an unconfigured node it asks whether to create a cluster or join with a private invitation, collects the missing name/file, signs in with GitHub, and starts the per-user service. It offers shell PATH and completion setup for Zsh, Bash or Fish. Each step remains available independently:

```sh
gent auth login
gent cluster new my-cluster
gent daemon install
gent hooks install
```

For explicit setup or a headless machine:

```sh
gent daemon install --new my-cluster --headless
gent daemon install --invite-file /private/path/laptop.gent-invite --name laptop --headless
```

`--headless` allows device login; `--no-browser` prints the browser login URL and waits for its callback instead of opening a browser. `--service ORIGIN` selects an alternate account service. The installer never selects that origin from a newly supplied invitation. Existing setup pins the account service and relay; changing `--service` cannot move it.

JSON output and non-terminal input never trigger setup questions. Sign in separately, then pass `--new NAME` or `--invite-file FILE --name NODE` with `--no-input` for scripts. `--no-input` also prevents starting login. An explicit `--headless` or `--no-browser` may initiate the existing bounded login flow without a terminal. Add `--hooks --shell zsh` (or `bash`/`fish`) to install shell support explicitly; `--rc-file PATH` chooses a startup file. Shell setup preserves unrelated content. A shell failure after enrollment reports that the daemon is already installed and gives the separate retry command.

The installer checks service-manager availability and service ownership before sign-in. Cancellation or missing choices leave a fresh state directory uncreated. Completed installs preserve node identity and can be repeated while the managed daemon runs, without an account request or a daemon restart when the service definition is unchanged. Interrupted cluster creation resumes with bare `gent daemon install`; interrupted invitation enrollment needs the original file/name, or an explicit `--continue` with a valid replacement. Pending SSH joins must resume through the original `gent cluster join --via ...` command. Stop the daemon before a retry that needs enrollment or credential repair. The running daemon renews active sessions before expiry; expired credentials still require the reconnect procedure below.

After installation, connect hosts with `gent integration install codex` and `gent integration install claude-code`. The daemon installer prints these commands; host settings use their separate installers.

Use `gent auth login --service https://YOUR_ACCOUNT_ORIGIN` for an alternate deployment. The account service advertises its relay through authenticated `GET /v1/transport/config`. Account credentials go only to the saved login origin. The CLI accepts HTTPS origins, with HTTP restricted to explicit loopback fixtures; an HTTPS account service cannot select an HTTP relay. The initial relay address is pinned locally. A later discovery response cannot silently move an existing node to another relay.

`gent cluster new NAME` requires an unconfigured state directory, allowing an existing login under `auth/`. It creates the node and cluster UUIDs, owner signing key, node signing key and signed genesis locally before reserving their IDs at the account service. The service receives those IDs and a transport credential, never the signing keys, policy or display names. The credential grants access to cluster ciphertext; local signed authority still controls agents and decryption.

`--local` retains the independent development setup. Existing development or SSH-paired clusters are not automatically converted to service transport. They can have compacted mailbox history that requires a separate migration procedure.

## Add another machine with an invitation

Sign into the same Gent service and GitHub account on both machines. With the owner daemon running, create a private invitation file:

```sh
gent cluster invite --out /private/path/laptop.gent-invite
```

Transfer that file through an independently trusted channel. On the new machine:

```sh
gent cluster join --invite-file /private/path/laptop.gent-invite --name laptop
gent daemon install
```

Alternatively, combine enrollment and service installation with `gent daemon install --invite-file /private/path/laptop.gent-invite --name laptop`. A repeated completed install with that same file/name preserves the running service. Keep the private invitation available for retries until setup finishes.

The file expires after 15 minutes. Its secrets authenticate the native encrypted enrollment channel; the service cannot supply a replacement trust anchor. Each node gets its own transport credential and keeps its signing key locally. New nodes may edit configuration by default; create the invitation with `--no-configure` for messaging-only membership.

Rerun the original command after an interruption. An expired or revoked offer requires an explicit replacement and `--continue`; see the invitation guide before replacing a partially completed join. `gent cluster invitations` lists offers, and `gent cluster invitations revoke INVITATION_ID` closes admission without removing membership already granted.

## Add another machine through SSH

On the new machine, sign into the same Gent service and GitHub account as the owner:

```sh
gent auth login
gent cluster join CLUSTER_UUID --via user@owner-host --name laptop
gent daemon install
```

The owner's daemon must be running and its SSH host key already trusted. Use `--remote-gent` or `--remote-home` for nondefault owner paths. Service joins use the owner's pinned relay address and reject `--relay-endpoint` overrides. For local service proofs, mirror the loopback account and relay ports over SSH so both machines see the same origins.

An owner configured by the earlier source build may lack the new local `[service]` metadata. Stop its daemon, run `gent cluster connect`, then start it again before accepting service joins. This adds metadata from its pinned setup record without changing keys or relay storage.

SSH protects the trust anchor, signed enrollment request, configuration grants and key packages. The joining machine creates its signing key locally; the owner signs its membership. Service snapshots carry account/relay metadata and omit the owner's relay credential. The CLI checks its own account session and cluster ownership before requesting enrollment, then provisions a separate transport credential under that session using the actual joined node ID. The owner signing key stays on the owner. Both SSH and invitation enrollment currently require the same account on each machine; multi-user enrollment needs separate authorization work.

Joining preserves the existing `auth/` directory and the inodes of service, daemon and login lock files. Cryptographic state and pending credential admission remain in a private sibling directory named `~/.gent.joining`. Once ready, an immutable manifest records each runtime file's length and SHA-256 digest. Publication copies verified private files without overwriting conflicts and publishes `config.toml` last. A retry resumes partial publication from the same staged bytes. Temporary copy files stay in the staging directory. Completed publication removes staging copies; a later join retry can finish cleanup after an interruption.

Rerun the original join command to resume, including the original node name while staging remains. A pending join prevents `cluster new` or `daemon install --local` from replacing its identity. Stop an existing daemon before retrying a join or reconnecting. Existing development SSH joins continue to import only their shared development credential.

## Interrupted setup and reconnecting

Retry `gent cluster new NAME` with the original name, or use:

```sh
gent cluster connect
```

The private `~/.gent/service.json` record pins the account, service, relay and identities. It records the intended configuration before publication and the transport candidate before admission. Interrupted setup reuses those identities and keys. After configuration exists, deleting it or losing runtime keys/database requires restoration; setup does not silently reconstruct them from the journal.

Setup takes the service-manager, daemon and login mutation locks. Stop a running daemon before reconnecting:

```sh
gent daemon stop
gent auth login
gent cluster connect
gent daemon start
```

Use `gent daemon install` instead of `start` if the service is not installed. Setup verifies either the locally held owner identity or the existing enrolled node-only identity. The journal records which role it expects. Signing into another account or service cannot take over that state directory. The journal, `relay.key`, login record and local identity files remain private. Concurrent replacement of a configuration or credential file causes publication to fail so the command can be retried after resolving the change.

Each connect checks service authority. A valid credential is reused. Once a previously confirmed credential is revoked or expired, connect can issue another after a valid login, preserving encryption identity. A lost admission response retains its exact candidate. If that candidate is still unconfirmed after switching login sessions, retry may need to wait for its 15-minute admission window to close. Only an explicit expired-candidate response permits replacing an unconfirmed token; network errors and a timestamp ahead of the service clock do not. Node retirement remains permanent and cannot be bypassed with connect.

Sessions initially last 30 days. The running daemon checks on startup and hourly and renews during the final seven days, extending the active session and its authorized node credentials to 30 days from renewal. It does not open a browser, contact GitHub or replace keys. Use `gent auth renew` to check and renew explicitly; outside the renewal window this confirms the current lease without extending it. `gent auth status --json` reports the authoritative expiry, and `gent daemon logs` reports renewal failures. An outage leaves the saved credential intact for retry. If the session expires before renewal succeeds, use fresh login and the stopped-daemon reconnect procedure above.

Renewal preserves bearer credentials and can keep an active installation signed in indefinitely. Logging out revokes credentials issued by that session without deleting local messages or keys, and the daemon cannot renew a disabled or revoked login. `cluster connect` restores transport authorization only; it does not recover lost encryption keys, move ciphertext, restore retired nodes, or perform invitation enrollment.

## Local verification

`scripts/prove_setup.py` runs against the private repository's real local account Worker and synthetic GitHub provider. Its forwarding proxy interrupts responses after database commits. The proof covers durable identity, publication before/after configuration, lost reservation and enrollment responses, process termination, competing setup/logout, credential publication conflicts, missing-state and file-link rejection, account pinning, user-service installation, daemon exclusion, credential replacement and permanent retirement. It checks both Linux systemd and Mac launchd through deliberate SSH testing.

The first-owner setup proof does not exercise relay ciphertext delivery. The private account harness's `--relay --pairing` mode runs `scripts/prove_pairing.py` between Linux and the Mac Studio with separate fixture account sessions. It checks service records against real node IDs, different node credentials, encrypted configuration and MCP image/file/reply delivery, restarts, and joined-node credential replacement after logout. Its account sessions are supplied by the synthetic provider fixture; independent CLI login tests cover the browser/device flows. Separate native service-relay proofs cover maximum-size 32 MiB encrypted files. The invitation guide records the distinct private-file enrollment proofs. Real GitHub authorization, hosted deployment and lost-state recovery still precede daily use.
