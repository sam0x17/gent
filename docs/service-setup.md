# Service cluster setup

After installing the public `stable` release, start the setup wizard in a terminal. [Installation guide](installation.md)

```sh
gent setup
```

On your first machine, choose **Create a cluster** and sign in with GitHub. New accounts start on Free. Free includes one person and one active node per cluster. A native machine or a hosted node counts toward that limit. Chats on the same node share its enrollment. Gent uses the account service at `https://api.gent.link` and the ciphertext relay at `https://relay.gent.link`.

To use multiple active nodes in one cluster, open your account with `gent auth billing` on a signed-in machine. Pro costs $8 USD per month for one person and includes chat dashboards and Babysitter. Pro has no plan limit on active nodes per cluster. Protocol limits still apply. The account page shows whether checkout is available. [Plans and pricing](https://gent.link/pricing)

If you already have a cluster, choose to join with a node invitation code or an invitation file. After enrollment the wizard starts the per-user daemon and offers the integrations below. `gent daemon install` runs the same wizard.

Every interactive run offers these choices, including when completing an
already enrolled node. Every yes/no setup question defaults to Yes:

- Codex CLI, with automatic incoming-message delivery on new installs.
- Codex in VS Code, as a separate opt-in to the experimental editor route.
- Claude Code, covering its CLI and VS Code extension.
- Shell PATH and completions for the detected Zsh, Bash or Fish shell.

Selecting Codex also starts or reuses its background server when that route
needs one. A provider-switcher editor route starts its own per-window server.
Existing custom sockets, delivery opt-outs and unrelated settings are preserved.
Declining an integration leaves any existing installation unchanged. After
installation, reload open hosts or VS Code windows and connect the intended chat.
Claude Code sessions remain under the host's control.

The wizard asks about native chat discovery on each interactive run, defaulting
to Yes. Answer No to keep it disabled or disable a previously enabled setting.
It offers Linux startup before login if linger is not already enabled. Optional
step failures leave the daemon running, allow the remaining choices, and report
retry commands. Exit status 3 and `setup_complete: false` identify partial setup;
rerun `gent setup` to retry. Closing input also preserves completed work.

Each step remains available independently:

```sh
gent auth login
gent cluster new my-cluster
gent daemon install
gent hooks install
```

On Linux servers, use `gent daemon install --linger` to keep Gent running after logout and start it before login at boot. This explicitly changes the OS user's systemd linger setting for all their services. Host policy may require an administrator; Gent reports that requirement without running `sudo`. A denied linger change leaves the daemon installed. Rerun the same command after the administrator enables it. `gent daemon status` distinguishes startup at boot from startup with a login session. See [daemon services](local-proof.md#daemon-services) for scope and removal behavior.

For explicit setup or a headless machine:

```sh
gent daemon install --new my-cluster --headless
gent daemon install --invite-file /private/path/laptop.gent-invite --name laptop --headless
```

`--headless` allows device login; `--no-browser` prints the browser login URL and waits for its callback instead of opening a browser. `--service ORIGIN` selects an alternate account service. The installer never selects that origin from a newly supplied invitation. Existing setup pins the account service and relay; changing `--service` cannot move it.

JSON output, `--verbose`, `--no-input` and non-terminal input never trigger setup questions. Sign in separately, then pass `--new NAME` or `--invite-file FILE --name NODE` with `--no-input` for scripts. `--no-input` also prevents starting login. An explicit `--headless` or `--no-browser` may initiate the existing bounded login flow without a terminal. Add `--hooks --shell zsh` (or `bash`/`fish`) to install shell support explicitly; `--rc-file PATH` chooses a startup file. Shell setup preserves unrelated content. Use `--discover-chats true` or `--discover-chats false` to set discovery explicitly. A shell failure after enrollment leaves the daemon running and reports its retry command.

The installer checks service-manager availability and service ownership before enrollment. Cancellation or missing choices leave a fresh state directory uncreated. Completed installs preserve node identity and can be repeated while the managed daemon runs, without an account request or a daemon restart when the service definition is unchanged. Interrupted first-node creation resumes with bare `gent daemon install`; interrupted code enrollment resumes with `gent cluster join`; private-file enrollment needs the original file/name, or an explicit `--continue` with a valid replacement. Pending SSH joins must resume through the original `gent cluster join --via ...` command. Stop the daemon before a retry that needs enrollment or credential repair. The running daemon renews active sessions before expiry; expired credentials still require the reconnect procedure below.

The guided questions reuse the same installers as `gent integration install codex` and `gent integration install claude-code`, including their ownership checks and retry journals.

Use `gent auth login --service https://YOUR_ACCOUNT_ORIGIN` for an alternate deployment. The account service advertises its relay through authenticated `GET /v1/transport/config`. Account credentials go only to the saved login origin. The CLI accepts HTTPS origins, with HTTP restricted to explicit loopback fixtures; an HTTPS account service cannot select an HTTP relay. The initial relay address is pinned locally. A later discovery response cannot silently move an existing node to another relay.

`gent cluster new NAME` creates the node in `~/.gent`, allowing an existing login under `auth/`. It creates fresh node and cluster IDs, keys and transport state. Once configured, the node cannot create or join another cluster until `gent node reset`. `gent cluster new NAME --local` creates a development cluster without service enrollment; existing development or SSH-paired clusters are not automatically converted to service transport.

`--local` retains the independent development setup. Existing development or SSH-paired clusters are not automatically converted to service transport. They can have compacted mailbox history that requires a separate migration procedure.

## Add another machine through Gent

To enroll a second active node, use a Pro cluster. Run the following command on an existing node with configuration authority.

```sh
gent node add laptop
```

This prints a one-time code and the complete command for the new machine:

```sh
gent cluster join CODE
```

The code supplies both the cluster and the signed node name. The `Invitation code` line and join command show the same complete prefixed code; `Invitation ID` is the separate identifier used to manage the invitation. There is no approval command to run afterward. Joining checks the existing GitHub login, offers device login if needed in a terminal, enrolls the node, and installs and starts its daemon. It then offers the same integration, shell and discovery questions as `gent setup`. You can also run `gent setup` later to finish configuration.

Gent carries the invitation and enrollment over its HTTPS services; direct access between machines is unnecessary. An authorized joined node forwards issuance to the signing owner over its established encrypted connection. The signing owner must remain online during issuance and enrollment. Messaging-only nodes cannot issue codes. `gent node add laptop --no-configure` creates a messaging-only invitation.

Codes look like `gent2-personal.laptop.SECRET`: the cluster and node names are visible, followed by 256 random bits. Special characters in names are percent-encoded so the code is safe to paste as one shell argument. The labels are authenticated with the encrypted invitation; changing them invalidates the code. Existing `gent1-` codes remain accepted. Codes expire after 15 minutes and admit one identity. See the [invitation enrollment guide](invitation-enrollment.md) for protected transfer and interrupted-join recovery.

If a join is interrupted, run `gent cluster join` again. It resumes the saved invitation, key and stream setup. Once the code expires, run `gent node add NAME` on an existing node and pass the fresh code to `gent cluster join CODE` on the joining machine. If membership was already committed, the owner binds the continuation to that exact node key. A second machine cannot take its place by reusing its name. Keep `~/.gent` and `~/.gent.joining`; a timeout does not require `gent node reset`.

For scripts, use `gent node add NAME --code-out PRIVATE_FILE` and `gent cluster join --code-file PRIVATE_FILE`. With no pending join, `gent cluster join` prompts for a code instead of putting it in shell history. JSON output omits the code. Add `--no-input` to prohibit login and all setup prompts while using an existing account session. `--no-daemon` limits joining to enrollment when a separate manager controls the daemon. Private retry state lives under `auth/enrollment/`.

## Re-enroll an existing machine

A node belongs to one cluster. CLI commands, services and every chat use the same node in `~/.gent`; there is no profile selection. Older installations with profiles require a clean reset:

```sh
gent node reset
```

Reset stops and uninstalls Gent's managed daemon and gateway services, including legacy children under `~/.gent/clusters/`. It removes managed Codex and Claude Code entries for those directories while preserving unrelated host settings. It archives the old directory as a private sibling named `.gent.retired-UUID`, keeps that archive offline, and restores only `auth/session.json` into a fresh `~/.gent`. Repeat the command if interrupted. Foreground processes must be stopped first; edited host entries require resolution before reset can proceed.

Reset is local: it does not remove membership from the old cluster. On an existing owner node, remove the retired node ID with `gent node remove OLD_NODE_ID`, then issue a fresh code with `gent node add NAME`. On the reset machine:

```sh
gent cluster join CODE
gent integration install codex
gent integration install claude-code
gent doctor --online
```

Join assigns the name from the code and starts the daemon. The node and its chats receive fresh identities; old messages and bindings stay in the archive. Reload the host's Gent MCP connection after reinstalling. For Codex in VS Code, run **Developer: Reload Window** and reopen the chat. There is no profile move step.

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

SSH protects the trust anchor, signed enrollment request, configuration grants and key packages. The joining machine creates its signing key locally; the owner signs its membership. Service snapshots carry account/relay metadata and omit the owner's relay credential. The CLI checks its own account session and cluster ownership before requesting enrollment, then provisions a separate transport credential under that session using the actual joined node ID. The owner signing key stays on the owner. Sign in with the cluster owner’s GitHub account on each machine for either enrollment method.

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

The first-owner setup proof does not exercise relay ciphertext delivery. The private account harness's `--relay --pairing` mode runs `scripts/prove_pairing.py` between Linux and the Mac Studio with separate fixture account sessions. It checks service records against real node IDs, different node credentials, encrypted configuration and MCP image/file/reply delivery, restarts, and joined-node credential replacement after logout. Its account sessions are supplied by the synthetic provider fixture; independent CLI login tests cover the browser/device flows. Separate native service-relay proofs cover maximum-size 32 MiB encrypted files. The invitation guide records the distinct private-file enrollment proofs. Those local proofs covered synthetic sign-in and local Workers. Real GitHub authorization, hosted deployment and lost-state recovery were separate acceptance checks.
