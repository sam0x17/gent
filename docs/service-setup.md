# Service cluster setup

The source build can provision the first owner node against a configured Gent account service. The public account and messaging services are not deployed yet. Real GitHub consent, invitation enrollment and additional service-backed nodes still need integration work.

For a configured service:

```sh
gent auth login
gent cluster new my-cluster
gent daemon install
gent hooks install
```

Use `gent auth login --service https://YOUR_ACCOUNT_ORIGIN` for an alternate deployment. The account service advertises its relay through authenticated `GET /v1/transport/config`. Account credentials go only to the saved login origin. The CLI accepts HTTPS origins, with HTTP restricted to explicit loopback fixtures; an HTTPS account service cannot select an HTTP relay. The initial relay address is pinned locally. A later discovery response cannot silently move an existing node to another relay.

`gent cluster new NAME` requires an unconfigured state directory, allowing an existing login under `auth/`. It creates the node and cluster UUIDs, owner signing key, node signing key and signed genesis locally before reserving their IDs at the account service. The service receives those IDs and a transport credential, never the signing keys, policy or display names. The credential grants access to cluster ciphertext; local signed authority still controls agents and decryption.

`--local` retains the independent development setup. Existing development or SSH-paired clusters are not automatically converted to service transport. They can have compacted mailbox history that requires a separate migration procedure. The existing SSH join path refuses to copy a service credential. A service-created cluster currently supports its owner node; adding other nodes requires the next enrollment stage.

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

Use `gent daemon install` instead of `start` if the service is not installed. Setup verifies the locally held owner signing identity. Signing into another account or service cannot take over that state directory. The journal, `relay.key`, login record and local identity files remain private. Concurrent replacement of a configuration or credential file causes publication to fail so the command can be retried after resolving the change.

Each connect checks service authority. A valid credential is reused. Once a previously confirmed credential is revoked or expired, connect can issue another after a valid login, preserving encryption identity. A lost admission response retains its exact candidate. If that candidate is still unconfirmed after switching login sessions, retry may need to wait for its 15-minute admission window to close. Only an explicit expired-candidate response permits replacing an unconfirmed token; network errors and a timestamp ahead of the service clock do not. Node retirement remains permanent and cannot be bypassed with connect.

Credentials expire with their issuing account session, currently after 30 days. Automatic renewal and an installer that guides all missing login/enrollment steps remain unfinished. Logging out revokes credentials issued by that session without deleting local messages or keys. `cluster connect` restores transport authorization only; it does not recover lost encryption keys, move ciphertext, restore retired nodes, or perform invitation enrollment.

## Local verification

`scripts/prove_setup.py` runs against the private repository's real local account Worker and synthetic GitHub provider. Its forwarding proxy interrupts responses after database commits. The proof covers durable identity, publication before/after configuration, lost reservation and enrollment responses, process termination, competing setup/logout, credential publication conflicts, missing-state and file-link rejection, account pinning, user-service installation, daemon exclusion, credential replacement and permanent retirement. It checks both Linux systemd and Mac launchd through deliberate SSH testing.

The setup proof does not exercise relay ciphertext delivery. Separate native service-relay proofs cover MLS synchronization and 32 MiB encrypted file transport. Real GitHub authorization, hosted deployment, end-to-end onboarding of a second node and lost-state recovery still precede daily use.
