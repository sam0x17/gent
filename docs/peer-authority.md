# Peer administration and ordered configuration

Accepted architecture, November 17, 2026. This replaces the planned permanent node-owner role. It is not implemented by the current release, which still uses one signing owner and delegated configuration proposals. That runtime must be migrated before these guarantees apply.

## Equal node authority

Every newly enrolled node has full cluster administration by default. The node that creates a cluster has no permanent extra privilege. Any unrestricted node can change shared configuration, enroll another node, manage permissions and remove a node. Explicit restrictions can remove these capabilities. There is one node administration model, with no separate owner tier.

Agent permissions remain separate. Installing Gent on a fully authorized node does not give every chat unrestricted configuration tools. Agent requests retain their authenticated identity and delegated scope, and the executing daemon checks that scope against the current configuration.

A node going offline does not revoke it, trigger ownership transfer, or stop the other nodes from administering the cluster. Any surviving unrestricted node must be sufficient, provided the Gent service is reachable. The unavailable node's own agents and local conversation history remain unavailable unless their host provides separate recovery.

## Sequence and finality

One Cloudflare Durable Object per cluster maintains a durable ordered log of encrypted configuration commits. It provides ordering, not plaintext configuration processing. The service remains an availability dependency for finalizing configuration; no individual member node or majority of member nodes is required.

Each accepted commit has a monotonically increasing cluster-wide sequence number and an authenticated reference to its predecessor. Sequence allocation, the committed ciphertext, the new head and the request's retry result must be stored atomically. Acknowledgment follows durable commit. A crash before commit allocates no final sequence; a lost response after commit must be recoverable without allocating another one. Sequence numbers must never wrap, reset after a node disappears, or depend on device clocks.

The highest valid committed sequence determines the shared configuration. A newer commit replaces the previous effective configuration. Older commits remain final historical facts; a later write does not rewrite them. Local edits and pending requests are not final before service acceptance.

The write path is:

1. Fetch and verify the current committed head and any missing history.
2. Check the originating node's or agent's permission against that state.
3. Prepare, sign and encrypt the requested configuration change, binding its cluster, predecessor and expected next sequence.
4. Submit with a stable operation ID, an intent fingerprint and the expected current head.
5. Atomically commit only if the expected head still matches. Return the original result for an already committed retry with the same intent; reject reuse of its ID for a different intent.
6. If another write won the race, sync to that head, recheck permission and retry the same requested change. Do not blindly resubmit a stale snapshot or restore retired identities and grants.
7. Persist the verified result locally and immediately notify connected nodes to fetch it. Offline nodes catch up automatically when they reconnect.

Concurrent writes need no user merge. If two authorized writers change the same setting, the one committed later wins. A targeted edit reapplies its requested operation to the current state; an explicit whole-configuration replacement replaces the user-editable shared configuration. Identity retirement, cryptographic continuity and local-only settings are not overwritten by a stale TOML file.

For example, two nodes start at sequence 41. A commits sequence 42. B's attempt against 41 conflicts, so B obtains 42 and checks its permission again. If still authorized, B commits its change as 43, which becomes effective everywhere. If 42 revoked B's write permission, B cannot produce an authorized 43. Neither outcome depends on the original cluster creator being online.

## Encryption and authorization

Configuration contents, private names, agent policy and key material remain end-to-end encrypted. Ordering metadata such as sequence numbers, opaque cluster/request identifiers, ciphertext lengths and digests is visible to the service. Account and transport authentication alone does not establish permission to change the encrypted configuration.

Endpoint signatures must bind the operation to an authorized node and the exact ordered record. Receiving endpoints verify the cluster, signature, predecessor, sequence and applicable authorization before exposing new policy. The service cannot substitute keys or author a valid configuration merely by assigning a sequence number. Finality depends on the ordering service preserving its durable log; encryption does not make a malicious or rolled-back ordering service trustworthy. Endpoints retain checkpoints and reject conflicting or older histories.

The concrete write-admission protocol must preserve private permissions while excluding restricted writers. It must handle permission revocation racing with a write, lost commit responses, and capability rotation in the same sequence as the permission change. This is an implementation requirement, not authorization to upload plaintext policy or copy the legacy owner signing secret to every node.

Admission, encryption-key distribution and joining must work through any authorized node. Removing a node must exclude it from future configuration keys and write authority, while preserving the signed retirement history. Previously delivered plaintext and keys cannot be recalled.

## Replication and offline behavior

All nodes retain their verified configuration and accepted checkpoint. Notification loss only delays delivery: reconnection and periodic reconciliation recover from durable storage. Applying a commit and saving its checkpoint are transactional; projecting it into `~/.gent/config.toml` is atomic and retryable. Machine-local settings remain local.

An offline node may retain a durable pending edit. When it reconnects, it obtains current state and rechecks permission before submitting that edit. A pending write is reported as pending, never as a finalized cluster change. Service unavailability cannot be bypassed by inventing a local final sequence. Existing messaging freshness and revocation rules still apply during disconnection.

Operations whose responses are lost must remain retryable across daemon restarts and membership changes. A committed request returns its original result instead of reapplying against newer configuration. An uncommitted request has to pass current authorization, even if it was allowed when first queued.

## Migration from the current runtime

The existing implementation has owner dependencies in signed authority, configuration proposals, lease renewal, invitations, stream grants, mesh setup and recovery. Renaming the ADMIN column does not remove them.

The migration must introduce a versioned authority protocol and a verifiable transition from each cluster's pinned existing state. It must preserve node and agent identities, messages, file keys, request IDs, permission restrictions and accepted checkpoints. New nodes default to full authority; an upgrade must not silently undo an existing explicit restriction.

The old writer must be fenced before the new log becomes authoritative, with a durable record distinguishing an uncommitted transition from a committed one. After activation, no legacy writer or old replica may publish a competing history or reset the sequence. Older clients must report an upgrade requirement rather than silently maintaining a separate authority. Recovery must consult the committed transition; binary rollback cannot reopen a retired signing path.

The account owner's billing/account role and the local user's RPC credential are separate from the node role being removed. They must not become hidden requirements that route ordinary cluster administration back through the first machine.

## Required acceptance evidence

- Create a three-node cluster, stop the creating node, then edit configuration, manage permissions and enroll another node from a remaining node. Repeat with only one unrestricted original node online.
- Run simultaneous writes from different nodes. Verify unique, increasing committed sequences, deterministic latest-write behavior and equal final state after reconnecting every node.
- Race a restriction or removal against a write. Verify stale authority cannot commit a change after its restriction becomes effective, and denied writes cannot change configuration.
- Lose the response after durable commit, restart the submitting daemon, and retry the operation. Verify one committed change and the original result.
- Stop the Durable Object at each publication boundary and restart it. Verify the head, ciphertext and retry result agree and no acknowledged commit disappears.
- Reorder notifications, interrupt synchronization and restart nodes during local projection. Verify automatic catch-up, checkpoint continuity and preservation of local-only settings.
- Inspect stored service data and request logs for plaintext configuration or keys. Exercise ciphertext/signature tampering, cross-cluster substitution, replay and conflicting history.
- Interrupt migration before and after commitment. Verify either the original authority remains valid or every upgraded node follows the new authority, with no simultaneous writers under incompatible rules.
- Preserve agent permissions, messaging, files, wake adapters and chat identities across migration. Verify that losing a member only makes that member's hosted agents unavailable.

These are release gates for enabling peer administration in existing clusters. The current owner-based behavior remains accurately documented until the replacement passes them.
