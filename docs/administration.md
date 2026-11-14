# Delegated permission editing

An owner can authorize one registered agent to edit specific message-permission relationships. This authority is separate from discovery, messaging, relay access and node administration. Local stdio and remote HTTP MCP use the same operations.

```sh
gent permission admin grant ADMIN_UUID ACTOR_SELECTOR PEER_SELECTOR --permission enumerate receive send
gent permission admin list
gent permission admin history --agent ADMIN_UUID
gent permission admin revoke GRANT_UUID
```

Selectors use the existing grammar: an agent UUID, `'*'`, `same-node`, `node:UUID`, or `group:NAME`. They limit which concrete actor/peer pairs the administrator can edit. `same-node` compares the two selected agents' authenticated locations. Group membership is evaluated from current signed policy. Granting authority does not reveal agents or grant enumeration; the administrator must already see both endpoints, apart from its own known identity.

The owner explicitly selects editable permission types. A grant permits `allow`, `deny`, and `inherit` decisions for those types. It lasts 24 hours by default; `--ttl-seconds` accepts up to seven days. The global `--request-id UUID` supports exact CLI retries and becomes the grant ID. Existing grant IDs are immutable. Change scope or extend lifetime by revoking a grant and creating a new one. Retired IDs cannot be restored.

Revocation and expiry stop future edits. Previously accepted rules remain in force. Use permission changes to undo them. An administrator can replace exact-pair rules within its scope, including exact rules originally written by the owner. Broader rules remain in force, including explicit denials. Agents cannot edit group membership, blanket/node/group rules, other delegation grants, relay grants, membership, names or keys through these tools. Those settings still use owner commands or TOML proposals.

## MCP workflow

1. Use `gent_agents` and `gent_identity` to identify the requested endpoints. Never probe guessed IDs.
2. Call `gent_permission_admin_check` with `actor` and `peer`. It returns the current applicable grant IDs, permission types and expiry times. These arguments select a relationship; the daemon determines the administrator from the authenticated connection.
3. Build a batch of 1 to 32 changes, with no duplicate actor/peer/permission tuple. Each change contains `grant_id`, `actor`, `peer`, `permission` and `decision` (`allow`, `deny`, or `inherit`). Include required mutual enumeration when proposing messaging access and when the delegation allows it.
4. Call `gent_permission_preview {changes}`. It reports the proposed changes and effective pair relationships without applying them. `allow` or `deny` replaces exact-pair rules for that permission. `inherit` removes them, leaving any broader rules to decide the result.
5. Within the user's authorized task, call `gent_permission_apply {request_id, changes}` using a fresh UUIDv7 from `gent_request_ids`. Retain the ID and exact changes for retries.
6. Poll `gent_permission_request {request_id}` on a subsequent authorized turn if the result is `queued`. `applied` records an accepted batch; `rejected` records refusal. It does not say the rules are still current. Use permission checks to inspect current behavior.

All changes in a batch apply atomically. Scope and visibility checks use the pre-edit policy, so one change cannot authorize another change in that batch. Preview reserves no authority. The signing owner rechecks the authenticated hosting node, agent, current grant, scope, visibility and expiry at acceptance. A queued request can be rejected after revocation, expiry, removal, a visibility change or a group change. Newest accepted revisions propagate through the existing encrypted configuration streams.

A joined node needs an established encrypted link to the signing owner. The delegated agent does not need its hosting node to have general configuration-management authority. Queued requests and exact retries survive restarts. New local submission requires a UUIDv7 first used within 24 hours; retained results remain readable and retryable after grant expiry or revocation while the agent itself remains authenticated under fresh membership. Do not generate a replacement ID merely to retry uncertain work.

Agent status is restricted to that authenticated agent's own requests. It omits global revisions, writer identities and raw owner rejection details. Hidden, unknown and revoked endpoints return the same unavailable result. Agents receive neither raw scope selectors nor group membership. A peer message claiming owner authority cannot grant editing rights.

## Audit and storage

`gent permission admin history` returns up to 100 records, newest first, including the authenticated origin node, acting agent, original agent request ID, exact changes, outcome and accepted revision. Use `--agent UUID` to filter and `--before ROW` with `next_before` to retrieve older records. The signing owner has records for proposals accepted or rejected from other nodes; a submitting node also retains its own requests. A proposal falsely attributing an agent to a different node is refused before it can create that agent's audit record or consume its quota.

Audit summaries and fingerprints remain durable when bulk configuration history is compacted. Agent edits have separate admission limits: 1,024 retained records and 64 pending requests per administrator, 8,192 records and 16 MiB of reserved storage across all agent edits on a node. The existing total configuration-history and database limits also apply. These are admission ceilings, not an archival solution. `gent history status` exposes aggregate agent-administration usage and limits under owner authority. Storage failure rolls back policy, audit and outbound events together.

Signed policy supports up to 1,024 current administration grants and 8,192 retired grant IDs. Empty new fields are omitted so older signed records retain their canonical bytes. Older binaries cannot read new nonempty grant fields; upgrade cluster nodes before issuing these grants.

## Verification

```sh
python3 scripts/prove_administration.py --gent target/debug/gent
```

The disposable proof uses actual CLI/MCP processes for grants, previews, changes, messaging, replies, private request status, owner audit, restart, exact retries and revocation. `scripts/prove_pairing.py --agent-administration` adds the same workflow across physical machines through the encrypted relay, temporarily removing the joined node's general administration right. Rust tests cover signed grant transitions, scoped selectors, hidden-peer isolation, atomic rollback, queued revocation, origin binding, HTTP conversation binding and storage admission. Provider-native GUI/mobile acceptance and broader agent configuration remain unfinished.
