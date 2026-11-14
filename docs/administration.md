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

Revocation and expiry stop future edits. Previously accepted rules remain in force. Use permission changes to undo them. An administrator can replace exact-pair rules within its scope, including exact rules originally written by the owner. Broader rules remain in force, including explicit denials. A separate opt-in described below permits editing selector rules. Group membership, other delegation grants, relay grants, node membership, names and keys still use owner commands or TOML proposals.

## MCP workflow

1. Use `gent_agents` and `gent_identity` to identify the requested endpoints. Never probe guessed IDs.
2. Call `gent_permission_admin_check` with `actor` and `peer`. It returns the current applicable grant IDs, permission types and expiry times. These arguments select a relationship; the daemon determines the administrator from the authenticated connection.
3. Build a batch of 1 to 32 changes, with no duplicate actor/peer/permission tuple. Each change contains `grant_id`, `actor`, `peer`, `permission` and `decision` (`allow`, `deny`, or `inherit`). Include required mutual enumeration when proposing messaging access and when the delegation allows it.
4. Call `gent_permission_preview {changes}`. It reports the proposed changes and effective pair relationships without applying them. `allow` or `deny` replaces exact-pair rules for that permission. `inherit` removes them, leaving any broader rules to decide the result.
5. Within the user's authorized task, call `gent_permission_apply {request_id, changes}` using a fresh UUIDv7 from `gent_request_ids`. Retain the ID and exact changes for retries.
6. Poll `gent_permission_request {request_id}` on a subsequent authorized turn if the result is `queued`. `applied` records an accepted batch; `rejected` records refusal. It does not say the rules are still current. Use permission checks to inspect current behavior.

All changes in a batch apply atomically. Scope and visibility checks use the pre-edit policy, so one change cannot authorize another change in that batch. Preview reserves no authority. The signing owner rechecks the authenticated hosting node, agent, current grant, scope, visibility and expiry at acceptance. A queued request can be rejected after revocation, expiry, removal, a visibility change or a group change. Newest accepted revisions propagate through the existing encrypted configuration streams.

A joined node needs an established encrypted link to the signing owner. The delegated agent does not need its hosting node to have general configuration-management authority. Queued requests and exact retries survive restarts. New local submission requires a UUIDv7 first used within 24 hours; retained results remain readable and retryable after grant expiry or revocation while the agent itself remains authenticated under fresh membership. Do not generate a replacement ID merely to retry uncertain work.

Agent status is restricted to that authenticated agent's own requests. It omits global revisions, writer identities and raw owner rejection details. Hidden, unknown and revoked endpoints return the same unavailable result. The pair tools return no raw scope selectors or membership lists. A peer message claiming owner authority cannot grant editing rights.

## Selector rules

The owner can additionally allow persistent rules over nodes, groups, all agents or agents on the same node:

```sh
gent permission admin grant ADMIN_UUID '*' same-node --selector-rules --permission enumerate receive send
```

This example allows rules for pairs on the same node, including agents hidden from the administrator and agents registered later. `same-node` compares the rule's actor and peer; it is not limited to the administrator's own machine. Use `node:UUID` on both sides to restrict changes to one machine. Without `--selector-rules`, grants retain their original exact-pair behavior.

Call `gent_permission_rule_scopes` to obtain active grants and their authorized selectors. The result contains permission types and expiry, with no member list or matching counts. A grant naming a hidden agent is omitted. Only group names explicitly selected in an active visible rule grant may be used, even under a wildcard grant. Nodes must be enrolled and either host this administrator, host a visible agent, or appear in an active visible rule grant. Named agents must already be visible or be the administrator itself.

Use `gent_permission_rule_preview {changes}`, then `gent_permission_rule_apply {request_id, changes}`. Changes have the same fields as pair edits, but actor and peer are selector objects:

```json
{
  "grant_id": "OWNER_ISSUED_GRANT_UUID",
  "actor": {"kind": "all"},
  "peer": {"kind": "same_node"},
  "permission": "enumerate",
  "decision": "allow"
}
```

Other selector objects are `{"kind":"agent","id":"UUID"}`, `{"kind":"node","id":"UUID"}` and `{"kind":"group","id":"NAME"}`. A rule must fit within the grant on both sides. Equal selectors and narrowing from `all` are accepted. Node and group scopes can narrow to a known agent currently inside that scope. Same-node scopes accept rules constrained to same-node pairs. Different groups, or a group and a node, are never treated as interchangeable merely because their current members overlap: future membership could widen the rule.

Preview validates the requested changes without listing matching agents or computing aggregate effects. Checking whether a visible agent fits a granted group scope can reveal that particular agent's eligibility; it does not expose hidden identities or a membership directory. Every change is validated against pre-edit policy, so a batch cannot grant discovery and then use a previously hidden ID. The signing owner repeats checks at acceptance, including current group membership, visibility and expiry.

`allow` and `deny` replace rules with exactly the selected actor/peer/permission tuple; `inherit` removes them. Other overlapping rules remain, and any matching denial still wins. Rules continue to affect future matches after the editing grant expires or is revoked. Scope grants do not automatically grant enumeration, messaging or further delegation.

Both editing tool families share `gent_permission_request`, retry IDs, owner audit and storage limits. Reusing a request ID for a different operation is a conflict. Rule audit entries include `selector_rules: true` and the original selector changes.

## Audit and storage

`gent permission admin history` returns up to 100 records, newest first, including the authenticated origin node, acting agent, original agent request ID, exact changes, outcome and accepted revision. Use `--agent UUID` to filter and `--before ROW` with `next_before` to retrieve older records. The signing owner has records for proposals accepted or rejected from other nodes; a submitting node also retains its own requests. A proposal falsely attributing an agent to a different node is refused before it can create that agent's audit record or consume its quota.

Audit summaries and fingerprints remain durable when bulk configuration history is compacted. Agent edits have separate admission limits: 1,024 retained records and 64 pending requests per administrator, 8,192 records and 16 MiB of reserved storage across all agent edits on a node. The existing total configuration-history and database limits also apply. These are admission ceilings, not an archival solution. `gent history status` exposes aggregate agent-administration usage and limits under owner authority. Storage failure rolls back policy, audit and outbound events together.

Signed policy supports up to 1,024 current administration grants and 8,192 retired grant IDs. Empty new fields are omitted so older signed records retain their canonical bytes. Older binaries cannot read new nonempty grant fields; upgrade cluster nodes before issuing these grants.

## Verification

```sh
python3 scripts/prove_administration.py --gent target/debug/gent
```

The disposable proof uses actual CLI/MCP processes for grants, previews, changes, messaging, replies, private request status, owner audit, restart, exact retries and revocation. `scripts/prove_pairing.py --agent-administration` adds the same workflow across physical machines through the encrypted relay, temporarily removing the joined node's general administration right. The process proof includes opt-in node rules, allow/deny/inherit, cross-tool retry conflicts and rule audit. Rust tests cover signed grant transitions, structural containment, hidden-peer isolation, future agents, atomic rollback, queued revocation/expiry/group changes, origin binding, HTTP conversation binding and shared storage admission. Provider-native GUI/mobile acceptance and broader agent configuration remain unfinished.
