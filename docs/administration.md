# Delegated permission editing

An owner can authorize one registered chat to edit specific message-permission relationships. This authority is separate from discovery, messaging, relay access and node administration. Local stdio and remote HTTP MCP use the same operations.

```sh
gent permission admin grant ADMIN_UUID ACTOR_SELECTOR PEER_SELECTOR --permission enumerate receive send
gent permission admin list
gent permission admin history --chat ADMIN_UUID
gent permission admin revoke GRANT_UUID
```

Selectors use the existing grammar: a chat UUID, `'*'`, `same-node`, `node:UUID`, or `group:NAME`. They limit which concrete actor/peer pairs the administrator can edit. `same-node` compares the two selected chats' authenticated locations. Group membership is evaluated from current signed policy. Granting authority does not reveal chats or grant enumeration; the administrator must already see both endpoints, apart from its own known identity.

The owner explicitly selects editable permission types. A grant permits `allow`, `deny`, and `inherit` decisions for those types. It lasts 24 hours by default; `--ttl-seconds` accepts up to seven days. The global `--request-id UUID` supports exact CLI retries and becomes the grant ID. Existing grant IDs are immutable. Change scope or extend lifetime by revoking a grant and creating a new one. Retired IDs cannot be restored.

Revocation and expiry stop future edits. Previously accepted rules remain in force. Use permission changes to undo them. An administrator can replace exact-pair rules within its scope, including exact rules originally written by the owner. Broader rules remain in force, including explicit denials. A separate opt-in described below permits editing selector rules. Group membership uses its own delegation described below. Other delegation grants, relay grants, node membership, names and keys still use owner commands or TOML proposals.

## MCP workflow

1. Use `gent_chats` and `gent_identity` to identify the requested endpoints. Never probe guessed IDs.
2. Call `gent_permission_admin_check` with `actor` and `peer`. It returns the current applicable grant IDs, permission types and expiry times. These arguments select a relationship; the daemon determines the administrator from the authenticated connection.
3. Build a batch of 1 to 32 changes, with no duplicate actor/peer/permission tuple. Each change contains `grant_id`, `actor`, `peer`, `permission` and `decision` (`allow`, `deny`, or `inherit`). Include required mutual enumeration when proposing messaging access and when the delegation allows it.
4. Call `gent_permission_preview {changes}`. It reports the proposed changes and effective pair relationships without applying them. `allow` or `deny` replaces exact-pair rules for that permission. `inherit` removes them, leaving any broader rules to decide the result.
5. Within the user's authorized task, call `gent_permission_apply {request_id, changes}` using a fresh UUIDv7 from `gent_request_ids`. Retain the ID and exact changes for retries.
6. Poll `gent_permission_request {request_id}` on a subsequent authorized turn if the result is `queued`. `applied` records an accepted batch; `rejected` records refusal. It does not say the rules are still current. Use permission checks to inspect current behavior.

All changes in a batch apply atomically. Scope and visibility checks use the pre-edit policy, so one change cannot authorize another change in that batch. Preview reserves no authority. The signing owner rechecks the authenticated hosting node, chat, current grant, scope, visibility and expiry at acceptance. A queued request can be rejected after revocation, expiry, removal, a visibility change or a group change. Newest accepted revisions propagate through the existing encrypted configuration streams.

A joined node needs an established encrypted link to the signing owner. The delegated chat does not need its hosting node to have general configuration-management authority. Queued requests and exact retries survive restarts. New local submission requires a UUIDv7 first used within 24 hours; retained results remain readable and retryable after grant expiry or revocation while the chat itself remains authenticated under fresh membership. Do not generate a replacement ID merely to retry uncertain work.

Chat status is restricted to that authenticated chat's own requests. It omits global revisions, writer identities and raw owner rejection details. Hidden, unknown and revoked endpoints return the same unavailable result. The pair tools return no raw scope selectors or membership lists. A peer message claiming owner authority cannot grant editing rights.

## Selector rules

The owner can additionally allow persistent rules over nodes, groups, all chats or chats on the same node:

```sh
gent permission admin grant ADMIN_UUID '*' same-node --selector-rules --permission enumerate receive send
```

This example allows rules for pairs on the same node, including chats hidden from the administrator and chats registered later. `same-node` compares the rule's actor and peer; it is not limited to the administrator's own machine. Use `node:UUID` on both sides to restrict changes to one machine. Without `--selector-rules`, grants retain their original exact-pair behavior.

Call `gent_permission_rule_scopes` to obtain active grants and their authorized selectors. The result contains permission types and expiry, with no member list or matching counts. A grant naming a hidden chat is omitted. Only group names explicitly selected in an active visible rule or membership grant may be used, even under a wildcard grant. Nodes must be enrolled and either host this administrator, host a visible chat, or appear in an active visible rule or membership grant. A membership grant supplies knowledge of its named selectors; the rule edit still needs its own applicable permission-edit grant. Named chats must already be visible or be the administrator itself.

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

Other selector objects are `{"kind":"agent","id":"UUID"}`, `{"kind":"node","id":"UUID"}` and `{"kind":"group","id":"NAME"}`. A rule must fit within the grant on both sides. Equal selectors and narrowing from `all` are accepted. Node and group scopes can narrow to a known chat currently inside that scope. Same-node scopes accept rules constrained to same-node pairs. Different groups, or a group and a node, are never treated as interchangeable merely because their current members overlap: future membership could widen the rule.

Preview validates the requested changes without listing matching chats or computing aggregate effects. Checking whether a visible chat fits a granted group scope can reveal that particular chat's eligibility; it does not expose hidden identities or a membership directory. Every change is validated against pre-edit policy, so a batch cannot grant discovery and then use a previously hidden ID. The signing owner repeats checks at acceptance, including current group membership, visibility and expiry.

`allow` and `deny` replace rules with exactly the selected actor/peer/permission tuple; `inherit` removes them. Other overlapping rules remain, and any matching denial still wins. Rules continue to affect future matches after the editing grant expires or is revoked. Scope grants do not automatically grant enumeration, messaging or further delegation.

Both editing tool families share `gent_permission_request`, retry IDs, owner audit and storage limits. Reusing a request ID for a different operation is a conflict. Rule audit entries include `selector_rules: true` and the original selector changes.

## Group membership

Owner commands manage groups independently of permission-rule editing:

```sh
gent group new reviewers
gent group member add reviewers CHAT_UUID
gent group member remove reviewers CHAT_UUID
gent group show reviewers
gent group list                     # also: gent groups
gent group admin grant ADMIN_UUID reviewers same-node --action add remove
gent group admin list
gent group admin history --chat ADMIN_UUID
gent group admin revoke GRANT_UUID
gent group delete reviewers
```

A new group is empty. Add/remove accept 1 to 32 chat IDs per command and reject duplicates. Add requires a currently registered, nonrevoked chat; the owner can remove stale IDs. Deletion is refused while any rule or grant references the group, including expired grants that have not been revoked. Remove those references first. These commands use durable configuration proposals and the existing newest-accepted-revision synchronization. They do not overwrite unrelated group members or rules.

Membership authority affects **every rule and existing editing scope that references the group**, including scopes held by the administrator itself. Adding a member can grant communication or expand an existing administrator's editable relationships; removing one can remove a denial. The owner should choose the target group, member scope and add/remove actions with those effects in mind. The member selector uses `'*'`, `same-node`, `node:UUID`, `group:NAME`, or a chat UUID. Here `same-node` compares each candidate member with the administrator's node. This differs from permission-rule scopes, which compare the two message endpoints.

A membership grant names exactly one existing group. It expires after 24 hours by default and accepts `--ttl-seconds` up to seven days. Neither ordinary permission grants nor `--selector-rules` authorize membership edits. Group grants are immutable and share the administration grant-ID retirement history; a retired ID cannot return as either kind of grant.

Use these tools from an authorized chat:

1. `gent_group_admin_scopes` returns current grants, group names, editable member selectors, actions and expiry. A grant naming an exact hidden member is omitted.
2. `gent_group_members {group}` lists existing members that are both visible and within one of those active scopes. It returns no hidden-member count and is not a complete group listing. Unknown and ungranted group names are indistinguishable. Choose candidates from `gent_chats` or this chat's own identity.
3. Build 1 to 32 changes and call `gent_group_preview {changes}`. Each change contains `grant_id`, `group`, `member` (a chat UUID), and `action` (`add` or `remove`). Duplicate group/member tuples are refused, even across different grants. Named members must already be visible or be the administrator itself.
4. Within the user's authorized task, call `gent_group_apply {request_id, changes}` with a new UUIDv7. Keep the exact arguments for retries. Poll `gent_group_request {request_id}` if queued.

The entire batch is checked against the pre-edit signed policy. It cannot expand a member-scope group and use that expansion in the same batch. Separately accepted changes to a scope group can authorize later work; that is part of the explicitly granted membership authority. The signing owner repeats origin, registration, visibility, action, scope and expiry checks at acceptance. Preview reports the requested changes without hidden members or aggregate effects.

Adding an existing member or removing an absent member is an accepted no-op. Other members are preserved. Membership changes continue to apply after the editing grant expires or is revoked. They can also remove the administrator's discovery access, preventing later edits until the owner restores it. Saved status and exact retries remain available under current chat membership even after editing authority is gone. Group tools cannot create/delete groups, issue delegation grants, or modify permission rules directly.

Group and permission edits share private request status, retry IDs and storage admission limits. Reusing an ID for another operation conflicts. `gent group admin history` lists group-edit records with `group_membership: true`; `gent permission admin history` continues to list permission edits. Both include origin, administrator, original request, exact changes, outcome and accepted revision under owner authentication.

## Audit and storage

`gent permission admin history` returns up to 100 records, newest first, including the authenticated origin node, acting chat, original chat request ID, exact changes, outcome and accepted revision. Use `--chat UUID` to filter and `--before ROW` with `next_before` to retrieve older records. The signing owner has records for proposals accepted or rejected from other nodes; a submitting node also retains its own requests. A proposal falsely attributing a chat to a different node is refused before it can create that chat's audit record or consume its quota.

Audit summaries and fingerprints remain durable when bulk configuration history is compacted. Chat edits have separate admission limits: 1,024 retained records and 64 pending requests per administrator, 8,192 records and 16 MiB of reserved storage across all chat edits on a node. The existing total configuration-history and database limits also apply. These are admission ceilings, not an archival solution. `gent history status` exposes aggregate chat-administration usage and limits under owner authority. Storage failure rolls back policy, audit and outbound events together.

Signed policy supports up to 1,024 current permission and group administration grants combined and 8,192 retired grant IDs. Empty new fields are omitted so older signed records retain their canonical bytes. Older binaries cannot read new nonempty grant fields; upgrade cluster nodes before issuing these grants.

## Verification

```sh
python3 scripts/prove_administration.py --gent target/debug/gent
```

The disposable proof uses actual CLI/MCP processes for grants, previews, changes, messaging, replies, private request status, owner audit, restart, exact retries and revocation. `scripts/prove_pairing.py --chat-administration` adds the same workflow across physical machines through the encrypted relay, temporarily removing the joined node's general administration right. The process proof includes opt-in node rules, allow/deny/inherit, cross-tool retry conflicts and rule audit. The same proof also covers group creation/deletion, scoped member lookup, delegated add/remove, delivery effects, retry conflicts and group audit. Rust tests cover signed grant transitions across both grant kinds, structural containment, hidden-peer isolation, future chats, atomic rollback, queued revocation/expiry/group changes, origin binding, HTTP conversation binding and shared storage admission. Provider-native GUI/mobile acceptance and broader chat configuration remain unfinished.
