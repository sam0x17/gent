# Permissions

To start an exchange, register each chat with Gent and choose distinct names. Ask the sending chat: “Use Gent to send laptop-codex on sam-laptop this message: … and ask it to reply through Gent.” It discovers the destination with `gent_agents` and uses its returned ID. The recipient replies with `gent_reply`; acknowledgments alone are not replies.

New clusters allow every registered agent to discover, send to, and receive from every other agent in the cluster, including agents added later and agents on other nodes. Permissions use a blacklist by default: configure them when you want to restrict an agent. Text, images and explicitly sent files use the same messaging policy.

The owner can list registered IDs with `gent agents`. To block an agent's messaging with all other agents, then later restore its inherited permissions:

```sh
gent permission deny AGENT_UUID '*' --permission send receive
gent permission inherit AGENT_UUID '*' --permission send receive
```

Replace `'*'` with a peer UUID to restrict just that relationship. To hide an agent from the directory, use `gent permission deny '*' AGENT_UUID --permission enumerate`. Denies override matching allows regardless of rule order. `inherit` removes only the exact actor/peer/permission overrides; other restrictions remain. Adding an allow does not remove a deny.

New-cluster TOML contains three wildcard allow rules for `enumerate`, `receive`, and `send`. This representation works with older nodes. Existing policies retain their meaning on upgrade, including intentionally restrictive empty policies. To enable blacklist behavior in an existing cluster while preserving its explicit denies, run:

```sh
gent permission allow '*' '*' --permission enumerate receive send
```

Rules follow the normal signed configuration synchronization flow. Allowlist setups remain possible by removing the wildcard allows with `gent config edit` and applying the configuration before adding selective grants. Ordinary communication does not confer administration, relay delegation, transcript browsing, or authorization to perform requested work. Automatic replies additionally require the recipient's [host wake adapter](wake.md) to be active. Wake installation does not change cluster policy.

The local owner can inspect the effective policy between two registered agents:

```sh
gent permission explain ACTOR_UUID PEER_UUID
gent --json permission explain ACTOR_UUID PEER_UUID
```

Both forms return a JSON report from this node's running daemon. They use the latest committed signed policy. Unapplied TOML edits and queued configuration proposals do not affect the result. The command changes no permissions.

The report identifies the actor and peer, then shows these policy gates:

| Field under `policy` | Meaning |
| --- | --- |
| `enumerate` | The actor may discover the peer. |
| `send_unsolicited` | The actor may initiate an ordinary exchange with the peer under current policy. |
| `receive_unsolicited` | The peer may initiate an ordinary exchange with the actor under current policy. |
| `reply_policy` | Policy permits replies between these two agents, subject to an actual accepted exchange. |

Each messaging gate has `allowed` and `blocked_by` fields. `sender` and `recipient` refer to the direction of that gate: for `receive_unsolicited`, the peer is the sender. For `reply_policy`, the actor is the sender; its policy checks are symmetric. Both sides must enumerate each other. An unsolicited send also needs the sender's Send allow and the recipient's Receive allow. An explicit Receive deny on either side blocks replies. A missing Receive grant on the original sender still permits replies to an accepted exchange. Self-messaging is always blocked.

Owner reports include `authority` (revision, expiry, freshness), revocation flags, directional `traces`, and the matching rules. Trace decisions distinguish `allow`, `explicit_deny`, `no_matching_rule`, and `revoked`. Rule indices are zero-based positions in that signed revision. All matching rules are listed, including allows that follow a matching deny. Deny wins regardless of order. Group membership lists and unrelated rules are omitted.

An owner may inspect expired authority; `authority.fresh: false` means that snapshot cannot authorize agent operations. A report is not a reservation, reply grant, connectivity check or delivery guarantee. Sending still checks current authority, exchange participants, expiry, quotas and any relay grant. A reply needs a received message from an accepted, unexpired exchange with capacity remaining. Relay messages use `gent_relay_respond`.

## Agent checks

The shared local and remote MCP tool is:

```json
{"name":"gent_permission_check","arguments":{"peer":"PEER_UUID"}}
```

Get the peer ID from `gent_agents`. The daemon supplies the actor from the authenticated conversation binding. The tool cannot accept a different actor. It returns the pair's policy gates and their blockers, without raw rules, rule indices, group names, membership lists, counts or cluster revision metadata. Hidden, unknown and revoked peers all return `recipient or message unavailable`. Normal fresh authority and registration checks still apply.

This tool does not edit policy. [Delegated permission editing](administration.md) uses separate owner-issued grants and MCP tools for exact agent-pair changes. Broader configuration still uses the [owner commands](local-proof.md#configuration-administration).

## Verification

```sh
python3 scripts/prove_permissions.py --gent target/debug/gent
```

The disposable native proof exercises communication without pair grants, hidden-peer isolation, actor binding, owner-only traces, one-way initiation with replies, daemon restart, immediate denies and restoration through `inherit`. Rust tests cover new-cluster defaults, unchanged legacy policies, all 729 combinations of the six directional allow/deny/absent decisions, selector matching, revocation, expired authority and HTTP gateway conversation binding. These checks require no provider inference or deployed service.
