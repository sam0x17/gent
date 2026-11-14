# Inspecting permissions

The local owner can inspect the effective policy between two registered agents:

```sh
gent permission explain ACTOR_UUID PEER_UUID
gent --json permission explain ACTOR_UUID PEER_UUID
```

Both forms return a JSON report from the running daemon in the selected cluster profile. They use the latest committed signed policy. Unapplied TOML edits and queued configuration proposals do not affect the result. The command changes no permissions.

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

This tool does not edit policy. Agent-scoped configuration administration remains unfinished; use the [owner configuration commands](local-proof.md#configuration-administration) for now.

## Verification

```sh
python3 scripts/prove_permissions.py --gent target/debug/gent
```

The disposable native proof exercises the CLI and independent MCP processes, including hidden-peer isolation, actor binding, owner-only traces, one-way initiation with replies, daemon restart, and newly applied denies. Rust tests cover all 729 combinations of the six directional allow/deny/absent decisions, selector matching, revocation, expired authority and HTTP gateway conversation binding. These checks require no provider inference or deployed service.
