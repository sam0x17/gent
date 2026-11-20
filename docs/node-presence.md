# Node connectivity

`gent nodes` reports the owner's view of signed cluster membership and recent daemon communication. `gent nodes --json` includes the same evidence as structured fields. Chat discovery still uses each chat's enumeration permissions; node diagnostics do not expose hidden chats to an MCP caller.

| Status | Meaning |
| --- | --- |
| `local` | This daemon is answering the command. |
| `connected` | A matching encrypted probe reply arrived within 30 seconds, the observation is no more than 90 seconds old, and no later probe timed out. |
| `degraded` | A later probe timed out while a previous success is still recent, or local configuration authority, enrollment or relay setup prevents a current check. |
| `disconnected` | An outstanding probe has timed out or a late reply recorded a failure, and no recent successful round trip remains. |
| `unknown` | The node is unpaired, awaiting a probe, or its last verified round trip aged out during inactivity. |

An established `data_link` records pairing to the current signing key. It does not establish connectivity. `last_seen` is the local persisted timestamp of the last accepted round trip, not chat activity. The `presence` object includes the reason, observation time, pending probe start, last observed late-reply timeout, and response/freshness windows. Human output shows the verified time and evidence age. These are local observations; statuses on two machines can differ during one-way failures.

Disconnected describes the communication path. It does not prove that a remote machine, daemon or chat has stopped. Connected does not promise delivery, grant permission, establish model availability or attest that a task ran. Slow transport or a backlog can cause a timeout even while both daemons are running. Use `gent doctor` for account and relay diagnostics.

## Probes and storage

The background synchronizer sends a fresh random UUIDv4 challenge over the existing authenticated, encrypted node stream. Only the corresponding peer's reply to the outstanding challenge can refresh the observation. Pairing, relay storage receipts, one-way traffic and chat registration do not count. Both current membership and the pinned peer key are checked; expired configuration cannot authorize probes.

New links get an initial probe. After a success, a real change that needs peer capabilities or an explicit `gent nodes` check can request another probe once 30 seconds have elapsed. Background inventory reads use cached evidence. When a quiet peer's proof ages out, its status becomes `unknown` and its last verified timestamp remains visible. The CLI briefly waits for newly requested probes and can return a pending result for a slow peer. Each peer has at most one outstanding challenge, persisted across restarts. An offline peer does not accumulate periodic probes. A delayed matching reply clears that challenge and makes a fresh probe due immediately, without refreshing connectivity. Duplicate or unrelated replies do nothing. A late reply also preserves the timeout condition until a fresh round trip succeeds, even if an older success is still within the freshness window.

Each pass admits at most 32 probes. The diagnostic cache is bounded by signed membership and prunes removed or replaced peer keys. Queueing and cache changes commit together. Failed response commits retain the authenticated input for retry. Probe retry metadata has a 120-second retirement deadline; unconfirmed transport packets remain under the existing reliable-stream retention rules. Control-traffic quotas remain in effect.

Probes contain no chat messages, registrations or task content. They do not update chat activity, create exchanges, acknowledge chat messages or submit host input. The relay sees the existing opaque routing identifiers, ciphertext sizes and traffic timing. It cannot read the encrypted challenges or replies. Timing still reveals traffic activity.

## Pre-release upgrades

Upgrade both nodes to a build that supports presence before expecting communication to continue. This pre-release event has no capability negotiation: an older daemon cannot decode `presence` and stalls that incoming application stream. Its authenticated buffered record remains stored. An upgraded daemon can drain that record and resume subsequent messages. Do not delete its database or encryption state to clear the stall.

This is not seamless mixed-version support. A retained pre-presence reader is part of the private two-machine acceptance fixture, alongside delayed replies, daemon downtime, restart recovery, message delivery and ciphertext inspection. The local Worker proof does not establish hosted-service or mobile acceptance.
