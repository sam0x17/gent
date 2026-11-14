# Owner recovery evidence

`gent recovery` collects signed reports of the configuration checkpoints accepted by surviving nodes. It identifies missing nodes, differing revisions and conflicting signatures before an owner-recovery decision. Owner replacement is not implemented. Collecting or inspecting these reports does not authorize a new owner, stop an existing writer or activate a restored database.

This workflow complements [encrypted backups and fresh joined-node replacement](recovery.md). It can run on a surviving joined node without the cluster owner's signing secret. The local owner's RPC credential is required to create a challenge or sign a report. Agents have no MCP tool for these operations.

`gent recovery status` reports the local owner epoch, whether signing is frozen, the issued handoff request and successor node, and prepared/completed candidate counts. It does not return keys or private configuration. The [handoff preparation APIs](owner-succession.md#preparation-on-separate-nodes) are available to trusted Rust callers; the CLI exposes their status only until coordinated activation exists.

## Collect reports

Start on a surviving node whose local state and cluster identity you trust independently:

```sh
gent recovery challenge --out ~/gent-recovery-review/challenge.json
gent recovery witness ~/gent-recovery-review/challenge.json --out ~/gent-recovery-review/this-node.json
```

Transfer the challenge file to each other surviving node over an independently trusted private channel, such as authenticated SSH. On each node, run:

```sh
gent recovery witness ~/gent-recovery-review/challenge.json --out ~/gent-recovery-review/other-node.json
```

Bring those report files back through the same trusted channel, then inspect them together:

```sh
gent recovery inspect ~/gent-recovery-review/challenge.json ~/gent-recovery-review/this-node.json ~/gent-recovery-review/other-node.json
```

All commands support `--json`. Challenge and witness commands honor normal live cluster selection. Inspection works offline without an initialized Gent home or daemon and rejects `--cluster`. It may read evidence from an offline recovery directory, but neither follows that directory's profile registry nor activates its saved state.

The challenge expires after 15 minutes. Every observation binds to that exact challenge, its cluster trust anchor and baseline checkpoint. If collection takes longer, create a new challenge and collect fresh reports. This is a collection deadline, not a guarantee that no configuration changed while reports were being collected.

Files contain full signed private cluster configuration and public node keys. They contain no private signing keys, but they are plaintext and must remain private. Inputs must be regular, single-link files owned by the current user with no group or other permissions. New files use mode 0600; newly created parent directories use 0700. Existing parent directories must be owned by the current user and not writable by others. Existing destinations, symlinks and hard links are refused. CLI summaries omit the full configuration.

## Interpret the review

The baseline lists the nodes expected to report. A report must carry the exact node key pinned in that baseline and a valid signature under that key. Unknown or changed keys are refused; obtain a current independently trusted baseline before reviewing changed membership. Missing reports remain explicit, including the missing old owner. The baseline is not itself an observation from its creator.

Each accepted report has one relation to the baseline:

| Relation | Meaning |
| --- | --- |
| `matches` | The revision and configuration hash match. |
| `behind` | The reported revision is lower. |
| `ahead` | The reported revision is higher. |
| `conflict` | The revision equals the baseline but its hash differs. |

`conflicting_revisions` also catches differing hashes at an equal revision reported by other nodes. Different revisions require history verification; comparing their numbers does not establish that one descends from another. The review never selects a winner by revision or timestamp. Duplicate observers fail rather than count twice.

`all_match_baseline` means every node pinned in the baseline supplied a matching report. Even that result leaves `authorizes_owner_change`, `proves_writer_stopped` and `proves_global_freshness` false. A signature authenticates a node's claim. A compromised node can lie, a disconnected writer can have newer state, and nodes can accept changes after reporting. Self-contained signatures cannot establish that the supplied baseline is the cluster the user intended to recover.

Expired signed configuration can still be reported, with `state_expired` calculated when inspection finishes. This does not renew its lease or authorize agent operations. Report collection uses the normal request transaction and can update the local request clock and TOML projection. It performs no signing-key or authority change; ordinary background synchronization and maintenance continue independently.

## Protocol boundary

The version-1 challenge contains a random UUID, the existing trust anchor, exact baseline checkpoint and collection interval. The baseline adds the corresponding signed configuration. A node signs its challenge, identity, observation timestamp and complete accepted signed configuration under the Ed25519 domain `gent/recovery-observation/v1\0`.

Files use strict canonical JCS JSON. Challenges are limited to 4 KiB; baselines and reports to the signed-state limit plus 8 KiB. Inspection accepts at most 1,024 report files and retains only verified summaries while reading reports individually. Verification checks the owner signature, pinned genesis for revision zero, member key, node signature, challenge equality and time bounds. The deadline and observation times are checked again when the review finishes.

## Required before owner replacement

The cluster trust anchor pins the original owner public key. The [signer succession protocol](owner-succession.md) now verifies delegation to a fresh signer while retaining that root, including configuration grants, invitations and legacy agent certificates. Live clusters still use their original signer because coordinated activation remains unimplemented. Merely copying its secret from an archive would let both copies sign competing histories.

The remaining activation and lost-key recovery work must define and verify:

- Recovery authority established before loss, independent of service login. Existing clusters with no such authority cannot infer a replacement signer from matching reports. A complete loss may instead require explicit creation of a fresh cluster and trusted re-enrollment.
- Installation and propagation of the implemented succession record, bound to the old authority, an exact current checkpoint, a fresh owner key and a monotonically accepted authority epoch. Recovery evidence alone does not provide this authorization.
- Durable retirement of old authority on participating endpoints and service credentials. Offline peers must verify succession before accepting more traffic. The design must state what happens to peers that never receive it and to a still-running old writer.
- History reconciliation and explicit handling of unavailable or conflicting peers. A majority of reports is not currently a quorum or a recovery policy.
- Atomic persistence, restart behavior and rejection of replayed succession records. Recovering processes need fresh node identities and encrypted sending state where rollback cannot be excluded.
- Migration rules for invitations, administrative grants, agent bindings, peer permissions and unfinished work. An old signature or backup must not silently restore revoked authority.

Until those requirements are implemented and tested, use these commands to inspect evidence only. There is no owner-activation command.
