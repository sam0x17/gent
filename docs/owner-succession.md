# Owner signer succession protocol

The Rust authority protocol can transfer configuration-signing authority to a fresh owner key while retaining the cluster's original trust anchor. Accepted history records every transfer. Once a verifier accepts a handoff, it rejects subsequent revisions from the retired signer and refuses a competing succession chain.

This is a protocol and standalone authority-storage implementation. Live daemon activation is not implemented. The live encrypted store refuses successor epochs on initialization, update and load, before publishing authority changes. There is no CLI, MCP or service operation to activate a successor. [Recovery observations](owner-recovery.md) remain evidence only.

## Authorization and state

`VerifiedState::transfer_owner(current, successor, now)` requires both the current owner's private signing key and a fresh successor key. It returns the next signed state without changing storage or exporting either secret. A valid current signer can authorize a handoff even after its configuration lease expires, as it can authorize a renewal. The resulting state must have a fresh lease before authorizing operations.

The current owner signs a version-1 `OwnerTransition` containing:

- The original cluster trust anchor.
- The next consecutive owner epoch and digest of the preceding signed transition. The first transition uses the pinned genesis digest instead.
- The exact preceding configuration checkpoint, including revision and state hash.
- The successor public key and activation timestamp.

The signature domain is `gent/owner-succession/v1\0`. Transition digests cover the complete signed record under `gent/owner-succession-record/v1\0`. All encoding uses strict canonical JCS JSON.

The successor then signs the first state in its epoch. That state contains the complete transition chain, so the signature binds both its configuration and its claimed succession history. The normal state-signature domain remains unchanged; the signed version and transition fields distinguish this format.

The first state of an epoch advances the configuration revision by one and must reference the exact checkpoint named by the transition. Its timestamp must equal the transition timestamp. Only signing authority, the revision links and lease timestamps may change in that handoff. Membership, names, policy and retirement records must remain byte-equivalent. The successor can change configuration in subsequent ordinary revisions under the existing permission and retirement rules.

The original `TrustAnchor.owner_key` remains the root of the delegation chain. `ClusterState.owner_key` identifies its current signer. Epoch zero keeps version-1 state and omits the empty `owner_transitions` field, preserving existing canonical bytes and signatures. Successor states use version 2. Earlier binaries reject them rather than interpreting a new owner as the original one.

## Verification and retirement

Each link is verified under the preceding owner key. Epoch numbers must be consecutive, transition digests must link exactly, and base revisions and timestamps cannot move backwards. Owner keys cannot repeat or reuse active or retired node signing keys. Node membership cannot use any current or former owner signing key.

A history update must retain the accepted transition chain unchanged or append exactly one link at the accepted checkpoint. It cannot remove a link, replace an accepted epoch, skip a handoff, or select a competing chain with a larger revision number. A valid signature from a retired owner remains historical evidence; it cannot authorize the next update. Verification checks the whole batch before replacing the in-memory state.

The standalone `Replica` commits the successor state, checkpoint and history in one transaction. Compare-and-swap checks reject stale writers. An injected checkpoint-write failure leaves the original state and history intact, and reopening after a successful handoff preserves the accepted epoch. `Replica` does not install owner keys, run a daemon or control service credentials.

`SignedState::verified_checkpoint` authenticates one record, including its delegation chain. It does not select that record as current or prove continuity from an existing endpoint. `VerifiedState::restore` still requires an exact checkpoint supplied by trusted endpoint storage. Neither operation makes an old backup safe to resume.

## Other owner-signed records

Configuration-stream grants, legacy agent certificates and invitation offers carry their signer's transition chain. Their signatures bind that chain. The current signer can create these records; retired keys are refused by their creation APIs.

Configuration-grant admission requires both the current owner epoch and the exact current checkpoint. Live legacy registrations use `verify_current`, requiring the current epoch and an enrolled node. Invitation admission also uses `verify_current`, which checks the issuer's current membership and lease. A certificate or offer from a retired epoch requires reissuance; it does not silently acquire successor authority.

Historical signature verification remains available for retained records and already pinned configuration-stream recovery. An invitation's standalone signature/deadline check authenticates the offered channel; actual admission must also enforce the current epoch and service revocation. New invitation channels pass the ordinary Noise handshake and node-claim verification. These changes add no automatic migration of old bindings or active streams.

## Bounds

There can be at most 64 owner transitions, with a 128 KiB canonical chain limit and a 4 KiB limit per signed transition. Hitting the history limit refuses another handoff while ordinary revisions and owner-signed operations remain available. Pruning or checkpointing owner delegation history is not implemented.

State records retain their 2 MiB limit, including the chain. Configuration grants and invitation offers permit the chain plus 8 KiB; legacy bindings permit the chain plus 4 KiB. Private invitation encodings permit the chain plus 16 KiB. These bounds allow all supported owner epochs without silently truncating their authorization proofs.

## Remaining activation and recovery work

The protocol retires an old signer at an endpoint only after that endpoint accepts the transition. It cannot stop a process, prove that all peers have caught up, or prevent a disconnected peer from following a competing old-owner history. It supplies no distributed consensus or global writer lock. Signed node observations do not change those limits.

Live activation must install the new key and hosting-node role durably, preserve crash/retry behavior, migrate or replace affected streams, retire the old node's service credentials where required, and handle peers with missing or conflicting history. Legacy agent certificates and invitations need an explicit reissuance strategy. Old encryption-state snapshots must remain offline.

Complete loss of the current signing key is also unresolved. This API cannot authorize a successor from GitHub login, matching reports or possession of a node key. Recovery must use a separately protected copy of the current signer solely for authenticated succession, or a recovery authority established before loss. It must never resume an archived owner as a competing writer. A preauthorized offline recovery-key mechanism is not yet implemented.
