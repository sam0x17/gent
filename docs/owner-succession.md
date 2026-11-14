# Owner signer succession protocol

The Rust authority protocol can transfer configuration-signing authority to a fresh owner key while retaining the cluster's original trust anchor. Accepted history records every transfer. Once a verifier accepts a handoff, it rejects subsequent revisions from the retired signer and refuses a competing succession chain.

The daemon has trusted Rust APIs for preparation and live activation. They keep the successor key on its enrolled node, verify signed readiness evidence before stopping the old signer, adopt its completed decisions and reroute retained pending proposals. Activation independently checks confirmed replacement streams to every other enrolled node. Encrypted orchestration and a handoff command remain unfinished; no CLI, MCP or service operation can prepare or activate a successor. `gent recovery status` reports preparation, readiness storage and runtime activation support. [Recovery observations](owner-recovery.md) remain evidence only.

## Preparation on separate nodes

`Store::prepare_owner_handoff` requires the successor node's local owner RPC credential. It creates a separate owner key and a candidate signed by both that key and the enrolled node key. The candidate names the request, original cluster anchor, exact accepted checkpoint, node ID/key and a 15-minute approval window. The current owner node cannot prepare its own replacement through this API. Candidate keys stay in private `owner-candidates/REQUEST.key` files; the database stores only public signed records. Neither private signing key travels to the other node.

`Store::authorize_owner_handoff` requires the current owner's local credential, a valid candidate at the current checkpoint and saved, fresh readiness evidence as described below. Its signed transition includes the candidate digest, successor node binding and a commitment to the completed configuration-request journal. Before returning that authorization, one immediate database transaction stores the baseline, candidate, authorization, journal pages and signing stop. A failed transaction returns no authorization. Repeating the exact request returns the committed authorization even after the approval window expires; another candidate cannot replace it. There is no timeout or abort that resumes the old signer.

`Store::accept_owner_handoff` runs on the successor node. It verifies the authorization against the saved candidate and checkpoint and requires the committed journal to be fully received and verified, then records the successor-signed state. It installs no active key and publishes no authority change. Exact retries preserve the same result after a lost response, restart or candidate expiry. Missing, linked, shared-readable or changed key files fail instead of generating a replacement. Preparation is bounded to 64 local candidates, including unpublished key files left by interrupted database writes. Accepted transfers can repeat, including returning to an earlier node with a fresh owner key. Cleanup remains unfinished.

The daemon rechecks the signing stop in authority transactions, automatic renewal and owner signing operations. New configuration-stream grants check it inside their encryption transaction as well. Existing handles cannot continue signing after another handle issues a handoff. Missing or inconsistent journal records cause startup and signing to fail. This protects intact endpoint storage; restoring an older complete backup or copying a signing key is not proof that the original writer has stopped.

New configuration requests remain pending while signing is frozen. Previously committed results remain available for exact retries. Transport acknowledgment can retire sender ciphertext after durable receipt; the receiver retains the unapplied request in its local inbox across restart. A pending request can temporarily block later records on the same ordered stream. Activation adopts completed decisions, and origins reroute retained pending inputs as described below. Already permitted messaging continues on unblocked streams while membership and configuration authority remain fresh.

The signed successor binding supplies the configuration-writer address, independent of old streams. Runtime owner-role checks compare the local key and node against accepted authority. The active successor node cannot be removed or replaced until another handoff changes that binding. A role check alone cannot install a signing key or admit an unrecorded epoch.

Origins [retain full pending proposals](security.md#configuration-edit-storage) until an authenticated result commits, independently of transport retirement. Older requests whose local bodies were already retired report `payload_retained: false`; an exact resubmission can restore the input. Rerouting skips missing bodies and does not reconstruct an edit from its compact summary.

## Prepared successor configuration streams

The successor can prepare its own encrypted configuration streams while the current owner still signs. Trusted local-owner APIs split group creation from grant authorization, so neither owner key leaves its machine:

1. `prepare_owner_configuration` uses a locally saved candidate and the reader's authenticated MLS key package. It commits the group, signed Welcome, request fingerprint and candidate binding together. The stream accepts no application traffic and remains unavailable to configuration publication.
2. `authorize_owner_configuration` verifies the candidate and Welcome against current authority, signs a grant for that exact group, reader and candidate, then saves the grant before returning it. After the signing stop, only an already committed exact authorization can be retrieved.
3. `install_owner_configuration` installs the grant on the successor. `receive_owner_configuration` installs it on the reader and returns a signed receipt for the committed origin. `confirm_owner_configuration` verifies and retains that receipt on the successor. Each operation requires its node's local owner credential.

The grant's optional `owner_candidate` digest binds the existing checkpoint and successor node. Ordinary grants omit it and retain their canonical encoding. A prepared stream can publish only after accepted authority selects that exact candidate at that checkpoint. Incoming configuration also checks this binding, even when the sender supplies a correctly signed and encrypted update. Standby grants do not participate in selecting the current configuration writer. A different candidate, an unbound handoff or an ordinary old-owner update cannot activate the stream.

Creation and first installation require the exact fresh checkpoint. Saved preparations and installed grants support exact retries after candidate or lease expiry, with current node/key checks; those retries create no new authorization. Failed writes roll back MLS state and their associated records. Request IDs cannot convert an existing data/raw group into a standby stream. An abandoned standby does not retain unrelated future configuration history.

Schema 21 adds preparation and owner-grant records, with a combined 4,096-record / 64 MiB metadata admission budget. Origin packets use the existing configuration transport budget. Configuration grant installation also enforces the dispatcher's 4,096-stream limit. Missing current-schema preparation tables fail startup. `gent recovery status` reports preparation record and byte counts. Cleanup of abandoned preparations remains future work.

These are local Rust coordination APIs. There is no CLI/MCP handoff command or automatic encrypted exchange of these artifacts yet. Newly needed grants cannot be signed after the irreversible stop. Source authorization now requires the successor's readiness report before it can issue that stop.

## Readiness before the signing stop

`Store::owner_handoff_readiness` runs on the successor under its local owner credential. It checks the protected candidate key, exact unchanged checkpoint, every installed candidate stream's signed sequence-zero receiver confirmation, and bidirectional data links to every other enrolled node. It then signs a report with both the node key and candidate owner key and commits that report before returning it. This observes durable endpoint state; it does not reserve availability or prove that a peer has accepted the future owner epoch.

The report binds the candidate digest and approval window, with exactly one entry for each other enrolled node in sorted order. Each entry contains the reader ID, a digest of its approved configuration grant and the reader's original signed receipt. Full grants stay in the source's existing approval table. The source independently verifies those grants, candidate/group/origin bindings, peer coverage and both report signatures. It does not accept an arbitrary caller-supplied grant in place of its saved approval. Grant digests use `gent/owner-readiness-grant/v1\0`; report signatures use `gent/owner-readiness/v1\0` and `gent/owner-readiness-key/v1\0`.

`Store::record_owner_readiness` saves verified evidence on the source without stopping signing. `authorize_owner_handoff` verifies it again against the current checkpoint and clock inside the signing-stop transaction. Missing, corrupted, expired or stale evidence refuses a first authorization, leaving the source able to sign. Ordinary configuration changes can make a prepared candidate stale; this stage does not pause configuration during preparation. A report cannot extend the candidate's original approval window.

Cached reports and already issued authorizations support exact retries after restart or expiry. Returning old evidence grants no new signing authority. Schema-22 issued handoffs retain their exact authorization and irreversible stop on migration, even though they have no readiness report. Every new authorization uses the readiness requirement. Activation continues to recheck actual successor storage, so a saved report cannot bypass a later missing key, receipt or link.

Schema 23 adds `owner_readiness`. Source and successor each retain their candidate, baseline and report under a shared local limit of 64 reports and 64 MiB. Missing current-schema storage fails startup. Individual canonical reports are limited to 1.5 MiB and 1,023 peer entries; the maximum 1,024-node cluster fits within the transport record budget, including maximum-length group IDs. Failed writes preserve existing reports and leave the source unfrozen. Cleanup remains unfinished. These reports contain private topology metadata and must travel through authenticated encrypted transport when orchestration is added.

## Live activation

`Store::activate_owner_handoff` requires the successor's local owner credential, protected candidate key, saved completion and fully verified decision journal. It checks signed sequence-zero receiver receipts for every enrolled peer, exact candidate/group/key/baseline bindings and established bidirectional data links. A peer may go offline after confirming preparation; an unprepared peer prevents activation. Unbound or unjournaled legacy transitions remain unsupported by the live runtime.

One immediate transaction adopts completed decisions, records the accepted epoch and local candidate-key reference, and persists the successor state. It also renews an expired or nearly expired lease before commit. Database failures roll back these changes together. Keys remain in their original protected candidate files. Every signing operation resolves the key from accepted durable authority, including handles opened before activation. Returning ownership to the original node never restores its bootstrap signer. Archived signing stops must agree with accepted history.

After commit, activation wakes synchronization, projects TOML and reconciles pending local proposals. These follow-up operations can fail after activation has committed; an exact activation retry resumes them without issuing another handoff. Startup retries projection, and maintenance retries pending work. Completed decisions retain their original deciding writer and exact outcome. Authenticated journal adoption may exceed the ordinary request-admission limit; existing records remain intact, new requests are refused at capacity, and already admitted pending work can still finish. The journal and aggregate database bounds continue to apply.

Schema 22 stores accepted epochs, local key references, request delivery routes and retained inputs received by retired writers. Existing peers accept a new epoch only through the stream prepared for that exact successor; ordinary authority application and older streams cannot activate it. Initial enrollment can install independently trusted historical epochs for remote owners. Local selection always requires the atomic activation record. Missing epoch records or current-schema tables fail closed.

Each outgoing configuration stream stops at the end of the owner epoch for which it was prepared. It can finish delivering retained earlier revisions without racing a later handoff's stream. Once its publication cursor reaches that boundary, it no longer pins unrelated future authority history. Incoming duplicate history still checks saved accepted digests.

Origins reconcile at most eight retained proposals per pass. Route changes, cancellation of old events and new queue entries commit together. Successor request/result event IDs bind the owner epoch and writer, so transport deduplication cannot suppress rerouted work. A new owner returns an imported decision with its original deciding writer. A pending request ignores results from retired delivery routes; authenticated duplicate completed results must match exactly. A successor executes its own pending proposals through the same decision transaction.

A retired owner retains newly received undecided inputs without executing them, allowing later records on that stream to drain. This archive has a 4,096-record / 64 MiB admission limit and appears under `gent history` diagnostics. Exhaustion preserves incoming work through rollback. Retrieval, repair and cleanup APIs for these legacy inputs remain unfinished. Inputs unavailable at their origin are not automatically recovered from this archive.

Configuration signing authority is separate from service account ownership. Both enrolled nodes retain their existing relay credentials after transfer; historical owner/joined installation roles no longer override signed membership during service reconnect. This does not transfer a GitHub account, remove a node or grant a new service credential.

## Completed-request journal transfer

A result lost during handoff must not cause the successor to execute the same edit again. The source snapshots every completed configuration request, including rejections, in the transaction that stops signing. Each entry retains its origin, request ID, deciding writer, fingerprint, compact edit summary and exact result. Full legacy edits are reduced to summaries after checking their fingerprints. Pending requests are excluded because they have no decision yet.

The canonical manifest binds the candidate digest, exact checkpoint, entry count, total bytes and each page's length and hash. The old owner's signed transition commits to its digest. Page hashes bind both candidate and page position, allowing independent verification in any arrival order. Domains are `gent/owner-journal-manifest/v1\0` and `gent/owner-journal-page/v1\0`.

Trusted local-owner callers export through `owner_handoff_manifest/page`, then use `begin_owner_handoff_import`, `import_owner_handoff_page` and `owner_handoff_import_status` on the successor. Exact retries and restarts retain verified pages. Imports reserve the entire declared byte budget before receiving any page. Missing pages prevent completion; a corrupt page or failed database write leaves prior progress intact. The final page commits only after the assembled snapshot passes semantic checks. These Rust APIs return private plaintext to their trusted caller; encrypted network orchestration is still required before exposing a handoff command. No journal transfer is available through CLI, MCP or the hosted relay yet.

The successor checks canonical encoding, record count, ordering, identities, fingerprints, summaries, results and overlap with its local request history. Existing accepted-revision evidence must match applied results. A node enrolled later may lack old digests; the signed journal supplies decision evidence without inventing or overwriting accepted configuration history. Completion rechecks the stored pages and local evidence. Import alone changes neither the live request table nor active authority.

Schema 19 adds source/import manifests and page storage. Each snapshot permits 65,536 entries and 80 MiB, in pages of at most 256 KiB, with a 128 KiB manifest limit. Local imports and source snapshots share a 160 MiB reservation limit and at most 65 records. The database's aggregate allocation ceiling also applies. Transfer cleanup remains part of activation work. `gent recovery status` reports snapshot counts and reserved bytes, without exposing decisions. Schema-18 handoffs keep their original signatures and signing stop; migration does not fabricate a missing journal or enable their activation. Authorizations without a journal retain their original canonical encoding.

## Authorization and state

`VerifiedState::transfer_owner(current, successor, now)` requires both the current owner's private signing key and a fresh successor key. It returns the next signed state without changing storage or exporting either secret. A valid current signer can authorize a handoff even after its configuration lease expires, as it can authorize a renewal. The resulting state must have a fresh lease before authorizing operations.

The current owner signs a version-1 `OwnerTransition` containing:

- The original cluster trust anchor.
- The next consecutive owner epoch and digest of the preceding signed transition. The first transition uses the pinned genesis digest instead.
- The exact preceding configuration checkpoint, including revision and state hash.
- The successor public key and activation timestamp.
- For separate-node preparation, the enrolled successor node ID/key, signed candidate digest and optional journal commitment. The original single-process API omits this optional field and retains its original canonical encoding.

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

The remaining coordinator must exchange preparation, readiness and journal artifacts through encrypted channels and expose a resumable command. Physical cross-machine handoff acceptance, interrupted preparation, missing/conflicting-peer handling and service-policy verification remain unfinished. Legacy agent certificates and invitations need an explicit reissuance strategy. Old encryption-state snapshots must remain offline.

Complete loss of the current signing key is also unresolved. This API cannot authorize a successor from GitHub login, matching reports or possession of a node key. Recovery must use a separately protected copy of the current signer solely for authenticated succession, or a recovery authority established before loss. It must never resume an archived owner as a competing writer. A preauthorized offline recovery-key mechanism is not yet implemented.
