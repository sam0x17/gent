# Native transport

Gent persists each outgoing message before choosing a path. Native nodes try
QUIC over a reachable LAN, VPN or public IP address. With wire version 7, a
third enrolled node can introduce the peers to each other and forward traffic
when they cannot connect directly. If native transport fails, peers can exchange
packets over their Cloudflare WebSocket or collect them later from the durable
mailbox. Each path carries the same MLS ciphertext. The receiver signs the
committed stream head, and the sender verifies that receipt before retiring
history. A lost reply can cause a replay. The receiver deduplicates packets
before chat delivery.

## Cluster helpers

Each native daemon can advertise its helper's IPv4 addresses and TLS certificate
in its encrypted address record. A helper admits a connection when the Iroh
endpoint identity matches the current signed cluster membership and endpoint
binding. It checks enrolled clients again while they are connected.

Both peers must be able to register with the same helper. They can reach it
through different addresses, for example a LAN address on one side and a public
address on the other. Gent shortlists helpers using the sum of the two measured
legs, then times an authenticated round trip to the destination peer through
each shortlisted candidate. It keeps a working route across small RTT changes. Peers can
upgrade a helper connection to a direct IP path when their networks allow UDP.
When UDP is blocked they can still exchange encrypted data through a reachable
helper over TCP. The cluster can operate without a tailnet.

A node maintains up to 16 helper registrations. It tries other advertised
addresses and helpers when registration fails. In a larger cluster, two peers
with no common registered helper can still use the Cloudflare fallback.

The helper listens on IPv4 TCP and UDP port 7842 by default. If that port is occupied,
Gent tries an available port and advertises it. Reachability across a router
depends on its existing firewall and forwarding rules. A host on a public IP can
act as a helper for two outbound-only networks when both can reach its listener.

Optional settings in `~/.gent/config.toml` apply after a daemon restart.

```toml
[transport]
direct = "auto" # "off" uses the Cloudflare transport
helper = "auto" # "off" disables hosting while allowing use of other helpers
udp = true      # false permits TCP helper connections and disables direct IP paths
relays = []     # up to four explicitly configured HTTPS Iroh relays
# helper_port = 7842
# helper_public_address = "203.0.113.10:7842" # existing public IPv4 port mapping
```

The direct dial budget is 250 ms and a native batch attempt has a three-second
deadline, including helper selection and the signed reply. Endpoint address
advertisements expire after three minutes. Queued work and on-demand presence
checks can refresh them. Older peers continue using their negotiated address
format and existing transports.

Direct access follows the cluster's signed configuration and its expiry. Cloud
account suspension denies service access; it does not instantly erase an
already-issued cluster membership on another machine. Revoking a node in the
cluster configuration denies it once that configuration arrives. A disconnected
node cannot observe a new revocation until synchronization resumes, and expired
authority denies further transport.

## Relay efficiency

Native peers that negotiate wire version 6 compress ordinary chat, directory,
presence and receipt fragments with zstd level 9 before MLS encryption. Gent
uses a fresh compression context for each fragment and keeps the compressed
form when it saves bytes. Records carrying private file grants, invitations or
configuration credentials retain their original encoding. Separate file objects
and configuration streams use their existing formats.

Gent records the peer's compression capability when it queues the event. Mixed
versions can exchange messages while nodes update. Retries on either network
path reuse the saved ciphertext, including after a restart.

Wire version 5 sends compact directory hashes. Unchanged directories carry only
the root, sequence, and database incarnation. First advertisements, changed
roots, repairs, and periodic refreshes while awaiting agreement include the
bounded branch summaries. After authenticated agreement the peers compare
roots until the directory or replica changes.
Missing records are pushed automatically. Version 4 peers retain their complete
summary format; negotiation makes rolling upgrades possible. Registration
generations remain authoritative across directory sequence rollback.

Version 2 relay watches subscribe to relevant packet and receipt streams.
A node and relay that negotiate acknowledged notifications keep the cloud
WebSocket silent while their queues are drained. A packet or signed checkpoint
change wakes its subscribed reader or writer. The daemon acknowledges scheduling
the read, and verifies the encrypted history separately. The relay retains
outstanding changes on the socket across hibernation and retries a missed
acknowledgment. Reconnecting reconciles the current directory of streams.
An outstanding upload, explicit connectivity check, or expiring configuration
authority can also trigger a check. Legacy watches retain timed repair scans,
and a lost watch falls back to mailbox reconciliation while it reconnects.

An uploaded packet can wait for its signed receipt without triggering another
upload on each scheduler pass. A timed repair sweep can compare several incoming
mailbox heads and signed-checkpoint fingerprints in one read. A changed stream,
reconnect, uncertain write or missed notification still triggers reconciliation.

The client combines up to 16 mailbox operations into one bounded HTTP exchange.
Clients and relays negotiate a binary envelope and a compact representation of
canonical packets and receipts. Older relays continue to accept JSON exchanges.
The service checks authorization once after its storage gate, preserves operation
order within each mailbox, and returns individual results. Operations across
mailboxes can run concurrently; an exchange is not an atomic transaction.
Unsupported servers use the existing individual requests. Authorization errors
and lost responses do not cause an immediate replay through another route.

## Inspection

`gent nodes` shows the last observed transfer path alongside presence.
`gent nodes --verbose` includes the time, sequence, direction of evidence and
helper ID when known. A signed receipt confirms the recipient committed that
stream sequence. A mailbox upload confirms the relay accepted ciphertext.
An exchange that used multiple QUIC paths, or whose STREAM counters could
not account for the transfer, is labeled accordingly. A hosted web node shows
its carrier's native transport evidence. Restarting the daemon clears the
observations.

`gent sync --json` reports mailbox operations and empty batch reads under
`relay_traffic`, QUIC traffic and dial/receipt failures under `direct_traffic`,
and separate counters for bulk sweeps and relayed WebSocket sessions. Counters
reset when the daemon starts. Include the WebSocket and sweep bytes when
comparing Cloudflare traffic. These process counters exclude TLS, address
discovery and other services.

Gent stages encrypted attachments in cloud storage before publishing their
messages. A recipient with a reachable sender can fetch its missing chunks
over a separate QUIC connection. It checks each chunk against the message's
manifest and resumes from cloud storage if the sender disconnects. A peer
serves a chunk only to the current authorized recipient's node. Direct file
bytes appear separately under `direct_traffic`.

Web connectors enter through Cloudflare and use the carrier and checkpoint
system. A native carrier may use direct transport to another node. Ordered
cluster configuration uses the cloud path.
