# Native transport

Gent persists outgoing messages before choosing a network path. Native nodes
try an authenticated QUIC connection when a peer has advertised a reachable
address. Otherwise they use the encrypted Cloudflare mailbox. Both paths carry
the same saved MLS packets and use the receiver's signed receipt to retire
history. A lost response can therefore be retried without importing the message
twice.

Direct setup has a 250 ms connection deadline and a three-second total attempt
deadline. Failed endpoints back off for 30 seconds while mailbox delivery stays
available. Each daemon has one UDP endpoint and bounded incoming and cached
outgoing connections. Endpoint keys and addresses travel inside the encrypted
node stream. Receivers recheck current signed membership and the endpoint-key
binding on each request. Address advertisements expire after three minutes and
refresh when addresses change or their lifetime is nearly half spent.

The default uses reachable LAN, VPN, or public IP addresses. It does not enable
router port mapping, public address lookup, or an external Iroh relay. Networks
that prevent direct UDP communication continue through Cloudflare. This is not
a claim of universal NAT traversal.

These optional settings are local to the node in `~/.gent/config.toml`:

```toml
[transport]
direct = "auto" # default; use "off" to require Cloudflare mailboxes
relays = []     # optional explicit HTTPS Iroh relay URLs, at most four
```

Restart the daemon after changing transport settings. Turning direct delivery
off also takes effect on subsequent requests before restart. A configured Iroh
relay can help establish paths through NAT and may itself relay encrypted
traffic. It is separate from Gent's durable Cloudflare mailbox.

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
roots, repairs, and periodic refreshes include the bounded branch summaries.
Missing records are pushed automatically. Version 4 peers retain their complete
summary format; negotiation makes rolling upgrades possible. Registration
generations remain authoritative across directory sequence rollback.

Version 2 relay watches subscribe to relevant packet and receipt streams.
Notifications only schedule reconciliation; they never prove delivery or advance
a cursor. Queued work runs immediately, and a periodic full scan recovers lost
hints. Scheduling rotates between streams to prevent a busy peer starving others.

The client combines up to 16 mailbox operations into one bounded HTTP exchange.
The service checks authorization once after its storage gate, preserves operation
order within each mailbox, and returns individual results. Operations across
mailboxes can run concurrently; an exchange is not an atomic transaction.
Unsupported servers use the existing individual requests. Authorization errors
and lost responses do not cause an immediate replay through another route.

## Inspection

`gent sync --json` includes `relay_traffic` and `direct_traffic` under transport
status, alongside directory agreement and queue state. Counters reset with the
daemon. Relay counters cover mailbox exchanges and their fallback requests;
they exclude configuration, files, HTTP framing, and other services. Direct
packet counters exclude QUIC framing and address discovery. Read the returned
scope before treating either counter as a network bill.

Web connectors still enter through Cloudflare and use the existing carrier and
checkpoint system. A native carrier may use direct transport to another node.
Large file objects and ordered cluster configuration retain their cloud paths.
