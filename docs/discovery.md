# Discover native chats automatically

`gent node discovery enable` lets this node publish supported native chat names
and accept messages for them before their first Gent tool call. Existing nodes
keep this disabled. Interactive enrollment asks whether to enable it; scripts
can use `gent cluster join CODE --discover-chats true` or `false`.

Install Gent's host integration and leave the Gent daemon running:

```sh
gent integration install codex --vscode
gent integration install claude-code
gent node discovery enable
gent node discovery refresh
gent node discovery status
```

Use `--vscode` for Codex's VS Code extension. CLI-only installations can omit it.
Codex's shared native server must be available for indexing. Start it with
`gent integration start codex` if needed. The node status reports unavailable
hosts and partial inventories; it does not claim that every indexed chat can
currently receive a turn.

The same preference can be edited in `~/.gent/config.toml`:

```toml
[discovery]
enabled = true
```

`enable` starts a scan immediately. If the daemon already has a scan running,
the command shows its saved results and marks the scan as in progress. Status
also shows the age of the last check, so an empty first scan is distinguishable
from a completed inventory.

Managed daemons often have a smaller `PATH` than an interactive shell. Gent also
checks standard user installation directories, Codex's standalone package, and
Homebrew locations for native executables. It does not source shell startup
files. You do not need to reinstall the daemon to pick up these locations.

This setting belongs to the local node and survives synchronized cluster
configuration changes. The daemon normally checks inventory once a minute;
initial large inventories are registered in batches. Up to 4,096 native chats
can be indexed. Indexing reads native metadata and explicit titles, without
running model turns or publishing transcript bodies. Names follow ordinary
encrypted chat registration and cluster visibility rules.

Codex history is read in pages of 32 chats, including archived history. Each
page is saved before the next is requested; a failed read retains earlier chats
and retries its cursor. After three failures Gent restarts the read-only scan
in case the host expired its cursor. Inventory reads may wait up to 30 seconds;
message submissions retain their existing timeout and uncertainty rules.

Each native session ID maps to one Gent identity. Later MCP calls in that chat
reuse it. Identical titles produce separate entries, including on the same
node. Use `gent_resolve` (or CLI `gent resolve`) to select the most recently active
exact match, then send by its returned ID. Native title changes do not overwrite
a name the user already set in Gent.

## Directory reconciliation

Registration publishes a chat immediately. Installing an encrypted link to a new
node also publishes every existing local registration, including manually
registered chats. Native discovery normally scans once a minute; a chat found by
that scan uses the same registration and publication path.

Version 4 carries each replica's directory root, persistent local sequence and a
bounded hash frontier on ordinary encrypted records, including heartbeats.
The tree includes every known committed chat registration in the cluster. A
receiver immediately pushes differing records, including records learned from
other trusted enrolled nodes. The original node need not be online. No repair
request or forwarding grant is required. Message senders still authenticate as
their actual carrier, and chat permissions remain unchanged.

The frontier covers the complete tree with at most 128 subtree summaries. It
contains no individual chat records. Large trees keep some branches coarse;
repair sends at most 32 registrations per page and retains one pending page per
peer. Pages continue locally without requests for subsequent pages. Matching
branches send no registrations. Chat messages and receipts take priority over
repair pages. A full repair queue retains its cursor for retry without rejecting
an incoming chat message.

Each machine persists its own sequence and increments it when its known tree
changes. Sequences from different machines are never compared. Older snapshots
from the same node cannot restart newer repair work; equal sequences with
different roots still reconcile. A sequence is not a claim that a replica is
complete. Registration generations select newer records, and roots establish
whether replicas actually agree. Normal heartbeat traffic supplies the idle
fallback. Unchanged snapshots do not generate acknowledgement loops.

Version 3 peers retain the once-a-minute request/reply comparison of a native
carrier and its hosted web chats. Earlier peers continue ordinary announcements.
Queued ciphertext and older codecs remain valid during rolling updates.

`gent sync` reports directory comparisons separately from transport progress,
including the time and chat count of the last match. Its JSON output also includes
the local sequence, peer sequences and deferred repair errors. This is evidence about
registered metadata; it does not prove native discovery has indexed every chat
or that a model can receive a turn. Activity and polling timestamps do not change
directory roots. Existing activity synchronization remains separate.

Revocations remain in the tree even when hidden from the local listing. An
unexplained extra entry is reported as a remaining difference, never deleted
solely because it is absent from a peer's response. Reconciliation does not
change chat visibility rules, permissions, messages, or wake state.

## Conversation activity

The daemon stores `last_activity_at` separately from `last_seen`. Discovery
refreshes it from Codex's native `updatedAt` metadata and Claude's most recent
non-meta user/assistant record timestamp in a bounded transcript tail. New
outbound Gent messages also record activity; identical send retries do not.
Polling, listing, registration and synchronization never make a chat more recent.
Unknown native activity stays null; transcript modification time is not a substitute.

Updates travel as metadata over the existing encrypted node links. Peers merge
timestamps monotonically, so delayed updates cannot move activity backward.
Older daemons continue ordinary messaging; activity sync starts after both
endpoints support it. Only the hosting node can publish a chat's activity.
The record contains an identity and timestamp, without transcript content.

Name resolution uses exact case-insensitive names and optional node/provider
qualifiers. Full chat IDs take precedence over names. When multiple visible
active matches all have activity and one is strictly newest, it becomes the
default. Missing or tied timestamps require a choice. Retired registrations
never participate. Once attached, a relay keeps its target ID until explicitly
changed; activity updates and retries cannot redirect an existing exchange.

## Waking an indexed chat

Codex uses the managed shared server's loaded-thread queue. A chat with completed
history and an empty native queue can also be resumed for a new pending message.
Gent preserves its saved model settings. Incomplete turns, approval holds and
uncertain previous deliveries retain the existing recovery restrictions.
Custom native sockets can deliver to loaded threads but are not automatically
started. Per-window provider-switcher servers remain outside this inventory.

Claude indexes local session identities and explicit titles, plus the native
`claude agents --json --all` inventory. A loaded chat with Gent's native plugin
can receive messages even if it has never called a Gent tool. Supported native
background sessions can be reopened through the existing recovery adapter.
Closed interactive sessions must be reopened in Claude before delivery. Gent
does not create a replacement session to imitate the original conversation.

Automatic recovery spends the same bounded, persistent retry budget as explicit
recovery selections. Incoming messages still pass the cluster's permissions;
discovery does not answer native approval requests or authorize unrelated work.

`gent node discovery disable` stops new indexing and discovery-driven recovery.
Previously published registrations remain, and already loaded native chats keep
their normal Gent integration. Use `gent chat revoke AGENT_ID` to remove a
chat's access, or uninstall the host's integration to stop native
delivery. Disabling indexing cannot recall names already shared with peers.
