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
encrypted agent registration and cluster visibility rules.

Codex history is read in pages of 32 chats, including archived history. Each
page is saved before the next is requested; a failed read retains earlier chats
and retries its cursor. After three failures Gent restarts the read-only scan
in case the host expired its cursor. Inventory reads may wait up to 30 seconds;
message submissions retain their existing timeout and uncertainty rules.

Each native session ID maps to one Gent identity. Later MCP calls in that chat
reuse it. Identical titles produce separate entries, including on the same
node. Send by the returned agent ID after resolving a unique name; ask the user
to choose when several entries match. Native title changes do not overwrite a
name the user already set in Gent.

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
their normal Gent integration. Use `gent agent revoke AGENT_ID` to remove an
agent's access, or uninstall/disable the host's wake integration to stop native
delivery. Disabling indexing cannot recall names already shared with peers.
