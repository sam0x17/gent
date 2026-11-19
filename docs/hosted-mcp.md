# Connect a web or mobile chat

On a cluster machine that will stay online:

```sh
gent node add claude-personal --web
```

Gent creates a named web node and displays its private MCP URL. Paste that URL
into your provider's custom connector settings and select **No authentication**.
The URL itself is the credential; no OAuth client ID, secret or approval step is
needed. Keep it out of chat prompts, screenshots and public logs.

Use another name for each provider account, for example `claude-work` or
`chatgpt-personal`. Each web node has its own enrolled identity and conversation
bindings. Its native host provides the current chat directory, message storage
and encrypted links to other machines. A web node does not join the transport
mesh or maintain a separate directory replica. The machine's current cluster
and native node identity stay the same. Web nodes have the usual open default
permissions; use node/chat restrictions when needed. Node restrictions and
same-node rules continue to use the web node's own identity.

The machine's Gent daemon starts and supervises their gateways automatically.
Keep it online and signed in. It renews their service leases without copying
GitHub credentials into them. Updates restart their runtimes using the new
binary. Their messages, node identities and chat bindings persist. Upgrade all
native cluster nodes with `gent update` for hosted-node routing. Existing web
nodes migrate on their hosting machine and keep their connector URLs and chat
IDs; there is no need to reenroll or register the conversation again.

Migration reads a fixed snapshot while holding the child daemon lock. Before
committing the imported application state and migration record in one parent
transaction, it saves the child's required local hosting feature to block an
independent writer, including older binaries. It then activates the signed
hosting relationship. The original child database remains on disk as a
retained snapshot; conversation bindings stay in the child filesystem. The
parent becomes the live store. If the commit fails, the child stays fenced and
a retry imports the unchanged source again. Once the record is committed,
retries use it without importing again. A failed config save rolls back the
parent transaction.

Migration refuses conflicting records or combined storage limits that would
be exceeded. It also refuses unsupported legacy chat bindings, tracked
plaintext file handoffs/exports, and retained child permission or group
administration requests. Those requests retain their original configuration
origin and cannot safely be reassigned. A refusal preserves the source state
and rolls back the import; these cases need explicit migration support.

This route is **not end-to-end encrypted**. The model provider, Gent/Cloudflare's
web endpoint, and your hosting machine can read connector messages and files.
Other node-to-node traffic continues to use Gent's encrypted transport.

## Use the connector

Set up the connector on the provider's web or desktop interface first. In a new
chat, enable Gent and ask:

> Register this chat with Gent and let me talk to my target chat through you.

`gent_chats` lists permitted chats from the native host's synchronized directory,
with node names and stable IDs. A unique name such as `cit` is enough. Exact
duplicate names resolve to the most recently active chat when timestamps permit;
remaining ambiguity requires a choice. Native discovery can also register
supported conversations. An absent name alone does not establish a different
cluster: the host may still be synchronizing, or a restriction may hide it.

The connector opens a conversation handle, attaches to the selected chat,
sends each turn once, and retrieves the reply. The target needs a working
native wake adapter to answer while idle. The intermediary can be any active
chat with the connector. Neither ChatGPT nor Claude hosted MCP starts a new
turn in an idle web/mobile conversation.

After web works, try the same connector on your phone. Availability depends on
your account and the provider's current rollout. Actual Claude and ChatGPT
mobile acceptance is still being verified. Native Gent mobile apps are future
work.

## Manage a web node

```sh
gent node web list
gent node web url claude-personal
gent node web rotate claude-personal
gent node web revoke claude-personal
```

`list` shows connectivity without printing credentials. `url` retrieves the
current private URL. `rotate` invalidates the old URL and preserves the node's
existing chats and conversation handles. Update the provider's connector
settings with the replacement URL. URLs expire after one year; rotation
renews that lifetime. `revoke` disables the connector and stops its hosted
runtime while retaining data. Use a new name to create another web node, or
`gent node remove NODE_ID` to remove the revoked node from cluster membership.

For scripted setup, write the URL to a private file:

```sh
gent node add claude-personal --web --code-out ~/.gent/claude-url.txt
gent node web url claude-personal --out ~/.gent/claude-url.txt
```

Setup retries reuse the same node and URL. If setup reports the node is saved
but offline, keep the updated daemon running and check `gent node web list`.
An interrupted URL rotation resumes from its private journal. A revoked URL
cannot be reactivated by repeating setup.

Each machine can host up to 16 web nodes. Hosted state lives under `~/.gent/web`;
these are managed runtimes, with no profile selection or separate logins.
Existing OAuth gateway commands remain available for hosts that require OAuth;
see [OAuth setup](gateway-oauth.md).

## Interruptions and files

An offline gateway returns `503`. Gent does not replay interrupted tool calls.
Retry a send with its original request ID, or inspect its work/turn status;
creating a new request ID can duplicate work. A disconnected waiting call can
be resumed against the same turn ID. Replies remain on the daemon.

`gent_file_read` and `gent_file_view` work through the bridge. Inline raster
images are supported. Hosted bearer download links are not supported yet,
and provider attachment rendering still needs acceptance testing.

Conversation handles separate saved chats within each connector. They do not
authenticate the provider's actual chat ID. Someone with both the connector URL
and a copied handle can access that conversation. Rotation preserves handles;
revocation blocks all further connector requests. Apply mandatory restrictions
to the web node when needed.
