# Connect a web or mobile chat

The hosted gateway publishes your node at
`https://mcp.gent.link/clusters/CLUSTER_UUID/nodes/NODE_UUID/mcp`. Your node opens an outbound
connection; no inbound port or separate tunnel is required. Keep this node and
its Gent daemon online. The target agent can run on another cluster node.

This route is **not end-to-end encrypted**. The model provider, Gent/Cloudflare's
web endpoint, and your gateway node can read connector messages and files.
Other node-to-node traffic continues to use Gent's encrypted transport.

The Worker/native round trip has local integration coverage. Actual Claude and
ChatGPT mobile acceptance is still being verified. The native Gent mobile app
is a separate, future project.

## Prepare the gateway

Run `gent cluster --json` on the node that will stay online and copy its
`node.id` and `cluster.id`. Replace `NODE_UUID` and `CLUSTER_UUID` below with
those values. Register each provider
separately; credentials belong in the provider's connector settings, never in
a chat prompt.

For Claude:

```sh
gent gateway clients add claude --conversation-handles \
  --oauth-resource https://mcp.gent.link/clusters/CLUSTER_UUID/nodes/NODE_UUID/mcp \
  --redirect-uri https://claude.ai/api/mcp/auth_callback \
  --out ~/.gent/claude-connector.json
```

For ChatGPT:

```sh
gent gateway clients add chatgpt --conversation-handles \
  --oauth-resource https://mcp.gent.link/clusters/CLUSTER_UUID/nodes/NODE_UUID/mcp \
  --redirect-uri https://chatgpt.com/connector_platform_oauth_redirect \
  --out ~/.gent/chatgpt-connector.json
```

Gent implements issuer identification, which permits ChatGPT's stable callback.
Check the callback shown in your MCP management page; if it differs, register
that exact URL instead. Existing registrations cannot change callbacks through
an installation retry. See [OAuth setup](gateway-oauth.md) for signed clients,
client metadata documents and revocation.

The private export's `client` is the OAuth client ID; `token` is the client
secret. Registration retries with the same options and export preserve them.
The registration defaults to a thirty-day lifetime.

Install and inspect the publisher:

```sh
gent gateway service install --hosted
gent gateway service status --json
```

`connected: true` means the publisher reached Gent's bridge. It does
not prove that a provider has connected. `gent gateway run --hosted` is the
foreground alternative. Service installation and updates retain hosted mode.

## Connect the provider

In Claude's web or desktop connector settings, add a custom connector with the
MCP URL above. Select OAuth and **Use your own OAuth client**, then enter the
export's client ID and secret. Custom connector setup on mobile is still a
provider beta; web or desktop setup is the primary route.

In ChatGPT's MCP/plugin management, add the same URL using a predefined OAuth
client and its separate export. Whether a private connector is available on
your phone depends on your account and the provider's current rollout.

Start the connection. Gent's browser page displays its request ID and callback.
On the gateway node:

```sh
gent gateway oauth requests
gent gateway oauth approve REQUEST_UUID
```

Approve only the request from the connection you just started, then click
**Continue after approval** in the browser. Normal chat turns require no
terminal access; reauthorization requires approval again.

Enable the connector in a chat and ask it to register with Gent, list agents,
and relay to the selected agent. The connector instructions open and retain
this chat's conversation handle, attach the target, send each turn once, and
wait for its response. A completed response preserves the target's text and
images. For longer work, keep the turn ID and retrieve its result later.

The selected remote agent needs a working native wake adapter to answer while
idle. An MCP connection by itself cannot wake a provider conversation.

## Interruptions and files

An offline gateway returns `503`. Gent does not replay interrupted tool calls.
Retry a send with its original request ID, or inspect its work/turn status;
creating a new request ID can duplicate work. A disconnected waiting call can
be resumed against the same turn ID. Replies remain on the daemon.

`gent_file_read` and `gent_file_view` work through the bridge. Inline raster
images are supported. Provider download imports require the existing explicit
origin policy. Hosted bearer download links (`--file-downloads`) are not yet
supported, and provider attachment rendering still needs acceptance testing.

Conversation handles separate saved agents and are scoped to the connector's
OAuth authorization. Refresh preserves them; reauthorization creates a new
scope. They do not authenticate a provider's actual chat ID. A copied handle
within the same authorization can be used by another chat, and a chat can open
more handles. Apply mandatory restrictions to the gateway node when needed.
