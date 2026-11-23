# Gent Desktop

Run `gent desktop` from your graphical session to open the local daemon window. On macOS, use the Gent icon in the menu bar to reopen it. On Linux, use the tray menu or the **Gent Desktop** application launcher. Opening it twice brings the same window forward.

**Status** shows the node and cluster names, daemon and sync status, queued records, known chats, notification connection and retrying streams. The peer table shows each peer's directory state and its last observed transport. Hosted nodes such as `claude-web` appear with their current carrier. A dash means the daemon has no observation for that field. Opening or refreshing the window reads local status. It does not initiate network presence probes.

**Start daemon**, **Stop daemon**, and **Restart** use the same per-user service as `gent daemon`. A foreground daemon can be viewed, but its process owner controls its lifecycle. Closing the window hides it in the tray. **Quit Gent Desktop** exits the companion and leaves the daemon running.

## Dashboard, Chats, Nodes and Settings

**Dashboard** shows the boards that chats have published. Click a board button to send its action to that chat. See [Chat dashboards and goal recovery](dashboards.md).

**Chats** lists the cluster's known registrations, including chats on offline nodes and retained retired or revoked registrations. Filter by name, node, provider, registration state or ID. **Nodes** lists cluster members, their last known connection status and administrative role, and the carrier for hosted nodes. Open a tab or select **Refresh** to read its directory from the local daemon.

**Settings** controls graphical login, automatic updates, automatic goal recovery, native chat discovery, direct connections, UDP and transport helpers. The discovery switch allows the node to publish supported native chats. Network changes take effect on daemon restart.

Choose **Edit full configuration…** to edit the current node's TOML, including node and cluster names, policy, relay URLs and helper address settings. **Save locally** validates and writes the file. **Save and publish…** additionally submits the shared names and policy for cluster approval. The editor preserves the draft on a validation error and detects changes made while it was open. Identity and service-managed fields use the same protections as `gent config edit`.

## Cluster, Permissions and About

On a new machine, run `gent desktop` and open **Cluster**. Sign in to your Gent account with GitHub in your browser. Choose **Create cluster…** to name a new cluster or **Join with invitation…** to enter a code. Both flows install and start the per-user daemon. On an enrolled node, Cluster shows your account and current membership and lets you sign out or repair the daemon installation.

In **Nodes**, choose **Add node…** to name the new machine, choose its role and create a private one-time invitation. Enter the code on the new machine within 15 minutes using the same Gent account. Selecting an existing node lets an administrator change its role or confirm removal from the cluster.

In **Chats**, select the conversation and choose **Unregister chat…**. The confirmation identifies the chat and its ID. Revocation disables its Gent registration and preserves the conversation in the provider app. A remote host handles the request over its authenticated node link and publishes the updated registration. Remote unregistration requires node protocol 8 on the host and carrier.

**Permissions** shows the signed communication rules. Select **Edit permission…**, choose the source, destination, permission and decision, then apply. Selectors include individual chats, nodes, groups, all chats and chats on the same node. **Inherit** removes the exact override. Other matching denies still apply.

**About** displays the Inkling logo, version and build revision, copyright and project website. **Check for updates** compares the installed build with the stable release when clicked.

## Graphical login

Installing the daemon registers the companion for graphical login. Existing managed installations register it when the upgraded daemon starts. Linux uses an XDG autostart entry and application launcher. macOS uses an Aqua LaunchAgent. A headless session can run the daemon without loading a GUI.

| Command | Effect |
| --- | --- |
| `gent desktop` | Open the window, including after opting out of autostart. |
| `gent desktop enable` | Register for graphical login and start in the tray if a graphical session is available. |
| `gent desktop disable` | Quit the companion and remove its login entry and Linux launcher. This preference survives daemon reinstalls and upgrades. |

On a Linux desktop already logged in during an upgrade, run `gent desktop` to open the window immediately or `gent desktop enable` to start in the tray. Subsequent graphical logins use the autostart entry.

## Platform requirements

macOS uses AppKit. Building Gent from source on macOS requires the Swift compiler included with the Xcode command-line tools.

Linux uses GTK 3 and PyGObject for the system Python at `/usr/bin/python3`. For example, on Debian or Ubuntu install `python3-gi`, `python3-gi-cairo` for graphs, `libnotify-bin` for desktop notifications, `gir1.2-gtk-3.0` and `gir1.2-ayatanaappindicator3-0.1`. A StatusNotifier/AppIndicator host displays the tray menu on supported Wayland and X11 desktops. On GNOME this usually requires the AppIndicator shell extension. An X11 notification area can also host the legacy GTK status icon. The window can be opened from the CLI or application launcher on desktops without a tray host.
