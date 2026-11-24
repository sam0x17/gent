# Gent Desktop

Run `gent desktop` from your graphical session to open the local daemon window. On macOS, use the Gent icon in the menu bar to reopen it. On Linux, use the tray menu or the **Gent Desktop** application launcher. Opening it twice brings the same window forward.

## Status

**Status** opens first. On an enrolled machine it shows the cluster and local node names, daemon and sync status, queued records, known chats, notification connection, and retrying streams. **Start daemon**, **Stop daemon**, and **Restart** control the per-user service. A foreground daemon can be viewed here and is controlled by its process owner.

The **Nodes** table lists the local node first. Each row shows the node’s role and last known connection status. Hover over the status for its evidence, such as a recent encrypted round trip or a timed-out presence check. For native peers, the directory column shows whether their chat directories agree, and the transport column shows the last observed route. For hosted members such as `claude-web`, **Hosted by** identifies the current carrier. A dash means there is no observation for that field. Filtering or refreshing the table uses the local daemon’s data.

Choose **Add node…** to create a private invitation. On the new machine, open Gent Desktop, sign in with the same GitHub account, and choose **Join with invitation…** within 15 minutes. Choose **Create cluster…** to start a new cluster. Signed-in users can also sign out here. Enrolled machines have an **Install or repair daemon…** action.

To rename a node, select its row and choose **Rename node…**. The dialog identifies the member by name and ID, including when you select a hosted connector. An administrator can also change a selected member’s role or remove it. If a change is queued, refresh after it is applied to see the result.

Closing the window hides it in the tray. **Quit Gent Desktop** exits the companion and leaves the daemon running.

## Dashboard, Chats and Settings

**Dashboard** shows the boards that chats have published. They share the available space, with vertical scrolling when needed. Charts follow your desktop’s colors. As a card widens, the plot expands while labels and lines keep their size. Click a link to open it in your default web browser, or a button to send its action to the publishing chat. See [Chat dashboards and goal recovery](dashboards.md).

**Chats** lists the cluster's known registrations, including chats on offline nodes and retained retired or revoked registrations. Filter by name, node, provider, registration state or ID. Open the tab or choose **Refresh** to read the directory from the local daemon.

In **Chats**, select the conversation and choose **Unregister chat…**. The confirmation identifies the chat and its ID. Revocation disables its Gent registration and preserves the conversation in the provider app. A remote host handles the request over its authenticated node link and publishes the updated registration. Remote unregistration requires node protocol 8 on the host and carrier.

**Settings** controls graphical login, automatic updates, automatic goal recovery, native chat discovery, direct connections, UDP and transport helpers. The discovery switch allows the node to publish supported native chats. Network changes take effect on daemon restart.

Choose **Edit full configuration…** to edit the current node's TOML, including node and cluster names, policy, relay URLs and helper address settings. **Save locally** validates and writes the file. **Save and publish…** additionally submits the shared names and policy for cluster approval. The editor preserves the draft on a validation error and detects changes made while it was open. Identity and service-managed fields use the same protections as `gent config edit`.

## Permissions and About

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

Linux uses GTK 3 and PyGObject for the system Python at `/usr/bin/python3`. For example, on Debian or Ubuntu install `python3-gi`, `python3-gi-cairo` and `gir1.2-rsvg-2.0` (librsvg 2.52 or newer) for charts, `libnotify-bin` for desktop notifications, `gir1.2-gtk-3.0` and `gir1.2-ayatanaappindicator3-0.1`. A StatusNotifier/AppIndicator host displays the tray menu on supported Wayland and X11 desktops. On GNOME this usually requires the AppIndicator shell extension. An X11 notification area can also host the legacy GTK status icon. The window can be opened from the CLI or application launcher on desktops without a tray host.
