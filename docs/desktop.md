# Gent Desktop

Run `gent desktop` from your graphical session to open the local daemon window. On macOS, use the Gent icon in the menu bar to reopen it. On Linux, use the tray menu or the **Gent Desktop** application launcher. Opening it twice brings the same window forward.

The window shows the node and cluster names, daemon and sync status, queued records, and known chat count. The peer table shows each peer's directory state and its last observed transport. A dash means the daemon has no observation for that field. Opening or refreshing the window reads local status. It does not initiate network presence probes.

**Start daemon**, **Stop daemon**, and **Restart** use the same per-user service as `gent daemon`. A foreground daemon can be viewed, but its process owner controls its lifecycle. Closing the window hides it in the tray. **Quit Gent Desktop** exits the companion and leaves the daemon running.

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

Linux uses GTK 3 and PyGObject for the system Python at `/usr/bin/python3`. For example, on Debian or Ubuntu install `python3-gi`, `gir1.2-gtk-3.0` and `gir1.2-ayatanaappindicator3-0.1`. A StatusNotifier/AppIndicator host displays the tray menu on supported Wayland and X11 desktops. On GNOME this usually requires the AppIndicator shell extension. An X11 notification area can also host the legacy GTK status icon. The window can be opened from the CLI or application launcher on desktops without a tray host.
