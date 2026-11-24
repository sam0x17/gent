"""A private default HTTP(S) handler that records each opened URL for GTK fixtures."""
import os
import subprocess


def install_fixture_browser(root):
    # Both the desktop and the association check inherit this private XDG configuration.
    config = root / "config"
    apps = root / "data/applications"
    config.mkdir(exist_ok=True)
    apps.mkdir(parents=True, exist_ok=True)
    opener = root / "opener"
    opener.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$HOME/opened"\n')
    opener.chmod(0o700)
    name = "gent-fixture-browser.desktop"
    (apps / name).write_text(f'[Desktop Entry]\nName=Fixture browser\nType=Application\nExec="{opener}" %u\n'
                             "MimeType=x-scheme-handler/http;x-scheme-handler/https;\n")
    (config / "mimeapps.list").write_text(f"[Default Applications]\nx-scheme-handler/http={name}\n"
                                          f"x-scheme-handler/https={name}\n")
    os.environ.update(HOME=str(root), XDG_CONFIG_HOME=str(config), XDG_DATA_HOME=str(apps.parent),
                      GTK_USE_PORTAL="0")
    for scheme in ("http", "https"):
        result = subprocess.check_output(["gio", "mime", "x-scheme-handler/" + scheme],
                                         env=dict(os.environ, LC_ALL="C"), text=True)
        assert result.splitlines()[0].endswith(": " + name), result
    return name
