"""Optional, isolated WebKitGTK surface for a Desktop-validated static document."""
from functools import lru_cache
import json
import os
import subprocess
import tempfile

STATIC_BOARD_URI = "gent-board://document/"
STATIC_BOARD_CSP = ("sandbox; default-src 'none'; style-src 'unsafe-inline'; "
                    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
# Block every resource except the one synthetic top-level response. Neither the
# rule nor the temporary compiled filter contains any board data.
STATIC_BOARD_RULES = [
    {"trigger": {"url-filter": ".*"}, "action": {"type": "block"}},
    {"trigger": {"url-filter": "^gent-board://document/$", "resource-type": ["document"]},
     "action": {"type": "ignore-previous-rules"}},
]


@lru_cache(maxsize=1)
def dashboard_browser():
    try:
        gi.require_version("WebKit2", "4.1")
        gi.require_version("Soup", "3.0")
        from gi.repository import Gio, Soup, WebKit2
        # WebKit aborts the application if it cannot spawn its sandbox proxy.
        # Probe namespace availability before creating a browser process.
        if os.environ.get("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"):
            return None
        probe = subprocess.run(["bwrap", "--unshare-user", "--unshare-net", "--unshare-pid",
                                "--ro-bind", "/", "/", "--proc", "/proc",
                                "--", "/usr/bin/true"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=2, check=False)
        if probe.returncode or not hasattr(WebKit2.Settings, "get_all_features"):
            return None
        return WebKit2, Soup, Gio
    except (ImportError, ValueError, OSError, subprocess.TimeoutExpired):
        return None


class DashboardStatic(Gtk.Stack):
    def __init__(self, browser, source, revision):
        super().__init__(homogeneous=False)
        self.source, self.revision = source, revision
        self.web, self.soup, self.gio = browser
        self.native = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.add(self.native)
        self.view = None
        self.started = False
        self.served = False
        self.failed = False
        self.cancel = self.gio.Cancellable()
        self.temp = tempfile.TemporaryDirectory(prefix="gent-board-filter-")
        self.connect("destroy", self.cleanup)
        store = self.web.UserContentFilterStore.new(self.temp.name)
        store.save("static", GLib.Bytes.new(json.dumps(STATIC_BOARD_RULES).encode()), self.cancel, self.ready)

    # The document scrolls within its allocated native board. WebKit's natural
    # height can track its previous backing surface (including its device scale).
    def do_get_preferred_height(self):
        if self.view is not None and self.get_visible_child() == self.view:
            return 240, 240
        return Gtk.Stack.do_get_preferred_height(self)

    def do_get_preferred_height_for_width(self, width):
        if self.view is not None and self.get_visible_child() == self.view:
            return 240, 240
        return Gtk.Stack.do_get_preferred_height_for_width(self, width)

    def cleanup(self, *_):
        self.failed = True
        self.cancel.cancel()
        self.source = None
        self.view = None
        self.temp.cleanup()

    def ready(self, store, result):
        try:
            rule = store.save_finish(result)
            if self.cancel.is_cancelled():
                return
            web = self.web
            context = web.WebContext.new_ephemeral()
            context.set_sandbox_enabled(True)
            if not context.get_sandbox_enabled() or not context.is_ephemeral():
                return
            data = context.get_website_data_manager()
            data.set_persistent_credential_storage_enabled(False)
            data.get_cookie_manager().set_accept_policy(web.CookieAcceptPolicy.NEVER)
            security = context.get_security_manager()
            security.register_uri_scheme_as_no_access("gent-board")
            security.register_uri_scheme_as_display_isolated("gent-board")
            context.register_uri_scheme("gent-board", self.respond)
            context.connect("download-started", lambda _, download: download.cancel())
            settings = web.Settings(enable_javascript=False, enable_javascript_markup=False, auto_load_images=False,
                                    enable_html5_local_storage=False, enable_html5_database=False, enable_media=False,
                                    enable_webrtc=False, enable_webgl=False,
                                    allow_file_access_from_file_urls=False, allow_universal_access_from_file_urls=False)
            # Speculative connections can precede an ordinary subresource load.
            features = settings.get_all_features()
            for i in range(features.get_length()):
                feature = features.get(i)
                if feature.get_identifier() in ("LinkDNSPrefetch", "LinkPreconnect", "LinkPreconnectEarlyHints",
                                                "LinkPrefetch", "LinkPreload", "SpeculationRulesPrefetch"):
                    settings.set_feature_enabled(feature, False)
            manager = web.UserContentManager()
            manager.add_filter(rule)
            self.view = web.WebView(web_context=context, user_content_manager=manager, settings=settings,
                                    default_content_security_policy=STATIC_BOARD_CSP)
            self.view.set_size_request(1, 240)
            self.view.set_hexpand(True)
            self.view.set_vexpand(True)
            self.view.connect("decide-policy", self.policy)
            self.view.connect("permission-request", lambda _, request: request.deny() or True)
            self.view.connect("authenticate", lambda _, request: request.cancel() or True)
            self.view.connect("run-file-chooser", lambda _, request: request.cancel() or True)
            self.view.connect("context-menu", self.menu)
            self.view.connect("load-failed", self.fallback)
            self.view.connect("web-process-terminated", self.fallback)
            self.view.connect("load-changed", self.loaded)
            self.add(self.view)
            self.view.show()
            self.view.load_uri(STATIC_BOARD_URI)
        except (GLib.Error, TypeError, ValueError, AttributeError, OSError):
            self.fallback()

    def respond(self, request):
        if self.failed or self.served or request.get_uri() != STATIC_BOARD_URI or request.get_web_view() != self.view:
            request.finish_error(GLib.Error.new_literal(self.gio.io_error_quark(), "Unavailable",
                                                        self.gio.IOErrorEnum.PERMISSION_DENIED))
            return
        self.served = True
        content = GLib.Bytes.new(self.source.encode("utf-8"))
        stream = self.gio.MemoryInputStream.new_from_bytes(content)
        response = self.web.URISchemeResponse.new(stream, content.get_size())
        response.set_status(200, "OK")
        headers = self.soup.MessageHeaders.new(self.soup.MessageHeadersType.RESPONSE)
        headers.append("Content-Security-Policy", STATIC_BOARD_CSP)
        headers.append("X-DNS-Prefetch-Control", "off")
        headers.append("Cache-Control", "no-store")
        response.set_http_headers(headers)
        response.set_content_type("text/html; charset=utf-8")
        request.finish_with_response(response)

    def policy(self, _, decision, kind):
        web = self.web
        if kind == web.PolicyDecisionType.NAVIGATION_ACTION:
            request = decision.get_navigation_action().get_request()
            if not self.started and request.get_uri() == STATIC_BOARD_URI:
                self.started = True
                decision.use()
                return True
        elif kind == web.PolicyDecisionType.RESPONSE:
            if self.served and decision.is_main_frame_main_resource() and decision.get_response().get_uri() == STATIC_BOARD_URI:
                decision.use()
                return True
        decision.ignore()
        return True

    def menu(self, _, menu, event, hit):
        allowed = self.web.ContextMenuAction
        for item in menu.get_items():
            if item.get_stock_action() not in (allowed.COPY, allowed.SELECT_ALL):
                menu.remove(item)
        return not menu.get_items()

    def loaded(self, _, event):
        if event == self.web.LoadEvent.FINISHED and self.served and not self.failed:
            self.set_visible_child(self.view)

    def fallback(self, *_):
        self.failed = True
        if not self.cancel.is_cancelled():
            self.set_visible_child(self.native)
        return True
