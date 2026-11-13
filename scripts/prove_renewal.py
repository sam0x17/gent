#!/usr/bin/env python3
"""Native daemon renewal against an isolated synthetic account fixture.

The private harness provides one near-expiry login in a private file. This uses
the real systemd/launchd service and intentionally loses a renewal response.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    assert args.fixture.stat().st_mode & 0o077 == 0
    fixture = json.loads(args.fixture.read_text())
    token, original = fixture['token'], fixture['session']
    root = Path(tempfile.mkdtemp(prefix='gent-renewal-cli-', dir='/tmp')).resolve()
    root.chmod(0o700)
    home = root / 'node'
    (home / 'auth').mkdir(parents=True, mode=0o700)
    home.chmod(0o700)
    calls = []
    lost = threading.Event()

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_request(self):
            calls.append((self.command, self.path))
            headers = {k: v for k, v in self.headers.items() if k.lower() in ('authorization', 'content-type')}
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            try:
                response = urlopen(Request(args.service + self.path, method=self.command,
                    headers=headers, data=body or None), timeout=25)
            except HTTPError as error:
                response = error
            with response:
                status, data = response.status, response.read()
            if self.path == '/v1/auth/session/renew' and not lost.is_set():
                assert status == 200, 'renewal must commit before losing its response'
                status, data = 503, b'{"error":"fixture_lost_response"}'
                lost.set()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_DELETE = handle_request

    proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{proxy.server_port}'
    path = home / 'auth/session.json'
    path.write_text(json.dumps({'version': 1, 'service': origin, 'token': token,
        'phase': 'active', 'session': original}))
    path.chmod(0o600)
    installed = False

    def cli(*commands, code=0):
        result = subprocess.run([str(args.binary.resolve()), '--home', str(home), '--json', *commands],
            text=True, capture_output=True, timeout=60)
        assert token not in result.stdout + result.stderr, 'account credential printed'
        assert result.returncode == code, (commands, result.returncode, result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def wait(check):
        until = time.monotonic() + 20
        while not check():
            assert time.monotonic() < until, 'daemon renewal did not reach expected state'
            time.sleep(.1)

    print(f'Renewal proof state: {root}', flush=True)
    try:
        installed = True
        service = cli('daemon', 'install', '--new', 'renewal-proof', '--no-input')
        assert service['daemon']['managed']
        identity = {name: (home / name).read_bytes() for name in ('identity.key', 'owner.key', 'relay.key')}
        assert lost.wait(20), 'daemon did not attempt renewal on startup'
        wait(lambda: 'renewal pending' in '\n'.join(cli('daemon', 'logs')['lines']))
        assert json.loads(path.read_text())['session'] == original, 'failed response changed cached authority'
        current = cli('auth', 'status')['account']
        assert current['expires_at'] > original['expires_at']
        cli('daemon', 'restart')
        wait(lambda: json.loads(path.read_text())['session']['expires_at'] == current['expires_at'])
        assert calls.count(('POST', '/v1/auth/session/renew')) == 1, 'recovery repeated the renewal mutation'
        assert json.loads(path.read_text())['token'] == token
        assert {name: (home / name).read_bytes() for name in identity} == identity

        # A wrong login origin or disabled credential must never be used by the
        # daemon. These changes model local logout/reconfiguration, not clocks.
        cli('daemon', 'stop')
        saved = path.read_bytes()
        for mutation, diagnostic in [({'service': 'http://127.0.0.1:9'}, 'pinned to'),
                                     ({'phase': 'revoking'}, 'finish gent auth login')]:
            changed = json.loads(saved)
            changed.update(mutation)
            path.write_text(json.dumps(changed))
            count = len(calls)
            cli('daemon', 'start')
            wait(lambda: diagnostic in '\n'.join(cli('daemon', 'logs')['lines']))
            cli('daemon', 'stop')
            assert len(calls) == count, 'daemon used an unpinned or disabled login'
        path.write_bytes(saved)
        assert cli('auth', 'renew')['account']['expires_at'] == current['expires_at']
        assert calls.count(('POST', '/v1/auth/session/renew')) == 1
        cli('auth', 'logout')
        cli('auth', 'renew', code=1)
        assert {name: (home / name).read_bytes() for name in identity} == identity
        cli('daemon', 'uninstall')
        installed = False
        report = {'result': 'passed', 'service_backend': service['service']['backend'],
            'checks': ['automatic startup renewal', 'lost response and restart recovery',
                'unchanged account/node credentials and signing keys', 'pinned/disabled login refusal',
                'explicit renewal before due time', 'logout prevents renewal'],
            'provider': 'synthetic near-expiry session', 'relay_transport': 'not exercised',
            'periodic_hourly_timer': 'startup and restart checked; an hour-long wait was not run'}
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS: native automatic renewal, response-loss recovery, account pins, logout and unchanged keys', flush=True)
    finally:
        if installed:
            cli('daemon', 'uninstall')
        if json.loads(path.read_text()) is not None:
            cli('auth', 'logout')
        proxy.shutdown()
        proxy.server_close()


if __name__ == '__main__':
    main()
