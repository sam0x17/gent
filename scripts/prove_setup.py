#!/usr/bin/env python3
"""Native owner setup against the private account Worker/GitHub fixture.

Uses an isolated forwarding proxy to interrupt responses after real D1 commits.
Requires test-auth-provider and Python 3.11+. Never uses real GitHub credentials.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
import tomllib
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--github-origin', required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix='gent-setup-cli-', dir='/tmp')).resolve()
    root.chmod(0o700)
    home = root / 'owner'
    env = dict(os.environ, GENT_TEST_GITHUB_ORIGIN=args.github_origin)
    base = [str(args.binary.resolve()), '--json', '--home', str(home)]
    fault = {}
    entered, release = threading.Event(), threading.Event()
    calls, credentials = [], []
    print(f'Setup proof state: {root}', flush=True)

    def http(path, method='GET', data=None, token=None, status=200):
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        try:
            response = urlopen(Request(args.service + path, method=method,
                data=json.dumps(data).encode() if data is not None else None, headers=headers), timeout=25)
        except HTTPError as error:
            response = error
        with response:
            body = response.read()
            assert response.status == status, ('fixture request', path, response.status, status)
            return json.loads(body) if body else None

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle_request(self):
            calls.append((self.command, self.path))
            headers = {k: v for k, v in self.headers.items() if k.lower() in ('authorization', 'content-type')}
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            if fault.get('before') == self.path:
                fault.clear()
                status, data = 503, b'{"error":"fixture_unavailable"}'
            else:
                try:
                    response = urlopen(Request(args.service + self.path, method=self.command,
                        headers=headers, data=body or None), timeout=25)
                except HTTPError as error:
                    response = error
                with response:
                    status, data = response.status, response.read()
                if fault.get('after') == self.path or (
                    fault.get('enroll') and self.command == 'PUT' and '/nodes/' in self.path
                ):
                    write_conflict = fault.get('write_conflict')
                    if fault.get('hold'):
                        entered.set()
                        assert release.wait(30), 'held response was not released'
                    fault.clear()
                    if write_conflict:
                        (home / 'relay.key').write_text('preserve concurrent file')
                        (home / 'relay.key').chmod(0o600)
                    else:
                        status, data = 503, b'{"error":"fixture_lost_response"}'
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = do_PUT = do_POST = do_DELETE = handle_request

    proxy = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    origin = f'http://127.0.0.1:{proxy.server_port}'
    pending = None
    service_installed = False

    def cli(*commands, code=0, node_home=None):
        command = base if node_home is None else [str(args.binary.resolve()), '--json', '--home', str(node_home)]
        result = subprocess.run(command + list(commands), env=env, text=True, capture_output=True, timeout=50)
        assert not any(secret in result.stdout + result.stderr for secret in credentials), 'credential printed'
        assert result.returncode == code, ('CLI exit', commands, result.returncode, code, result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def saved():
        return json.loads((home / 'auth' / 'session.json').read_text())

    def journal():
        return json.loads((home / 'service.json').read_text())

    def config():
        return tomllib.loads((home / 'config.toml').read_text())

    def preserve():
        return {p: hashlib.sha256((home / p).read_bytes()).hexdigest()
            for p in ['identity.key', 'owner.key']}

    def check_preserved(before, ids):
        assert preserve() == before, 'setup changed encryption keys'
        current = config()
        assert (current['cluster']['id'], current['node']['id']) == ids

    try:
        cli('cluster', 'new', 'setup-proof', code=1)
        assert not (home / 'config.toml').exists()
        cli('auth', 'login', '--headless', '--service', origin)
        credentials.append(saved()['token'])
        fault.update(before='/v1/transport/config')
        cli('cluster', 'new', 'setup-proof', code=1)
        assert not (home / 'service.json').exists() and not (home / 'owner.key').exists()

        # Hold discovery at the proxy only to learn the allocated cluster from
        # its first reservation request. The fault applies after its D1 commit.
        original = Proxy.handle_request
        def first_reservation(self):
            if self.command == 'PUT' and self.path.startswith('/v1/clusters/') and '/nodes/' not in self.path:
                fault.update(after=self.path)
                Proxy.do_PUT = original
            original(self)
        Proxy.do_PUT = first_reservation
        cli('cluster', 'new', 'setup-proof', code=1)
        initial = config()
        ids = initial['cluster']['id'], initial['node']['id']
        keys = preserve()
        bootstrap = json.loads((home / 'identity.key').read_bytes()[72:])
        assert (bootstrap['anchor']['cluster_id'], bootstrap['node']) == ids
        cluster_path = '/v1/clusters/' + ids[0]
        assert any(c['id'] == ids[0] for c in http('/v1/clusters', token=saved()['token']))
        assert journal()['initial'] is None and journal()['credential'] is None
        cli('daemon', 'run', code=1)  # No provisioned relay key yet.

        # D1 admits the candidate; terminate the waiting process before it can
        # observe that success. Concurrent setup/logout must both refuse.
        fault.update(enroll=True, hold=True)
        pending = subprocess.Popen(base + ['cluster', 'connect'], env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert entered.wait(15), 'enrollment did not reach the service'
        with ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(cli, 'cluster', 'connect', code=1)
            b = pool.submit(cli, 'auth', 'logout', code=1)
            a.result(timeout=10)
            b.result(timeout=10)
        token = journal()['credential']['token']
        credentials.append(token)
        assert journal()['credential']['confirmed'] is False
        pending.kill()
        pending.communicate(timeout=5)
        pending = None
        release.set()
        session = http('/v1/transport/session', token=token)
        assert (session['cluster_id'], session['node_id']) == ids
        fault.update(after='/v1/transport/session', write_conflict=True)
        cli('cluster', 'connect', code=1)
        assert journal()['credential']['confirmed']
        assert (home / 'relay.key').read_text() == 'preserve concurrent file'
        (home / 'relay.key').unlink()
        configured = cli('cluster', 'new', 'setup-proof')
        assert configured['status'] == 'configured' and not configured['cluster']['local_only']
        assert journal()['credential']['confirmed'] and (home / 'relay.key').read_text() == token
        before = sum(method == 'PUT' and '/nodes/' in path for method, path in calls)
        cli('cluster', 'connect')
        assert sum(method == 'PUT' and '/nodes/' in path for method, path in calls) == before
        check_preserved(keys, ids)
        cli('cluster', 'new', 'different', code=1)
        cli('cluster', 'new', 'local', '--local', code=1)
        print('PASS: durable keys/IDs, lost reservation, killed enrollment, concurrent setup/logout and exact retries', flush=True)

        # Replay the earlier crash boundary: a durable intent and owner RPC key,
        # with config.toml not yet published. The intended UUIDs must survive.
        early = root / 'early-bootstrap'
        (early / 'auth').mkdir(parents=True, mode=0o700)
        early.chmod(0o700)
        prepared = journal()
        initial = config()
        initial.pop('applied_revision', None)
        initial['cluster'].update(id=str(uuid.uuid4()), name='early-bootstrap')
        initial['node']['id'] = str(uuid.uuid4())
        initial['relay']['credential_file'] = str(early / 'relay.key')
        prepared.update(name='early-bootstrap', cluster_id=initial['cluster']['id'],
            node_id=initial['node']['id'], initial=initial, credential=None)
        early_key = secrets.token_hex(32)
        credentials.append(early_key)
        for relative, content in [('auth/session.json', json.dumps(saved())),
                                  ('owner.key', early_key), ('service.json', json.dumps(prepared))]:
            target = early / relative
            target.write_text(content)
            target.chmod(0o600)
        recovered = cli('cluster', 'connect', node_home=early)
        assert recovered['cluster']['id'] == initial['cluster']['id']
        assert recovered['node']['id'] == initial['node']['id']
        assert (early / 'owner.key').read_text() == early_key
        print('PASS: replay before config publication preserves intended UUIDs and the existing owner RPC credential', flush=True)

        for name in ['service.json', 'relay.key', 'owner.key', 'identity.key', 'config.toml']:
            assert (home / name).stat().st_mode & 0o077 == 0
        # Verify missing state is refused, not recreated under fresh identities.
        for name in ['config.toml', 'identity.key', 'state.sqlite3']:
            path = home / name
            backup = home / (name + '.proof-backup')
            path.rename(backup)
            try:
                cli('cluster', 'connect', code=1)
                assert not path.exists(), 'missing state was recreated'
            finally:
                backup.rename(path)
        relay = home / 'relay.key'
        relay.rename(home / 'relay.proof-backup')
        try:
            relay.symlink_to(home / 'relay.proof-backup')
            cli('cluster', 'connect', code=1)
        finally:
            relay.unlink()
            (home / 'relay.proof-backup').rename(relay)
        path = home / 'service.json'
        path.chmod(0o644)
        try:
            cli('cluster', 'connect', code=1)
        finally:
            path.chmod(0o600)
        # A different valid account cannot take over local cryptographic state.
        auth_path = home / 'auth' / 'session.json'
        original_auth = auth_path.read_bytes()
        other_token = f'gent_s1.{int(time.time())}.{secrets.token_hex(32)}'
        credentials.append(other_token)
        other_session = http('/v1/auth/github/token', 'POST', {
            'github_access_token': 'gho_bob_synthetic', 'session_token': other_token})
        other = dict(saved(), token=other_token, session=other_session)
        auth_path.write_text(json.dumps(other))
        try:
            cli('cluster', 'connect', code=1)
        finally:
            auth_path.write_bytes(original_auth)
            http('/v1/auth/session', 'DELETE', token=other_token, status=204)
        check_preserved(keys, ids)

        # Install a real isolated user service, then verify setup refuses the
        # running daemon before any account request or state mutation.
        service_installed = True
        installed = cli('daemon', 'install')
        assert installed['daemon']['managed'] and installed['cluster']['id'] == ids[0]
        before = len(calls)
        cli('cluster', 'connect', code=1)
        assert len(calls) == before
        cli('daemon', 'stop')
        cli('cluster', 'connect')
        assert cli('daemon', 'start')['daemon']['managed']
        cli('daemon', 'uninstall')
        service_installed = False
        check_preserved(keys, ids)
        print('PASS: private files, link/missing-state/account rejection, real service lifecycle and daemon exclusion', flush=True)

        # Confirmed revoked credentials can be replaced after a fresh login.
        cli('auth', 'logout')
        http('/v1/transport/session', token=token, status=401)
        cli('auth', 'login', '--headless', '--service', origin)
        credentials.append(saved()['token'])
        cli('cluster', 'connect')
        replacement = (home / 'relay.key').read_text()
        credentials.append(replacement)
        assert replacement != token and journal()['credential']['confirmed']
        assert http('/v1/transport/session', token=replacement)['node_id'] == ids[1]
        check_preserved(keys, ids)

        # A timestamp ahead of the service clock is not an expired candidate.
        # Retain it on failure; replacing it could orphan delayed admission.
        original_record = path.read_bytes()
        future = journal()
        future['credential'].update(token=f'gent_t1.{int(time.time())+3600}.{secrets.token_hex(32)}', confirmed=False)
        path.write_text(json.dumps(future))
        try:
            cli('cluster', 'connect', code=1)
            assert journal()['credential']['token'] == future['credential']['token']
        finally:
            path.write_bytes(original_record)

        # An unadmitted expired candidate is replaceable only after the service
        # rejects its timestamp. This fixture does not alter actual authority.
        record = journal()
        record['credential'].update(token=f'gent_t1.{int(time.time())-1000}.{secrets.token_hex(32)}', confirmed=False)
        path.write_text(json.dumps(record))
        cli('cluster', 'connect')
        current = (home / 'relay.key').read_text()
        credentials.append(current)
        assert current != record['credential']['token']
        check_preserved(keys, ids)

        # Node retirement cannot be bypassed by retry or a new local candidate.
        http(cluster_path + '/nodes/' + ids[1], 'DELETE', token=saved()['token'], status=204)
        cli('cluster', 'connect', code=1)
        refused = journal()['credential']['token']
        cli('cluster', 'connect', code=1)
        assert journal()['credential']['token'] == refused
        http('/v1/transport/session', token=current, status=401)
        check_preserved(keys, ids)
        cli('auth', 'logout')
        report = {'result': 'passed', 'cluster_id': ids[0], 'node_id': ids[1],
            'service_backend': installed['service']['backend'], 'relay_transport': 'not exercised by this setup proof'}
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS: reauthentication/credential replacement, expired admission, retirement and stable encryption identity', flush=True)
    finally:
        release.set()
        if pending and pending.poll() is None:
            pending.kill()
            pending.communicate(timeout=5)
        if service_installed:
            cli('daemon', 'uninstall')
        proxy.shutdown()
        proxy.server_close()


if __name__ == '__main__':
    main()
