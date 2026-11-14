#!/usr/bin/env python3
"""Diagnose real disposable daemon/MCP installations without changing state.

No provider calls, real host configuration edits or service installation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import threading
import time


def snapshot(root):
    result = {}
    for path in sorted(root.rglob('*')):
        meta = path.lstat()
        if stat.S_ISREG(meta.st_mode):
            result[str(path.relative_to(root))] = (meta.st_mode, hashlib.sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISDIR(meta.st_mode):
            result[str(path.relative_to(root))] = (meta.st_mode, 'directory')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, required=True)
    binary = parser.parse_args().gent.resolve()
    with tempfile.TemporaryDirectory(prefix='gent-doctor-', dir='/tmp') as temporary:
        root = Path(temporary).resolve()
        home = root / 'node'
        process = None
        host_flags = ['--codex-config-dir', str(root / 'codex'), '--claude-config-dir', str(root / 'claude'),
                      '--shell', 'zsh', '--rc-file', str(root / 'zshrc')]

        def cli(*args, code=0):
            result = subprocess.run([str(binary), '--home', str(home), '--json', *args],
                                    capture_output=True, text=True, timeout=15)
            assert result.returncode == code, (result.returncode, result.stderr)
            return json.loads(result.stdout)

        def doctor(code=0, cluster=None):
            before = snapshot(root)
            selection = ['--cluster', cluster] if cluster else []
            value = cli(*selection, 'doctor', *host_flags, code=code)
            assert snapshot(root) == before, 'doctor changed disposable state'
            assert value['version'] == 1
            return value, {c['id']: c for c in value['checks']}

        try:
            _, checks = doctor(code=3)
            assert checks['configuration']['status'] == 'fail' and not home.exists()
            cli('cluster', 'new', 'doctor-proof', '--local')
            _, checks = doctor(code=3)
            assert checks['daemon']['status'] == 'fail'
            for host, directory in [('codex', 'codex'), ('claude-code', 'claude')]:
                cli('integration', 'install', host, '--config-dir', str(root / directory))
            cli('hooks', 'install', '--shell', 'zsh', '--rc-file', str(root / 'zshrc'))
            log = root / 'daemon.log'
            with log.open('wb') as output:
                process = subprocess.Popen([str(binary), '--home', str(home), 'daemon', 'run'],
                                           stdin=subprocess.DEVNULL, stdout=output, stderr=output)
            for _ in range(200):
                assert process.poll() is None
                if (home / 'daemon.sock').exists():
                    break
                time.sleep(0.025)
            initial = cli('cluster')
            cluster = initial['cluster']['id']
            # Wait for the daemon's immediate maintenance pass before snapshots.
            time.sleep(0.2)
            value, checks = doctor()
            assert checks['daemon']['status'] == checks['authority']['status'] == 'pass'
            assert checks['codex']['status'] == checks['claude_code']['status'] == checks['shell']['status'] == 'pass'
            assert checks['relay']['status'] == 'skip'
            assert value['home'] == str(home)
            key = (home / 'owner.key').read_text().strip()
            assert key not in json.dumps(value)
            cli('gateway', 'clients', 'add', 'diagnostic-host', '--conversation-key', 'fixture/thread',
                '--out', str(root / 'host-grant.json'))
            # No gateway is running: a missing lock must not be recreated by inspection.
            (home / 'gateway' / 'state.lock').unlink()
            value, checks = doctor()
            assert checks['gateway']['status'] == 'pass'
            assert not (home / 'gateway' / 'state.lock').exists()
            host_token = json.loads((root / 'host-grant.json').read_text())['token']
            assert host_token not in json.dumps(value)
            # A pending projection and clock rollback are diagnosed, not repaired.
            import sqlite3
            with sqlite3.connect(home / 'state.sqlite3') as db:
                old_floor, = db.execute('SELECT floor FROM request_clock').fetchone()
                db.execute("INSERT OR REPLACE INTO metadata VALUES('config_projection','pending')")
                db.execute('UPDATE request_clock SET floor=?', (int(time.time()) + 3600,))
            _, checks = doctor(code=3)
            assert checks['authority']['evidence']['clock_ahead'] is True
            assert checks['config_projection']['status'] == 'warn'
            with sqlite3.connect(home / 'state.sqlite3') as db:
                db.execute('DELETE FROM metadata WHERE key=?', ('config_projection',))
                db.execute('UPDATE request_clock SET floor=?', (old_floor,))
            # Persistent installations stay pinned when CLI selection changes.
            cli('cluster', 'new', 'other-profile', '--local')
            value, checks = doctor(cluster=cluster)
            assert value['cluster_id'] == cluster and checks['daemon']['status'] == 'pass'
            value, checks = doctor(code=3)
            assert value['cluster_id'] != cluster and checks['daemon']['status'] == 'fail'
            assert checks['codex']['status'] == 'skip'
            # Raw host parse errors must never enter the diagnostic report.
            host_config = root / 'codex' / 'config.toml'
            original = host_config.read_bytes()
            host_config.write_text('[PRIVATE-HOST-SENTINEL\n')
            value, checks = doctor(code=3, cluster=cluster)
            assert checks['codex']['status'] == 'warn'
            assert 'PRIVATE-HOST-SENTINEL' not in json.dumps(value)
            assert checks['codex']['next']['command'][-3:] == ['codex', '--config-dir', str(root / 'codex')]
            host_config.write_bytes(original)
            process.terminate()
            assert process.wait(timeout=15) == 0
            process = None
            # An unresponsive owned socket cannot hang the diagnostic command.
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(str(home / 'daemon.sock'))
            os.chmod(home / 'daemon.sock', 0o600)
            listener.listen(1)
            stop = threading.Event()

            def stall():
                conn, _ = listener.accept()
                with conn:
                    conn.recv(8192)
                    stop.wait(8)

            thread = threading.Thread(target=stall, daemon=True)
            thread.start()
            try:
                started = time.monotonic()
                _, checks = doctor(code=3, cluster=cluster)
                assert time.monotonic() - started < 8
                assert checks['daemon']['status'] == 'fail'
            finally:
                stop.set()
                thread.join(timeout=2)
                listener.close()
                (home / 'daemon.sock').unlink()
            assert key not in log.read_text()
            print(json.dumps({'status': 'passed', 'proof': 'doctor', 'platform': os.uname().sysname,
                              'checks': ['missing setup', 'both installed MCP hosts', 'live authenticated probe',
                                         'no file changes', 'gateway inspection without lock creation',
                                         'clock and projection diagnosis', 'profile isolation',
                                         'host-error redaction', 'bounded unresponsive socket']}))
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == '__main__':
    main()
