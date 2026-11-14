#!/usr/bin/env python3
"""Prove encrypted offline backups with real CLI/MCP state and SQLite crashes.

Uses disposable state and generic MCP clients. Never activates extracted state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import time

from smoke_mcp import Client, PNG


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, required=True)
    parser.add_argument('--peer', help='Optional SSH host for cross-platform verification/extraction')
    parser.add_argument('--remote-gent', default='/tmp/gent-proof.9w8yGG/target/debug/gent')
    args = parser.parse_args()
    binary = str(args.gent.resolve())
    with tempfile.TemporaryDirectory(prefix='gent-backup-', dir='/tmp') as directory:
        folder = Path(directory).resolve()
        folder.chmod(0o700)
        home, key, archive, restored = [folder / name for name in ('node', 'recovery.key', 'node.age', 'offline')]
        clients = []
        daemon = None

        def cli(*args, state=home, error=False):
            result = subprocess.run([binary, '--home', str(state), '--json', *map(str, args)],
                                    input='', text=True, capture_output=True, timeout=60)
            if error:
                assert result.returncode != 0, args
                return result.stderr
            assert result.returncode == 0, (args, result.stderr)
            return json.loads(result.stdout)

        def start():
            nonlocal daemon
            daemon = subprocess.Popen([binary, '--home', str(home), 'daemon', 'run'],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 15
            while not (home / 'daemon.sock').exists():
                assert daemon.poll() is None, daemon.stderr.read()
                assert time.monotonic() < deadline, 'daemon startup timed out'
                time.sleep(.025)

        def stop():
            nonlocal daemon
            if daemon:
                daemon.terminate()
                try:
                    assert daemon.wait(timeout=10) == 0, daemon.stderr.read()
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
                    raise
                finally:
                    daemon.stderr.close()
                    daemon = None

        def connect():
            for name in ('builder', 'reviewer'):
                clients.append(Client([binary, '--home', str(home), 'mcp', 'serve',
                                       '--binding', str(home / 'bindings' / (name + '.key'))]))
            return clients[-2:]

        try:
            cli('backup', 'keygen', '--output', key)
            assert not home.exists()
            cli('cluster', 'new', 'backup-proof', '--local')
            start()
            a, b = connect()
            aid, bid = [c.call('gent_register', {'name': n, 'provider': 'generic-proof'})[0]['agent']['id']
                        for c, n in ((a, 'builder'), (b, 'reviewer'))]
            cli('permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
            cli('permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
            payload = bytes(range(256)) * 8192
            staged = Path(a.call('gent_file_paths')[0]['import_directory']) / 'visual-data.bin'
            staged.write_bytes(payload)
            staged.chmod(0o600)
            imported = a.call('gent_file_import', {'request_id': a.request_id(), 'name': staged.name,
                                                  'media_type': 'application/octet-stream'})[0]
            a.call('gent_send', {'request_id': a.request_id(), 'recipient': bid,
                                'text': 'pending visual review', 'file_ids': [imported['file']['id']],
                                'files': [{'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': PNG}]})
            assert b.call('gent_inbox')[0][0]['text'] == 'pending visual review'
            cli('backup', 'create', archive, '--identity', key, error=True)
            assert not archive.exists()
            for client in clients:
                client.close()
            clients.clear()
            stop()
            # A killed legacy writer leaves committed data only in its WAL.
            subprocess.run([sys.executable, '-c', '''
import os, sqlite3, sys
d=sqlite3.connect(sys.argv[1]); d.execute('PRAGMA journal_mode=WAL'); d.execute('PRAGMA wal_autocheckpoint=0')
d.execute('CREATE TABLE backup_probe (id INTEGER PRIMARY KEY, value BLOB)')
d.execute('INSERT INTO backup_probe VALUES (1, ?)', (b'committed-wal',)); d.commit(); os._exit(0)
''', str(home / 'state.sqlite3')], check=True, timeout=15)
            assert (home / 'state.sqlite3-wal').exists()
            created = cli('backup', 'create', archive, '--identity', key)
            assert not (home / 'state.sqlite3-wal').exists()
            inspected = cli('backup', 'inspect', archive, '--identity', key, '--files', state=folder / 'absent')
            assert inspected['archive_id'] == created['archive_id']
            assert not (folder / 'absent').exists()
            assert cli('backup', 'verify', archive, '--identity', key)['state'] == 'verified'
            assert cli('backup', 'extract', archive, '--identity', key, '--output', restored)['activation'] == 'unsupported'
            if args.peer:
                remote = subprocess.check_output(['ssh', args.peer, 'mktemp -d /tmp/gent-backup-cross.XXXXXXXX'], text=True, timeout=15).strip()
                assert re.fullmatch(r'/tmp/gent-backup-cross\.[A-Za-z0-9]+', remote), remote
                def remote_cli(*command, error=False):
                    result = subprocess.run(['ssh', args.peer, shlex.join([args.remote_gent, '--json', *command])],
                                            capture_output=True, text=True, timeout=60)
                    if error:
                        assert result.returncode != 0 and 'offline recovery directory' in result.stderr
                        return None
                    assert result.returncode == 0, result.stderr
                    return json.loads(result.stdout)
                try:
                    subprocess.run(['scp', '-p', str(archive), str(key), args.peer + ':' + remote + '/'], check=True, timeout=60,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    remote_archive, remote_key, remote_output = remote + '/node.age', remote + '/recovery.key', remote + '/offline'
                    assert remote_cli('backup', 'verify', remote_archive, '--identity', remote_key)['archive_id'] == created['archive_id']
                    assert remote_cli('backup', 'extract', remote_archive, '--identity', remote_key, '--output', remote_output)['state'] == 'extracted_offline'
                    remote_cli('--home', remote_output, 'daemon', 'run', error=True)
                    copied = folder / 'peer-state.sqlite3'
                    subprocess.run(['scp', args.peer + ':' + remote_output + '/state.sqlite3', str(copied)], check=True, timeout=60,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    assert copied.read_bytes() == (restored / 'state.sqlite3').read_bytes()
                finally:
                    subprocess.run(['ssh', args.peer, shlex.join(['rm', '-rf', '--', remote])], check=True, timeout=15)
            for entry in inspected['entries']:
                source, target = home / entry['path'], restored / entry['path']
                assert target.stat().st_mode & 0o777 == (0o700 if entry['kind'] == 'directory' else 0o600)
                if entry['kind'] == 'file':
                    assert hashlib.sha256(source.read_bytes()).hexdigest() == entry['sha256']
                    assert target.read_bytes() == source.read_bytes()
            with sqlite3.connect(restored / 'state.sqlite3') as db:
                assert db.execute('SELECT value FROM backup_probe').fetchone()[0] == b'committed-wal'
            assert 'offline recovery directory' in cli('daemon', 'run', state=restored, error=True)
            assert 'offline recovery directory' in cli('mcp', 'serve', state=restored, error=True)
            assert 'offline recovery directory' in cli('backup', 'create', folder / 'invalid.age', '--identity', key, state=restored, error=True)
            cli('backup', 'extract', archive, '--identity', key, '--output', restored, error=True)
            cli('backup', 'create', archive, '--identity', key, error=True)
            # A killed rollback-journal writer must not enter the next archive.
            subprocess.run([sys.executable, '-c', '''
import os, sqlite3, sys
d=sqlite3.connect(sys.argv[1]); d.execute('PRAGMA journal_mode=DELETE'); d.execute('PRAGMA cache_size=1')
d.execute('UPDATE backup_probe SET value=?', (b'old' * 700000,)); d.commit()
d.execute('BEGIN IMMEDIATE'); d.execute('UPDATE backup_probe SET value=?', (b'new' * 700000,)); os._exit(0)
''', str(home / 'state.sqlite3')], check=True, timeout=15)
            assert (home / 'state.sqlite3-journal').exists()
            second, recovered2 = folder / 'second.age', folder / 'offline2'
            cli('backup', 'create', second, '--identity', key)
            assert not (home / 'state.sqlite3-journal').exists()
            cli('backup', 'extract', second, '--identity', key, '--output', recovered2)
            with sqlite3.connect(recovered2 / 'state.sqlite3') as db:
                assert db.execute('SELECT value FROM backup_probe').fetchone()[0] == b'old' * 700000
            damaged = folder / 'damaged.age'
            damaged.write_bytes(second.read_bytes()[:-1])
            damaged.chmod(0o600)
            failed = folder / 'failed'
            cli('backup', 'extract', damaged, '--identity', key, '--output', failed, error=True)
            assert not failed.exists() and not list(folder.glob('.gent-*'))
            # Only the original current node returns to service.
            start()
            a, b = connect()
            assert a.call('gent_register', {'name': 'builder', 'provider': 'generic-proof'})[0]['agent']['id'] == aid
            assert b.call('gent_register', {'name': 'reviewer', 'provider': 'generic-proof'})[0]['agent']['id'] == bid
            assert b.call('gent_inbox')[0][0]['text'] == 'pending visual review'
            print(json.dumps({'status':'passed','proof':'encrypted-backup','platform':os.uname().sysname,'peer':args.peer,
                              'checks':['real MCP text/image/native file state','live daemon refusal',
                                        'full verification and private exact extraction','WAL crash checkpoint',
                                        'hot-journal rollback','guarded activation','no overwrite or failed staging',
                                        'original node restart and pending inbox']}))
        finally:
            for client in clients:
                client.close()
            stop()


if __name__ == '__main__':
    main()
