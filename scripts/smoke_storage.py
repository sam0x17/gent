#!/usr/bin/env python3
"""Prove journal migration and blocked-reader recovery with native CLI/MCP.

Only disposable state is changed. No model calls or permanent services.
"""
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time

from smoke_mcp import Client


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gent').resolve())
    with tempfile.TemporaryDirectory(prefix='gent-storage-', dir='/tmp') as directory:
        home = Path(directory).resolve() / 'state'
        base = [binary, '--home', str(home)]
        clients = []
        daemon = None
        reader = None

        def cli(*args, structured=True):
            output = subprocess.check_output(base + (['--json'] if structured else []) + list(args), text=True)
            return json.loads(output) if structured else output

        def start():
            nonlocal daemon
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 15
            while not (home / 'daemon.sock').exists():
                assert daemon.poll() is None and time.monotonic() < deadline, 'daemon startup failed'
                time.sleep(.05)

        def stop():
            nonlocal daemon
            if daemon and daemon.poll() is None:
                daemon.send_signal(signal.SIGTERM)
                assert daemon.wait(timeout=10) == 0
            if daemon:
                daemon.stderr.close()
                daemon = None

        def connect():
            for name in ('builder', 'reviewer'):
                clients.append(Client(base + ['mcp', 'serve', '--binding', str(home / 'bindings' / (name + '.key'))]))
            return clients[-2:]

        try:
            cli('cluster', 'new', 'storage-proof', '--local')
            start()
            a, b = connect()
            aid = a.call('gent_register', {'name': 'builder', 'provider': 'generic'})[0]['agent']['id']
            bid = b.call('gent_register', {'name': 'reviewer', 'provider': 'generic'})[0]['agent']['id']
            cli('permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
            cli('permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
            status = cli('files')['database']
            assert status['journal_mode'] == 'delete'
            assert status['max_bytes'] == status['configured_max_bytes'] == 2 * 1024**3
            assert 'configured limit: 2147483648' in cli('files', structured=False)
            request = {'request_id': a.request_id(), 'recipient': bid, 'text': 'retry after reader releases its snapshot'}
            reader = sqlite3.connect(home / 'state.sqlite3')
            reader.execute('BEGIN')
            before = reader.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
            result = a.call('gent_send', request, error=True)
            assert 'database is locked' in json.dumps(result), result
            assert reader.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == before
            reader.close()
            reader = None
            assert not (home / 'state.sqlite3-wal').exists()
            sent = a.call('gent_send', request)[0]
            assert any(m['id'] == sent['message_id'] for m in b.call('gent_inbox')[0])
            b.call('gent_ack', {'message_id': sent['message_id']})
            for client in clients:
                client.close()
            clients.clear()
            stop()
            # Simulate an old daemon that exited without checkpointing its WAL.
            subprocess.run([sys.executable, '-c', '''
import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('PRAGMA journal_mode=WAL')
db.execute('PRAGMA wal_autocheckpoint=0')
db.execute('PRAGMA user_version=11')
db.execute("INSERT INTO metadata VALUES('storage-proof','committed in WAL')")
db.commit()
os._exit(0)
''', str(home / 'state.sqlite3')], check=True)
            assert (home / 'state.sqlite3-wal').stat().st_size > 0
            start()
            a, b = connect()
            assert a.call('gent_send', request)[0]['message_id'] == sent['message_id']
            assert a.call('gent_message_status', {'message_id': sent['message_id']})[0]['state'] == 'delivered'
            with sqlite3.connect(home / 'state.sqlite3') as db:
                assert db.execute('PRAGMA user_version').fetchone()[0] == 25
                assert db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete'
                assert db.execute("SELECT value FROM metadata WHERE key='storage-proof'").fetchone()[0] == 'committed in WAL'
                assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
            assert not (home / 'state.sqlite3-wal').exists()
            assert cli('files')['database']['max_bytes'] == 2 * 1024**3
            print('PASS: database limits, CLI diagnostics, pinned-reader atomic refusal, MCP retry/delivery, crash-left WAL migration and exact retry after restart')
        finally:
            if reader:
                reader.close()
            for client in clients:
                client.close()
            stop()


if __name__ == '__main__':
    main()
