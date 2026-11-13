#!/usr/bin/env python3
"""Test CLI/MCP file retention against an isolated daemon; no models or relay.

The harness advances only its temporary database deadlines to test expiry.
"""
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from smoke_mcp import Client


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gent').resolve())
    with tempfile.TemporaryDirectory(prefix='gent-retention-', dir='/tmp') as directory:
        root = Path(directory).resolve()
        home = root / 'state'
        base = [binary, '--home', str(home)]
        clients = []
        daemon = None

        def cli(*args, structured=True):
            output = subprocess.check_output(base + (['--json'] if structured else []) + list(args), text=True)
            return json.loads(output) if structured else output

        def wait_for(check):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if check():
                    return
                time.sleep(.05)
            raise AssertionError('retention proof timed out')

        def start():
            nonlocal daemon
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            def ready():
                assert daemon.poll() is None, 'test daemon exited'
                return (home / 'daemon.sock').exists()
            wait_for(ready)

        def stop():
            nonlocal daemon
            if daemon and daemon.poll() is None:
                daemon.send_signal(signal.SIGTERM)
                assert daemon.wait(timeout=10) == 0
            if daemon:
                daemon.stderr.close()
                daemon = None

        def expiry():
            with sqlite3.connect(home / 'state.sqlite3') as db:
                db.executescript('UPDATE file_objects SET expires_at=1; UPDATE file_handoffs SET expires_at=1,next_attempt=0;')

        try:
            cli('cluster', 'new', 'retention-proof', '--local')
            start()
            for name in ('builder', 'reviewer'):
                clients.append(Client(base + ['mcp', 'serve', '--binding', str(home / 'bindings' / (name + '.key'))]))
            a, b = clients
            aid = a.call('gent_register', {'name': 'builder', 'provider': 'generic'})[0]['agent']['id']
            bid = b.call('gent_register', {'name': 'reviewer', 'provider': 'generic'})[0]['agent']['id']
            cli('permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
            cli('permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
            source = root / 'saved-original.bin'
            payload = bytes(range(256)) * 8192
            source.write_bytes(payload)
            outbox = Path(a.call('gent_file_paths')[0]['import_directory'])
            staged = outbox / 'proof.bin'
            staged.write_bytes(payload)
            request = {'request_id': str(uuid.uuid4()), 'name': staged.name, 'media_type': 'application/octet-stream'}
            imported = a.call('gent_file_import', request)[0]
            assert imported['cleanup_after'] > time.time()
            sent = a.call('gent_send', {'request_id': str(uuid.uuid4()), 'recipient': bid,
                'text': 'retention proof', 'file_ids': [imported['file']['id']]})[0]
            received = b.call('gent_inbox')[0][0]
            exported = b.call('gent_file_export', {'file_id': received['attachments'][0]['id']})[0]
            target = Path(exported['path'])
            assert target.read_bytes() == source.read_bytes()
            b.call('gent_ack', {'message_id': sent['message_id']})
            status = cli('files', 'status')
            assert status['handoffs']['tracked_copies'] == status['objects']['count'] == 2
            assert 'Tracked handoff copies: 2' in cli('files', structured=False)
            expiry()
            preview = cli('files', 'clean', '--dry-run')
            assert preview['handoffs_removed'] == preview['expired_objects'] == 2
            assert staged.exists() and target.exists()
            assert cli('files')['retained_messages'] == 1
            result = cli('files', 'clean')
            assert result['plaintext_bytes_removed'] == 2 * len(payload)
            assert not staged.exists() and not target.exists()
            assert source.read_bytes() == payload
            assert cli('files')['retained_import_retries'] == 1

            # Crash-equivalent recovery: stop, rename one tracked path to its
            # persistent recovery name, replace the original, then restart.
            staged.write_bytes(payload)
            request['request_id'] = str(uuid.uuid4())
            a.call('gent_file_import', request)
            for client in clients:
                client.close()
            clients.clear()
            stop()
            expiry()
            with sqlite3.connect(home / 'state.sqlite3') as db:
                handoff = db.execute('SELECT id FROM file_handoffs').fetchone()[0]
            recovery = staged.with_name('.gent-clean-' + handoff + '.tmp')
            staged.rename(recovery)
            staged.write_bytes(b'user replacement')
            start()
            wait_for(lambda: cli('files')['handoffs']['tracked_copies'] == 0)
            assert not recovery.exists() and staged.read_bytes() == b'user replacement'
            assert source.read_bytes() == payload
            assert cli('files')['retained_messages'] == 1
            assert cli('files')['retained_import_retries'] == 2
            print('PASS: native MCP files, CLI status/preview/cleanup, original preservation, and startup recovery')
        finally:
            for client in clients:
                client.close()
            stop()


if __name__ == '__main__':
    main()
