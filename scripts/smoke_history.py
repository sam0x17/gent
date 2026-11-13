#!/usr/bin/env python3
"""Exercise history cleanup and retry admission through real CLI/MCP processes.

Only the isolated database's request clock advances; the system clock is unchanged.
No relay, model calls, or permanent service changes.
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
    with tempfile.TemporaryDirectory(prefix='gent-history-', dir='/tmp') as directory:
        home = Path(directory).resolve() / 'state'
        base = [binary, '--home', str(home)]
        clients = []
        daemon = None

        def cli(*args, structured=True):
            output = subprocess.check_output(base + (['--json'] if structured else []) + list(args), text=True)
            return json.loads(output) if structured else output

        def start():
            nonlocal daemon
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
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

        def advance(timestamp):
            with sqlite3.connect(home / 'state.sqlite3') as db:
                db.execute('UPDATE request_clock SET floor=?', (timestamp,))
            cli('cluster', 'renew')

        def retired(client, tool, args):
            result = client.call(tool, args, error=True)
            assert 'expired' in json.dumps(result) or 'unavailable' in json.dumps(result), result

        try:
            cli('cluster', 'new', 'history-proof', '--local')
            start()
            a, b = connect()
            aid = a.call('gent_register', {'name': 'builder', 'provider': 'generic'})[0]['agent']['id']
            bid = b.call('gent_register', {'name': 'reviewer', 'provider': 'generic'})[0]['agent']['id']
            cli('permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
            cli('permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
            issued = a.call('gent_request_ids', {'count': 32})[0]
            assert len(set(issued['request_ids'])) == 32
            a.call('gent_request_ids', {'count': 33}, error=True)
            started = cli('history')['request_clock']
            unused = a.request_id()
            source = Path(a.call('gent_file_paths')[0]['import_directory']) / 'proof.bin'
            source.write_bytes(bytes(range(256)) * 8192)
            imported_request = {'request_id': a.request_id(), 'name': source.name, 'media_type': 'application/octet-stream'}
            imported = a.call('gent_file_import', imported_request)[0]
            request = {'request_id': a.request_id(), 'recipient': bid, 'text': 'old request', 'file_ids': [imported['file']['id']]}
            sent = a.call('gent_send', request)[0]
            reply = {'message_id': sent['message_id'], 'request_id': b.request_id(), 'text': 'old reply'}
            response = b.call('gent_reply', reply)[0]
            advance(started + 25 * 3600)
            assert a.call('gent_send', request)[0]['message_id'] == sent['message_id']
            assert b.call('gent_reply', reply)[0]['message_id'] == response['message_id']
            assert a.call('gent_file_import', imported_request)[0]['file'] == imported['file']
            retired(a, 'gent_send', {'request_id': unused, 'recipient': bid, 'text': 'never admitted'})
            advance(started + 9 * 86400)
            live = {'request_id': a.request_id(), 'recipient': bid, 'text': 'live work'}
            live_id = a.call('gent_send', live)[0]['message_id']
            assert cli('history')['messages'] == 3
            human = cli('history', structured=False)
            assert 'Gent messages: 3 / 8192' in human
            assert 'Configuration edit retries:' in human and 'legacy bodies:' in human
            assert 'Peer setup jobs: 0 / 65536' in human
            assert 'Retry records retained.' in cli('history', 'clean', '--dry-run', structured=False)
            cli('files', 'clean')
            preview = cli('history', 'clean', '--dry-run')
            assert preview['messages_removed'] == 2 and preview['import_retries_removed'] == 1
            assert cli('history')['messages'] == 3
            cleaned = cli('history', 'clean')
            assert cleaned['messages_removed'] == 2 and cleaned['exchanges_removed'] == 1
            retired(a, 'gent_send', request)
            retired(b, 'gent_reply', reply)
            source.write_bytes(bytes(range(256)) * 8192)
            retired(a, 'gent_file_import', imported_request)
            a.call('gent_send', dict(live, request_id=str(uuid.uuid4())), error=True)
            for client in clients:
                client.close()
            clients.clear()
            stop()
            start()
            a, b = connect()
            retired(a, 'gent_send', request)
            assert a.call('gent_send', live)[0]['message_id'] == live_id
            assert cli('history')['messages'] == 1
            # Startup maintenance must use the same persisted admission floor.
            advance(started + 18 * 86400)
            for client in clients:
                client.close()
            clients.clear()
            stop()
            start()
            deadline = time.monotonic() + 15
            while cli('history')['messages']:
                assert time.monotonic() < deadline, 'startup history maintenance did not finish'
                time.sleep(.05)
            a, b = connect()
            retired(a, 'gent_send', live)
            # Fill only this disposable database with synthetic reservations.
            # Real verification evidence is never deleted to make quota space.
            known_id = str(uuid.uuid4())
            known = cli('--request-id', known_id, 'cluster', 'renew')
            usage = cli('transport')['authority_history']
            limit = usage['max_accepted_revisions']
            assert limit == 1048576 and usage['max_digest_payload_bytes'] == 32 * 1024 * 1024
            count = limit - usage['accepted_revisions']
            synthetic_start = 10000000
            with sqlite3.connect(home / 'state.sqlite3') as db:
                checkpoint = db.execute('SELECT checkpoint FROM authority').fetchone()[0]
                db.execute('''WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<?)
                    INSERT INTO authority_digests SELECT ?+i,zeroblob(32) FROM n''', (count, synthetic_start))
            stop()
            start()
            assert cli('--request-id', known_id, 'cluster', 'renew')['revision'] == known['revision']
            blocked_id = str(uuid.uuid4())
            failed = subprocess.run(base + ['--json', '--request-id', blocked_id, 'cluster', 'renew'], capture_output=True, text=True, timeout=30)
            assert failed.returncode != 0 and 'accepted revision history quota' in failed.stderr
            with sqlite3.connect(home / 'state.sqlite3') as db:
                assert db.execute('SELECT checkpoint FROM authority').fetchone()[0] == checkpoint
                assert db.execute('SELECT COUNT(*) FROM configuration_edits WHERE id=?', (blocked_id,)).fetchone()[0] == 0
            cli('transport', 'clean')
            assert cli('transport')['authority_history']['accepted_revisions'] == limit
            assert 'Accepted revisions: 1048576 / 1048576' in cli('transport', structured=False)
            admitted = a.call('gent_send', {'recipient': bid, 'request_id': a.request_id(), 'text': 'existing authority at capacity'})[0]
            assert any(m['id'] == admitted['message_id'] for m in b.call('gent_inbox')[0])
            b.call('gent_ack', {'message_id': admitted['message_id']})
            assert a.call('gent_message_status', {'message_id': admitted['message_id']})[0]['state'] == 'delivered'
            with sqlite3.connect(home / 'state.sqlite3') as db:
                assert db.execute('DELETE FROM authority_digests WHERE revision>? AND revision<=?', (synthetic_start, synthetic_start + count)).rowcount == count
            accepted = cli('--request-id', blocked_id, 'cluster', 'renew')
            assert accepted['state'] == 'applied' and accepted['revision'] == known['revision'] + 1
            with sqlite3.connect(home / 'state.sqlite3') as db:
                assert db.execute('PRAGMA foreign_key_check').fetchall() == []
            print('PASS: UUIDv7 admission, retained retries, CLI preview/cleanup, native-file retry retirement, restart, and startup maintenance')
            print('PASS: accepted-revision quota, restart, exact owner retry, atomic refusal, CLI diagnostics, continued MCP delivery and retry after fixture capacity release')
        finally:
            for client in clients:
                client.close()
            stop()


if __name__ == '__main__':
    main()
