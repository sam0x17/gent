#!/usr/bin/env python3
"""Exercise local work reconciliation through native CLI/MCP and daemon crashes.

Disposable state and a synthetic host output only. No models or hosted service.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

from smoke_mcp import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', required=True, type=Path)
    args = parser.parse_args()
    binary = str(args.gent.resolve())
    with tempfile.TemporaryDirectory(prefix='gent-work-', dir='/tmp') as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        home = root / 'state'
        output = root / 'host-output.txt'
        base = [binary, '--home', str(home)]
        clients = []
        daemon = None

        def cli(*command, error=False):
            result = subprocess.run(base + ['--json', *map(str, command)],
                                    text=True, capture_output=True, timeout=30)
            if error:
                assert result.returncode != 0, command
                return result.stderr
            assert result.returncode == 0, (command, result.stderr)
            return json.loads(result.stdout)

        def start():
            nonlocal daemon
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                assert daemon.poll() is None, daemon.stderr.read()
                if (home / 'daemon.sock').exists():
                    probe = subprocess.run(base + ['daemon', 'status'], capture_output=True, timeout=3)
                    if probe.returncode == 0:
                        return
                time.sleep(.02)
            raise AssertionError('daemon did not become ready')

        def stop(crash=False):
            nonlocal daemon
            for client in clients:
                client.close()
            clients.clear()
            if daemon is not None:
                try:
                    if crash:
                        daemon.kill()
                    else:
                        daemon.terminate()
                    code = daemon.wait(timeout=15)
                    assert code == (-9 if crash else 0), daemon.stderr.read()
                finally:
                    if daemon.poll() is None:
                        daemon.kill()
                        daemon.wait()
                    daemon.stderr.close()
                    daemon = None

        def connect(name):
            client = Client(base + ['mcp', 'serve', '--binding', str(home / 'bindings' / (name + '.key'))])
            clients.append(client)
            identity = client.call('gent_register', {'name': name, 'provider': 'generic-work-proof'})[0]['agent']['id']
            return client, identity

        try:
            cli('cluster', 'new', 'work-proof', '--local')
            start()
            source, source_id = connect('source')
            target, target_id = connect('target')
            outsider, _ = connect('outsider')
            cli('permission', 'allow', source_id, target_id, '--permission', 'enumerate', 'send')
            cli('permission', 'allow', target_id, source_id, '--permission', 'enumerate', 'receive')
            sent = source.call('gent_send_non_blocking', {'recipient': target_id, 'request_id': source.request_id(),
                                            'text': 'create the disposable proof output'})[0]
            message = sent['message_id']
            begin = {'message_id': message, 'expect_revision': 0, 'description': 'create synthetic host output'}
            assert target.call('gent_work_status', {'message_id': message})[0]['record'] is None
            outsider.call('gent_work_status', {'message_id': message}, error=True)
            # Send begin without consuming its response. Observe the durable
            # record through a separate owner process, then crash the daemon.
            target.counter += 1
            target.write({'jsonrpc': '2.0', 'id': target.counter, 'method': 'tools/call',
                          'params': {'name': 'gent_work_begin', 'arguments': begin}})
            deadline = time.monotonic() + 10
            while not cli('work')['entries']:
                assert time.monotonic() < deadline, 'begin was not persisted'
                time.sleep(.02)
            stop(crash=True)
            start()
            source, resumed_source = connect('source')
            target, resumed_target = connect('target')
            assert (resumed_source, resumed_target) == (source_id, target_id)
            retry = target.call('gent_work_begin', begin)[0]
            assert retry['started_now'] is False and retry['record']['attempts'] == 1
            assert not output.exists()
            assert source.call('gent_inbox')[0] == []
            target.call('gent_work_reconcile', {'message_id': message}, error=True)
            target.call('gent_work_begin', dict(begin, expect_revision=1), error=True)
            print('PASS: lost MCP response and daemon crash preserve uncertainty; no automatic retry or reply', flush=True)

            # The test owner checks that the isolated host output never existed.
            abandoned = cli('work', 'reconcile', message, '--expect-revision', 1,
                            '--decision', 'abandoned', '--note', 'checked: synthetic output absent')
            assert abandoned['record']['revision'] == 2
            approval_args = ['work', 'reconcile', message, '--expect-revision', 2,
                             '--decision', 'retry-approved', '--note', 'checked: one fresh fixture attempt is authorized']
            approved = cli(*approval_args)
            assert cli(*approval_args) == approved
            cli('work', 'reconcile', message, '--expect-revision', 1,
                '--decision', 'retry-approved', '--note', 'stale approval', error=True)
            begin['expect_revision'] = 3
            assert target.call('gent_work_begin', begin)[0]['started_now'] is True
            output.write_text('one authorized fixture attempt\n')
            output.chmod(0o600)
            stop(crash=True)
            start()
            source, _ = connect('source')
            target, _ = connect('target')
            repeated = target.call('gent_work_begin', begin)[0]
            assert repeated['started_now'] is False and repeated['record']['attempts'] == 2
            assert output.read_text() == 'one authorized fixture attempt\n'
            completion = {'message_id': message, 'expect_revision': 4,
                          'note': 'checked: exactly one fixture output line exists'}
            completed = target.call('gent_work_complete', completion)[0]
            assert completed['execution_verified'] is False
            assert target.call('gent_work_complete', completion)[0] == completed
            assert source.call('gent_inbox')[0] == []
            target.call('gent_reply', {'message_id': message, 'request_id': target.request_id(),
                                       'text': output.read_text()})
            assert len(source.call('gent_inbox')[0]) == 1
            journal = cli('work', 'show', message)
            assert [event['state'] for event in journal['events']] == [
                'started', 'abandoned', 'retry_approved', 'started', 'completed']
            assert journal['record']['revision'] == 5
            print('PASS: explicit owner review, stale approval rejection, one authorized retry, checked completion and separate reply', flush=True)
        finally:
            stop()


if __name__ == '__main__':
    main()
