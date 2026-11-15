#!/usr/bin/env python3
"""Exercise local wake claims across a lost socket response and daemon restart.

Uses generic MCP clients and synthetic host submission IDs. Invokes no model or
host queue. Retains private temporary evidence for inspection.
"""
import argparse
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import uuid

from smoke_mcp import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, default=Path('target/debug/gent'))
    binary = str(parser.parse_args().gent.resolve())
    root = Path(tempfile.mkdtemp(prefix='gent-wake-journal-', dir='/tmp')).resolve()
    home = root / 'state'
    base = [binary, '--home', str(home), '--json']
    daemon = None
    clients = []
    log = (root / 'daemon.log').open('w')
    report = {'passed': False, 'host_execution': False}
    print(f'Proof state: {root}', flush=True)

    def cli(*arguments):
        return json.loads(subprocess.check_output(base + list(arguments), text=True))

    def start():
        process = subprocess.Popen(base + ['daemon', 'run'], stdout=log, stderr=log)
        for _ in range(200):
            if subprocess.run(base + ['daemon', 'status'], capture_output=True).returncode == 0:
                return process
            assert process.poll() is None, 'daemon exited during startup'
            time.sleep(.05)
        process.terminate()
        process.wait(timeout=10)
        raise AssertionError('daemon startup timed out')

    def rpc(credential, action, discard=False, role='agent', expect_error=False):
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(10)
            connection.connect(str(home / 'daemon.sock'))
            connection.sendall((json.dumps({'role': role, 'credential': credential,
                                           'action': action}) + '\n').encode())
            if discard:
                return None
            response = json.loads(connection.makefile('rb').readline())
            if expect_error:
                assert response['status'] == 'error', response
                return response
            assert response['status'] == 'ok', response
            return response['data']

    def advance(seconds):
        # Only the disposable fixture's admission clock changes. No OS clock,
        # real host queue or actual model submission is involved in this proof.
        with sqlite3.connect(home / 'state.sqlite3') as database:
            database.execute('UPDATE request_clock SET floor=floor+?', (seconds,))

    try:
        cli('cluster', 'new', 'wake-proof', '--local')
        daemon = start()
        for name in ('sender', 'receiver'):
            clients.append(Client(base + ['mcp', 'serve', '--binding', str(home / (name + '.key'))]))
        sender, receiver = clients
        a = sender.call('gent_register', {'name': 'sender', 'provider': 'generic'})[0]['agent']['id']
        b = receiver.call('gent_register', {'name': 'receiver', 'provider': 'generic'})[0]['agent']['id']
        cli('permission', 'allow', a, b, '--permission', 'enumerate', 'send')
        cli('permission', 'allow', b, a, '--permission', 'enumerate', 'receive')
        declared = receiver.rpc('tools/list', {})['result']['tools']
        assert not any(tool['name'].startswith('gent_wake_') for tool in declared)
        receiver.call('gent_wake_pending', error=True)
        message = sender.call('gent_send', {'recipient': b, 'request_id': sender.request_id(),
                                          'text': 'synthetic wake request'})[0]['message_id']
        credential = (home / 'receiver.key').read_text().strip()
        pending = rpc(credential, {'op': 'wake_pending'})
        assert pending['pending'][0]['message_id'] == message
        assert 'synthetic wake request' not in json.dumps(pending)
        claim = {'op': 'wake_claim', 'message_id': message, 'attempt_id': str(uuid.uuid4()),
                 'target': {'host': 'codex', 'thread_id': str(uuid.uuid4())}}
        rpc(credential, claim, discard=True)
        # Check authoritative daemon state, never infer a commit from elapsed time.
        for _ in range(200):
            observed = cli('wake')['entries']
            if observed:
                break
            time.sleep(.02)
        assert len(observed) == 1 and observed[0]['state'] == 'uncertain'
        assert observed[0]['message_id'] == message
        daemon.terminate()
        assert daemon.wait(timeout=10) == 0
        daemon = start()
        repeated = rpc(credential, claim)
        assert repeated['may_submit'] is False
        assert repeated['record'] == observed[0]
        report['lost_response_restart_preserves_one_uncertain_claim'] = True
        inbox = receiver.call('gent_inbox')[0]
        assert len(inbox) == 1 and inbox[0]['id'] == message and not inbox[0]['acknowledged']
        seen = cli('wake', 'show', message)
        assert seen['state'] == 'uncertain' and seen['inbox_seen_at'] is not None
        submitted = rpc(credential, {'op': 'wake_submitted', 'message_id': message,
            'attempt_id': claim['attempt_id'], 'submission_id': str(uuid.uuid4())})
        assert submitted['state'] == 'submitted' and submitted['inbox_seen_at'] == seen['inbox_seen_at']
        assert cli('wake', 'show', message) == submitted
        assert receiver.call('gent_identity')[0]['delivery'] == 'polling'
        assert not cli('work')['entries']
        receiver.call('gent_ack', {'message_id': message})
        assert cli('wake', 'show', message) == submitted
        report['inbox_receipt_and_work_remain_separate'] = True
        report['host_operations_not_exposed_as_mcp_tools'] = True
        assert cli('wake', 'status')['submitted_and_observed'] == 1
        assert cli('wake', 'clean', '--dry-run')['records_removed'] == 0
        advance(5)
        second = sender.call('gent_send', {'recipient': b, 'request_id': sender.request_id(),
                                          'text': 'keep uncertain delivery'})[0]['message_id']
        second_claim = dict(claim, message_id=second, attempt_id=str(uuid.uuid4()))
        assert rpc(credential, second_claim)['may_submit'] is True
        receiver.call('gent_inbox')
        advance(9 * 86400)
        assert cli('wake', 'status')['eligible'] == 0
        assert cli('history', 'clean')['messages_removed'] == 2
        before = cli('wake', 'status')
        assert before['eligible'] == 1 and before['uncertain'] == 1
        assert cli('wake', 'clean', '--dry-run')['records_removed'] == 1
        assert cli('wake', 'status') == before
        assert cli('wake', 'clean')['records_removed'] == 1
        assert cli('wake', 'show', second)['state'] == 'uncertain'
        # Renew synthetic authority so replay rejection is checked against the
        # absent source/claim, rather than merely against an expired lease.
        rpc((home / 'owner.key').read_text().strip(), {'op': 'renew'}, role='owner')
        assert 'unavailable' in json.dumps(rpc(credential, claim, expect_error=True))
        assert rpc(credential, second_claim)['may_submit'] is False
        report['owner_preview_cleanup_and_replay_rejection'] = True
        rpc(credential, {'op': 'wake_submitted', 'message_id': second,
            'attempt_id': second_claim['attempt_id'], 'submission_id': str(uuid.uuid4())})
        assert cli('wake', 'clean')['records_removed'] == 0
        daemon.terminate()
        assert daemon.wait(timeout=10) == 0
        advance(7 * 86400)
        daemon = start()
        # Startup maintenance runs asynchronously; observe committed evidence.
        for _ in range(200):
            if cli('wake', 'status')['records'] == 0:
                break
            time.sleep(.02)
        assert cli('wake', 'status')['records'] == 0
        report['startup_cleanup_after_late_submission_retention'] = True
        report['passed'] = True
    except BaseException as error:
        report['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        try:
            for client in clients:
                client.close()
            if daemon is not None and daemon.poll() is None:
                daemon.terminate()
                daemon.wait(timeout=10)
        finally:
            log.close()
            (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()
