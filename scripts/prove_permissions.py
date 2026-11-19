#!/usr/bin/env python3
"""Exercise permission explanations through a disposable CLI, daemon and MCP clients."""
import argparse
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from mcp_client import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, required=True)
    binary = parser.parse_args().gent.resolve()
    with tempfile.TemporaryDirectory(prefix='gent-permission-', dir='/tmp') as directory:
        home = Path(directory).resolve() / 'node'
        base = [str(binary), '--home', str(home)]
        daemon = None
        clients = []

        def cli(*args):
            result = subprocess.run(base + ['--json', *args], check=False, capture_output=True, text=True, timeout=15)
            assert result.returncode == 0, result.stderr
            return json.loads(result.stdout)

        def start():
            nonlocal daemon
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            for _ in range(200):
                assert daemon.poll() is None, daemon.stderr.read()
                if (home / 'daemon.sock').exists():
                    probe = subprocess.run(base + ['daemon', 'status'], check=False, capture_output=True, timeout=5)
                    if probe.returncode == 0:
                        return
                time.sleep(0.025)
            raise AssertionError('daemon did not start')

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

        def connect(name):
            client = Client(base + ['mcp', 'serve', '--binding', str(home / 'bindings' / (name + '.key'))])
            clients.append(client)
            return client

        def check(client, peer):
            return client.call('gent_permission_check', {'peer': peer})[0]

        def unavailable(client, peer):
            result = client.call('gent_permission_check', {'peer': peer}, error=True)['result']
            assert result['isError']
            assert result['content'][0]['text'] == 'recipient or message unavailable'
            return result

        try:
            cli('cluster', 'new', 'permissions-proof', '--local')
            start()
            a, b, hidden = [connect(name) for name in ('a', 'b', 'hidden')]
            aid, bid, hid = [client.call('gent_register', {'name': name, 'provider': 'generic-proof'})[0]['agent']['id']
                             for client, name in ((a, 'a'), (b, 'b'), (hidden, 'hidden'))]
            assert {entry['id'] for entry in a.call('gent_agents')[0]} == {aid, bid, hid}
            assert check(a, bid)['policy']['send_unsolicited']['allowed'] is True
            assert check(a, bid)['policy']['receive_unsolicited']['allowed'] is True
            for sender, recipient, receiver in ((a, bid, b), (b, aid, a)):
                sent = sender.call('gent_send_non_blocking', {'recipient': recipient, 'request_id': sender.request_id(), 'text': 'no grants needed'})[0]
                assert any(m['id'] == sent['message_id'] for m in receiver.call('gent_inbox')[0])
                receiver.call('gent_ack', {'message_id': sent['message_id']})
            cli('permission', 'deny', '*', hid, '--permission', 'enumerate')
            cli('permission', 'deny', hid, '*', '--permission', 'enumerate')
            cli('permission', 'deny', bid, aid, '--permission', 'send')
            # An allow does not undo a matching explicit restriction.
            cli('permission', 'allow', bid, aid, '--permission', 'send')
            summary = check(a, bid)
            assert summary['actor'] == aid and summary['peer'] == bid
            assert summary['policy']['send_unsolicited']['allowed'] is True
            assert summary['policy']['receive_unsolicited']['allowed'] is False
            assert summary['policy']['reply_policy']['allowed'] is True
            assert not {'authority', 'revision', 'traces', 'matching_rules', 'groups'} & summary.keys()
            assert hid not in json.dumps(summary)
            assert unavailable(a, hid) == unavailable(a, str(uuid.uuid4()))
            a.call('gent_permission_check', {'peer': bid, 'actor': hid}, error=True)
            a.call('gent_permission_explain', {'actor': aid, 'peer': bid}, error=True)
            explained = cli('permission', 'explain', aid, bid)
            assert explained['policy'] == summary['policy']
            assert explained['authority']['fresh'] is True
            assert explained['traces']['actor_to_peer'][1]['decision'] == 'allow'
            assert explained['traces']['peer_to_actor'][2]['decision'] == 'explicit_deny'
            assert [r['index'] for r in explained['matching_rules']] == [0, 1, 2, 5, 6]
            sent = a.call('gent_send_non_blocking', {'recipient': bid, 'request_id': a.request_id(), 'text': 'review'})[0]
            b.call('gent_send_non_blocking', {'recipient': aid, 'request_id': b.request_id(), 'text': 'unsolicited'}, error=True)
            b.call('gent_reply', {'message_id': sent['message_id'], 'request_id': b.request_id(), 'text': 'reviewed'})
            assert a.call('gent_inbox')[0][0]['text'] == 'reviewed'
            stop()
            start()
            assert check(a, bid) == summary
            assert cli('permission', 'explain', aid, bid) == explained
            cli('permission', 'deny', aid, bid, '--permission', 'receive')
            blocked = check(a, bid)
            assert blocked['policy']['send_unsolicited']['blocked_by'] == ['sender_receive_denied']
            assert blocked['policy']['reply_policy']['allowed'] is False
            explained = cli('permission', 'explain', aid, bid)
            assert explained['policy'] == blocked['policy']
            assert explained['traces']['actor_to_peer'][1]['decision'] == 'explicit_deny'
            a.call('gent_send_non_blocking', {'recipient': bid, 'request_id': a.request_id(), 'text': 'blocked'}, error=True)
            b.call('gent_reply', {'message_id': sent['message_id'], 'request_id': b.request_id(), 'text': 'blocked'}, error=True)
            cli('permission', 'deny', aid, bid, '--permission', 'enumerate')
            assert unavailable(a, bid) == unavailable(a, hid)
            assert cli('permission', 'explain', aid, bid)['policy']['enumerate'] is False
            assert (home / 'owner.key').read_text().strip() not in json.dumps(explained)
            cli('permission', 'inherit', aid, bid, '--permission', 'enumerate', 'receive')
            cli('permission', 'inherit', bid, aid, '--permission', 'send')
            restored = check(a, bid)['policy']
            assert restored['send_unsolicited']['allowed'] and restored['receive_unsolicited']['allowed']
            assert unavailable(a, hid) == unavailable(a, str(uuid.uuid4()))
            stop()
            start()
            assert check(a, bid)['policy'] == restored
            print(json.dumps({'status': 'passed', 'proof': 'permissions', 'platform': os.uname().sysname,
                              'checks': ['default bidirectional communication', 'hidden-peer isolation', 'bound identity',
                                         'owner-only traces', 'one-way initiation and replies',
                                         'restart persistence', 'immediate deny precedence',
                                         'inherit restores defaults without removing other restrictions']}))
        finally:
            for client in clients:
                client.close()
            stop()


if __name__ == '__main__':
    main()
