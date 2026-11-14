#!/usr/bin/env python3
"""Prove delegated permission editing with real disposable CLI/MCP processes."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from smoke_mcp import Client


def exercise(a, b, aid, bid, owner, restart, wait_for):
    """Shared by single-node and physical Linux/Mac encrypted transport proofs."""
    granted = owner('permission', 'admin', 'grant', aid, '*', '*', '--permission', 'enumerate', 'receive', 'send')
    assert granted['state'] == 'applied'
    grant = granted['grant_id']
    pair = {'actor': aid, 'peer': bid}
    wait_for(lambda: any(g['grant_id'] == grant for g in a.call('gent_permission_admin_check', pair)[0]['grants']))
    assert b.call('gent_permission_admin_check', pair)[0]['grants'] == []
    changes = [dict(grant_id=grant, actor=x, peer=y, permission=p, decision='allow')
               for x, y, p in [(aid, bid, 'enumerate'), (bid, aid, 'enumerate'),
                                (aid, bid, 'send'), (bid, aid, 'receive')]]
    preview = a.call('gent_permission_preview', {'changes': changes})[0]
    assert next(r for r in preview['relationships'] if r['actor'] == aid)['policy']['send_unsolicited']['allowed']
    request = {'request_id': a.request_id(), 'changes': changes}
    b.call('gent_permission_apply', request, error=True)
    a.call('gent_permission_apply', dict(request, administrator=bid), error=True)
    result = a.call('gent_permission_apply', request)[0]
    assert result['state'] in ('queued', 'applied')
    wait_for(lambda: a.call('gent_permission_request', {'request_id': request['request_id']})[0]['state'] == 'applied')
    result = a.call('gent_permission_request', {'request_id': request['request_id']})[0]
    assert not {'writer', 'revision', 'config_saved', 'config_error'} & result.keys()
    b.call('gent_permission_request', {'request_id': request['request_id']}, error=True)
    wait_for(lambda: owner('permission', 'explain', aid, bid)['policy']['send_unsolicited']['allowed'])
    sent = a.call('gent_send', {'recipient': bid, 'request_id': a.request_id(), 'text': 'delegated permission proof'})[0]
    wait_for(lambda: any(m['id'] == sent['message_id'] for m in b.call('gent_inbox')[0]))
    b.call('gent_ack', {'message_id': sent['message_id']})
    reply = b.call('gent_reply', {'message_id': sent['message_id'], 'request_id': b.request_id(), 'text': 'accepted delegated exchange'})[0]
    wait_for(lambda: any(m['id'] == reply['message_id'] for m in a.call('gent_inbox')[0]))
    a.call('gent_ack', {'message_id': reply['message_id']})
    restart()
    assert a.call('gent_permission_apply', request)[0] == result
    denied = [dict(grant_id=grant, actor=aid, peer=bid, permission='receive', decision='deny')]
    blocked = a.call('gent_permission_preview', {'changes': denied})[0]
    assert blocked['relationships'][0]['policy']['send_unsolicited']['allowed'] is False
    changed = {'request_id': a.request_id(), 'changes': denied}
    a.call('gent_permission_apply', changed)
    wait_for(lambda: a.call('gent_permission_request', {'request_id': changed['request_id']})[0]['state'] == 'applied')
    wait_for(lambda: not b.call('gent_permission_check', {'peer': aid})[0]['policy']['reply_policy']['allowed'])
    b.call('gent_reply', {'message_id': sent['message_id'], 'request_id': b.request_id(), 'text': 'blocked'}, error=True)
    # Inherit removes the exact deny; no broader policy is removed.
    inherited = {'request_id': a.request_id(), 'changes': [dict(denied[0], decision='inherit')]}
    a.call('gent_permission_apply', inherited)
    wait_for(lambda: a.call('gent_permission_request', {'request_id': inherited['request_id']})[0]['state'] == 'applied')
    wait_for(lambda: a.call('gent_permission_check', {'peer': bid})[0]['policy']['send_unsolicited']['allowed'])
    owner('permission', 'admin', 'revoke', grant)
    wait_for(lambda: a.call('gent_permission_admin_check', pair)[0]['grants'] == [])
    assert a.call('gent_permission_apply', request)[0] == result
    a.call('gent_permission_apply', dict(request, request_id=a.request_id()), error=True)
    assert a.call('gent_permission_check', {'peer': bid})[0]['policy']['send_unsolicited']['allowed']
    assert grant in owner('permission', 'admin', 'list')['retired']
    audit = owner('permission', 'admin', 'history', '--agent', aid)['entries']
    assert len(audit) == 3 and all(r['state'] == 'applied' and r['changes'] and r['revision'] for r in audit)


def exercise_rules(a, b, aid, bid, owner, restart, wait_for):
    """Opt-in broad rules over the same authenticated MCP and owner flow."""
    grant = owner('permission', 'admin', 'grant', aid, '*', '*', '--selector-rules',
                  '--permission', 'enumerate', 'receive', 'send')['grant_id']
    wait_for(lambda: any(g['grant_id'] == grant for g in a.call('gent_permission_rule_scopes')[0]['grants']))
    assert b.call('gent_permission_rule_scopes')[0]['grants'] == []
    anode = a.call('gent_identity')[0]['agent']['node_id']
    bnode = b.call('gent_identity')[0]['agent']['node_id']
    changes = [dict(grant_id=grant, actor={'kind': 'node', 'id': bnode},
                    peer={'kind': 'node', 'id': anode}, permission='receive', decision='deny')]
    preview = a.call('gent_permission_rule_preview', {'changes': changes})[0]
    assert preview['changes'] == changes and not {'relationships', 'members', 'revision'} & preview.keys()
    assert bid not in json.dumps(preview)
    request = {'request_id': a.request_id(), 'changes': changes}
    b.call('gent_permission_rule_apply', request, error=True)
    a.call('gent_permission_rule_apply', dict(request, administrator=bid), error=True)
    a.call('gent_permission_rule_apply', request)
    wait_for(lambda: a.call('gent_permission_request', {'request_id': request['request_id']})[0]['state'] == 'applied')
    wait_for(lambda: not a.call('gent_permission_check', {'peer': bid})[0]['policy']['send_unsolicited']['allowed'])
    a.call('gent_send', {'recipient': bid, 'request_id': a.request_id(), 'text': 'blocked by node rule'}, error=True)
    result = a.call('gent_permission_request', {'request_id': request['request_id']})[0]
    assert not {'revision', 'writer', 'config_saved', 'config_error'} & result.keys()
    a.call('gent_permission_apply', {'request_id': request['request_id'], 'changes': [
        dict(grant_id=grant, actor=bid, peer=aid, permission='receive', decision='deny')]}, error=True)
    restart()
    assert a.call('gent_permission_rule_apply', request)[0] == result
    for decision in ('allow', 'inherit'):
        changed = {'request_id': a.request_id(), 'changes': [dict(changes[0], decision=decision)]}
        a.call('gent_permission_rule_apply', changed)
        wait_for(lambda: a.call('gent_permission_request', {'request_id': changed['request_id']})[0]['state'] == 'applied')
        wait_for(lambda: a.call('gent_permission_check', {'peer': bid})[0]['policy']['send_unsolicited']['allowed'])
        sent = a.call('gent_send', {'recipient': bid, 'request_id': a.request_id(), 'text': 'node rule ' + decision})[0]
        wait_for(lambda: any(m['id'] == sent['message_id'] for m in b.call('gent_inbox')[0]))
        b.call('gent_ack', {'message_id': sent['message_id']})
    owner('permission', 'admin', 'revoke', grant)
    wait_for(lambda: a.call('gent_permission_rule_scopes')[0]['grants'] == [])
    assert a.call('gent_permission_rule_apply', request)[0] == result
    a.call('gent_permission_rule_apply', dict(request, request_id=a.request_id()), error=True)
    records = [r for r in owner('permission', 'admin', 'history', '--agent', aid)['entries'] if r.get('selector_rules')]
    assert len(records) == 3 and all(r['state'] == 'applied' and r['changes'] and r['revision'] for r in records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, required=True)
    binary = str(parser.parse_args().gent.resolve())
    with tempfile.TemporaryDirectory(prefix='gent-admin-', dir='/tmp') as directory:
        home = Path(directory).resolve() / 'node'
        base = [binary, '--home', str(home), '--json']
        clients = []
        daemon = None

        def cli(*args):
            r = subprocess.run(base + list(args), capture_output=True, text=True, timeout=15)
            assert r.returncode == 0, r.stderr
            return json.loads(r.stdout)

        def wait_for(check):
            end = time.monotonic() + 15
            while not check():
                assert time.monotonic() < end, 'operation timed out'
                time.sleep(.05)

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

        def restart():
            nonlocal daemon
            stop()
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

            def ready():
                assert daemon.poll() is None, daemon.stderr.read()
                return (home / 'daemon.sock').exists() and subprocess.run(base + ['daemon', 'status'], capture_output=True, timeout=5).returncode == 0

            wait_for(ready)

        try:
            cli('cluster', 'new', 'admin-proof', '--local')
            restart()
            for name in ('a', 'b'):
                clients.append(Client(base + ['mcp', 'serve', '--binding', str(home / (name + '.key'))]))
            a, b = clients
            aid, bid = [c.call('gent_register', {'name': name, 'provider': 'generic'})[0]['agent']['id']
                        for c, name in zip(clients, ('a', 'b'))]
            cli('permission', 'allow', aid, bid, '--permission', 'enumerate')
            cli('permission', 'allow', bid, aid, '--permission', 'enumerate')
            exercise(a, b, aid, bid, cli, restart, wait_for)
            exercise_rules(a, b, aid, bid, cli, restart, wait_for)
            audit = [r for r in cli('config', 'requests') if r.get('administrator') == aid]
            assert len(audit) == 6 and all(r['state'] == 'applied' and r['changes'] and r['revision'] for r in audit)
            print(json.dumps({'status': 'passed', 'proof': 'agent administration', 'platform': os.uname().sysname,
                              'checks': ['owner CLI grants', 'scoped preview', 'bound identity', 'atomic batches',
                                         'private request status', 'actual messages and replies',
                                         'exact retries', 'restart', 'deny and inherit', 'revocation', 'owner audit',
                                         'selector-rule opt-in', 'node selectors', 'shared request namespace']}))
        finally:
            for client in clients:
                client.close()
            stop()


if __name__ == '__main__':
    main()
