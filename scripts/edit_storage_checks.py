"""Configuration edit storage checks against disposable two-machine proof nodes."""
import copy
import hashlib
import json
import socket
import sqlite3
import time
import uuid


def submit(home, request, edit):
    body = {'role': 'owner', 'credential': (home / 'owner.key').read_text().strip(),
            'action': {'op': 'configure', 'request_id': request, 'edit': edit}}
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(15)
        sock.connect(str(home / 'daemon.sock'))
        sock.sendall(json.dumps(body).encode() + b'\n')
        with sock.makefile('rb') as response:
            result = json.loads(response.readline(6 * 1024 * 1024 + 1))
    assert result['status'] == 'ok', result
    return result['data']


def queue_edits(home, cli):
    """Call while the owner is stopped; retain full bodies in the event queue."""
    policy = copy.deepcopy(cli('config')['policy'])
    # Rules for an absent synthetic agent leave the existing proof permissions.
    absent = str(uuid.uuid4())
    policy['rules'].extend([{'actor': {'kind': 'agent', 'id': absent},
                            'peer': {'kind': 'all'}, 'permission': 'enumerate',
                            'effect': 'deny'} for _ in range(2200)])
    edit = {'op': 'policy', 'policy': policy}
    requests = [str(uuid.uuid4()) for _ in range(10)]
    for request in requests:
        assert submit(home, request, edit)['state'] == 'queued'

    with sqlite3.connect(home / 'state.sqlite3') as db:
        # Recreate the canonical field order of the Rust protocol structs. A
        # digest check below must pass before restoring any old redundant body.
        # The event may already have moved to the encrypted transport queue.
        canonical = {'rules': [{key: rule[key] for key in ('actor', 'peer', 'permission', 'effect')}
                               for rule in policy['rules']], 'groups': dict(sorted(policy['groups'].items()))}
        if policy.get('relay_grants'):
            canonical['relay_grants'] = {key: {field: grant[field] for field in ('intermediary', 'target', 'issued_at', 'expires_at')}
                                         for key, grant in sorted(policy['relay_grants'].items())}
        for rule in canonical['rules']:
            for key in ('actor', 'peer'):
                selector = rule[key]
                rule[key] = {'kind': selector['kind'], **({'id': selector['id']} if 'id' in selector else {})}
        encoded = json.dumps({'op': 'policy', 'policy': canonical}, ensure_ascii=False, separators=(',', ':')).encode()
        cases = []
        for request in requests:
            digest, size = db.execute('SELECT fingerprint,length(edit) FROM configuration_edits WHERE id=?', (request,)).fetchone()
            assert hashlib.sha256(encoded).hexdigest() == digest
            assert len(encoded) > 256 * 1024 and size < 100
            cases.append((request, encoded))
        assert len(cases) == len(requests)

    def restore():
        with sqlite3.connect(home / 'state.sqlite3') as db:
            for request, body in cases:
                assert db.execute('UPDATE configuration_edits SET edit=?,compact=0 WHERE id=?', (body, request)).rowcount == 1

    restore()
    before = cli('history')['configuration_edits']
    preview = cli('history', 'clean', '--dry-run')['configuration_edits']
    assert preview['records_compacted'] == 8 and preview['more_due'] == 2
    assert preview['body_bytes_removed'] > 2 * 1024 * 1024
    assert cli('history')['configuration_edits'] == before
    assert cli('history', 'clean')['configuration_edits'] == preview
    restore()
    return cases


def after_restart(cli, cases, wait_for):
    # Startup maintenance performs one bounded batch. Explicit maintenance
    # finishes any remainder without removing pending proposals or retries.
    wait_for(lambda: cli('history')['configuration_edits']['legacy_records'] <= 2)
    while cli('history', 'clean')['configuration_edits']['records_compacted']:
        pass
    for request, _ in cases:
        assert cli('config', 'request', request)['state'] == 'queued'


def completed(home, cli, owner_cli, cases):
    for request, body in cases:
        result = cli('config', 'request', request)
        assert result['state'] == 'applied'
        assert submit(home, request, json.loads(body)) == result
    for command in (cli, owner_cli):
        usage = command('history')['configuration_edits']
        assert usage['legacy_records'] == usage['pending'] == 0
        assert usage['stored_bytes'] < usage['records'] * 1024
        assert usage['max_records'] == 65536 and usage['max_reserved_bytes'] == 64 * 1024 * 1024
    print('PASS: ten large offline policy edits, compact new records, bounded legacy preview/cleanup, startup maintenance, both-machine results and exact retries', flush=True)


def wait_for_results(cli, cases, wait_for):
    requests = {request for request, _ in cases}
    previous = None
    start = time.monotonic()

    def caught_up():
        nonlocal previous
        statuses = [r for r in cli('config', 'requests') if r['request_id'] in requests]
        assert len(statuses) == len(requests)
        assert all(r['state'] in ('queued', 'applied') for r in statuses), statuses
        applied = sum(r['state'] == 'applied' for r in statuses)
        if applied != previous:
            print(f'Large policy recovery: {applied}/{len(cases)} results after {time.monotonic()-start:.1f}s', flush=True)
            previous = applied
        return applied == len(cases)

    # This fixture recovers ten >256 KiB signed policies in fragmented streams.
    wait_for(caught_up, timeout=300)
