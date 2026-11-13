"""Synthetic two-machine transport storage checks used by prove_pairing.py."""

# Restore the redundant ciphertext copies that existed in schema v3. The caller
# runs this only against disposable proof state; no private values leave Python.
RESTORE_COPIES = r'''
import base64,json,pathlib,sqlite3,sys
with sqlite3.connect(pathlib.Path(sys.argv[1])/'state.sqlite3') as db:
    rows=db.execute('SELECT id,packet FROM stream_outbox WHERE sequence=0 ORDER BY rowid LIMIT 12').fetchall()
    assert rows
    for request,wire in rows:
        raw=base64.b64decode(json.loads(wire)['ciphertext'])
        assert db.execute('UPDATE outbox SET bytes=? WHERE id=?',(raw,request)).rowcount==1
'''


def exercise_storage(a, b, target, cli, owner_cli, restore, restart, wait_for):
    first = None
    for index in range(70):
        request = {'recipient': target, 'request_id': a.request_id(), 'text': f'transport storage {index}'}
        sent = a.call('gent_send', request)[0]
        if first is None:
            first = (request, sent['message_id'])

        def incoming(client, message):
            return next((m for m in client.call('gent_inbox')[0] if m['id'] == message), None)

        wait_for(lambda: incoming(b, sent['message_id']))
        assert incoming(b, sent['message_id'])['text'] == request['text']
        b.call('gent_ack', {'message_id': sent['message_id']})
        reply = b.call('gent_reply', {'message_id': sent['message_id'], 'request_id': b.request_id(), 'text': f'review {index}'})[0]
        wait_for(lambda: incoming(a, reply['message_id']))
        assert incoming(a, reply['message_id'])['text'] == f'review {index}'
        a.call('gent_ack', {'message_id': reply['message_id']})
    for command in (cli, owner_cli):
        wait_for(lambda: command('transport')['outgoing']['data']['packets'] < 32)
        wait_for(lambda: command('transport')['outgoing']['data']['retry_records'] < 32)
        status = command('transport', 'status')
        assert status['confirmed_streams'] > 0
        assert status['retired_packet_tombstones'] == 0
        assert status['outgoing']['data']['retry_records'] == status['outgoing']['data']['packets']
        assert status['duplicate_copies'] == status['accepted_digests_due'] == status['wire_receipts_due'] == 0
    restore()
    for command in (cli, owner_cli):
        copies = command('transport')['duplicate_copies']
        assert copies > 0
        preview = command('transport', 'clean', '--dry-run')
        assert preview['duplicate_copies_compacted'] == min(copies, 8)
        assert command('transport')['duplicate_copies'] == copies
        cleaned = command('transport', 'clean')
        assert cleaned['duplicate_copies_compacted'] == min(copies, 8) and cleaned['duplicate_bytes_removed'] > 0
        assert command('transport')['duplicate_copies'] == max(copies - 8, 0)
    restore()
    restart()
    for command in (cli, owner_cli):
        wait_for(lambda: command('transport')['duplicate_copies'] == 0)
    assert a.call('gent_send', first[0])[0]['message_id'] == first[1]
    assert not a.call('gent_inbox')[0] and not b.call('gent_inbox')[0]
    print('PASS: 70 two-machine exchanges, authenticated packet and retry-metadata retirement, bounded replay evidence, CLI preview/compaction, startup cleanup, and exact agent retry after restart', flush=True)


def exercise_authority_history(cli, owner_cli, applied, restart, wait_for):
    for _ in range(80):
        result = owner_cli('cluster', 'renew')
        assert result['state'] == 'applied'
    revision = result['revision']
    wait_for(lambda: applied(revision))
    for command in (cli, owner_cli):
        wait_for(lambda: command('transport')['authority_history']['pending_join_pins'] == 0)
        wait_for(lambda: command('transport')['outgoing']['configuration']['allocated_retry_records'] == 0)
        while command('transport', 'clean')['authority_records_compacted']:
            pass
        history = command('transport')['authority_history']
        assert history['full_records'] == 64 and history['full_records_due'] == 0
        assert history['accepted_digests'] >= 80
    restart()
    for command in (cli, owner_cli):
        assert command('transport')['authority_history']['full_records'] == 64
    changed = cli('node', 'name', 'set', 'after-history-compaction')
    assert changed['state'] == 'applied'
    wait_for(lambda: applied(changed['revision']))
    print('PASS: 80 signed revisions, bounded full-history retention, retired configuration retry metadata, released join pins, both daemon restarts, and remote configuration edit after compaction', flush=True)
