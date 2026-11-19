"""Disposable joined-node replacement checks used by prove_pairing.py."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess

from smoke_mcp import Client, PNG


def exercise(binary, old_home, join, old_agent, peer, peer_id, owner, restart_owner, wait_for):
    from prove_pairing import stop

    def run(home, *args, check=True):
        return subprocess.run([binary, '--home', str(home), '--json', *args],
                              capture_output=True, text=True, check=check, timeout=60)

    def cli(home, *args):
        return json.loads(run(home, *args).stdout)

    def links(home):
        with sqlite3.connect('file:' + str(home / 'state.sqlite3') + '?mode=ro', uri=True) as db:
            return db.execute('SELECT outgoing,incoming FROM network_links ORDER BY peer').fetchall()

    old_id = cli(old_home, 'node')['id']
    old_identity = (old_home / 'identity.key').read_bytes()
    old_links = links(old_home)
    before = owner('config')['applied_revision']
    key = old_home.parent / 'recovery.key'
    archive = old_home.parent / 'old.age'
    extracted = old_home.parent / 'offline'
    cli(old_home, 'backup', 'keygen', '--output', str(key))
    cli(old_home, 'backup', 'create', str(archive), '--identity', str(key))
    cli(old_home, 'backup', 'extract', str(archive), '--identity', str(key), '--output', str(extracted))
    assert run(extracted, *join, '--replace-node', old_id, check=False).returncode != 0
    home = old_home.parent / 'replacement'
    command = [*join, '--replace-node', old_id]
    first = cli(home, *command)
    new_id = first['node']['id']
    assert first['replaced_node'] == old_id and new_id != old_id
    assert (home / 'identity.key').read_bytes()[8:40] != old_identity[8:40]
    assert (home / 'owner.key').read_bytes() != (old_home / 'owner.key').read_bytes()
    assert set(group for row in links(home) for group in row).isdisjoint(
        group for row in old_links for group in row)
    assert cli(home, *command)['already_configured']
    assert owner('config')['applied_revision'] == before + 1
    members = owner('nodes')
    assert old_id not in {node['id'] for node in members}
    assert next(node for node in members if node['id'] == new_id)['can_configure'] is False
    removal = next(row for row in owner('node', 'removals')['removals'] if row['node_id'] == old_id)
    assert removal['replacement']['node_id'] == new_id and removal['revision'] == before + 1
    assert run(old_home.parent / 'competitor', *command, check=False).returncode != 0
    assert owner('config')['applied_revision'] == before + 1
    assert (old_home / 'identity.key').read_bytes() == old_identity
    with sqlite3.connect('file:' + str(home / 'state.sqlite3') + '?mode=ro', uri=True) as db:
        assert db.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM agents WHERE id=?', [old_agent]).fetchone()[0] == 0

    daemon = client = None
    with (old_home.parent / 'replacement.log').open('a') as log:
        def start():
            process = subprocess.Popen([binary, '--home', str(home), 'daemon', 'run'],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            wait_for(lambda: run(home, 'daemon', 'status', check=False).returncode == 0)
            return process

        def incoming(message):
            return next((m for m in client.call('gent_inbox')[0] if m['id'] == message), None)

        try:
            daemon = start()
            client = Client([binary, '--home', str(home), 'mcp', 'serve', '--binding', str(home / 'visual.key')])
            new_agent = client.call('gent_register', {'name': 'replacement', 'provider': 'generic-mcp'})[0]['agent']['id']
            assert new_agent != old_agent
            wait_for(lambda: any(agent['id'] == new_agent for agent in owner('agents')))
            assert client.call('gent_agents')[0] == [], 'old agent-specific grants must not migrate'
            owner('permission', 'allow', new_agent, peer_id, '--permission', 'enumerate', 'send')
            granted = owner('permission', 'allow', peer_id, new_agent, '--permission', 'enumerate', 'receive')
            wait_for(lambda: cli(home, 'config')['applied_revision'] >= granted['revision'])
            wait_for(lambda: any(agent['id'] == peer_id for agent in client.call('gent_agents')[0]))
            sent = client.call('gent_send_non_blocking', {'recipient': peer_id, 'request_id': client.request_id(),
                'text': 'fresh identity image', 'files': [{'name': 'fresh.png', 'media_type': 'image/png', 'data_base64': PNG}]})[0]
            wait_for(lambda: any(m['id'] == sent['message_id'] for m in peer.call('gent_inbox')[0]))
            inbox, raw = peer.call('gent_inbox')
            assert any(part['type'] == 'image' and part['data'] == PNG for part in raw['content'])
            peer.call('gent_ack', {'message_id': sent['message_id']})
            wait_for(lambda: client.call('gent_message_status', {'message_id': sent['message_id']})[0]['state'] == 'delivered')
            source = Path(client.call('gent_file_paths')[0]['import_directory']) / 'fresh.bin'
            content = b'fresh-node-proof\0' + bytes(range(256)) * 8192
            source.write_bytes(content)
            source.chmod(0o600)
            file = client.call('gent_file_import', {'name': source.name, 'media_type': 'application/octet-stream', 'request_id': client.request_id()})[0]['file']
            request = {'recipient': peer_id, 'request_id': client.request_id(), 'text': 'fresh file', 'file_ids': [file['id']]}
            sent_file = client.call('gent_send_non_blocking', request)[0]
            stop(daemon)
            daemon = None
            restart_owner()
            daemon = start()
            assert client.call('gent_send_non_blocking', request)[0]['message_id'] == sent_file['message_id']
            def remote_file():
                return next((m for m in peer.call('gent_inbox')[0] if m['id'] == sent_file['message_id']), None)
            wait_for(remote_file)
            received = remote_file()['attachments'][0]
            wait_for(lambda: peer.call('gent_file_status', {'file_id': received['id']})[0]['state'] == 'ready')
            reply = peer.call('gent_reply', {'message_id': sent_file['message_id'], 'request_id': peer.request_id(),
                'text': 'fresh file returned', 'file_ids': [received['id']]})[0]
            wait_for(lambda: incoming(reply['message_id']))
            returned = incoming(reply['message_id'])['attachments'][0]
            wait_for(lambda: client.call('gent_file_status', {'file_id': returned['id']})[0]['state'] == 'ready')
            output = Path(client.call('gent_file_export', {'file_id': returned['id']})[0]['path'])
            assert output.read_bytes() == content
            assert returned['sha256'] == hashlib.sha256(content).hexdigest()
            stop(daemon)
            daemon = None
            assert cli(home, *command)['replaced_node'] == old_id
            assert run(extracted, 'daemon', 'run', check=False).returncode != 0
            assert owner('node', 'removals')['removals'][0]['replacement']['node_id'] == new_id
            print('PASS: fresh SSH replacement, single signed retirement, independent keys/streams, exact retries, competing replacement refusal and preserved admin restriction')
            print('PASS: new agent with explicit grants, image/receipt and exact 2 MiB file round trip across both daemon restarts; archived state remains guarded')
        finally:
            if client:
                client.close()
            stop(daemon)
