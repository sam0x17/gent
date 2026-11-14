#!/usr/bin/env python3
"""Recover an archived agent's history for a fresh node/agent through real MCP.

Disposable nodes and files only. No provider login, model call or service relay.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

from smoke_mcp import Client, PNG


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, required=True)
    args = parser.parse_args()
    binary = str(args.gent.resolve())
    with tempfile.TemporaryDirectory(prefix='gent-recovered-', dir='/tmp') as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        old, fresh = root / 'old', root / 'fresh'
        key, archive = root / 'recovery.key', root / 'old.age'
        daemons, clients = [], []

        def cli(node, *command, error=False):
            result = subprocess.run([binary, '--home', str(node), '--json', *map(str, command)],
                                    text=True, capture_output=True, timeout=90)
            if error:
                assert result.returncode != 0, command
                return result.stderr
            assert result.returncode == 0, (command, result.stderr)
            return json.loads(result.stdout)

        def start(node):
            process = subprocess.Popen([binary, '--home', str(node), 'daemon', 'run'],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, text=True)
            daemons.append(process)
            deadline = time.monotonic() + 15
            while not (node / 'daemon.sock').exists():
                assert process.poll() is None, process.stderr.read()
                assert time.monotonic() < deadline, 'daemon did not start'
                time.sleep(.02)
            return process

        def stop(process):
            process.terminate()
            try:
                assert process.wait(timeout=15) == 0, process.stderr.read()
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
            finally:
                process.stderr.close()
                daemons.remove(process)

        def connect(node, name):
            client = Client([binary, '--home', str(node), 'mcp', 'serve', '--binding', str(node / 'bindings' / (name + '.key'))])
            clients.append(client)
            agent = client.call('gent_register', {'name': name, 'provider': 'generic-proof'})[0]['agent']['id']
            return client, agent

        def close(client):
            client.close()
            clients.remove(client)

        try:
            cli(old, 'cluster', 'new', 'old-history', '--local')
            process = start(old)
            source, source_id = connect(old, 'builder')
            peer, peer_id = connect(old, 'reviewer')
            hidden_a, hidden_a_id = connect(old, 'unrelated-private-a')
            hidden_b, hidden_b_id = connect(old, 'unrelated-private-b')
            for a, b in ((source_id, peer_id), (hidden_a_id, hidden_b_id)):
                cli(old, 'permission', 'allow', a, b, '--permission', 'enumerate', 'send')
                cli(old, 'permission', 'allow', b, a, '--permission', 'enumerate', 'receive')
            payload = bytes(range(256)) * 8192
            staged = Path(source.call('gent_file_paths')[0]['import_directory']) / 'visual.bin'
            staged.write_bytes(payload)
            staged.chmod(0o600)
            imported = source.call('gent_file_import', {'request_id': source.request_id(), 'name': staged.name,
                                                       'media_type': 'application/octet-stream'})[0]
            sent = source.call('gent_send', {'request_id': source.request_id(), 'recipient': peer_id,
                                            'text': 'archived visual request', 'file_ids': [imported['file']['id']],
                                            'files': [{'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': PNG}]})[0]
            hidden_a.call('gent_send', {'request_id': hidden_a.request_id(), 'recipient': hidden_b_id,
                                       'text': 'UNRELATED PRIVATE EXCHANGE'})
            for client in list(clients):
                close(client)
            stop(process)
            cli(old, 'backup', 'keygen', '--output', key)
            cli(old, 'backup', 'create', archive, '--identity', key)

            cli(fresh, 'cluster', 'new', 'recovered-history', '--local')
            process = start(fresh)
            target, target_id = connect(fresh, 'replacement')
            outsider, _ = connect(fresh, 'other-current-agent')
            original_identity = (fresh / 'identity.key').read_bytes()
            assert original_identity != (old / 'identity.key').read_bytes()
            command = ['history', 'import', archive, '--identity', key, '--from-agent', source_id, '--agent', target_id]
            result = cli(fresh, *command)
            import_id = result['import_id']
            assert result['messages'] == 1 and result['revision'] == 1 and not result['duplicate']
            assert cli(fresh, *command)['duplicate']
            assert (fresh / 'identity.key').read_bytes() == original_identity
            assert target.call('gent_agents')[0] == [] and target.call('gent_inbox')[0] == []
            assert outsider.call('gent_history_imports')[0]['historical_imports'] == []
            outsider.call('gent_history_messages', {'import_id': import_id}, error=True)
            imports = target.call('gent_history_imports')[0]['historical_imports']
            assert len(imports) == 1 and imports[0]['origin']['source_agent']['id'] == source_id
            page = target.call('gent_history_messages', {'import_id': import_id})[0]
            assert len(page['messages']) == 1 and not page['has_more']
            assert 'UNRELATED' not in json.dumps(page) and hidden_a_id not in json.dumps(page)
            record = page['messages'][0]
            assert record['message']['id'] == sent['message_id']
            assert record['message']['text'] == 'archived visual request'
            assert record['message']['files'] == [] and record['message'].get('attachments', []) == []
            expected = {'visual.bin': payload, 'pixel.png': base64.b64decode(PNG)}
            assert sorted(file['name'] for file in record['files']) == sorted(expected)
            for file in record['files']:
                base = {'import_id': import_id, 'message_id': sent['message_id'], 'file_index': file['file_index']}
                recovered = bytearray()
                chunk = 0
                while chunk is not None:
                    part = target.call('gent_history_file_read', dict(base, chunk_index=chunk))[0]
                    recovered.extend(base64.b64decode(part['data_base64']))
                    chunk = part['next_chunk_index']
                assert bytes(recovered) == expected[file['name']]
                assert hashlib.sha256(recovered).hexdigest() == file['sha256']
                if file['media_type'] == 'image/png':
                    metadata, content = target.call('gent_history_file_view', base)
                    assert 'data_base64' not in metadata
                    images = [block for block in content['content'] if block['type'] == 'image']
                    assert len(images) == 1 and base64.b64decode(images[0]['data']) == expected['pixel.png']
            target.call('gent_reply', {'message_id': sent['message_id'], 'request_id': target.request_id(), 'text': 'not a new request'}, error=True)
            print('PASS: fresh identity, explicit recipient, unrelated-history isolation, PNG view and exact 2 MiB file recovery; live inbox/directory unchanged', flush=True)

            close(target)
            close(outsider)
            stop(process)
            process = start(fresh)
            target, resumed = connect(fresh, 'replacement')
            assert resumed == target_id
            assert target.call('gent_history_messages', {'import_id': import_id})[0]['messages'] == page['messages']
            assert cli(fresh, 'history', 'remove', import_id, '--expect-revision', '1')['revision'] == 2
            assert target.call('gent_history_imports')[0]['historical_imports'] == []
            target.call('gent_history_messages', {'import_id': import_id}, error=True)
            cli(fresh, *command, error=True)
            assert cli(fresh, *command, '--restore-revision', '2')['revision'] == 3
            cli(fresh, 'history', 'remove', import_id, '--expect-revision', '1', error=True)
            assert target.call('gent_history_messages', {'import_id': import_id})[0]['messages'] == page['messages']
            assert (fresh / 'identity.key').read_bytes() == original_identity
            status = cli(fresh, 'history', 'status')
            assert status['messages'] == 0 and status['recovered']['imports'] == 1
            print('PASS: restart persistence, safe duplicate import, immediate removal, explicit restoration, stale-revision refusal and unchanged current keys', flush=True)
            print(json.dumps({'status': 'passed', 'proof': 'history-import', 'source_agent': source_id,
                              'target_agent': target_id, 'native_file_bytes': len(payload)}), flush=True)
        finally:
            for client in list(clients):
                close(client)
            for process in list(daemons):
                stop(process)


if __name__ == '__main__':
    main()
