#!/usr/bin/env python3
"""Opt-in SSH pairing, config sync, and encrypted MCP messages between two machines.

Requires a running local development relay and an already trusted SSH owner host.
Uses temporary clusters, makes no model calls, and removes its nodes afterward.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time
import tomllib
import uuid
from urllib.parse import urlparse
from smoke_mcp import Client, PNG
from relay_checks import exercise_turns


PREPARE = r'''
import json, os, pathlib, subprocess, sys, tempfile
p = json.load(sys.stdin)
home = pathlib.Path(tempfile.mkdtemp(prefix='gent-owner-pairing-'))
result = subprocess.run([p['binary'], '--home', str(home), '--json', 'cluster', 'new', 'ssh-proof', '--local'], check=True, capture_output=True, text=True)
config = json.loads(result.stdout)
with open(home / 'config.toml', 'a') as f:
    f.write('\n[relay]\nendpoint = ' + json.dumps(p['relay']) + '\ncredential_file = "relay.key"\n')
fd = os.open(home / 'relay.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write(p['token'])
print(json.dumps({'home': str(home), 'cluster': config['cluster']['id'], 'node': config['node']['id']}))
'''
LAUNCH = r'''
import os, pathlib, sys
home, binary = sys.argv[1:]
pathlib.Path(home, 'daemon.pid').write_text(str(os.getpid()))
os.execv(binary, [binary, '--home', home, 'daemon', 'run'])
'''
REMOVE = r'''
import os, pathlib, shutil, signal, sys, time
home = pathlib.Path(sys.argv[1])
if home.exists():
    path = home / 'daemon.pid'
    if path.exists():
        pid = int(path.read_text())
        try:
            os.kill(pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        for _ in range(100):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(.05)
        else:
            raise RuntimeError('owner daemon did not stop; retaining its state')
    shutil.rmtree(home)
'''


STOP_OWNER = r'''
import os, pathlib, signal, sys, time
path = pathlib.Path(sys.argv[1]) / 'daemon.pid'
pid = int(path.read_text())
os.kill(pid, signal.SIGINT)
for _ in range(100):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        path.unlink()
        break
    time.sleep(.05)
else:
    raise RuntimeError('owner daemon did not stop')
'''


def wait_for(check):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.1)
    raise AssertionError('timed out waiting for node/configuration/message')


def stop(process):
    if process and process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--remote-binary', required=True, help='Absolute Gent binary path on the owner')
    parser.add_argument('--remote-join-helper', help='Optional join_local example binary to test a second remote node and peer mesh')
    parser.add_argument('--binary', default='target/debug/gent')
    parser.add_argument('--relay-url', default='http://127.0.0.1:18787')
    parser.add_argument('--relay-token-file', required=True)
    parser.add_argument('--file-objects', action='store_true', help='Also prove native files through authenticated MCP and separate ciphertext storage')
    parser.add_argument('--remote-relay-port', type=int, default=18789)
    args = parser.parse_args()
    url = urlparse(args.relay_url)
    assert url.scheme == 'http' and url.hostname == '127.0.0.1' and url.port
    assert args.remote_binary.startswith('/') and 1024 <= args.remote_relay_port < 65536
    key = Path(args.relay_token_file)
    assert not key.is_symlink() and key.stat().st_mode & 0o077 == 0
    token = key.read_text().strip()
    assert len(token) == 64 and all(c in '0123456789abcdefABCDEF' for c in token)
    ssh = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', '-o', 'ForwardAgent=no']

    def remote(command, payload=None, check=True):
        return subprocess.run(ssh + ['--', args.owner, shlex.join(command)], input=payload, capture_output=True, text=True, check=check, timeout=30)

    binary = str(Path(args.binary).resolve())
    owner_home = None
    peer_home = None
    local_daemon = owner_daemon = peer_daemon = tunnel = None
    clients = []
    with tempfile.TemporaryDirectory(prefix='gent-joined-pairing-') as folder:
        home = Path(folder) / 'node'
        local = [binary, '--home', str(home), '--json']

        def cli(*command):
            result = subprocess.run(local + list(command), check=True, capture_output=True, text=True, timeout=40)
            return json.loads(result.stdout)

        def applied(revision):
            # Read the projection directly. An RPC status request wakes local
            # sync and would mask a broken push notification path in this proof.
            return tomllib.loads((home / 'config.toml').read_text())['applied_revision'] == revision

        try:
            setup = json.loads(remote(['python3', '-c', PREPARE], json.dumps({'binary': args.remote_binary, 'relay': f'http://127.0.0.1:{args.remote_relay_port}', 'token': token})).stdout)
            owner_home = setup['home']
            owner = [args.remote_binary, '--home', owner_home, '--json']
            with open(Path(folder) / 'tunnel.log', 'a') as log:
                tunnel = subprocess.Popen(ssh + ['-o', 'ExitOnForwardFailure=yes', '-N', '-R', f'127.0.0.1:{args.remote_relay_port}:127.0.0.1:{url.port}', '--', args.owner], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            wait_for(lambda: remote(['python3', '-c', 'import socket,sys; socket.create_connection(("127.0.0.1",int(sys.argv[1])),2).close()', str(args.remote_relay_port)], check=False).returncode == 0)
            def start_owner():
                with open(Path(folder) / 'owner.log', 'a') as log:
                    return subprocess.Popen(ssh + ['--', args.owner, shlex.join(['python3', '-c', LAUNCH, owner_home, args.remote_binary])], stdin=subprocess.DEVNULL, stdout=log, stderr=log)

            owner_daemon = start_owner()
            wait_for(lambda: remote(owner + ['daemon', 'status'], check=False).returncode == 0)
            join = ['cluster', 'join', setup['cluster'], '--via', args.owner, '--name', 'joining-machine', '--remote-gent', args.remote_binary, '--remote-home', owner_home, '--relay-endpoint', args.relay_url]
            assert cli(*join)['joined']
            identity = (home / 'identity.key').read_bytes()
            assert identity.startswith(b'GENTKEY2')
            assert cli(*join)['already_joined']
            assert (home / 'identity.key').read_bytes() == identity

            def start_local():
                with open(Path(folder) / 'joined.log', 'a') as log:
                    return subprocess.Popen(local + ['daemon', 'run'], stdin=subprocess.DEVNULL, stdout=log, stderr=log)

            local_daemon = start_local()
            wait_for(lambda: (home / 'daemon.sock').exists())
            nodes = cli('nodes')
            assert len(nodes) == 2 and len({n['id'] for n in nodes}) == 2
            time.sleep(1.2)
            started = time.monotonic()
            changed = json.loads(remote(owner + ['node', 'name', 'set', 'owner-after-join']).stdout)
            wait_for(lambda: applied(changed['revision']))
            config_latency = time.monotonic() - started
            assert next(n for n in cli('nodes') if n['id'] == setup['node'])['name'] == 'owner-after-join'
            assert cli('node', 'name') == 'joining-machine'
            stop(local_daemon)
            local_daemon = None
            changed = json.loads(remote(owner + ['node', 'name', 'set', 'owner-while-peer-offline']).stdout)
            local_daemon = start_local()
            wait_for(lambda: (home / 'daemon.sock').exists())
            wait_for(lambda: applied(changed['revision']))
            assert next(n for n in cli('nodes') if n['id'] == setup['node'])['name'] == 'owner-while-peer-offline'
            a = Client(local + ['mcp', 'serve', '--binding', str(home / 'visual.key')])
            clients.append(a)
            b = Client(ssh + ['--', args.owner, shlex.join(owner + ['mcp', 'serve', '--binding', owner_home + '/visual.key'])])
            clients.append(b)
            aid = a.call('gent_register', {'name': 'linux-visual', 'provider': 'generic-mcp'})[0]['agent']['id']
            bid = b.call('gent_register', {'name': 'mac-review', 'provider': 'generic-mcp'})[0]['agent']['id']
            wait_for(lambda: len(cli('agents')) == 2)
            wait_for(lambda: len(json.loads(remote(owner + ['agents']).stdout)) == 2)
            assert a.call('gent_agents')[0] == b.call('gent_agents')[0] == []
            cli('permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
            granted = cli('permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
            wait_for(lambda: applied(granted['revision']))
            wait_for(lambda: len(a.call('gent_agents')[0]) == 1)
            files = [{'name': 'visual.png', 'media_type': 'image/png', 'data_base64': PNG}]
            attempt = {'recipient': bid, 'request_id': str(uuid.uuid4()), 'text': 'review this image', 'files': files}
            sent = a.call('gent_send', attempt)[0]
            assert a.call('gent_send', attempt)[0]['duplicate']
            wait_for(lambda: len(b.call('gent_inbox')[0]) == 1)
            inbox, raw = b.call('gent_inbox')
            assert inbox[0]['id'] == sent['message_id']
            assert base64.b64decode(inbox[0]['files'][0]['data_base64']) == base64.b64decode(PNG)
            assert any(part['type'] == 'image' and part['data'] == PNG for part in raw['content'])
            b.call('gent_send', {'recipient': aid, 'request_id': str(uuid.uuid4()), 'text': 'unsolicited'}, error=True)
            b.call('gent_ack', {'message_id': sent['message_id']})
            wait_for(lambda: a.call('gent_message_status', {'message_id': sent['message_id']})[0]['state'] == 'delivered')
            reply = b.call('gent_reply', {'message_id': sent['message_id'], 'request_id': str(uuid.uuid4()), 'text': 'image reviewed', 'files': files})[0]
            wait_for(lambda: len(a.call('gent_inbox')[0]) == 1)
            inbox, raw = a.call('gent_inbox')
            assert inbox[0]['id'] == reply['message_id'] and inbox[0]['reply_to'] == sent['message_id']
            assert any(part['type'] == 'image' and part['data'] == PNG for part in raw['content'])
            a.call('gent_ack', {'message_id': reply['message_id']})
            stop(local_daemon)
            local_daemon = None
            queued = b.call('gent_reply', {'message_id': sent['message_id'], 'request_id': str(uuid.uuid4()), 'text': 'follow-up while offline'})[0]
            local_daemon = start_local()
            wait_for(lambda: (home / 'daemon.sock').exists())
            wait_for(lambda: any(m['id'] == queued['message_id'] for m in a.call('gent_inbox')[0]))
            a.call('gent_ack', {'message_id': queued['message_id']})
            grant = cli('relay', 'grant', aid, bid)
            assert grant['state'] == 'applied'
            attached = a.call('gent_relay_attach', {'target': bid, 'request_id': str(uuid.uuid4())})[0]
            assert attached['attachment']['security_mode'] == 'encrypted_daemon_link'

            def restart_relay_nodes():
                nonlocal local_daemon, owner_daemon
                stop(local_daemon)
                remote(['python3', '-c', STOP_OWNER, owner_home])
                stop(owner_daemon)
                owner_daemon = start_owner()
                local_daemon = start_local()
                wait_for(lambda: remote(owner + ['daemon', 'status'], check=False).returncode == 0)
                wait_for(lambda: subprocess.run(local + ['daemon', 'status'], capture_output=True).returncode == 0)

            exercise_turns(a, b, attached['attachment']['id'], files, wait_for, restart_relay_nodes)
            print('PASS: two-machine ordered relay turns, PNG forwarding, restart recovery, cancellation, final outcomes, and exact retries')
            if args.file_objects:
                import hashlib
                folders = a.call('gent_file_paths')[0]
                source = Path(folders['import_directory']) / 'native-review.bin'
                assert source.resolve().is_relative_to(home.resolve())
                content = b'gent-native-mcp-private-file\0' + bytes(range(256)) * 8192
                source.write_bytes(content)
                imported = a.call('gent_file_import', {'name': source.name, 'media_type': 'application/octet-stream', 'request_id': str(uuid.uuid4())})[0]['file']
                request = {'recipient': bid, 'request_id': str(uuid.uuid4()), 'text': 'native file review', 'file_ids': [imported['id']]}
                sent_file = a.call('gent_send', request)[0]
                restart_relay_nodes()
                assert a.call('gent_send', request)[0]['message_id'] == sent_file['message_id']
                def incoming(client, message_id):
                    return next((m for m in client.call('gent_inbox')[0] if m['id'] == message_id), None)
                wait_for(lambda: incoming(b, sent_file['message_id']))
                received = incoming(b, sent_file['message_id'])['attachments'][0]
                assert received['id'] != imported['id']
                wait_for(lambda: b.call('gent_file_status', {'file_id': received['id']})[0]['state'] == 'ready')
                exported = b.call('gent_file_export', {'file_id': received['id']})[0]
                verify = "import hashlib,pathlib,sys; p=pathlib.Path(sys.argv[1]).resolve(); assert p.is_relative_to(pathlib.Path(sys.argv[2]).resolve()); print(hashlib.sha256(p.read_bytes()).hexdigest())"
                digest = remote(['/opt/homebrew/bin/python3', '-c', verify, exported['path'], owner_home]).stdout.strip()
                assert digest == hashlib.sha256(content).hexdigest() == received['sha256']
                result = b.call('gent_reply', {'message_id': sent_file['message_id'], 'request_id': str(uuid.uuid4()), 'text': 'native bytes reviewed', 'file_ids': [received['id']]})[0]
                restart_relay_nodes()
                wait_for(lambda: incoming(a, result['message_id']))
                returned = incoming(a, result['message_id'])['attachments'][0]
                assert returned['id'] not in (imported['id'], received['id'])
                wait_for(lambda: a.call('gent_file_status', {'file_id': returned['id']})[0]['state'] == 'ready')
                output = Path(a.call('gent_file_export', {'file_id': returned['id']})[0]['path'])
                assert output.resolve().is_relative_to(home.resolve()) and output.read_bytes() == content
                b.call('gent_ack', {'message_id': sent_file['message_id']})
                a.call('gent_ack', {'message_id': result['message_id']})
                print('PASS: two-machine native MCP files, exact 2 MiB bytes, scoped forwarding, and both daemon restarts')

            rename_id = str(uuid.uuid4())
            renamed = cli('--request-id', rename_id, 'node', 'name', 'set', 'joined-after-edit')
            assert renamed['state'] == 'applied'
            assert cli('--request-id', rename_id, 'node', 'name', 'set', 'joined-after-edit')['revision'] == renamed['revision']
            assert cli('node', 'name') == 'joined-after-edit'
            remote(['python3', '-c', STOP_OWNER, owner_home])
            stop(owner_daemon)
            owner_daemon = None
            pending_id = str(uuid.uuid4())
            pending = cli('--request-id', pending_id, 'node', 'name', 'set', 'pending-while-owner-offline')
            assert pending['state'] == 'queued' and not pending['applied']
            assert cli('node', 'name') == 'joined-after-edit'
            stop(local_daemon)
            local_daemon = start_local()
            wait_for(lambda: (home / 'daemon.sock').exists())
            assert cli('config', 'request', pending_id)['state'] == 'queued'
            owner_daemon = start_owner()
            wait_for(lambda: remote(owner + ['daemon', 'status'], check=False).returncode == 0)
            wait_for(lambda: cli('config', 'request', pending_id)['state'] == 'applied')
            assert cli('node', 'name') == 'pending-while-owner-offline'
            node = cli('node')['id']
            revoked = json.loads(remote(owner + ['node', 'admin', 'revoke', node]).stdout)
            wait_for(lambda: applied(revoked['revision']))
            denied = subprocess.run(local + ['node', 'name', 'set', 'not-authorized'], capture_output=True, text=True, timeout=15)
            assert denied.returncode != 0 and 'configuration-management grant' in denied.stderr
            assert cli('node', 'name') == 'pending-while-owner-offline'
            if args.remote_join_helper:
                peer_home = remote(['python3', '-c', 'import tempfile; print(tempfile.mkdtemp(prefix="gent-mesh-proof-"))']).stdout.strip()
                remote([args.remote_join_helper, owner_home, peer_home])
                peer_cli = [args.remote_binary, '--home', peer_home, '--json']
                with open(Path(folder) / 'mac-peer.log', 'a') as log:
                    peer_daemon = subprocess.Popen(ssh + ['--', args.owner, shlex.join(['python3', '-c', LAUNCH, peer_home, args.remote_binary])], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                wait_for(lambda: remote(peer_cli + ['daemon', 'status'], check=False).returncode == 0)
                c = Client(ssh + ['--', args.owner, shlex.join(peer_cli + ['mcp', 'serve', '--binding', peer_home + '/visual.key'])])
                clients.append(c)
                cid = c.call('gent_register', {'name': 'mac-peer', 'provider': 'generic-mcp'})[0]['agent']['id']
                peer_node = json.loads(remote(peer_cli + ['node']).stdout)['id']
                wait_for(lambda: any(n['id'] == peer_node and n['data_link'] for n in cli('nodes')))
                wait_for(lambda: len(cli('agents')) == 3 and len(json.loads(remote(peer_cli + ['agents']).stdout)) == 3)
                remote(owner + ['permission', 'allow', aid, cid, '--permission', 'enumerate', 'send'])
                remote(owner + ['permission', 'allow', cid, aid, '--permission', 'enumerate', 'receive'])
                wait_for(lambda: any(agent['id'] == cid for agent in a.call('gent_agents')[0]))
                wait_for(lambda: any(agent['id'] == aid for agent in c.call('gent_agents')[0]))
                remote(['python3', '-c', STOP_OWNER, owner_home])
                stop(owner_daemon)
                owner_daemon = None
                sent = a.call('gent_send', {'recipient': cid, 'request_id': str(uuid.uuid4()), 'text': 'direct mesh image with owner offline', 'files': files})[0]
                wait_for(lambda: len(c.call('gent_inbox')[0]) == 1)
                inbox, raw = c.call('gent_inbox')
                assert inbox[0]['id'] == sent['message_id'] and any(part['type'] == 'image' and part['data'] == PNG for part in raw['content'])
                c.call('gent_ack', {'message_id': sent['message_id']})
                wait_for(lambda: a.call('gent_message_status', {'message_id': sent['message_id']})[0]['state'] == 'delivered')
                stop(local_daemon)
                local_daemon = None
                direct_reply = c.call('gent_reply', {'message_id': sent['message_id'], 'request_id': str(uuid.uuid4()), 'text': 'direct mesh feedback', 'files': files})[0]
                local_daemon = start_local()
                wait_for(lambda: (home / 'daemon.sock').exists())
                wait_for(lambda: any(m['id'] == direct_reply['message_id'] for m in a.call('gent_inbox')[0]))
                inbox, raw = a.call('gent_inbox')
                assert any(part['type'] == 'image' and part['data'] == PNG for part in raw['content'])
                unseen = remote(['python3', '-c', 'import sqlite3,sys; db=sqlite3.connect(sys.argv[1]+"/state.sqlite3"); print(db.execute("SELECT COUNT(*) FROM messages WHERE id IN (?,?)",sys.argv[2:]).fetchone()[0])', owner_home, sent['message_id'], direct_reply['message_id']]).stdout.strip()
                assert unseen == '0'
                print('PASS: direct joined Linux-Mac MCP image/reply/receipt, owner offline, peer restart, and no owner message copy')
            print('PASS: two-machine pairing, encrypted MCP images/replies/receipts, remote permission edits and renaming, idempotent requests, offline owner recovery, and administration revocation')
            print(f'Configuration applied in {config_latency * 1000:.0f} ms, including the SSH owner command; observation made no daemon requests')
        finally:
            for client in clients:
                client.close()
            stop(local_daemon)
            if peer_home:
                remote(['python3', '-c', REMOVE, peer_home])
            stop(peer_daemon)
            if owner_home:
                remote(['python3', '-c', REMOVE, owner_home])
            stop(owner_daemon)
            stop(tunnel)


if __name__ == '__main__':
    main()
