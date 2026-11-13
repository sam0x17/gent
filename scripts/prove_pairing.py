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
    parser.add_argument('--binary', default='target/debug/gent')
    parser.add_argument('--relay-url', default='http://127.0.0.1:18787')
    parser.add_argument('--relay-token-file', required=True)
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
    local_daemon = owner_daemon = None
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
            with open(Path(folder) / 'owner.log', 'w') as log:
                owner_daemon = subprocess.Popen(ssh + ['-o', 'ExitOnForwardFailure=yes', '-R', f'127.0.0.1:{args.remote_relay_port}:127.0.0.1:{url.port}', '--', args.owner, shlex.join(['python3', '-c', LAUNCH, owner_home, args.remote_binary])], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
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
            remote(owner + ['permission', 'allow', aid, bid, '--permission', 'enumerate', 'send'])
            granted = json.loads(remote(owner + ['permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive']).stdout)
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
            print('PASS: two-machine SSH pairing, encrypted configuration sync, MCP images in both directions, scoped replies, authenticated receipts, and offline catch-up')
            print(f'Configuration applied in {config_latency * 1000:.0f} ms, including the SSH owner command; observation made no daemon requests')
        finally:
            for client in clients:
                client.close()
            stop(local_daemon)
            if owner_home:
                remote(['python3', '-c', REMOVE, owner_home])
            stop(owner_daemon)


if __name__ == '__main__':
    main()
