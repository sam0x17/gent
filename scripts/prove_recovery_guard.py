#!/usr/bin/env python3
"""Check that offline copies cannot activate, redirect commands, or connect MCP.

Uses disposable node state and generic MCP text/image messages. This is a
recovery-guard proof, not backup creation or restored-node activation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import tomllib

from smoke_mcp import Client, PNG


def snapshot(home):
    return {str(path.relative_to(home)): (
        path.stat().st_mode,
        hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
        for path in home.rglob('*') if not path.is_socket()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, required=True)
    binary = str(parser.parse_args().gent.resolve())
    with tempfile.TemporaryDirectory(prefix='gent-recovery-', dir='/tmp') as directory:
        folder = Path(directory).resolve()
        home, peer, recovered = [folder / name for name in ('source', 'peer', 'recovered')]
        daemon = None
        clients = []

        def command(state, *args, blocked=False):
            result = subprocess.run([binary, '--home', str(state), '--json', *args],
                                    input='', capture_output=True, text=True, timeout=15)
            if blocked:
                assert result.returncode != 0 and 'offline recovery directory' in result.stderr, (
                    args, result.returncode, result.stderr)
                assert not result.stdout
                return None
            assert result.returncode == 0, (args, result.stderr)
            return json.loads(result.stdout)

        try:
            command(home, 'cluster', 'new', 'source', '--local')
            command(peer, 'cluster', 'new', 'peer', '--local')
            daemon = subprocess.Popen([binary, '--home', str(home), 'daemon', 'run'],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 10
            while not (home / 'daemon.sock').exists():
                assert daemon.poll() is None, daemon.stderr.read()
                assert time.monotonic() < deadline, 'daemon startup timed out'
                time.sleep(0.025)
            for name in ('a', 'b'):
                clients.append(Client([binary, '--home', str(home), 'mcp', 'serve',
                                       '--binding', str(home / 'bindings' / (name + '.key'))]))
            a, b = clients
            aid, bid = [client.call('gent_register', {'name': name, 'provider': 'generic-proof'})[0]['agent']['id']
                        for client, name in zip(clients, ('a', 'b'))]
            command(home, 'permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
            command(home, 'permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
            a.call('gent_send', {'recipient': bid, 'request_id': a.request_id(),
                                'text': 'retained offline', 'files': [
                                    {'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': PNG}]})
            assert b.call('gent_inbox')[0][0]['text'] == 'retained offline'
            for client in clients:
                client.close()
            clients.clear()
            daemon.terminate()
            assert daemon.wait(timeout=10) == 0, daemon.stderr.read()
            daemon.stderr.close()
            daemon = None
            shutil.copytree(home, recovered)
            # Make the copied registry internally valid, with a live external
            # peer selected. The guard must run before resolving that reference.
            config = recovered / 'config.toml'
            text = config.read_text().replace(str(home), str(recovered))
            own = tomllib.loads(text)
            external = tomllib.loads((peer / 'config.toml').read_text())
            text = text.replace('version = 1', 'version = 2', 1)
            text += '\n[contexts]\nversion = 1\nactive_cluster = ' + json.dumps(external['cluster']['id']) + '\n'
            for path, cfg in [(recovered, own), (peer, external)]:
                text += '\n[contexts.profiles.' + json.dumps(cfg['cluster']['id']) + ']\n'
                text += 'home = ' + json.dumps(str(path)) + '\nnode_id = ' + json.dumps(cfg['node']['id']) + '\n'
            config.write_text(text)
            marker = recovered / 'recovery-required.json'
            marker.write_text('{"version":1}')
            marker.chmod(0o600)
            before, peer_before = snapshot(recovered), snapshot(peer)
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(peer / 'daemon.sock'))
                listener.listen()
                listener.setblocking(False)
                for args in [
                    ('config',), ('nodes',), ('cluster',),
                    ('cluster', 'new', 'fresh', '--local'),
                    ('daemon', 'run'), ('daemon', 'status'), ('auth', 'status'),
                    ('doctor', '--online'), ('gateway',),
                    ('mcp', 'serve', '--binding', str(folder / 'external.key')),
                ]:
                    command(recovered, *args, blocked=True)
                alias = folder / 'alias'
                alias.symlink_to(recovered, target_is_directory=True)
                command(alias, 'nodes', blocked=True)
                command(recovered / 'missing', 'cluster', 'new', 'fresh', '--local', blocked=True)
                try:
                    connection, _ = listener.accept()
                except BlockingIOError:
                    pass
                else:
                    connection.close()
                    raise AssertionError('recovered profile connected to the live peer')
            (peer / 'daemon.sock').unlink()
            assert snapshot(recovered) == before
            assert snapshot(peer) == peer_before
            assert not (folder / 'external.key').exists()
            assert (recovered / 'identity.key').read_bytes() == (home / 'identity.key').read_bytes()
            assert (recovered / 'state.sqlite3').read_bytes() == (home / 'state.sqlite3').read_bytes()
            # The original remains usable for offline configuration inspection.
            assert command(peer, 'config')['cluster']['name'] == 'peer'
            print(json.dumps({'status': 'passed', 'proof': 'recovery-guard', 'platform': os.uname().sysname,
                              'checks': ['real MCP message/image state', 'daemon and MCP refusal',
                                         'external-profile isolation', 'nested and aliased paths',
                                         'unchanged keys/databases', 'no socket or binding side effects']}))
        finally:
            for client in clients:
                client.close()
            if daemon:
                daemon.terminate()
                try:
                    daemon.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
                daemon.stderr.close()


if __name__ == '__main__':
    main()
