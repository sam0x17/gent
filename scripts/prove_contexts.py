#!/usr/bin/env python3
"""Prove cluster selection against two native services and installed MCP entries.

Uses isolated systemd/launchd services and synthetic host metadata. No model,
account service, network relay, or real host settings are involved.
"""
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from smoke_mcp import Client, PNG


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gent').resolve())
    folder = Path(tempfile.mkdtemp(prefix='gent-contexts-', dir='/tmp')).resolve()
    root, peer = folder / 'primary', folder / 'secondary'
    clients, installed, hosts = [], [], []
    ids = {}

    def cli(home, *args, code=0):
        result = subprocess.run([binary, '--home', str(home), '--json', *args],
            text=True, capture_output=True, timeout=30)
        assert result.returncode == code, (args, result.returncode, result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def primary(*args, code=0):
        return cli(root, '--cluster', ids[root], *args, code=code)

    def connect(spec, name):
        client = Client([spec['command'], *spec['args']], client_name=name)
        clients.append(client)
        return client

    def generic(command):
        client = Client(command)
        clients.append(client)
        return client

    try:
        for home, name in [(root, 'alpha'), (peer, 'beta')]:
            cli(home, 'cluster', 'new', name, '--local')
            ids[home] = cli(home, 'config')['cluster']['id']
            installed.append(home)
            assert cli(home, 'daemon', 'install')['daemon']['managed']
        original_pids = {home: cli(home, 'daemon', 'status')['daemon']['pid'] for home in installed}
        identities = {home: (home / 'identity.key').read_bytes() for home in installed}
        owner_keys = {home: (home / 'owner.key').read_bytes() for home in installed}
        files, specs = {}, {}
        for host in ('codex', 'claude-code'):
            directory = folder / host
            primary('integration', 'install', host, '--config-dir', str(directory))
            hosts.append((host, directory))
            path = directory / ('config.toml' if host == 'codex' else '.claude.json')
            files[path] = path.read_bytes()
            cfg = tomllib.loads(path.read_text()) if host == 'codex' else json.loads(path.read_text())
            specs[host] = cfg['mcp_servers' if host == 'codex' else 'mcpServers']['gent']
        settings_path = folder / 'claude-code/settings.json'
        files[settings_path] = settings_path.read_bytes()
        hook = json.loads(settings_path.read_text())['hooks']['PreToolUse'][0]['hooks'][0]['command']
        codex = connect(specs['codex'], 'codex-mcp-client')
        claude = connect(specs['claude-code'], 'claude-code')
        meta = {'threadId': 'same-thread-through-switch', 'sessionId': 'tree'}

        def claude_call(tool, arguments=None):
            arguments = arguments or {}
            use = 'toolu_' + uuid.uuid4().hex
            event = {'session_id': 'same-chat-through-switch', 'tool_use_id': use,
                'tool_name': 'mcp__gent__' + tool, 'tool_input': arguments,
                'hook_event_name': 'PreToolUse'}
            subprocess.run(['/bin/sh', '-c', hook], input=json.dumps(event), text=True,
                capture_output=True, check=True, timeout=15)
            return claude.call(tool, arguments, meta={'claudecode/toolUseId': use})[0]

        aid = codex.call('gent_register', {'name': 'sender', 'provider': 'codex'}, meta=meta)[0]['agent']['id']
        bid = claude_call('gent_register', {'name': 'recipient', 'provider': 'claude-code'})['agent']['id']
        primary('permission', 'allow', aid, bid, '--permission', 'send', 'enumerate')
        primary('permission', 'allow', bid, aid, '--permission', 'receive', 'enumerate')
        message = codex.call('gent_send', {'recipient': bid, 'request_id': codex.request_id(meta=meta),
            'text': 'queued in alpha while beta is selected',
            'files': [{'name': 'image.png', 'media_type': 'image/png', 'data_base64': PNG}]}, meta=meta)[0]
        binding = folder / 'chat.key'
        fixed = generic([binary, '--home', str(root), 'mcp', 'serve', '--binding', str(binding)])
        fixed_id = fixed.call('gent_register', {'name': 'generic', 'provider': 'generic'})[0]['agent']['id']
        cli(root, 'cluster', 'add', str(peer))
        assert len(cli(root, 'clusters')['profiles']) == 2
        assert cli(root, 'cluster', 'switch', 'beta')['active_cluster'] == ids[peer]
        assert cli(root, 'cluster')['cluster']['id'] == ids[peer]
        assert primary('cluster')['cluster']['id'] == ids[root]
        assert cli(root, 'config', 'path') == str(peer / 'config.toml')
        assert cli(root, 'agents') == []
        assert primary('daemon', 'status')['daemon']['pid'] == original_pids[root]
        assert cli(root, 'daemon', 'status')['daemon']['pid'] == original_pids[peer]
        assert codex.call('gent_identity', meta=meta)[0]['agent']['id'] == aid
        assert claude_call('gent_identity')['agent']['id'] == bid
        assert fixed.call('gent_identity')[0]['agent']['id'] == fixed_id
        # Installed entries retain their physical home across a fresh process.
        codex.close()
        claude.close()
        codex = connect(specs['codex'], 'codex-mcp-client')
        claude = connect(specs['claude-code'], 'claude-code')
        assert codex.call('gent_identity', meta=meta)[0]['agent']['id'] == aid
        assert claude_call('gent_identity')['agent']['id'] == bid
        inbox = claude_call('gent_inbox')
        assert inbox[0]['id'] == message['message_id'] and inbox[0]['files'][0]['data_base64'] == PNG
        assert cli(root, 'agents') == []
        assert claude_call('gent_file_paths')['import_directory'].startswith(str(root) + '/')
        # A bare new connection uses beta, while an existing fixed binding may
        # never be silently registered in beta after reconnecting.
        selected_command = ['/usr/bin/env', f'GENT_HOME={root}', binary]
        fresh = generic(selected_command + ['mcp', 'serve'])
        fresh_id = fresh.call('gent_register', {'name': 'beta-only', 'provider': 'generic'})[0]['agent']['id']
        assert [a['id'] for a in cli(root, 'agents')] == [fresh_id]
        fixed.close()
        rejected = subprocess.run(selected_command + ['mcp', 'serve', '--binding', str(binding)],
            input='', text=True, capture_output=True, timeout=15)
        assert rejected.returncode == 1 and 'another cluster' in rejected.stderr
        assert [a['id'] for a in cli(root, 'agents')] == [fresh_id]
        fixed = generic(selected_command + ['--cluster', ids[root], 'mcp', 'serve', '--binding', str(binding)])
        assert fixed.call('gent_identity')[0]['agent']['id'] == fixed_id
        primary('node', 'name', 'set', 'alpha-renamed')
        assert cli(root, 'clusters')['active_cluster'] == ids[peer]
        primary('daemon', 'restart')
        assert primary('cluster')['cluster']['id'] == ids[root]
        assert cli(root, 'daemon', 'status')['daemon']['pid'] == original_pids[peer]
        cli(root, 'daemon', 'restart')
        assert codex.call('gent_identity', meta=meta)[0]['agent']['id'] == aid
        assert claude_call('gent_inbox')[0]['id'] == message['message_id']
        assert fresh.call('gent_identity')[0]['agent']['id'] == fresh_id
        assert cli(root, 'clusters')['active_cluster'] == ids[peer]
        for path, original in files.items():
            assert path.read_bytes() == original, 'switch rewrote host installation'
        for home in installed:
            assert (home / 'identity.key').read_bytes() == identities[home]
            assert (home / 'owner.key').read_bytes() == owner_keys[home]
        cli(root, 'cluster', 'switch', code=1)  # JSON/non-terminal never prompts.
        listing = cli(root, 'clusters')['profiles']
        index = next(i + 1 for i, p in enumerate(listing) if p['cluster_id'] == ids[root])
        master, slave = pty.openpty()
        process = subprocess.Popen([binary, '--home', str(root), 'cluster', 'switch'],
            stdin=slave, stderr=slave, stdout=subprocess.PIPE, text=True)
        os.close(slave)
        try:
            seen = b''
            deadline = time.monotonic() + 10
            while b'Select a cluster number:' not in seen:
                assert time.monotonic() < deadline, 'missing terminal selection prompt'
                if select.select([master], [], [], .1)[0]:
                    seen += os.read(master, 4096)
            os.write(master, f'{index}\n'.encode())
            output, _ = process.communicate(timeout=10)
            assert process.returncode == 0 and ids[root] in output
        finally:
            os.close(master)
            if process.poll() is None:
                process.kill()
                process.wait()
        assert cli(root, 'cluster')['cluster']['id'] == ids[root]
        report = {'result': 'passed', 'scope': 'two native services, synthetic MCP host calls, one physical host',
            'checks': ['read-only per-command selection', 'unchanged service PIDs on switch',
                'installed Codex and Claude reconnect and per-call hook pinning', 'queued PNG retained in original cluster',
                'generic binding rejects wrong-cluster reconnect', 'independent daemon restarts',
                'configuration projection preserves selection', 'noninteractive refusal and real PTY selection',
                'unchanged signing keys and host configuration']}
        (folder / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS: cluster selection, pinned services/MCP, queued PNG and restart recovery', flush=True)
        print(f'Proof state: {folder}', flush=True)
    finally:
        for client in clients:
            client.close()
        for host, directory in hosts:
            primary('integration', 'uninstall', host, '--config-dir', str(directory))
        for home in installed:
            cli(home, '--cluster', ids[home], 'daemon', 'uninstall')


if __name__ == '__main__':
    main()
