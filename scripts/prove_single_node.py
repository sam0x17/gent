#!/usr/bin/env python3
"""Prove one-node setup and legacy reset using real systemd/launchd services.

Uses disposable node directories and host settings, synthetic MCP metadata and
no account or model calls. Leaves a private report and offline archive in /tmp.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import uuid

from mcp_client import Client


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gent').resolve())
    folder = Path(tempfile.mkdtemp(prefix='gent-node-', dir='/tmp')).resolve()
    os.chmod(folder, 0o700)
    home = folder / 'node'
    child = home / 'clusters' / 'old'
    env = dict(os.environ, CODEX_HOME=str(folder / 'codex'), CLAUDE_CONFIG_DIR=str(folder / 'claude'))
    clients, services = [], []

    def cli(directory, *args, code=0):
        result = subprocess.run([binary, '--home', str(directory), '--json', *args],
                                env=env, text=True, capture_output=True, timeout=60)
        assert result.returncode == code, (args, result.returncode, result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def install(directory):
        services.append(directory)
        result = cli(directory, 'daemon', 'install', '--no-input')
        assert result['daemon']['running'] and result['daemon']['managed']
        return Path(result['service']['file'])

    def agents(directory):
        result = {}
        for host in ['codex', 'claude-code']:
            status = cli(directory, 'integration', 'install', host)
            assert status['current_home'] is True
            config = Path(status['server_config'])
            cfg = tomllib.loads(config.read_text()) if host == 'codex' else json.loads(config.read_text())
            spec = cfg['mcp_servers' if host == 'codex' else 'mcpServers']['gent']
            assert spec['args'][spec['args'].index('--home') + 1] == str(directory)
            client = Client([spec['command'], *spec['args']], client_name='codex-mcp-client' if host == 'codex' else 'claude-code')
            clients.append(client)
            args = {'name': host, 'provider': host}
            if host == 'codex':
                meta = {'threadId': 'same-thread', 'sessionId': 'same-session'}
            else:
                use = 'toolu_' + uuid.uuid4().hex
                settings = json.loads(Path(status['settings_config']).read_text())
                hook = settings['hooks']['PreToolUse'][0]['hooks'][0]['command']
                event = {'session_id': 'same-chat', 'tool_use_id': use,
                         'tool_name': 'mcp__gent__gent_register', 'tool_input': args,
                         'hook_event_name': 'PreToolUse'}
                subprocess.run(['/bin/sh', '-c', hook], input=json.dumps(event), text=True,
                               capture_output=True, check=True, timeout=15)
                meta = {'claudecode/toolUseId': use}
            registered = client.call('gent_register', args, meta=meta)[0]
            assert registered['cluster_id'] == cli(directory, 'config')['cluster']['id']
            result[host] = registered['agent']['id']
        return result

    try:
        cli(home, 'cluster', 'new', 'original', '--local')
        root_file = install(home)
        cli(child, 'cluster', 'new', 'legacy', '--local')
        child_file = install(child)
        old_agents = agents(child)
        root_cfg = cli(home, 'config')
        child_cfg = cli(child, 'config')
        # Reproduce the former selected-child layout without relying on the
        # removed profile commands. Current runtimes already hold their paths.
        text = (home / 'config.toml').read_text().replace('version = 1', 'version = 2', 1)
        text += '\n[contexts]\nversion = 1\nactive_cluster = ' + json.dumps(child_cfg['cluster']['id']) + '\n'
        for path, cfg in [(home, root_cfg), (child, child_cfg)]:
            text += '\n[contexts.profiles.' + json.dumps(cfg['cluster']['id']) + ']\n'
            text += 'home = ' + json.dumps(str(path)) + '\nnode_id = ' + json.dumps(cfg['node']['id']) + '\n'
        (home / 'config.toml').write_text(text)
        cli(home, 'config', code=1)
        auth = home / 'auth'
        auth.mkdir(mode=0o700, exist_ok=True)
        session = auth / 'session.json'
        session.write_text('{"synthetic_session":"never-print-this"}')
        session.chmod(0o600)
        for client in clients:
            client.close()
        clients.clear()
        reset = cli(home, 'node', 'reset')
        archive = Path(reset['archive'])
        assert reset['login_preserved'] and archive.exists()
        assert session.read_text() == '{"synthetic_session":"never-print-this"}'
        assert not root_file.exists() and not child_file.exists()
        assert not (home / 'config.toml').exists() and not (home / 'clusters').exists()
        assert cli(home, 'node', 'reset')['reset'] is False
        for path in [archive, archive / 'clusters' / 'old']:
            cli(path, 'daemon', 'run', code=1)
        for host in ['codex', 'claude-code']:
            assert cli(home, 'integration', 'status', host)['state'] == 'absent'
        services.clear()
        cli(home, 'cluster', 'new', 'personal', '--local')
        new_cfg = cli(home, 'config')
        assert new_cfg['node']['id'] != root_cfg['node']['id']
        install(home)
        new_cfg = cli(home, 'config')
        assert cli(home, 'cluster', 'new', 'personal', '--local')['already_configured']
        for args in [('cluster', 'new', 'second', '--local'),
                     ('daemon', 'install', '--local', 'second', '--no-input')]:
            cli(home, *args, code=1)
        assert cli(home, 'config') == new_cfg
        fresh_agents = agents(home)
        assert all(fresh_agents[k] != old_agents[k] for k in old_agents)
        cli(home, 'daemon', 'restart')
        assert cli(home, 'cluster')['cluster']['id'] == new_cfg['cluster']['id']
        report = {'status': 'passed', 'platform': os.uname().sysname,
                  'checks': ['managed root and legacy child stopped', 'both host entries retired',
                             'login preserved', 'archives refuse activation', 'reset retry',
                             'fresh identities', 'second cluster refused', 'both MCP hosts share one node',
                             'managed daemon restart'], 'archive': str(archive)}
        (folder / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report))
    finally:
        for client in clients:
            client.close()
        for directory in reversed(services):
            subprocess.run([binary, '--home', str(directory), 'daemon', 'uninstall'],
                           env=env, capture_output=True, timeout=30)
        for host in ['codex', 'claude-code']:
            subprocess.run([binary, '--home', str(home), 'integration', 'uninstall', host],
                           env=env, capture_output=True, timeout=15)


if __name__ == '__main__':
    main()
