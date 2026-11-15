#!/usr/bin/env python3
"""Isolated installer concurrency and native host configuration discovery; no models."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/gent'))
    parser.add_argument('--codex', default='codex')
    parser.add_argument('--claude', default='claude')
    args = parser.parse_args()
    binary = str(args.binary.resolve())
    with tempfile.TemporaryDirectory(prefix='gent-install-', dir='/tmp') as root:
        root = Path(root)
        home = root / "state ' $HOME"
        base = [binary, '--home', str(home)]

        def cli(*command, check=True, env=None):
            return subprocess.run(base + list(command), capture_output=True, text=True, timeout=20, check=check, env=env)

        cli('cluster', 'new', 'install-proof', '--local')
        for host, env_name, executable in [('codex', 'CODEX_HOME', args.codex), ('claude-code', 'CLAUDE_CONFIG_DIR', args.claude)]:
            directory = root / host
            suffix = [host, '--config-dir', str(directory)]
            assert json.loads(cli('integration', 'status', *suffix).stdout)['state'] == 'absent'
            assert not directory.exists()
            # Separate processes contend for the same target, including the very
            # first installation before a lock or ownership record exists.
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                futures = [pool.submit(cli, 'integration', 'install', *suffix) for _ in range(8)]
                for future in futures:
                    assert json.loads(future.result().stdout)['state'] == 'configured'
            env = dict(os.environ, **{env_name: str(directory)})
            status = subprocess.run(base + ['integration', 'status', host], env=env,
                                    capture_output=True, text=True, check=True, timeout=20)
            assert json.loads(status.stdout)['state'] == 'configured'
            if host == 'codex':
                endpoint = directory.resolve() / 'app-server-control/app-server-control.sock'
                unrelated = root / 'unrelated-codex'
                other_env = dict(env, CODEX_HOME=str(unrelated))
                fragment = json.loads(cli('integration', 'config', host, '--wake', '--config-dir', str(directory), env=other_env).stdout)
                assert fragment['mcp_servers']['gent']['args'][-2:] == ['--wake-socket', str(endpoint)]
                inherited = json.loads(cli('integration', 'config', host, '--wake', env=env).stdout)
                assert inherited == fragment
                installed = json.loads(cli('integration', 'install', *suffix, '--wake', env=other_env).stdout)
                assert installed['wake_socket'] == str(endpoint)
                path = directory / 'config.toml'
                original = path.read_bytes()
                cli('integration', 'install', *suffix, '--wake', env=other_env)
                assert path.read_bytes() == original
                assert not endpoint.parent.exists() and not unrelated.exists()
                for command in [
                    ['install', *suffix, '--wake', '--wake-socket', str(root / 'other.sock')],
                    ['uninstall', *suffix, '--wake'],
                    ['config', host, '--config-dir', str(directory)],
                    ['install', 'claude-code', '--config-dir', str(unrelated), '--wake', '--wake-socket', str(root / 'other.sock')],
                ]:
                    assert cli('integration', *command, check=False).returncode != 0
                    assert path.read_bytes() == original and not unrelated.exists()
                custom = root / 'custom.sock'
                assert json.loads(cli('integration', 'install', *suffix, '--wake-socket', str(custom)).stdout)['wake_socket'] == str(custom)
                assert json.loads(cli('integration', 'install', *suffix).stdout)['wake_socket'] is None
                cli('integration', 'install', *suffix, '--wake')
                assert json.loads(cli('integration', 'status', *suffix).stdout)['wake_socket'] == str(endpoint)
                print('PASS: Codex default socket selection, explicit directory precedence, pinned arguments, opt-out and invalid-option preservation', flush=True)
            else:
                server_path, settings_path = directory / '.claude.json', directory / 'settings.json'
                ordinary = json.loads(server_path.read_text())['mcpServers']['gent']
                identity_settings = json.loads(settings_path.read_text())
                installed = json.loads(cli('integration', 'install', *suffix, '--wake').stdout)
                assert installed['claude_wake'] and installed['wake_socket'] is None
                module = directory / 'skills/gent-wake/hooks/register.ts'
                assert installed['claude_wake'] in module.read_text()
                settings = json.loads(settings_path.read_text())
                guards = [hook for entry in settings['hooks']['UserPromptSubmit'] for hook in entry['hooks']
                          if hook.get('command', '').startswith('# gent-wake-guard-v1\n')]
                assert len(guards) == 1 and guards[0]['onFailure'] == 'block'
                # Execute the installed wrapper, including quotes and literal
                # shell syntax in the Gent home path, without a running daemon.
                verdict = subprocess.run(['/bin/sh', '-c', guards[0]['command']], cwd=root, env=env,
                                         input=json.dumps({'hook_event_name':'UserPromptSubmit','prompt':'ordinary human input'}),
                                         capture_output=True, text=True, check=True, timeout=20)
                assert json.loads(verdict.stdout) == {'continue': True}
                before = {p: p.read_bytes() for p in (server_path, settings_path, module)}
                repeated = json.loads(cli('integration', 'install', *suffix, '--wake').stdout)
                assert repeated['claude_wake'] == installed['claude_wake']
                assert all(p.read_bytes() == data for p, data in before.items())
                assert json.loads(cli('integration', 'status', *suffix).stdout)['claude_wake'] == installed['claude_wake']
                assert cli('integration', 'config', host, '--wake', check=False).returncode != 0
                assert all(p.read_bytes() == data for p, data in before.items())
                disabled = json.loads(cli('integration', 'install', *suffix).stdout)
                assert disabled['claude_wake'] is None and not module.exists()
                assert json.loads(server_path.read_text())['mcpServers']['gent'] == ordinary
                after_opt_out = json.loads(settings_path.read_text())
                assert after_opt_out['hooks'].pop('UserPromptSubmit', []) == []
                assert after_opt_out == identity_settings
                restored = json.loads(cli('integration', 'install', *suffix, '--wake').stdout)
                assert restored['claude_wake'] not in (None, installed['claude_wake'])
                print('PASS: Claude opt-in, installed command guard, idempotence, opt-out and ordinary MCP preservation', flush=True)
            command = [executable, 'mcp', 'get', 'gent']
            if host == 'codex':
                command += ['--json']
            discovered = subprocess.run(command, env=env, cwd=root, capture_output=True, text=True, timeout=30)
            assert discovered.returncode == 0, discovered.stderr
            assert binary in discovered.stdout and 'serve' in discovered.stdout, discovered.stdout
            stranger = subprocess.run([binary, '--home', str(root / 'stranger'), 'integration', 'uninstall', *suffix],
                                      capture_output=True, text=True, timeout=20)
            assert stranger.returncode != 0
            cli('integration', 'remove', *suffix)
            assert json.loads(cli('integration', 'status', *suffix).stdout)['state'] == 'absent'
            print(f'PASS: {host} concurrent installation, environment override, host discovery, ownership and removal', flush=True)


if __name__ == '__main__':
    main()
