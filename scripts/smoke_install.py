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

        def cli(*command, check=True):
            return subprocess.run(base + list(command), capture_output=True, text=True, timeout=20, check=check)

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
