"""Guided installer acceptance checks, invoked by the private setup fixture.

Uses real per-user services and a PTY, isolated homes and shell files. Login is
synthetic; the account fixture does not provide a live ciphertext relay.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import time
import tomllib


def prove(binary, root, env, origin, fault, calls):
    installed = set()
    homes = []
    credentials = []

    def cli(home, *args, code=0):
        result = subprocess.run([str(binary), '--home', str(home), '--json', *args],
            env=env, text=True, capture_output=True, timeout=60)
        assert not any(secret in result.stdout + result.stderr for secret in credentials)
        assert result.returncode == code, (args, result.returncode, result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def terminal(home, steps, code=0):
        master, slave = pty.openpty()
        process = subprocess.Popen([str(binary), '--home', str(home), 'daemon', 'install',
            '--headless', '--service', origin], stdin=slave, stdout=slave, stderr=slave,
            env=dict(env, SHELL='/bin/zsh'))
        os.close(slave)
        output, index = b'', 0
        until = time.monotonic() + 75
        try:
            while True:
                assert time.monotonic() < until, 'guided terminal timed out'
                readable, _, _ = select.select([master], [], [], .1)
                if readable:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output += chunk
                if index < len(steps) and steps[index][0].encode() in output:
                    os.write(master, steps[index][1])
                    index += 1
                if process.poll() is not None and not readable:
                    break
            assert process.wait(timeout=5) == code, 'guided terminal failed; inspect transcript'
            assert index == len(steps), 'terminal skipped a required prompt'
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            os.close(master)
            (root / (home.name + '-terminal.log')).write_bytes(output)

    def identity(home):
        cfg = tomllib.loads((home / 'config.toml').read_text())
        return (cfg['cluster']['id'], cfg['node']['id'],
            hashlib.sha256((home / 'identity.key').read_bytes()).hexdigest())

    try:
        empty = root / 'guided-empty'
        cli(empty, 'daemon', 'install', '--no-input', code=1)
        assert not empty.exists()
        terminal(empty, [('Set up Gent:', b'q\n')], code=1)
        assert not empty.exists()
        terminal(empty, [('Set up Gent:', b'\x04')], code=1)
        assert not empty.exists()

        home = root / 'guided-scripted'
        homes.append(home)
        installed.add(home)  # Clean up even if an install partly succeeds.
        fault.update(enroll=True)
        cli(home, 'daemon', 'install', '--new', 'guided-scripted', '--headless',
            '--service', origin, code=1)
        before = identity(home)
        saved = json.loads((home / 'service.json').read_text())
        credentials.extend([saved['credential']['token'],
            json.loads((home / 'auth/session.json').read_text())['token']])
        assert not saved['credential']['confirmed']
        cli(home, 'daemon', 'install', '--new', 'different', '--no-input', code=1)
        cli(home, 'daemon', 'install', '--service', 'https://other.example', '--no-input', code=1)
        rc = root / 'guided.zshrc'
        original = 'export GENT_PROOF_UNRELATED=preserved'  # No final newline.
        rc.write_text(original)
        rc.chmod(0o600)
        args = ('daemon', 'install', '--no-input', '--hooks', '--shell', 'zsh', '--rc-file', str(rc))
        result = cli(home, *args)
        assert result['daemon']['managed'] and result['enrollment']['status'] == 'configured'
        pid = result['daemon']['pid']
        assert identity(home) == before
        count, contents = len(calls), rc.read_bytes()
        assert cli(home, *args)['daemon']['pid'] == pid
        assert cli(home, 'daemon', 'install', '--new', 'guided-scripted', '--no-input')['daemon']['pid'] == pid
        assert len(calls) == count, 'reinstall unexpectedly contacted the account service'
        assert rc.read_bytes() == contents and contents.count(b'# >>> gent shell v1:') == 1
        cli(home, 'hooks', 'uninstall', '--shell', 'zsh', '--rc-file', str(rc))
        assert rc.read_text() == original
        cli(home, 'daemon', 'uninstall')
        installed.remove(home)
        assert identity(home) == before

        home = root / 'guided-terminal'
        homes.append(home)
        installed.add(home)
        terminal(home, [('Set up Gent:', b'1\n'), ('Cluster name:', b'guided-terminal\n'),
            ('Install shell PATH and completions?', b'n\n')])
        status = cli(home, 'daemon', 'status')
        assert status['daemon']['managed'] and status['cluster']['name'] == 'guided-terminal'
        assert 'gent integration install codex' in (root / 'guided-terminal-terminal.log').read_text()
        cli(home, 'daemon', 'uninstall')
        installed.remove(home)
        report = {'result': 'passed', 'service_backend': status['service']['backend'],
            'checks': ['no-input refusal without state', 'PTY cancellation and EOF',
                'headless login and lost enrollment response', 'bare resume preserves identity',
                'wrong name/service rejection', 'repeat install preserves PID without account access',
                'shell block preservation and removal', 'PTY cluster and shell choices'],
            'provider': 'synthetic GitHub', 'relay_transport': 'not exercised'}
        (root / 'guided-report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('PASS: guided installer, PTY choices/cancellation, interrupted resume, repeated service and shell setup', flush=True)
    finally:
        for home in installed:
            cli(home, 'daemon', 'uninstall')
        for home in homes:
            if (home / 'auth/session.json').exists():
                cli(home, 'auth', 'logout')
