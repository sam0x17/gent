#!/usr/bin/env python3
"""Opt-in service lifecycle proof against the real user's systemd or launchd.

Creates one isolated service and synthetic MCP agents, then removes the service.
Retains its temporary directory if cleanup fails. Requires Python 3.9+.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from mcp_client import Client
from mcp_fixtures import PNG


def wait(check):
    end = time.monotonic() + 30
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.15)
    raise AssertionError('service did not reach expected state')


def main():
    source = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gent').resolve()
    folder = Path(tempfile.mkdtemp(prefix='gent-svc-', dir='/tmp'))
    binary = folder / 'gent "${HOME}%h&'
    shutil.copy2(source, binary)
    home = folder / 'node \'"${USER}%h&<xml>'
    command = [str(binary), '--home', str(home), '--json']
    clients = []
    service_file = service_bytes = unrelated = foreground = None

    def call(*args, expected=0):
        result = subprocess.run(command + list(args), check=False, capture_output=True, text=True, timeout=60)
        if result.returncode != expected:
            raise AssertionError(f'{args}: exit {result.returncode}: {result.stderr}')
        return json.loads(result.stdout) if result.stdout else None

    def status():
        result = subprocess.run(command + ['daemon', 'status'], check=False, capture_output=True, text=True, timeout=30)
        assert result.returncode in (0, 3), result.stderr
        return json.loads(result.stdout)

    def doctor(expected=0):
        value = call('doctor', '--codex-config-dir', str(folder / 'codex'),
                     '--claude-config-dir', str(folder / 'claude'),
                     '--shell', 'zsh', '--rc-file', str(folder / 'zshrc'), expected=expected)
        return {check['id']: check for check in value['checks']}

    try:
        before = call('daemon', 'status', expected=3)
        assert not before['service']['installed'] and not home.exists()
        call('daemon', 'install', expected=1)
        assert not home.exists()
        installed = call('daemon', 'install', '--local', 'service-proof')
        assert installed['daemon']['managed'] and installed['service']['enabled']
        diagnosed = doctor()
        assert diagnosed['daemon']['status'] == diagnosed['service']['status'] == 'pass'
        assert diagnosed['service']['evidence']['pid'] == installed['daemon']['pid']
        service_file = Path(installed['service']['file'])
        service_bytes = service_file.read_bytes()
        unrelated = service_file.with_name(service_file.name + '.proof-unrelated')
        with unrelated.open('x') as f:
            f.write('preserve unrelated configuration\n')
        assert service_file.stat().st_mode & 0o077 == 0
        identity = (home / 'identity.key').read_bytes()
        credential = (home / 'owner.key').read_text()
        config = call('config')
        pid = installed['daemon']['pid']
        assert call('daemon', 'install')['daemon']['pid'] == pid
        assert call('daemon', 'start')['daemon']['pid'] == pid

        for name in ['sender', 'recipient']:
            clients.append(Client(command + ['mcp', 'serve', '--binding', str(home / f'{name}.key')]))
        a, b = clients
        aid = a.call('gent_register', {'name': 'service-sender', 'provider': 'generic-mcp'})[0]['agent']['id']
        bid = b.call('gent_register', {'name': 'service-recipient', 'provider': 'generic-mcp'})[0]['agent']['id']
        call('permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
        call('permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
        sent = a.call('gent_send_non_blocking', {'recipient': bid, 'request_id': a.request_id(), 'text': 'survive service lifecycle', 'files': [{'name': 'image.png', 'media_type': 'image/png', 'data_base64': PNG}]})[0]
        assert not call('daemon', 'stop')['daemon']['running']
        assert not (home / 'daemon.sock').exists()
        call('daemon', 'status', expected=3)
        diagnosed = doctor(expected=3)
        assert diagnosed['daemon']['status'] == 'fail' and diagnosed['service']['status'] == 'warn'
        assert not call('daemon', 'stop')['daemon']['running']
        started = call('daemon', 'start')
        assert started['daemon']['managed'] and started['daemon']['pid'] != pid
        restarted = call('daemon', 'restart')
        assert restarted['daemon']['pid'] != started['daemon']['pid']
        os.kill(restarted['daemon']['pid'], signal.SIGKILL)
        wait(lambda: (s := status())['daemon']['managed'] and s['daemon']['pid'] != restarted['daemon']['pid'])
        inbox, raw = b.call('gent_inbox')
        assert len(inbox) == 1 and inbox[0]['id'] == sent['message_id']
        assert inbox[0]['files'][0]['data_base64'] == PNG
        assert any(part['type'] == 'image' and part['data'] == PNG for part in raw['content'])
        logs = call('daemon', 'logs', '--lines', '20')
        assert any('Gent daemon listening' in line for line in logs['lines'])
        assert credential not in '\n'.join(logs['lines'])

        try:
            service_file.write_bytes(service_bytes + b'\n')
            call('daemon', 'install', expected=1)
            call('daemon', 'uninstall', expected=1)
            assert service_file.read_bytes() == service_bytes + b'\n'
            assert doctor(expected=3)['service']['status'] == 'warn'
            assert service_file.read_bytes() == service_bytes + b'\n'
        finally:
            service_file.write_bytes(service_bytes)
        backup = service_file.with_name(service_file.name + '.proof-backup')
        service_file.rename(backup)
        try:
            service_file.symlink_to(backup)
            call('daemon', 'install', expected=1)
            assert backup.read_bytes() == service_bytes
        finally:
            service_file.unlink()
            backup.rename(service_file)
        removed = call('daemon', 'uninstall')
        assert not removed['daemon']['running'] and not removed['service']['installed']
        assert not service_file.exists() and (home / 'state.sqlite3').exists()
        call('daemon', 'uninstall')
        assert unrelated.read_text() == 'preserve unrelated configuration\n'

        # An external foreground process must not be mistaken for this service.
        with (folder / 'foreground.log').open('w') as log:
            foreground = subprocess.Popen(command + ['daemon', 'run'], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        wait(lambda: status()['daemon']['running'])
        assert not status()['daemon']['managed']
        assert doctor()['service']['status'] == 'skip'
        call('daemon', 'install', expected=1)
        assert not service_file.exists()
        foreground.send_signal(signal.SIGTERM)
        assert foreground.wait(timeout=10) == 0
        foreground = None
        assert not (home / 'daemon.sock').exists()
        assert call('daemon', 'install')['daemon']['managed']
        assert b.call('gent_inbox')[0][0]['id'] == sent['message_id']
        assert (home / 'identity.key').read_bytes() == identity
        assert (home / 'owner.key').read_text() == credential
        current = call('config')
        assert current['node']['id'] == config['node']['id'] and current['cluster']['id'] == config['cluster']['id']
        call('daemon', 'uninstall')
        print(f"PASS: {installed['service']['backend']} install/reinstall/start/stop/restart/uninstall, crash recovery, literal paths, file protection, foreground ownership, doctor status, and durable MCP image")
    finally:
        for client in clients:
            client.close()
        if foreground and foreground.poll() is None:
            foreground.send_signal(signal.SIGTERM)
            foreground.wait(timeout=10)
        cleanup = subprocess.run(command + ['daemon', 'uninstall'], check=False, capture_output=True, text=True, timeout=60)
        if cleanup.returncode:
            raise RuntimeError(f'service cleanup failed; retained {folder}: {cleanup.stderr}')
        if unrelated:
            unrelated.unlink(missing_ok=True)
        shutil.rmtree(folder)


if __name__ == '__main__':
    main()
