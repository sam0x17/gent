#!/usr/bin/env python3
"""Opt-in real-host /clear and /resume proof using synthetic conversations.

Uses normal host model access with built-in tools disabled. A transparent stdio
observer records only this proof's MCP traffic. Temporary state is retained.
"""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import uuid


def proxy():
    trace = Path(sys.argv[2])
    process = subprocess.Popen(sys.argv[3:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def pump(source, destination, direction):
        for line in iter(source.readline, b''):
            value = json.loads(line)
            event = {'pid': os.getpid(), 'direction': direction, 'frame': value}
            with trace.open('a') as log:
                fcntl.flock(log, fcntl.LOCK_EX)
                log.write(json.dumps(event) + '\n')
            destination.write(line)
            destination.flush()
        if direction == 'request':
            destination.close()

    outgoing = threading.Thread(target=pump, args=(process.stdout, sys.stdout.buffer, 'response'))
    outgoing.start()
    pump(sys.stdin.buffer, process.stdin, 'request')
    outgoing.join()
    raise SystemExit(process.wait())


class Terminal:
    def __init__(self, command, work, path):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.chdir(work)
            os.execvpe(command[0], command, dict(os.environ, TERM='xterm-256color', DISABLE_AUTOUPDATER='1'))
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 160, 0, 0))
        self.log = path.open('ab')
        self.text = ''
        self.accepted_test_folder = False
        self.trust_ready_at = None
        self.trust_selected_at = None

    def drain(self, seconds=.1):
        if select.select([self.fd], [], [], seconds)[0]:
            try:
                data = os.read(self.fd, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    raise AssertionError('host terminal exited; inspect terminal.raw') from error
                raise
            assert data, 'host terminal exited'
            self.log.write(data)
            self.log.flush()
            # Answer the terminal cursor query without inventing user input.
            if b'\x1b[6n' in data:
                os.write(self.fd, b'\x1b[1;1R')
            self.text += re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', data.decode(errors='replace'))
            if not self.accepted_test_folder and 'Yes,Itrustthisfolder' in re.sub(r'\s+', '', self.text):
                self.accepted_test_folder = True
                # Wait for startup rendering/terminal negotiation to settle.
                self.trust_ready_at = time.monotonic() + 1
        if self.trust_ready_at is not None and time.monotonic() >= self.trust_ready_at:
            os.write(self.fd, b'\x1b[B')
            self.trust_ready_at = None
            self.trust_selected_at = time.monotonic() + 1
        if self.trust_selected_at is not None and time.monotonic() >= self.trust_selected_at:
            os.write(self.fd, b'\r')
            self.trust_selected_at = None

    def send(self, text):
        os.write(self.fd, b'\x1b[200~' + text.encode() + b'\x1b[201~')
        self.drain(.2)
        os.write(self.fd, b'\r')

    def settle(self):
        # Slash-command rendering differs by host/version. Identity assertions
        # below verify the transition, rather than interpreting UI copy.
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            self.drain()

    def close(self):
        def reaped(timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if os.waitpid(self.pid, os.WNOHANG)[0]:
                    return True
                if select.select([self.fd], [], [], .05)[0]:
                    try:
                        data = os.read(self.fd, 65536)
                        self.log.write(data)
                        self.log.flush()
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
            return False
        try:
            if reaped(.1):
                return
            # Let the host close its MCP children before terminating its group.
            self.send('/exit')
            if reaped(5):
                return
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(self.pid, sig)
                except ProcessLookupError:
                    pass
                if reaped(5):
                    return
            raise AssertionError(f'host process {self.pid} did not exit after SIGKILL')
        finally:
            os.close(self.fd)
            self.log.close()


def responses(trace):
    calls, values = {}, []
    if not trace.exists():
        return values
    for line in trace.read_text().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        frame = event['frame']
        key = (event['pid'], frame.get('id'))
        if event['direction'] == 'request' and frame.get('method') == 'tools/call':
            calls[key] = frame['params']
        if event['direction'] == 'response' and key in calls:
            result = frame.get('result', {})
            assert not frame.get('error') and not result.get('isError'), frame
            value = json.loads(result['content'][0]['text'])
            values.append((calls[key], value))
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', choices=['codex', 'claude-code'], required=True)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/gent'))
    parser.add_argument('--host-binary')
    parser.add_argument('--provider-token-auth', action='store_true',
                        help='Codex only: bypass its ChatGPT login gate when the configured provider has its own bearer token')
    args = parser.parse_args()
    if args.provider_token_auth and args.host != 'codex':
        parser.error('--provider-token-auth is only supported for Codex')
    binary = args.binary.resolve()
    root = Path(tempfile.mkdtemp(prefix='gent-interactive-', dir='/tmp')).resolve()
    work, state, installed = root / 'work', root / 'state', root / 'host-config'
    work.mkdir()
    base = [str(binary), '--home', str(state)]
    trace = root / 'mcp.jsonl'
    print(f'Interactive proof state: {root}', flush=True)

    def cli(*command):
        return json.loads(subprocess.check_output(base + list(command), text=True))

    cli('cluster', 'new', 'interactive-proof', '--local')
    cli('integration', 'install', args.host, '--config-dir', str(installed))
    if args.host == 'codex':
        import tomllib
        entry = tomllib.loads((installed / 'config.toml').read_text())['mcp_servers']['gent']
    else:
        entry = json.loads((installed / '.claude.json').read_text())['mcpServers']['gent']
    observed = [str(Path(__file__).resolve()), 'proxy', str(trace), entry['command'], *entry['args']]
    first_session = str(uuid.uuid4()) if args.host == 'claude-code' else None
    host = args.host_binary or ('codex' if args.host == 'codex' else 'claude')
    if args.host == 'codex':
        import tomllib
        config = Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'config.toml'
        current = tomllib.loads(config.read_text()) if config.exists() else {}
        command = [host, '--no-daemon', '--no-alt-screen', '-C', str(work), '-s', 'read-only', '-a', 'never',
                   '--disable', 'shell_tool', '--disable', 'multi_agent', '--disable', 'apps',
                   '-c', 'web_search="disabled"', '-c', 'model_reasoning_effort="low"',
                   '-c', 'check_for_update_on_startup=false',
                   '-c', 'mcp_servers.gent.command=' + json.dumps(sys.executable),
                   '-c', 'mcp_servers.gent.args=' + json.dumps(observed),
                   '-c', 'mcp_servers.gent.enabled=true', '-c', 'mcp_servers.gent.required=true',
                   '-c', 'mcp_servers.gent.default_tools_approval_mode="approve"']
        if args.provider_token_auth:
            provider = current.get('model_provider')
            assert provider and current.get('model_providers', {}).get(provider, {}).get('experimental_bearer_token'), 'configured provider bearer token required'
            assert re.fullmatch(r'[A-Za-z0-9_-]+', provider), 'provider name must be one CLI configuration path segment'
            command += ['-c', f'model_providers.{provider}.requires_openai_auth=false']
        for table in ('mcp_servers', 'plugins'):
            for name in current.get(table, {}):
                if table != 'mcp_servers' or name != 'gent':
                    assert '.' not in name, 'host configuration name cannot contain a dot in this proof'
                    command += ['-c', f'{table}.{name}.enabled=false']
    else:
        observed_entry = dict(entry, command=sys.executable, args=observed)
        command = [host, '--setting-sources', '', '--strict-mcp-config', '--tools', '', '--no-chrome',
                   '--permission-mode', 'dontAsk', '--allowedTools', 'mcp__gent__*',
                   '--session-id', first_session, '--settings', str(installed / 'settings.json'),
                   '--mcp-config', json.dumps({'mcpServers': {'gent': observed_entry}})]
    prefix = 'Synthetic Gent integration proof. Use only Gent MCP tools. '
    first_prompt = prefix + f'Call gent_register with name "interactive-a" and provider "{args.host}". Then call gent_identity and gent_inbox. Your final answer must contain only INTERACTIVE_DONE_A. Do nothing else.'
    terminal, daemon, peer = None, None, None
    log = (root / 'daemon.log').open('a')

    def wait_for(predicate, timeout=150):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            terminal.drain()
            values = responses(trace)
            if predicate(values):
                return values
        raise AssertionError(f'host condition timed out; inspect {root}')

    def finish(marker):
        # Match the assistant response, not the marker echoed in our prompt.
        response = re.compile(r'[•●⏺]\s*' + re.escape(marker))
        def complete(_):
            found = response.search(terminal.text)
            return found and (args.host != 'codex' or 'state=done:app=codex' in terminal.text[found.end():])
        wait_for(complete)
        # Let the final text finish rendering before sending a slash command.
        end = time.monotonic() + 1
        while time.monotonic() < end:
            terminal.drain()
        terminal.text = ''

    try:
        daemon = subprocess.Popen(base + ['daemon', 'run'], stdout=log, stderr=log)
        for _ in range(200):
            if subprocess.run(base + ['daemon', 'status'], capture_output=True).returncode == 0:
                break
            assert daemon.poll() is None
            time.sleep(.05)
        from smoke_mcp import Client, PNG
        peer = Client(base + ['mcp', 'serve', '--binding', str(state / 'peer.key')])
        peer_id = peer.call('gent_register', {'name': 'fixture-peer', 'provider': 'generic'})[0]['agent']['id']
        terminal = Terminal(command, work, root / 'terminal.raw')
        # Interactive hosts can begin an initial prompt before MCP discovery
        # finishes. Wait for the actual tool list, then submit the first turn.
        def discovered(_):
            if not trace.exists():
                return False
            for line in trace.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event['direction'] == 'response' and event['frame'].get('result', {}).get('tools'):
                    return True
            return False
        wait_for(discovered)
        terminal.settle()
        terminal.send(first_prompt)
        first = wait_for(lambda v: any(c['name'] == 'gent_inbox' for c, _ in v))
        first_call, registration = next((c,v) for c,v in first if c['name'] == 'gent_register')
        a = registration['agent']['id']
        assert [v for c,v in first if c['name'] == 'gent_identity'][-1]['agent']['id'] == a
        assert [v for c,v in first if c['name'] == 'gent_inbox'][-1] == []
        if args.host == 'codex':
            first_session = first_call['_meta']['threadId']
        finish('INTERACTIVE_DONE_A')
        cli('permission', 'allow', peer_id, a, '--permission', 'enumerate', 'send')
        cli('permission', 'allow', a, peer_id, '--permission', 'enumerate', 'receive')
        file = {'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': PNG}
        sent = peer.call('gent_send', {'recipient': a, 'request_id': str(uuid.uuid4()), 'text': 'parent-only-interactive', 'files': [file]})[0]
        terminal.send('/clear')
        terminal.settle()
        terminal.text = ''
        terminal.send(prefix + f'Call gent_register with name "interactive-b" and provider "{args.host}". Then call gent_identity, gent_agents and gent_inbox. Your final answer must contain only INTERACTIVE_DONE_B. Do nothing else.')
        second = wait_for(lambda v: sum(c['name'] == 'gent_inbox' for c, _ in v) >= 2)
        b = [v['agent']['id'] for c,v in second if c['name'] == 'gent_register'][-1]
        assert b not in [a, peer_id]
        assert [v for c,v in second if c['name'] == 'gent_identity'][-1]['agent']['id'] == b
        assert [v for c,v in second if c['name'] == 'gent_inbox'][-1] == []
        assert [v for c,v in second if c['name'] == 'gent_agents'][-1] == []
        finish('INTERACTIVE_DONE_B')
        terminal.send('/resume ' + first_session)
        terminal.settle()
        terminal.text = ''
        terminal.send(prefix + 'Call gent_identity then gent_inbox. Acknowledge the one pending message using gent_ack. Your final answer must contain only INTERACTIVE_DONE_RESUME. Do nothing else.')
        resumed = wait_for(lambda v: any(c['name'] == 'gent_ack' for c, _ in v))
        assert [v for c,v in resumed if c['name'] == 'gent_identity'][-1]['agent']['id'] == a
        inbox = [v for c,v in resumed if c['name'] == 'gent_inbox'][-1]
        assert len(inbox) == 1 and inbox[0]['id'] == sent['message_id'] and inbox[0]['files'] == [file]
        assert peer.call('gent_message_status', {'message_id': sent['message_id']})[0]['state'] == 'delivered'
        finish('INTERACTIVE_DONE_RESUME')
        report = {'host':args.host,'result':'passed','initial_session':first_session,'first_agent':a,'cleared_agent':b,'host_pid':terminal.pid}
    finally:
        try:
            if terminal:
                terminal.close()
        finally:
            try:
                if peer:
                    peer.close()
            finally:
                if daemon and daemon.poll() is None:
                    daemon.terminate()
                    daemon.wait(timeout=10)
                log.close()
    (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: interactive /clear isolation and in-process /resume restores identity, queued image, and receipt', flush=True)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'proxy':
        proxy()
    main()
