#!/usr/bin/env python3
"""Opt-in real-host /clear and /resume proof using synthetic conversations.

Uses normal host model access with built-in tools disabled. A transparent stdio
observer records only this proof's MCP traffic. Temporary state is retained.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid


from host_terminal import Terminal
from mcp_trace import proxy, responses


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
        return json.loads(subprocess.check_output(base + ['--json', *command], text=True))

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
        sent = peer.call('gent_send', {'recipient': a, 'request_id': peer.request_id(), 'text': 'parent-only-interactive', 'files': [file]})[0]
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
        raise SystemExit(proxy(sys.argv[3:], Path(sys.argv[2])))
    main()
