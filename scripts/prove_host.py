#!/usr/bin/env python3
"""Opt-in synthetic MCP integration test using an installed, authenticated host.

Creates and resumes one test conversation, using that host's normal model access.
Retains private /tmp proof state and the host-managed test session for inspection.
No production host configuration is edited. Does not test automatic chat binding.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, choices=['codex', 'claude-code'])
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--use-host-config', action='store_true',
                        help='Codex: retain the configured model provider; disable configured MCP servers/plugins for this run')
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    binary = (args.binary or repository / 'target/debug/gent').resolve()
    specification = importlib.util.spec_from_file_location('generic_mcp', repository / 'scripts/smoke_mcp.py')
    generic = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(generic)
    root = Path(tempfile.mkdtemp(prefix='gent-host-', dir='/tmp'))
    state = root / 'state'
    work = root / 'work'
    work.mkdir()
    base = [str(binary), '--home', str(state)]
    print(f'Proof state: {root}', flush=True)

    def cli(*command):
        return json.loads(subprocess.check_output(base + list(command), text=True))

    daemon = None
    peer = None
    daemon_log = (root / 'daemon.log').open('a')

    def start():
        process = subprocess.Popen(base + ['daemon', 'run'], stdout=daemon_log, stderr=daemon_log)
        for _ in range(500):
            if process.poll() is not None:
                raise AssertionError('daemon exited; inspect daemon.log')
            probe = subprocess.run(base + ['daemon', 'status'], capture_output=True)
            if probe.returncode == 0:
                return process
            time.sleep(0.02)
        process.terminate()
        process.wait(timeout=5)
        raise AssertionError('daemon startup timed out')

    def stop():
        if daemon is not None and daemon.poll() is None:
            daemon.send_signal(signal.SIGINT)
            daemon.wait(timeout=5)

    binding = state / 'bindings' / 'host.key'
    launch = base[1:] + ['mcp', 'serve', '--binding', str(binding)]
    session = None

    def turn(prompt, label):
        nonlocal session
        if args.host == 'codex':
            command = ['codex', 'exec', '--json', '--skip-git-repo-check',
                       '--sandbox', 'read-only', '-C', str(work), '--disable', 'shell_tool',
                       '--disable', 'multi_agent', '--disable', 'apps',
                       '-c', 'approval_policy="never"', '-c', 'web_search="disabled"',
                       '-c', 'model_reasoning_effort="low"',
                       '-c', 'mcp_servers.gent.command=' + json.dumps(str(binary)),
                       '-c', 'mcp_servers.gent.args=' + json.dumps(launch),
                       '-c', 'mcp_servers.gent.enabled=true',
                       '-c', 'mcp_servers.gent.required=true',
                       '-c', 'mcp_servers.gent.default_tools_approval_mode="approve"']
            if args.use_host_config:
                import tomllib
                config_dir = Path(os.environ.get('CODEX_HOME', Path.home() / '.codex'))
                config_path = config_dir / 'config.toml'
                config = tomllib.loads(config_path.read_text()) if config_path.exists() else {}
                for table in ('mcp_servers', 'plugins'):
                    for name in config.get(table, {}):
                        if table == 'mcp_servers' and name == 'gent':
                            continue
                        command += ['-c', f'{table}.{json.dumps(name)}.enabled=false']
            else:
                command += ['--ignore-user-config']
            if session:
                command += ['resume', session, '-']
            else:
                command += ['-']
        else:
            command = ['claude', '-p', '--output-format', 'stream-json', '--verbose',
                       '--setting-sources', '', '--strict-mcp-config', '--tools', '',
                       '--disable-slash-commands', '--no-chrome', '--permission-mode', 'dontAsk',
                       '--allowedTools', 'mcp__gent__*', '--max-budget-usd', '1',
                       '--settings', '{"disableAllHooks":true}',
                       '--mcp-config', json.dumps({'mcpServers': {'gent': {'type': 'stdio', 'command': str(binary), 'args': launch}}})]
            if session:
                command += ['--resume', session]
        with (root / f'{label}.jsonl').open('w') as out, (root / f'{label}.stderr').open('w') as err:
            process = subprocess.run(command, input=prompt, text=True, cwd=work, stdout=out, stderr=err, timeout=180)
        assert process.returncode == 0, f'host failed; inspect {label}.stderr and {label}.jsonl'
        events = [json.loads(line) for line in (root / f'{label}.jsonl').read_text().splitlines() if line.strip()]
        for event in events:
            if args.host == 'codex' and event.get('type') == 'thread.started':
                reported = event['thread_id']
            elif args.host == 'claude-code' and event.get('type') == 'system' and event.get('subtype') == 'init':
                reported = event['session_id']
            else:
                continue
            if session:
                assert session == reported, 'resumed a different host conversation'
            session = reported
        assert session, 'host did not report a session ID'
        return events

    try:
        cli('cluster', 'new', 'synthetic-host-proof', '--local')
        daemon = start()
        peer = generic.Client(base + ['mcp', 'serve', '--binding', str(state / 'bindings/peer.key')])
        peer_id = peer.call('gent_register', {'name': 'fixture-sender', 'provider': 'generic-test-client'})[0]['agent']['id']
        turn('This is a synthetic Gent MCP integration test. Use only the Gent MCP tools. '
             f'Call gent_register with name "host-proof" and provider "{args.host}". '
             'Then call gent_identity and gent_agents. Report the agent ID and peer count. Do nothing else.', 'register')
        agents = cli('agents')
        registered = [agent for agent in agents if agent['name'] == 'host-proof']
        assert len(registered) == 1, 'host did not register exactly one agent'
        host_id = registered[0]['id']
        assert host_id != peer_id
        cli('permission', 'allow', peer_id, host_id, '--permission', 'enumerate', 'send')
        cli('permission', 'allow', host_id, peer_id, '--permission', 'enumerate', 'receive')
        marker = 'synthetic-' + uuid.uuid4().hex
        file = {'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': generic.PNG}
        sent = peer.call('gent_send', {'recipient': host_id, 'request_id': str(uuid.uuid4()),
                                     'text': marker, 'files': [file]})[0]
        peer.close()
        peer = None
        stop()
        daemon = start()
        turn('Continue this same Gent test conversation after a daemon restart. Use only Gent tools. '
             'Call gent_identity, then gent_inbox. For the one queued message, acknowledge receipt and '
             'reply using gent_reply with a fresh UUID request_id. In the reply text echo the exact marker '
             'from the message and describe the dominant color of its image. Include that same file in your '
             'reply files array, preserving its name, media_type, and exact data_base64. Do not send a new '
             'unsolicited exchange. Do nothing else.', 'resume')
        peer = generic.Client(base + ['mcp', 'serve', '--binding', str(state / 'bindings/peer.key')])
        inbox = peer.call('gent_inbox')[0]
        assert len(inbox) == 1, 'host did not send exactly one reply'
        reply = inbox[0]
        assert reply['sender'] == host_id and reply['reply_to'] == sent['message_id']
        assert marker in reply['text'], 'reply did not preserve marker'
        assert reply['files'] == [file], 'reply did not preserve file bytes'
        assert any(color in reply['text'].lower() for color in ('magenta', 'purple', 'pink')), 'image color not recognized'
        assert peer.call('gent_message_status', {'message_id': sent['message_id']})[0]['state'] == 'delivered'
        report = {'host': args.host, 'host_session': session, 'agent_id': host_id,
                  'result': 'passed', 'scope': 'explicit per-session binding; local Unix transport',
                  'reply_text': reply['text']}
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'PASS: {args.host} registration, same-session resume, restart inbox, image interpretation, file reply and acknowledgment', flush=True)
    finally:
        if peer:
            peer.close()
        stop()
        daemon_log.close()


if __name__ == '__main__':
    main()
