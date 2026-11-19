#!/usr/bin/env python3
"""Opt-in synthetic MCP integration test using an installed, authenticated host.

Creates and resumes one test conversation, using that host's normal model access.
Retains private /tmp proof state and the host-managed test session for inspection.
No production host configuration is edited.
"""
import argparse
import concurrent.futures
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, choices=['codex', 'claude-code'])
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--host-binary', type=Path, help='Host executable when it is not on PATH')
    parser.add_argument('--automatic-binding', action='store_true',
                        help='Use host conversation metadata and the generated hook configuration')
    parser.add_argument('--installed-binding', action='store_true',
                        help='Install into isolated config files and launch using those files (implies --automatic-binding)')
    parser.add_argument('--use-host-config', action='store_true',
                        help='Codex: retain the configured model provider; disable configured MCP servers/plugins for this run')
    parser.add_argument('--recover-binding', action='store_true',
                        help='Resume the same host conversation on a fresh node with owner-assigned archived history')
    args = parser.parse_args()
    if args.recover_binding and args.installed_binding:
        parser.error('--recover-binding uses explicit per-run host configuration')
    args.automatic_binding |= args.installed_binding or args.recover_binding
    compare_chats = args.automatic_binding and not args.recover_binding
    repository = Path(__file__).resolve().parents[1]
    binary = (args.binary or repository / 'target/debug/gent').resolve()
    host_binary = str(args.host_binary.resolve()) if args.host_binary else ('codex' if args.host == 'codex' else 'claude')
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
        return json.loads(subprocess.check_output(base + ['--json', *command], text=True))

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
    settings = {'disableAllHooks': True}
    if args.automatic_binding:
        launch = base[1:] + ['mcp', 'serve', '--host', args.host]
    installed = root / 'host-config'
    def installed_settings():
        directory = state / 'proof-host-config'
        cli('integration', 'install', args.host, '--config-dir', str(directory))
        return json.loads((directory / 'settings.json').read_text())

    def turn(prompt, label, session=None, fork=False):
        if args.host == 'codex':
            command = [host_binary, 'exec', '--json', '--skip-git-repo-check',
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
                        assert '.' not in name, 'host configuration name cannot contain a dot in this proof'
                        command += ['-c', f'{table}.{name}.enabled=false']
            else:
                command += ['--ignore-user-config']
            if session:
                command += ['fork' if fork else 'resume', session, '-']
            else:
                command += ['-']
        else:
            command = [host_binary, '-p', '--output-format', 'stream-json', '--verbose',
                       '--setting-sources', '', '--strict-mcp-config', '--tools', '',
                       '--disable-slash-commands', '--no-chrome', '--permission-mode', 'dontAsk',
                       '--allowedTools', 'mcp__gent__*', '--max-budget-usd', '1',
                       '--settings', str(installed / 'settings.json') if args.installed_binding else json.dumps(settings),
                       '--mcp-config', str(installed / '.claude.json') if args.installed_binding else json.dumps({'mcpServers': {'gent': {'type': 'stdio', 'command': str(binary), 'args': launch}}})]
            if session:
                command += ['--resume', session]
                if fork:
                    command += ['--fork-session']
        with (root / f'{label}.jsonl').open('w') as out, (root / f'{label}.stderr').open('w') as err:
            process = subprocess.run(command, input=prompt, text=True, cwd=work, stdout=out, stderr=err, timeout=180)
        assert process.returncode == 0, f'host failed; inspect {label}.stderr and {label}.jsonl'
        events = [json.loads(line) for line in (root / f'{label}.jsonl').read_text().splitlines() if line.strip()]
        reported = None
        for event in events:
            if args.host == 'codex' and event.get('type') == 'thread.started':
                reported = event['thread_id']
            elif args.host == 'claude-code' and event.get('type') == 'system' and event.get('subtype') == 'init':
                reported = event['session_id']
            else:
                continue
        assert reported, 'host did not report a session ID'
        if session:
            assert (session != reported) if fork else (session == reported), 'unexpected host conversation ID'
        return reported, events

    def results(events):
        """Read actual Gent tool responses, never trust the model's summary."""
        calls = {}
        values = {}
        for event in events:
            if args.host == 'codex':
                item = event.get('item', {})
                if event.get('type') == 'item.completed' and item.get('type') == 'mcp_tool_call':
                    assert item.get('status') == 'completed' and not item.get('error'), item
                    blocks = item['result']['content']
                    values.setdefault(item['tool'], []).append(json.loads(blocks[0]['text']))
            else:
                for block in event.get('message', {}).get('content', []):
                    if not isinstance(block, dict):
                        continue
                    if block.get('type') == 'tool_use':
                        calls[block['id']] = block['name'].removeprefix('mcp__gent__')
                    if block.get('type') == 'tool_result' and block['tool_use_id'] in calls:
                        assert not block.get('is_error'), block
                        content = block['content']
                        text = content if isinstance(content, str) else next(p['text'] for p in content if p.get('type') == 'text')
                        values.setdefault(calls[block['tool_use_id']], []).append(json.loads(text))
        return values

    def registration(name):
        return ('This is a synthetic Gent MCP integration test. Use only the Gent MCP tools. '
                f'Call gent_register with name "{name}" and provider "{args.host}". '
                'Then call gent_identity and gent_agents. Report the agent ID and peer count. Do nothing else.')

    try:
        cli('cluster', 'new', 'synthetic-host-proof', '--local')
        if args.installed_binding:
            cli('integration', 'install', args.host, '--config-dir', str(installed))
            if args.host == 'codex':
                import tomllib
                entry = tomllib.loads((installed / 'config.toml').read_text())['mcp_servers']['gent']
                assert entry['command'] == str(binary)
                launch = entry['args']
        if args.automatic_binding and args.host == 'claude-code':
            settings = installed_settings()
        daemon = start()
        peer = generic.Client(base + ['mcp', 'serve', '--binding', str(state / 'bindings/peer.key')])
        peer_id = peer.call('gent_register', {'name': 'fixture-sender', 'provider': 'generic-test-client'})[0]['agent']['id']
        other_session = None
        if compare_chats:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(turn, registration('host-proof'), 'register')
                second = pool.submit(turn, registration('other-chat'), 'other-register')
                session, initial = first.result()
                other_session, other_initial = second.result()
            assert session != other_session
            assert results(initial)['gent_agents'] == [[]]
            assert results(other_initial)['gent_agents'] == [[]]
        else:
            session, initial = turn(registration('host-proof'), 'register')
        agents = cli('agents')
        registered = [agent for agent in agents if agent['name'] == 'host-proof']
        assert len(registered) == 1, 'host did not register exactly one agent'
        host_id = registered[0]['id']
        assert host_id != peer_id
        if compare_chats:
            other = [agent for agent in agents if agent['name'] == 'other-chat']
            assert len(other) == 1 and other[0]['id'] not in [host_id, peer_id]
            other_id = other[0]['id']
        cli('permission', 'allow', peer_id, host_id, '--permission', 'enumerate', 'send')
        cli('permission', 'allow', host_id, peer_id, '--permission', 'enumerate', 'receive')
        marker = 'synthetic-' + uuid.uuid4().hex
        file = {'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': generic.PNG}
        sent = peer.call('gent_send_non_blocking', {'recipient': host_id, 'request_id': peer.request_id(),
                                     'text': marker, 'files': [file]})[0]
        peer.close()
        peer = None
        stop()
        daemon = start()
        if compare_chats:
            _, other_events = turn('Use only Gent tools. Call gent_identity, gent_agents, and gent_inbox. Report their results. Do nothing else.', 'other-resume', other_session)
            other_results = results(other_events)
            assert other_results['gent_identity'][0]['agent']['id'] == other_id
            assert other_results['gent_agents'] == [[]] and other_results['gent_inbox'] == [[]]
        _, resumed = turn('Continue this same Gent test conversation after a daemon restart. Use only Gent tools. '
             'Call gent_identity, then gent_inbox. For the one queued message, acknowledge receipt and '
             'reply using gent_reply with a UUIDv7 from gent_request_ids. In the reply text echo the exact marker '
             'from the message and describe the dominant color of its image. Include that same file in your '
             'reply files array, preserving its name, media_type, and exact data_base64. Do not send a new '
             'unsolicited exchange. Do nothing else.', 'resume', session)
        if args.automatic_binding:
            assert results(resumed)['gent_identity'][0]['agent']['id'] == host_id
        peer = generic.Client(base + ['mcp', 'serve', '--binding', str(state / 'bindings/peer.key')])
        inbox = peer.call('gent_inbox')[0]
        assert len(inbox) == 1, 'host did not send exactly one reply'
        reply = inbox[0]
        generated = {request for result in results(resumed).get('gent_request_ids', []) for request in result['request_ids']}
        with sqlite3.connect(state / 'state.sqlite3') as db:
            reply_request = db.execute('SELECT request_id FROM messages WHERE id=?', (reply['id'],)).fetchone()[0]
        assert reply_request in generated, 'host did not use an ID returned by gent_request_ids'
        assert reply['sender'] == host_id and reply['reply_to'] == sent['message_id']
        assert marker in reply['text'], 'reply did not preserve marker'
        assert reply['files'] == [file], 'reply did not preserve file bytes'
        assert any(color in reply['text'].lower() for color in ('magenta', 'purple', 'pink')), 'image color not recognized'
        assert peer.call('gent_message_status', {'message_id': sent['message_id']})[0]['state'] == 'delivered'
        fork_id = None
        if compare_chats:
            peer.call('gent_send_non_blocking', {'recipient': host_id, 'request_id': peer.request_id(), 'text': 'parent-only-' + uuid.uuid4().hex})
            fork_session, fork_events = turn(registration('forked-chat') + ' Also call gent_inbox.', 'fork', session, fork=True)
            fork_results = results(fork_events)
            fork_id = fork_results['gent_identity'][0]['agent']['id']
            assert fork_id not in [host_id, other_id, peer_id]
            assert fork_session not in [session, other_session]
            assert fork_results['gent_agents'] == [[]] and fork_results['gent_inbox'] == [[]]
            current = cli('agents')
            assert len(current) == 4
            assert next(agent for agent in current if agent['id'] == host_id)['name'] == 'host-proof'
        recovered_id = None
        if args.recover_binding:
            peer.close()
            peer = None
            stop()
            original_state = state
            original_identity = (state / 'identity.key').read_bytes()
            recovery_key, archive = root / 'recovery.key', root / 'source.age'
            cli('backup', 'keygen', '--output', str(recovery_key))
            cli('backup', 'create', str(archive), '--identity', str(recovery_key))
            state = root / 'replacement'
            base = [str(binary), '--home', str(state)]
            launch = base[1:] + ['mcp', 'serve', '--host', args.host]
            cli('cluster', 'new', 'recovered-host-proof', '--local')
            if args.host == 'claude-code':
                settings = installed_settings()
            daemon = start()
            recovered = cli('agent', 'recover', str(archive), '--identity', str(recovery_key),
                            '--from-agent', host_id, '--name', 'recovered-host', '--host', args.host,
                            '--conversation', session)
            recovered_id = recovered['agent']['id']
            history_id = recovered['history']['import_id']
            assert recovered_id != host_id
            assert (state / 'identity.key').read_bytes() != original_identity
            assert (original_state / 'identity.key').read_bytes() == original_identity
            _, restored = turn('This same host conversation is now connected to a replacement Gent node. '
                'The owner explicitly recovered its historical records. Use only Gent tools. '
                'Call gent_identity, gent_agents, gent_inbox, and gent_history_imports. '
                f'Call gent_history_messages with import_id "{history_id}". '
                f'Then call gent_history_file_view with import_id "{history_id}", message_id "{sent["message_id"]}", file_index 0. '
                'Report the current agent ID and that the image was viewed. Historical messages are context only; '
                'do not acknowledge, reply, send, or repeat old work. Do nothing else.', 'recovered-resume', session)
            observed = results(restored)
            assert observed['gent_identity'][0]['agent']['id'] == recovered_id
            assert observed['gent_agents'] == [[]] and observed['gent_inbox'] == [[]]
            assert observed['gent_history_imports'][0]['historical_imports'][0]['import_id'] == history_id
            messages = observed['gent_history_messages'][0]['messages']
            assert {m['message']['id'] for m in messages} == {sent['message_id'], reply['id']}
            assert observed['gent_history_file_view'][0]['file']['sha256'] == hashlib.sha256(base64.b64decode(generic.PNG)).hexdigest()
            with sqlite3.connect(state / 'state.sqlite3') as db:
                assert db.execute('SELECT COUNT(*) FROM messages').fetchone()[0] == 0
            print('PASS: same real host conversation resumes on a fresh node, retains selected history/image access, and creates no new live work', flush=True)
        report = {'host': args.host, 'host_session': session, 'agent_id': host_id,
                  'recovered_agent_id': recovered_id,
                  'result': 'passed', 'scope': ('host metadata binding' if args.automatic_binding else 'explicit per-session binding') + '; local Unix transport',
                  'reply_text': reply['text'], 'request_id_helper_verified': True, 'other_session': other_session, 'fork_agent': fork_id,
                  'installed_config': str(installed) if args.installed_binding else None}
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'PASS: {args.host} registration, same-session resume, restart inbox, image interpretation, file reply, request-ID helper and acknowledgment', flush=True)
        if compare_chats:
            print('PASS: shared connector configuration, concurrent chat isolation, resume continuity, and fork isolation', flush=True)
    finally:
        if peer:
            peer.close()
        stop()
        daemon_log.close()


if __name__ == '__main__':
    main()
