#!/usr/bin/env python3
"""Opt-in real Codex/Claude child-agent binding proof using synthetic state.

Uses normal host model access. Private proof state and host sessions are retained.
No production host settings are edited. MCP calls are observed, never simulated.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid

from smoke_mcp import Client, PNG


def hook(root):
    event = json.load(sys.stdin)
    with (root / 'hooks.jsonl').open('a') as log:
        fcntl.flock(log, fcntl.LOCK_EX)
        log.write(json.dumps({k: event.get(k) for k in (
            'hook_event_name', 'session_id', 'agent_id', 'agent_type', 'tool_use_id', 'tool_name', 'tool_input')}) + '\n')
    if event.get('hook_event_name') == 'PreToolUse' and event.get('tool_name', '').startswith('mcp__gent__'):
        proof = json.loads((root / 'proof.json').read_text())
        result = subprocess.run([proof['binary'], '--home', str(root / 'state'), 'integration', 'hook', 'claude-code'],
                                input=json.dumps(event), text=True, capture_output=True, timeout=15)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode
    print('{}')
    return 0


def calls(root, strict=False):
    hooks = {}
    if (root / 'hooks.jsonl').exists():
        for line in (root / 'hooks.jsonl').read_text().splitlines():
            event = json.loads(line)
            if event.get('tool_use_id'):
                assert event['tool_use_id'] not in hooks, 'duplicate hook identity'
                hooks[event['tool_use_id']] = event
    pending, result = {}, []
    if not (root / 'mcp.jsonl').exists():
        return result
    for line in (root / 'mcp.jsonl').read_text().splitlines():
        event = json.loads(line)
        frame = event['frame']
        key = (event['pid'], frame.get('id'))
        if event['direction'] == 'request' and frame.get('method') == 'tools/call':
            assert key not in pending, 'duplicate outstanding MCP request'
            pending[key] = frame['params']
        elif event['direction'] == 'response' and key in pending:
            request = pending.pop(key)
            meta = request.get('_meta', {})
            if 'threadId' in meta:
                scope = meta['threadId']
            else:
                event = hooks[meta['claudecode/toolUseId']]
                assert event['tool_name'] == 'mcp__gent__' + request['name']
                assert event['tool_input'] == request.get('arguments', {})
                scope = json.dumps([event['session_id'], event['agent_id']], separators=(',', ':'))
            response = frame.get('result', {})
            error = frame.get('error') or (response if response.get('isError') else None)
            value = None if error else json.loads(response['content'][0]['text'])
            result.append({'scope': scope, 'tool': request['name'], 'args': request.get('arguments', {}),
                           'value': value, 'error': error})
    if strict:
        assert not pending, 'unfinished MCP calls'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', choices=['codex', 'claude-code'], required=True)
    parser.add_argument('--binary', type=Path, default=Path('target/debug/gent'))
    parser.add_argument('--host-binary')
    parser.add_argument('--register-only', action='store_true', help='Inspect first-turn host capabilities before continuing')
    parser.add_argument('--audit-only', action='store_true', help='Audit a completed --root without starting a host or daemon')
    parser.add_argument('--root', type=Path, help='Continue this script\'s existing synthetic proof after its last completed phase')
    args = parser.parse_args()
    root = args.root.resolve() if args.root else Path(tempfile.mkdtemp(prefix='gent-subagent-', dir='/tmp')).resolve()
    root.chmod(0o700)
    work, home = root / 'work', root / 'state'
    work.mkdir(exist_ok=True)
    script = Path(__file__).resolve()
    binary = str(args.binary.resolve())
    host = args.host_binary or ('codex' if args.host == 'codex' else 'claude')
    proof = json.loads((root / 'proof.json').read_text()) if args.root else {
        'host': args.host, 'binary': binary, 'host_binary': host, 'phase': 0,
    }
    assert proof['host'] == args.host and proof['binary'] == binary
    host = args.host_binary or proof['host_binary']
    if args.audit_only:
        assert args.root and proof['phase'] == 4, '--audit-only requires a completed proof'
        from subagent_model_checks import audit
        print(json.dumps(audit(root, proof, calls(root, strict=True)), indent=2))
        return
    if 'host_version' not in proof:
        proof['host_version'] = subprocess.check_output([host, '--version'], text=True, timeout=15).strip()
    base = [binary, '--home', str(home), '--json']
    print(f'Proof state: {root}', flush=True)

    def save():
        (root / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')

    def cli(*command):
        return json.loads(subprocess.check_output(base + list(command), text=True, timeout=30))

    def start():
        process = subprocess.Popen(base + ['daemon', 'run'], stdout=daemon_log, stderr=daemon_log)
        deadline = time.monotonic() + 15
        while subprocess.run(base + ['daemon', 'status'], capture_output=True).returncode:
            assert process.poll() is None and time.monotonic() < deadline, 'daemon startup failed'
            time.sleep(.05)
        return process

    def stop():
        if daemon and daemon.poll() is None:
            daemon.send_signal(signal.SIGINT)
            assert daemon.wait(timeout=10) == 0

    if not args.root:
        cli('cluster', 'new', 'subagent-proof', '--local')
    save()
    observed = [str(script.with_name('prove_interactive.py')), 'proxy', str(root / 'mcp.jsonl'),
                binary, '--home', str(home), 'mcp', 'serve', '--host', args.host]
    settings = {}
    if args.host == 'claude-code':
        directory = home / 'proof-host-config'
        cli('integration', 'install', args.host, '--config-dir', str(directory))
        settings = json.loads((directory / 'settings.json').read_text())
    observer = shlex.join([sys.executable, str(script), 'hook', str(root)])
    if args.host == 'claude-code':
        settings['hooks']['PreToolUse'][0]['hooks'][0]['command'] = observer
        for event in ('SubagentStart', 'SubagentStop'):
            settings['hooks'][event] = [{'hooks': [{'type': 'command', 'command': observer, 'timeout': 15}]}]
    daemon, peer = None, None
    daemon_log = (root / 'daemon.log').open('a')

    def turn(prompt, label):
        assert not (root / f'{label}.jsonl').exists(), 'preserve failed evidence; start a fresh proof instead of replaying a partial turn'
        before = len(calls(root))
        if args.host == 'codex':
            current_path = Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'config.toml'
            current = tomllib.loads(current_path.read_text()) if current_path.exists() else {}
            command = [host, 'exec', '--json', '--skip-git-repo-check', '-C', str(work), '--sandbox', 'read-only',
                       '--disable', 'shell_tool', '--enable', 'multi_agent', '--disable', 'apps',
                       '-c', 'approval_policy="never"', '-c', 'web_search="disabled"',
                       '-c', 'model_reasoning_effort="medium"', '-c', 'agents.max_threads=3', '-c', 'agents.max_depth=1',
                       '-c', 'mcp_servers.gent.command=' + json.dumps(sys.executable),
                       '-c', 'mcp_servers.gent.args=' + json.dumps(observed),
                       '-c', 'mcp_servers.gent.enabled=true', '-c', 'mcp_servers.gent.required=true',
                       '-c', 'mcp_servers.gent.default_tools_approval_mode="approve"']
            for table in ('mcp_servers', 'plugins'):
                for name in current.get(table, {}):
                    if table == 'mcp_servers' and name == 'gent':
                        continue
                    assert '.' not in name, 'host configuration names with dots are unsupported'
                    command += ['-c', f'{table}.{name}.enabled=false']
            command += ['resume', proof['session'], '-'] if proof.get('session') else ['-']
        else:
            worker = {'description': 'Synthetic Gent child-agent isolation test worker',
                      'prompt': 'Use only Gent MCP tools for the exact test steps requested. Never spawn agents or use other tools.',
                      'tools': ['mcp__gent__*'], 'model': 'inherit'}
            command = [host, '-p', '--output-format', 'stream-json', '--verbose', '--setting-sources', '',
                       '--strict-mcp-config', '--tools', 'Agent,SendMessage,TaskOutput,TaskStop',
                       '--disable-slash-commands', '--no-chrome', '--permission-mode', 'dontAsk',
                       '--allowedTools', 'mcp__gent__*', 'Agent', 'SendMessage', 'TaskOutput', 'TaskStop',
                       '--max-budget-usd', '2', '--effort', 'low', '--agents', json.dumps({'gent-worker': worker}),
                       '--settings', json.dumps(settings),
                       '--mcp-config', json.dumps({'mcpServers': {'gent': {'type': 'stdio', 'command': sys.executable, 'args': observed}}})]
            if proof.get('session'):
                command += ['--resume', proof['session']]
        with (root / f'{label}.jsonl').open('x') as out, (root / f'{label}.stderr').open('x') as err:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err, text=True, cwd=work, start_new_session=True)
            try:
                process.communicate(prompt, timeout=300)
            except BaseException:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=10)
                raise
        assert process.returncode == 0, f'host failed; inspect {label}.stderr/jsonl in {root}'
        events = [json.loads(line) for line in (root / f'{label}.jsonl').read_text().splitlines() if line.strip()]
        sessions = [e['thread_id'] for e in events if e.get('type') == 'thread.started'] if args.host == 'codex' else [
            e['session_id'] for e in events if e.get('type') == 'system' and e.get('subtype') == 'init']
        assert len(set(sessions)) == 1, 'missing/ambiguous parent session'
        if proof.get('session'):
            assert sessions[0] == proof['session']
        proof['session'] = sessions[0]
        save()
        observed_calls = calls(root)[before:]
        (root / f'{label}-calls.json').write_text(json.dumps(observed_calls, indent=2) + '\n')
        return observed_calls

    prefix = ('Synthetic Gent MCP integration proof. Use only Gent MCP tools and native child-agent lifecycle tools. '
              'Never use filesystem, shell, web, or other tools. Wait for both child tasks to complete before finishing. '
              'Start or resume BOTH children before doing your own Gent work. Use the native agent wait tool for children; '
              'a code-mode cell wait only works with an actual running cell ID from exec. ')
    worker_type = 'gent-worker' if args.host == 'claude-code' else 'default'
    try:
        daemon = start()
        peer = Client([binary, '--home', str(home), 'mcp', 'serve', '--binding', str(home / 'peer.key')])
        peer_id = peer.call('gent_register', {'name': 'fixture-peer', 'provider': 'generic'})[0]['agent']['id']
        if proof['phase'] == 0:
            observed_calls = turn(prefix + f'You are the parent. Call gent_register(name="parent",provider="{args.host}"), then gent_identity and gent_agents. '
                f'Use your native agent-spawning tool to create exactly two real child agents of type {worker_type}: child-a and child-b. '
                f'Give each this task: Call gent_register with your assigned name and provider="{args.host}", then gent_identity, gent_agents and gent_inbox. '
                'Return only your Gent agent ID and whether directory/inbox are empty. Do not call their Gent tools on their behalf. '
                'Remember both native child IDs for later resumption. After both finish, call your own gent_identity again. '
                'Report the two native child IDs and all three Gent IDs. Do not create any other agents.', 'register')
            assert not [c for c in observed_calls if c['error']], 'registration tool failure'
            ids, scopes = {}, {}
            for c in observed_calls:
                if c['tool'] == 'gent_register':
                    name = c['args']['name']
                    assert name in ('parent', 'child-a', 'child-b')
                    ids[name] = c['value']['agent']['id']
                    scopes[name] = c['scope']
            assert len(set(ids.values())) == len(set(scopes.values())) == 3, 'parent/child bindings collapsed or child did not run'
            assert len(cli('agents')) == 4, 'unexpected registrations'
            for name, scope in scopes.items():
                scoped = [c for c in observed_calls if c['scope'] == scope]
                assert any(c['tool'] == 'gent_identity' and c['value']['agent']['id'] == ids[name] for c in scoped)
                assert any(c['tool'] == 'gent_agents' and c['value'] == [] for c in scoped)
                if name != 'parent':
                    assert any(c['tool'] == 'gent_inbox' and c['value'] == [] for c in scoped)
            proof.update(ids=ids, scopes=scopes, phase=1)
            save()
            print('PASS: actual parent/two-child MCP registrations have distinct host scopes and Gent identities', flush=True)
        if args.register_only:
            return
        if proof['phase'] == 1:
            for name in ('parent', 'child-a'):
                agent = proof['ids'][name]
                cli('permission', 'allow', peer_id, agent, '--permission', 'enumerate', 'send')
                cli('permission', 'allow', agent, peer_id, '--permission', 'enumerate', 'receive')
            proof['sent'] = {}
            for name in ('parent', 'child-a'):
                marker = 'private-' + uuid.uuid4().hex
                sent = peer.call('gent_send_non_blocking', {'recipient': proof['ids'][name], 'request_id': peer.request_id(), 'text': marker,
                                             'files': [{'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': PNG}]})[0]
                proof['sent'][name] = {'marker': marker, 'id': sent['message_id']}
            proof['phase'] = 2
            save()
        stop()
        daemon = start()
        if proof['phase'] == 2:
            observed_calls = turn(prefix + 'Resume the original child-a and child-b using their native child IDs from the previous turn. Do not spawn replacements. '
                'Each child must call gent_identity, gent_agents and gent_inbox. If its own inbox has a message, acknowledge it and reply using gent_reply '
                'with a new ID from gent_request_ids; echo the exact message text and include its exact files array unchanged. If empty, report empty. '
                'You must also call your own gent_identity, gent_agents and gent_inbox and perform the same acknowledgment/reply for your own message. '
                'Never pass message contents between parent/children or perform their Gent calls yourself.', 'resume')
            assert not [c for c in observed_calls if c['error']], 'resumed tool failure'
            for name, scope in proof['scopes'].items():
                scoped = [c for c in observed_calls if c['scope'] == scope]
                assert any(c['tool'] == 'gent_identity' and c['value']['agent']['id'] == proof['ids'][name] for c in scoped), f'{name} identity changed or not resumed'
                inboxes = [c['value'] for c in scoped if c['tool'] == 'gent_inbox']
                assert inboxes, f'{name} did not inspect inbox'
                expected = {proof['sent'][name]['id']} if name in proof['sent'] else set()
                assert {m['id'] for inbox in inboxes for m in inbox} == expected, f'{name} inbox isolation failed'
            inbox = peer.call('gent_inbox')[0]
            assert len(inbox) == 2, 'missing or duplicate replies'
            for name, sent in proof['sent'].items():
                reply = next(m for m in inbox if m['sender'] == proof['ids'][name])
                assert reply['reply_to'] == sent['id'] and sent['marker'] == reply['text']
                assert reply['files'] == [{'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': PNG}]
                assert peer.call('gent_message_status', {'message_id': sent['id']})[0]['state'] == 'delivered'
            proof['phase'] = 3
            save()
            print('PASS: original child identities survive host/daemon restart, isolated inboxes, exact image replies and receipts', flush=True)
        if proof['phase'] == 3:
            cli('agent', 'revoke', proof['ids']['child-a'])
            observed_calls = turn(prefix + 'Resume the same child-a and child-b again. Each must call gent_identity exactly once. '
                'child-a is intentionally revoked: report its expected tool error, without registering again or trying to fix it. '
                'child-b must call gent_identity and gent_inbox. You must call your own gent_identity. Do not create replacements or send messages.', 'revocation')
            denied = [c for c in observed_calls if c['scope'] == proof['scopes']['child-a'] and c['tool'] == 'gent_identity']
            assert denied and all(c['error'] and 'registration revoked' in json.dumps(c['error']) for c in denied)
            for name in ('parent', 'child-b'):
                assert any(c['scope'] == proof['scopes'][name] and c['tool'] == 'gent_identity' and not c['error']
                           and c['value']['agent']['id'] == proof['ids'][name] for c in observed_calls)
            assert len(cli('agents')) == 4
            proof['phase'] = 4
            save()
            print('PASS: child revocation remains isolated from parent and sibling', flush=True)
        from subagent_model_checks import audit
        audit(root, proof, calls(root, strict=True))
        print('PASS: native child provenance, tool audit, directory isolation and scoped request IDs', flush=True)
    finally:
        if peer:
            peer.close()
        stop()
        daemon_log.close()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'hook':
        raise SystemExit(hook(Path(sys.argv[2])))
    main()
