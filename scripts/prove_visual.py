#!/usr/bin/env python3
"""Opt-in visual iteration or relay turns between real CLI agents on two machines.

Requires a local development relay, authenticated hosts, and built Gent binaries.
Synthetic private state and host transcripts are retained; processes are stopped.
The harness schedules turns but never copies peer messages into model prompts.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
import zlib
from urllib.parse import urlparse


def render(color, side):
    """Render a small code-native graphic, with no image-library dependencies."""
    colors = {'red': '#d52f42', 'green': '#1b9c68', 'blue': '#346bd4'}
    assert color in colors and side in ('left', 'right')
    width, height, cx = 160, 100, 24 if side == 'left' else 136
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 160 100">'
           '<rect width="160" height="100" fill="white"/>'
           '<rect x="20" y="40" width="120" height="40" fill="#346bd4"/>'
           '<path d="M32 52h72v5H32zM32 64h48v5H32z" fill="white"/>'
           f'<circle cx="{cx}" cy="18" r="10" fill="{colors[color]}"/></svg>').encode()
    dot = bytes.fromhex(colors[color][1:])
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            pixel = b'\xff\xff\xff'
            if 20 <= x < 140 and 40 <= y < 80:
                pixel = bytes.fromhex('346bd4')
            if (32 <= x < 104 and 52 <= y < 57) or (32 <= x < 80 and 64 <= y < 69):
                pixel = b'\xff\xff\xff'
            if (x - cx) ** 2 + (y - 18) ** 2 < 100:
                pixel = dot
            rows.extend(pixel)

    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))

    png = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!2I5B', width, height, 8, 2, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))
    return [{'name': name, 'media_type': mime, 'data_base64': base64.b64encode(data).decode()}
            for name, mime, data in [('card.svg', 'image/svg+xml', svg), ('card.png', 'image/png', png)]]


def run_json(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=40, **kwargs)
    return json.loads(result.stdout)


def settings(root):
    return json.loads((root / 'proof.json').read_text())


def cli(root, *command):
    return run_json([settings(root)['binary'], '--home', str(root / 'state'), '--json', *command])


def prepare(data):
    root = Path(tempfile.mkdtemp(prefix='gent-relay-host-' if data.get('relay_turns') else 'gent-visual-', dir='/tmp')).resolve()
    (root / 'work').mkdir()
    data = dict(data, script=str(Path(__file__).resolve()), python=sys.executable)
    token = data.pop('token', None)
    (root / 'proof.json').write_text(json.dumps(data))
    if token:
        cli(root, 'cluster', 'new', 'visual-proof', '--local')
        with (root / 'state/config.toml').open('a') as out:
            out.write('\n[relay]\nendpoint = ' + json.dumps(data['relay']) + '\ncredential_file = "relay.key"\n')
        fd = os.open(root / 'state/relay.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write(token)
    return {'root': str(root)}


def install(root):
    return cli(root, 'integration', 'install', settings(root)['host'], '--config-dir', str(root / 'host-config'))


def inspect(root):
    with sqlite3.connect((root / 'state/state.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
        messages = []
        for payload, ack in db.execute('SELECT payload,acknowledged FROM messages ORDER BY rowid'):
            message = json.loads(payload)
            message['acknowledged'] = bool(ack)
            messages.append(message)
    return {'messages': messages, 'config': tomllib.loads((root / 'state/config.toml').read_text())}


def stop_process(process):
    if process and process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def stop_daemon(root):
    path = root / 'daemon.pid'
    if not path.exists():
        return
    pid = int(path.read_text())
    # Refuse to signal a reused PID belonging to a different process.
    description = subprocess.run(['ps', '-p', str(pid), '-o', 'args='], capture_output=True, text=True).stdout
    if str(root / 'state') not in description or 'daemon run' not in description:
        path.unlink()
        return
    os.kill(pid, signal.SIGINT)
    end = time.monotonic() + 10
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            path.unlink()
            return
        time.sleep(.05)
    raise AssertionError(f'daemon {pid} did not stop; retained {root}')


def tool_results(events, host):
    calls, results = {}, {}
    for event in events:
        if host == 'codex':
            item = event.get('item', {})
            if event.get('type') == 'item.completed' and item.get('type') == 'mcp_tool_call':
                assert item.get('status') == 'completed' and not item.get('error') and not item.get('result', {}).get('isError'), item
                content = item['result']['content']
                results.setdefault(item['tool'], []).append(json.loads(content[0]['text']))
        else:
            for block in event.get('message', {}).get('content', []):
                if not isinstance(block, dict):
                    continue
                if block.get('type') == 'tool_use' and block['name'].startswith('mcp__gent__'):
                    calls[block['id']] = block['name'].removeprefix('mcp__gent__')
                if block.get('type') == 'tool_result' and block['tool_use_id'] in calls:
                    assert not block.get('is_error'), block
                    content = block['content']
                    text = content if isinstance(content, str) else next(p['text'] for p in content if p.get('type') == 'text')
                    results.setdefault(calls[block['tool_use_id']], []).append(json.loads(text))
    return results


def gent_only(events, host):
    """Fail if a relay host obtained information through an unrelated tool."""
    calls = 0
    for event in events:
        if host == 'codex':
            item = event.get('item')
            if not item:
                continue
            assert item['type'] in ('agent_message', 'reasoning', 'todo_list', 'error', 'mcp_tool_call'), 'unexpected non-Gent host action'
            if item['type'] == 'mcp_tool_call':
                assert item.get('server') == 'gent' and item.get('tool', '').startswith('gent_'), 'unrelated MCP server used'
                calls += event.get('type') == 'item.completed'
        else:
            for block in event.get('message', {}).get('content', []):
                if isinstance(block, dict) and block.get('type') == 'tool_use':
                    assert block['name'].startswith('mcp__gent__gent_'), 'unexpected non-Gent host action'
                    calls += 1
    return calls


def audit(root):
    config = settings(root)
    assert config.get('relay_turns') and not config.get('allow_renderer'), 'not a relay-only proof'
    logs = list(root.glob('*.jsonl'))
    assert logs, 'no host transcripts'
    calls = sum(gent_only([json.loads(line) for line in path.read_text().splitlines() if line.strip()], config['host']) for path in logs)
    result = {'result': 'passed', 'host': config['host'], 'turn_logs': len(logs), 'gent_calls': calls}
    (root / 'tool-audit.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def turn(root, request):
    config = settings(root)
    host, installed = config['host'], root / 'host-config'
    allow_renderer = config.get('allow_renderer', True)
    renderer = shlex.join([config['python'], config['script'], 'render'])
    if host == 'codex':
        entry = tomllib.loads((installed / 'config.toml').read_text())['mcp_servers']['gent']
        path = Path(os.getenv('CODEX_HOME', Path.home() / '.codex')) / 'config.toml'
        current = tomllib.loads(path.read_text()) if path.exists() else {}
        command = [config['host_binary'], 'exec', '--json', '--skip-git-repo-check', '-C', str(root / 'work'),
                   '--sandbox', 'read-only', '--enable' if allow_renderer else '--disable', 'shell_tool', '--disable', 'multi_agent', '--disable', 'apps',
                   '-c', 'approval_policy="never"', '-c', 'web_search="disabled"',
                   '-c', 'model_reasoning_effort=' + json.dumps(config.get('reasoning_effort', 'low')),
                   '-c', 'mcp_servers.gent.command=' + json.dumps(entry['command']),
                   '-c', 'mcp_servers.gent.args=' + json.dumps(entry['args']),
                   '-c', 'mcp_servers.gent.enabled=true', '-c', 'mcp_servers.gent.required=true',
                   '-c', 'mcp_servers.gent.default_tools_approval_mode="approve"']
        for table in ('mcp_servers', 'plugins'):
            for name in current.get(table, {}):
                if table == 'mcp_servers' and name == 'gent':
                    continue
                assert '.' not in name, 'host configuration names containing dots are unsupported by this proof'
                command += ['-c', f'{table}.{name}.enabled=false']
        command += ['resume', request['session'], '-'] if request.get('session') else ['-']
    else:
        command = [config['host_binary'], '-p', '--output-format', 'stream-json', '--verbose',
                   '--setting-sources', '', '--strict-mcp-config', '--tools', 'Bash' if allow_renderer else '', '--disable-slash-commands',
                   '--no-chrome', '--permission-mode', 'dontAsk', '--max-budget-usd', '1',
                   '--allowedTools', 'mcp__gent__*', *([f'Bash({renderer} *)'] if allow_renderer else []),
                   '--settings', str(installed / 'settings.json'), '--mcp-config', str(installed / '.claude.json')]
        if request.get('session'):
            command += ['--resume', request['session']]
    prompt = ('Synthetic Gent visual integration test. Use Gent MCP for every peer message and file. '
              'The only shell command you may run is the supplied read-only graphic renderer, with its color and side arguments. '
              'Do not read other files, inspect Gent state, change configuration, spawn agents, or use the network directly. '
              f'Render command: {renderer} COLOR SIDE. It returns a files array containing SVG source and a PNG preview; '
              'copy both exact attachments into Gent tools without altering base64. Supported colors: red, green, blue. '
              'Supported sides: left, right. ' + request['prompt'])
    if not allow_renderer:
        prompt = ('Synthetic Gent relay integration test using temporary agents and files. '
                  'Only Gent MCP tools are available. Do not inspect local state, change configuration, spawn agents, '
                  'or use other connectors. Follow the bundled Gent guidance and the user instruction below. '
                  + request['prompt'])
    log = root / (request['label'] + '.jsonl')
    with log.open('w') as out, (root / (request['label'] + '.stderr')).open('w') as err:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err, text=True,
                                   cwd=root / 'work', start_new_session=True,
                                   env=dict(os.environ, DISABLE_AUTOUPDATER='1'))
        try:
            process.communicate(prompt, timeout=180)
            assert process.returncode == 0, f'host turn failed; inspect {log}'
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
    events = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
    if not allow_renderer:
        gent_only(events, host)
    session = next((e['thread_id'] for e in events if e.get('type') == 'thread.started'), None) if host == 'codex' else next(
        (e['session_id'] for e in events if e.get('type') == 'system' and e.get('subtype') == 'init'), None)
    assert session and (not request.get('session') or session == request['session']), 'host session changed'
    final_text = next((e['item']['text'] for e in reversed(events) if e.get('type') == 'item.completed'
                       and e.get('item', {}).get('type') == 'agent_message'), '') if host == 'codex' else next(
        (e.get('result', '') for e in reversed(events) if e.get('type') == 'result'), '')
    result = {'session': session, 'tools': tool_results(events, host), 'final_text': final_text}
    (root / (request['label'] + '-result.json')).write_text(json.dumps(result, indent=2))
    return result


def wait_for(check, description):
    end = time.monotonic() + 40
    while time.monotonic() < end:
        value = check()
        if value:
            return value
        time.sleep(.15)
    raise AssertionError('timed out: ' + description)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--relay-turns', action='store_true', help='Exercise real-model intermediary/target relay turns instead of visual revision')
    parser.add_argument('--owner', required=True)
    parser.add_argument('--remote-binary', required=True)
    parser.add_argument('--remote-script', required=True, help='Copy this script to the other machine first')
    parser.add_argument('--remote-python', default='/opt/homebrew/bin/python3')
    parser.add_argument('--local-host', choices=['codex', 'claude-code'], required=True)
    parser.add_argument('--remote-host', choices=['codex', 'claude-code'], required=True)
    parser.add_argument('--local-host-binary', required=True)
    parser.add_argument('--remote-host-binary', required=True)
    parser.add_argument('--binary', default='target/debug/gent')
    parser.add_argument('--relay-url', default='http://127.0.0.1:18787')
    parser.add_argument('--relay-token-file', required=True)
    parser.add_argument('--remote-relay-port', type=int, default=18789)
    args = parser.parse_args()
    url = urlparse(args.relay_url)
    assert url.scheme == 'http' and url.hostname == '127.0.0.1' and url.port
    assert args.remote_binary.startswith('/') and args.remote_script.startswith('/')
    assert 1024 <= args.remote_relay_port < 65536
    key = Path(args.relay_token_file)
    assert not key.is_symlink() and key.stat().st_mode & 0o077 == 0
    token = key.read_text().strip()
    assert len(token) == 64 and all(c in '0123456789abcdefABCDEF' for c in token)
    ssh = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', '-o', 'ForwardAgent=no']

    def remote(mode, root=None, data=None, extra=()):
        command = [args.remote_python, args.remote_script, mode, *([str(root)] if root else []), *extra]
        result = subprocess.run(ssh + ['--', args.owner, shlex.join(command)],
                                input=json.dumps(data) if data is not None else None,
                                text=True, capture_output=True, timeout=210)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    local_root = Path(prepare({'binary': str(Path(args.binary).resolve()), 'host': args.local_host,
                              'host_binary': args.local_host_binary, 'relay_turns': args.relay_turns,
                              'allow_renderer': not args.relay_turns,
                              'reasoning_effort': 'medium' if args.relay_turns else 'low'})['root'])
    remote_root = None
    local_daemon = owner_daemon = tunnel = None
    print('Local visual proof:', local_root, flush=True)

    def local_start():
        with (local_root / 'daemon.log').open('a') as log:
            return subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'daemon', str(local_root)],
                                    stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def remote_start():
        command = [args.remote_python, args.remote_script, 'daemon', remote_root]
        with (local_root / 'remote-daemon.log').open('a') as log:
            return subprocess.Popen(ssh + ['--', args.owner, shlex.join(command)], stdin=subprocess.DEVNULL, stdout=log, stderr=log)

    def local_cli(*command):
        return cli(local_root, *command)

    def remote_cli(*command):
        return remote('cli', remote_root, extra=command)

    def message_at(is_remote, mid):
        state = remote('inspect', remote_root) if is_remote else inspect(local_root)
        return next((m for m in state['messages'] if m['id'] == mid), None)

    def assert_files(message, expected):
        assert sorted(message['files'], key=lambda f: f['name']) == sorted(expected, key=lambda f: f['name']), 'attachment bytes changed'

    try:
        remote_root = remote('prepare', data={'binary': args.remote_binary, 'host': args.remote_host,
                                             'host_binary': args.remote_host_binary, 'relay_turns': args.relay_turns,
                                             'allow_renderer': not args.relay_turns,
                                             'reasoning_effort': 'medium' if args.relay_turns else 'low',
                                             'relay': f'http://127.0.0.1:{args.remote_relay_port}', 'token': token})['root']
        print('Remote visual proof:', remote_root, flush=True)
        # Different native zlib builds can encode identical pixels differently.
        # Compare exact bytes with the renderer at the attachment's source.
        reference_files = remote('render', extra=('green', 'right'))['files'] if not args.relay_turns else None
        with (local_root / 'tunnel.log').open('a') as log:
            tunnel = subprocess.Popen(ssh + ['-o', 'ExitOnForwardFailure=yes', '-N', '-R',
                                      f'127.0.0.1:{args.remote_relay_port}:127.0.0.1:{url.port}', '--', args.owner],
                                      stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        owner_daemon = remote_start()
        wait_for(lambda: remote('ready', remote_root), 'owner daemon')
        assert tunnel.poll() is None, 'SSH relay tunnel failed'
        cluster = remote_cli('cluster')['cluster']['id']
        local_cli('cluster', 'join', cluster, '--via', args.owner, '--name', 'visual-builder-node',
                  '--remote-gent', args.remote_binary, '--remote-home', remote_root + '/state', '--relay-endpoint', args.relay_url)
        local_daemon = local_start()
        wait_for(lambda: (local_root / 'state/daemon.sock').exists(), 'joined daemon')
        install(local_root)
        remote('install', remote_root)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(turn, local_root, {'label': 'register', 'prompt': f'Call gent_register with name visual-builder and provider {args.local_host}, then gent_identity and gent_agents. Do nothing else.'})
            b = pool.submit(remote, 'turn', remote_root, {'label': 'register', 'prompt': f'Call gent_register with name visual-reviewer and provider {args.remote_host}, then gent_identity and gent_agents. Do nothing else.'})
            builder, reviewer = a.result(), b.result()
        aid = builder['tools']['gent_register'][0]['agent']['id']
        bid = reviewer['tools']['gent_register'][0]['agent']['id']
        assert aid != bid and builder['session'] != reviewer['session']
        assert builder['tools']['gent_agents'] == reviewer['tools']['gent_agents'] == [[]]
        wait_for(lambda: len(remote_cli('agents')) == 2 and len(local_cli('agents')) == 2, 'agent announcements')
        remote_cli('permission', 'allow', aid, bid, '--permission', 'enumerate', 'send')
        grant = remote_cli('permission', 'allow', bid, aid, '--permission', 'enumerate', 'receive')
        wait_for(lambda: inspect(local_root)['config']['applied_revision'] == grant['revision'], 'permission sync')
        if args.relay_turns:
            from relay_model_checks import exercise_relay

            def local_turn(label, prompt):
                return turn(local_root, {'label': label, 'session': builder['session'], 'prompt': prompt})

            def remote_turn(label, prompt):
                return remote('turn', remote_root, {'label': label, 'session': reviewer['session'], 'prompt': prompt})

            def offline():
                nonlocal local_daemon
                stop_process(local_daemon)
                local_daemon = None

            def restart():
                nonlocal local_daemon, owner_daemon
                stop_process(local_daemon)
                remote('stop', remote_root)
                stop_process(owner_daemon)
                owner_daemon = remote_start()
                wait_for(lambda: remote('ready', remote_root), 'target restart')
                local_daemon = local_start()
                wait_for(lambda: (local_root / 'state/daemon.sock').exists(), 'intermediary restart')

            report = exercise_relay(
                aid, bid, local_turn, remote_turn, remote_cli,
                lambda: inspect(local_root), lambda: remote('inspect', remote_root),
                offline, restart, render('red', 'left'), wait_for)
            report.update({'local_host': args.local_host, 'remote_host': args.remote_host,
                           'local_root': str(local_root), 'remote_root': remote_root,
                           'intermediary_session': builder['session'], 'target_session': reviewer['session']})
            report['local_audit'] = audit(local_root)
            report['remote_audit'] = remote('audit', remote_root)
        else:
            marker = 'GENT_VISUAL_' + uuid.uuid4().hex
            initial = turn(local_root, {'label': 'initial', 'session': builder['session'], 'prompt':
                f'Call gent_identity and gent_agents. Render a card with red left. Send both files to visual-reviewer using gent_send with a fresh UUID request_id. '
                f'Text: "{marker}: Please inspect this card and send visual feedback with a reference image." Do nothing else.'})
            assert initial['tools']['gent_identity'][0]['agent']['id'] == aid
            first_id = initial['tools']['gent_send'][0]['message_id']
            first = wait_for(lambda: message_at(True, first_id), 'initial image delivery')
            assert first['sender'] == aid and first['recipient'] == bid and marker in first['text']
            assert_files(first, render('red', 'left'))
            assert_files(first, message_at(False, first_id)['files'])
            print('Initial image delivered through Gent; taking builder daemon offline', flush=True)
            stop_process(local_daemon)
            local_daemon = None
            feedback = remote('turn', remote_root, {'label': 'feedback', 'session': reviewer['session'], 'prompt':
                'Call gent_identity and gent_inbox. Inspect the actual PNG in the pending message. The acceptance criteria are a green status dot in the upper right and an unchanged blue panel. '
                'Acknowledge the message, then reply to it using gent_reply with a fresh UUID. Begin the text with "OBSERVED: COLOR SIDE" using the dot color and side you actually see, '
                'then explain the required correction. Render a green right reference card and include both returned files in your reply. Do nothing else.'})
            assert feedback['tools']['gent_identity'][0]['agent']['id'] == bid
            feedback_id = feedback['tools']['gent_reply'][0]['message_id']
            feedback_message = message_at(True, feedback_id)
            assert feedback_message['reply_to'] == first_id and feedback_message['sender'] == bid
            assert 'observed: red left' in feedback_message['text'].lower(), 'reviewer did not identify the original image'
            assert_files(feedback_message, reference_files)
            # Restart the sending daemon too while the destination is offline.
            remote('stop', remote_root)
            stop_process(owner_daemon)
            owner_daemon = remote_start()
            wait_for(lambda: remote('ready', remote_root), 'owner restart')
            local_daemon = local_start()
            wait_for(lambda: (local_root / 'state/daemon.sock').exists(), 'builder restart')
            recovered_feedback = wait_for(lambda: message_at(False, feedback_id), 'queued visual feedback after both daemon restarts')
            assert_files(recovered_feedback, feedback_message['files'])
            revised = turn(local_root, {'label': 'revision', 'session': builder['session'], 'prompt':
                'Call gent_identity and gent_inbox. Inspect your peer\'s visual feedback and reference PNG, acknowledge it, and use the renderer to implement the requested change. '
                'Reply to that feedback using gent_reply with a fresh UUID and both revised files. Explain what you changed. Do nothing else.'})
            assert revised['tools']['gent_identity'][0]['agent']['id'] == aid
            revision_id = revised['tools']['gent_reply'][0]['message_id']
            revision = wait_for(lambda: message_at(True, revision_id), 'revised image delivery')
            assert revision['reply_to'] == feedback_id and revision['sender'] == aid
            assert_files(revision, render('green', 'right'))
            assert_files(revision, message_at(False, revision_id)['files'])
            approved = remote('turn', remote_root, {'label': 'approval', 'session': reviewer['session'], 'prompt':
                'Call gent_identity and gent_inbox. Inspect the revised PNG against your previous acceptance criteria. Acknowledge the message and reply using gent_reply with a fresh UUID. '
                'If it passes, use exactly "APPROVED: green right" as the reply text. Otherwise explain the visual defect. Then use gent_message_status to check receipt of your earlier feedback. Do nothing else.'})
            assert approved['tools']['gent_identity'][0]['agent']['id'] == bid
            assert approved['tools']['gent_message_status'][-1]['state'] == 'delivered'
            approval_id = approved['tools']['gent_reply'][0]['message_id']
            approval = wait_for(lambda: message_at(False, approval_id), 'review approval')
            assert approval['reply_to'] == revision_id and approval['sender'] == bid
            assert approval['text'] == 'APPROVED: green right'
            done = turn(local_root, {'label': 'receipt', 'session': builder['session'], 'prompt':
                'Call gent_identity and gent_inbox, acknowledge your peer\'s final approval, and use gent_message_status to check receipt of your latest visual revision. Do nothing else.'})
            assert done['tools']['gent_identity'][0]['agent']['id'] == aid
            assert done['tools']['gent_message_status'][-1]['state'] == 'delivered'
            ids = [first_id, feedback_id, revision_id, approval_id]
            assert len(set(ids)) == 4
            wait_for(lambda: all(m['acknowledged'] for m in inspect(local_root)['messages'] if m['recipient'] == aid), 'local acknowledgments')
            assert {m['id'] for m in inspect(local_root)['messages']} == set(ids)
            assert {m['id'] for m in remote('inspect', remote_root)['messages']} == set(ids)
            assert len({m['exchange_id'] for m in [first, feedback_message, revision, approval]}) == 1
            report = {'result': 'passed', 'local_host': args.local_host, 'remote_host': args.remote_host,
                      'local_root': str(local_root), 'remote_root': remote_root, 'builder_session': builder['session'],
                      'reviewer_session': reviewer['session'], 'builder_agent': aid, 'reviewer_agent': bid,
                      'message_ids': ids, 'marker': marker, 'feedback': feedback_message['text'], 'approval': approval['text'],
                      'initial_files': [{**{k: f[k] for k in ('name', 'media_type')}, 'sha256': hashlib.sha256(base64.b64decode(f['data_base64'])).hexdigest()} for f in first['files']],
                      'revised_files': [{**{k: f[k] for k in ('name', 'media_type')}, 'sha256': hashlib.sha256(base64.b64decode(f['data_base64'])).hexdigest()} for f in revision['files']]}
    finally:
        try:
            stop_process(local_daemon)
            if remote_root:
                remote('stop', remote_root)
        finally:
            stop_process(owner_daemon)
            stop_process(tunnel)
    (local_root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: real-model ordered relay, faithful text/files, pending checks, restart, final outcomes, cancellation, and detach' if args.relay_turns else
          'PASS: real agents reviewed and revised PNG/SVG files across machines, with scoped replies and offline restart recovery', flush=True)


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    if mode == 'render':
        print(json.dumps({'files': render(*sys.argv[2:])}))
    elif mode == 'prepare':
        print(json.dumps(prepare(json.load(sys.stdin))))
    elif mode in ('turn', 'install', 'inspect', 'daemon', 'stop', 'cli', 'ready', 'audit'):
        root = Path(sys.argv[2]).resolve()
        if mode == 'daemon':
            (root / 'daemon.pid').write_text(str(os.getpid()))
            binary = settings(root)['binary']
            os.execv(binary, [binary, '--home', str(root / 'state'), 'daemon', 'run'])
        if mode == 'turn':
            value = turn(root, json.load(sys.stdin))
        elif mode == 'install':
            value = install(root)
        elif mode == 'inspect':
            value = inspect(root)
        elif mode == 'audit':
            value = audit(root)
        elif mode == 'stop':
            value = stop_daemon(root)
        elif mode == 'cli':
            value = cli(root, *sys.argv[3:])
        elif mode == 'ready':
            result = subprocess.run([settings(root)['binary'], '--home', str(root / 'state'), 'daemon', 'status'], capture_output=True)
            value = result.returncode == 0
        print(json.dumps(value))
    else:
        main()
