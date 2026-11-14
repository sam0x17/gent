#!/usr/bin/env python3
"""Recover explicit, Codex and Claude bindings using real CLI/MCP processes.

Disposable nodes and synthetic host metadata only; no model or provider calls.
"""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

from smoke_mcp import Client, PNG


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gent', type=Path, required=True)
    args = parser.parse_args()
    binary = str(args.gent.resolve())
    with tempfile.TemporaryDirectory(prefix='gent-agent-recovery-', dir='/tmp') as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        old, fresh = root / 'old', root / 'fresh'
        key, archive = root / 'recovery.key', root / 'original.age'
        processes, clients = [], []

        def cli(node, *command, error=False, input=None):
            result = subprocess.run([binary, '--home', str(node), '--json', *map(str, command)],
                                    text=True, capture_output=True, timeout=90, input=input)
            if error:
                assert result.returncode, command
                return result.stderr
            assert result.returncode == 0, (command, result.stderr)
            return json.loads(result.stdout)

        def start(node):
            process = subprocess.Popen([binary, '--home', str(node), 'daemon', 'run'],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            processes.append(process)
            deadline = time.monotonic() + 15
            while not (node / 'daemon.sock').exists():
                assert process.poll() is None, process.stderr.read()
                assert time.monotonic() < deadline
                time.sleep(.02)
            return process

        def stop(process):
            process.terminate()
            try:
                assert process.wait(timeout=15) == 0, process.stderr.read()
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
            finally:
                process.stderr.close()
                processes.remove(process)

        def fixed(node, path):
            client = Client([binary, '--home', str(node), 'mcp', 'serve', '--binding', str(path)])
            clients.append(client)
            return client

        def close(client):
            client.close()
            clients.remove(client)

        def host(node, kind):
            client = Client([binary, '--home', str(node), 'mcp', 'serve', '--host', kind],
                            client_name='codex-mcp-client' if kind == 'codex' else kind)
            clients.append(client)
            return client

        def call(client, case, name, arguments=None, error=False, node=None):
            arguments = arguments or {}
            meta = None
            if case['host'] == 'codex':
                meta = {'threadId': case['conversation']}
            elif case['host'] == 'claude-code':
                use = 'toolu_' + uuid.uuid4().hex
                event = {'hook_event_name': 'PreToolUse', 'session_id': case['conversation'],
                         'tool_use_id': use, 'tool_name': 'mcp__gent__' + name, 'tool_input': arguments}
                if case.get('subagent'):
                    event['agent_id'] = case['subagent']
                cli(node or fresh, 'integration', 'hook', 'claude-code', input=json.dumps(event))
                meta = {'claudecode/toolUseId': use}
            return client.call(name, arguments, error=error, meta=meta)

        try:
            cli(old, 'cluster', 'new', 'source', '--local')
            process = start(old)
            source = fixed(old, old / 'bindings/source.key')
            peer = fixed(old, old / 'bindings/peer.key')
            source_id = source.call('gent_register', {'name': 'source', 'provider': 'generic'})[0]['agent']['id']
            peer_id = peer.call('gent_register', {'name': 'peer', 'provider': 'generic'})[0]['agent']['id']
            cli(old, 'permission', 'allow', source_id, peer_id, '--permission', 'enumerate', 'send')
            cli(old, 'permission', 'allow', peer_id, source_id, '--permission', 'enumerate', 'receive')
            sent = source.call('gent_send', {'recipient': peer_id, 'request_id': source.request_id(),
                                            'text': 'historical visual request',
                                            'files': [{'name': 'pixel.png', 'media_type': 'image/png', 'data_base64': PNG}]})[0]
            old_credential = (old / 'bindings/source.key').read_bytes()
            close(source)
            close(peer)
            stop(process)
            cli(old, 'backup', 'keygen', '--output', key)
            cli(old, 'backup', 'create', archive, '--identity', key)
            cli(fresh, 'cluster', 'new', 'replacement', '--local')
            process = start(fresh)
            identity = (fresh / 'identity.key').read_bytes()
            stop(process)
            cases = [
                {'name': 'explicit', 'host': None, 'path': fresh / 'bindings/recovered.key'},
                {'name': 'codex', 'host': 'codex', 'conversation': 'original-codex-thread'},
                {'name': 'claude', 'host': 'claude-code', 'conversation': 'original-claude-session'},
                {'name': 'claude-child', 'host': 'claude-code', 'conversation': 'original-claude-session', 'subagent': 'child-a'},
            ]
            for case in cases:
                command = ['agent', 'recover', archive, '--identity', key, '--from-agent', source_id, '--name', case['name']]
                if case['host']:
                    command += ['--host', case['host'], '--conversation', case['conversation']]
                    if case.get('subagent'):
                        command += ['--subagent', case['subagent']]
                else:
                    command += ['--binding', case['path']]
                case['command'] = command
                cli(fresh, *command, error=True)  # daemon offline, publication remains pending
            assert len(list(fresh.rglob('*.recovery.json'))) == 4
            for case in cases:
                if case['host']:
                    client = host(fresh, case['host'])
                    result = call(client, case, 'gent_register', {'name': 'premature', 'provider': case['host']}, error=True)
                    assert 'recovery is pending' in json.dumps(result)
                    close(client)
                else:
                    result = subprocess.run([binary, '--home', str(fresh), 'mcp', 'serve', '--binding', str(case['path'])],
                                            input='', text=True, capture_output=True, timeout=15)
                    assert result.returncode and 'recovery is pending' in result.stderr
            process = start(fresh)
            assert cli(fresh, 'agents') == []
            recovered_ids = set()
            for case in cases:
                pending = {p: p.read_text() for p in fresh.rglob('*.recovery.json')}
                result = cli(fresh, *case['command'])
                agent_id = result['agent']['id']
                import_id = result['history']['import_id']
                path = Path(result['binding'])
                assert agent_id != source_id and agent_id not in recovered_ids
                recovered_ids.add(agent_id)
                assert path.read_bytes() != old_credential
                journal = Path(str(path) + '.recovery.json')
                assert path.read_text() not in journal.read_text() and path.read_text() not in json.dumps(result)
                # Simulate a committed daemon reply whose completion record was lost.
                journal.write_text(pending[journal])
                retry = cli(fresh, *case['command'])
                assert retry['agent']['id'] == agent_id and retry['history']['duplicate']
                before = (path.read_bytes(), journal.read_bytes())
                changed = list(case['command'])
                changed[changed.index('--name') + 1] = 'conflicting-name'
                cli(fresh, *changed, error=True)
                assert (path.read_bytes(), journal.read_bytes()) == before
                case.update(path=path, agent_id=agent_id, import_id=import_id)
                client = host(fresh, case['host']) if case['host'] else fixed(fresh, path)
                assert call(client, case, 'gent_identity')[0]['agent']['id'] == agent_id
                assert call(client, case, 'gent_agents')[0] == [] and call(client, case, 'gent_inbox')[0] == []
                imports = call(client, case, 'gent_history_imports')[0]['historical_imports']
                assert len(imports) == 1 and imports[0]['import_id'] == import_id
                page = call(client, case, 'gent_history_messages', {'import_id': import_id})[0]
                assert page['messages'][0]['message']['id'] == sent['message_id']
                _, content = call(client, case, 'gent_history_file_view', {'import_id': import_id,
                                  'message_id': sent['message_id'], 'file_index': 0})
                assert [base64.b64decode(b['data']) for b in content['content'] if b['type'] == 'image'] == [base64.b64decode(PNG)]
                cli(fresh, *case['command'], error=True)  # active binding cannot be changed
                close(client)
            assert len(cli(fresh, 'agents')) == 4
            assert (fresh / 'identity.key').read_bytes() == identity
            stop(process)
            process = start(fresh)
            claude = host(fresh, 'claude-code')
            for case in cases[2:]:
                assert call(claude, case, 'gent_identity')[0]['agent']['id'] == case['agent_id']
                other = cases[3] if case == cases[2] else cases[2]
                call(claude, case, 'gent_history_messages', {'import_id': other['import_id']}, error=True)
            close(claude)
            cli(fresh, 'history', 'remove', cases[0]['import_id'], '--expect-revision', '1')
            cli(fresh, *cases[0]['command'], error=True)
            cli(fresh, 'agent', 'revoke', cases[1]['agent_id'])
            cli(fresh, *cases[1]['command'], error=True)
            assert len(cli(fresh, 'agents')) == 4
            print('PASS: explicit/Codex/Claude/child bindings, pending refusal, lost-reply recovery, conflicts, busy locks, PNG bytes, isolation, restart, removal and revocation', flush=True)
            print(json.dumps({'status': 'passed', 'proof': 'agent-recovery', 'bindings': len(cases)}), flush=True)
        finally:
            for client in list(clients):
                close(client)
            for process in list(processes):
                stop(process)


if __name__ == '__main__':
    main()
