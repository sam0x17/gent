#!/usr/bin/env python3
"""Exercise host binding transitions over real MCP/RPC without model calls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from mcp_client import Client
from mcp_fixtures import PNG


def main():
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gent').resolve()
    with tempfile.TemporaryDirectory(prefix='gent-bind-', dir='/tmp') as folder:
        home = Path(folder) / "state ' $HOME"
        base = [str(binary), '--home', str(home)]
        clients = []
        daemon = None

        def cli(*args, **kwargs):
            return subprocess.run(base + list(args), text=True, capture_output=True, timeout=15, **kwargs)

        def connect(host):
            directory = Path(folder) / host
            cli('integration', 'install', host, '--config-dir', str(directory), check=True)
            configuration = (tomllib.loads((directory / 'config.toml').read_text()) if host == 'codex'
                             else json.loads((directory / '.claude.json').read_text()))
            spec = configuration['mcp_servers' if host == 'codex' else 'mcpServers']['gent']
            client = Client([spec['command'], *spec['args']], client_name='codex-mcp-client' if host == 'codex' else host)
            clients.append(client)
            return client

        try:
            cli('cluster', 'new', 'bindings-proof', '--local', check=True)
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 10
            while cli('daemon', 'status').returncode:
                assert daemon.poll() is None and time.monotonic() < deadline
                time.sleep(.05)
            codex = connect('codex')
            a, b = {'threadId': 'thread-a', 'sessionId': 'same-root'}, {'threadId': 'thread-b', 'sessionId': 'same-root'}
            aid = codex.call('gent_register', {'name': 'a', 'provider': 'codex'}, meta=a)[0]['agent']['id']
            bid = codex.call('gent_register', {'name': 'b', 'provider': 'codex'}, meta=b)[0]['agent']['id']
            assert aid != bid
            codex.call('gent_identity', {'threadId': 'thread-a'}, error=True, meta=b)
            codex.call('gent_identity', error=True, meta={'sessionId': 'same-root'})
            assert codex.call('gent_identity', meta=b)[0]['agent']['id'] == bid
            duplicate = connect('codex')
            duplicate.call('gent_identity', error=True, meta=a)
            duplicate.close()
            codex.close()
            codex = connect('codex')
            assert codex.call('gent_identity', meta=a)[0]['agent']['id'] == aid

            claude = connect('claude-code')
            settings = json.loads((Path(folder) / 'claude-code/settings.json').read_text())
            hook = settings['hooks']['PreToolUse'][0]['hooks'][0]['command']

            def call(session, tool, arguments=None, agent=None):
                arguments = arguments or {}
                use = 'toolu_' + uuid.uuid4().hex
                event = {'session_id': session, 'tool_use_id': use, 'tool_name': 'mcp__gent__' + tool,
                         'tool_input': arguments, 'hook_event_name': 'PreToolUse'}
                if agent:
                    event['agent_id'] = agent
                subprocess.run(['/bin/sh', '-c', hook], input=json.dumps(event), text=True, capture_output=True, check=True, timeout=15)
                return claude.call(tool, arguments, meta={'claudecode/toolUseId': use})[0]

            claude.call('gent_identity', error=True, meta={'claudecode/toolUseId': 'no-hook'})
            old = call('chat-old', 'gent_register', {'name': 'old', 'provider': 'claude-code'})['agent']['id']
            new = call('chat-new', 'gent_register', {'name': 'new', 'provider': 'claude-code'})['agent']['id']
            child = call('chat-old', 'gent_register', {'name': 'child', 'provider': 'claude-code'}, agent='child')['agent']['id']
            assert len({aid, bid, old, new, child}) == 5
            cli('permission', 'allow', aid, old, '--permission', 'enumerate', 'send', check=True)
            cli('permission', 'allow', old, aid, '--permission', 'enumerate', 'receive', check=True)
            sent = codex.call('gent_send_non_blocking', {'recipient': old, 'request_id': codex.request_id(meta=a), 'text': 'old chat only',
                                          'files': [{'name': 'image.png', 'media_type': 'image/png', 'data_base64': PNG}]}, meta=a)[0]
            assert call('chat-new', 'gent_inbox') == []
            assert call('chat-old', 'gent_inbox', agent='child') == []
            inbox = call('chat-old', 'gent_inbox')
            assert inbox[0]['id'] == sent['message_id'] and inbox[0]['files'][0]['data_base64'] == PNG
            claude.close()
            claude = connect('claude-code')
            assert call('chat-old', 'gent_identity')['agent']['id'] == old
            assert call('chat-old', 'gent_inbox')[0]['id'] == sent['message_id']
            cli('agent', 'revoke', old, check=True)
            use = 'toolu_' + uuid.uuid4().hex
            cli('integration', 'hook', 'claude-code', input=json.dumps({'session_id': 'chat-old', 'tool_use_id': use,
                'tool_name': 'mcp__gent__gent_register', 'tool_input': {'name': 'retry', 'provider': 'claude-code'}, 'hook_event_name': 'PreToolUse'}), check=True)
            claude.call('gent_register', {'name': 'retry', 'provider': 'claude-code'}, error=True, meta={'claudecode/toolUseId': use})
            print('PASS: per-call chat/subagent isolation, missing metadata/hook rejection, duplicate connection lock, reconnect, image visibility, and revocation')
            for host in ('codex', 'claude-code'):
                cli('integration', 'uninstall', host, '--config-dir', str(Path(folder) / host), check=True)
            assert (home / 'host-bindings').is_dir()
            print('PASS: installed MCP configuration and hook, idempotent installation, and removal retaining bindings')
        finally:
            for client in clients:
                client.close()
            if daemon and daemon.poll() is None:
                daemon.terminate()
                daemon.wait(timeout=10)


if __name__ == '__main__':
    main()
