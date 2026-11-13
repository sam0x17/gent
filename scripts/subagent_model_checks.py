"""Audit real child-agent provenance and observed Gent calls, never model summaries.

Native parent/child context sharing is outside Gent's permission boundary.
Only the exact synthetic Codex rollouts are opened; Claude emits child events.
"""
from collections import Counter
import json
import os
from pathlib import Path
import uuid


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def fingerprint(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def signature(scope, tool, arguments):
    return fingerprint([scope, tool, arguments])


def codex_audit(root, proof, observed):
    sessions = Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'sessions'
    actual, paths, activities = Counter(), {}, []
    for name, scope in proof['scopes'].items():
        assert str(uuid.UUID(scope)) == scope
        matches = list(sessions.rglob('*' + scope + '*.jsonl'))
        assert len(matches) == 1, 'synthetic Codex rollout unavailable or ambiguous'
        transcript = rows(matches[0])
        metadata = [e['payload'] for e in transcript if e['type'] == 'session_meta']
        # A child's stored fork context also contains the parent's session_meta.
        assert metadata[0]['id'] == scope
        assert all(m['id'] in {scope, proof['session']} for m in metadata)
        metadata = [m for m in metadata if m['id'] == scope]
        assert len(metadata) == 1
        assert Path(metadata[0]['cwd']).resolve() == root / 'work'
        if name == 'parent':
            assert scope == proof['session'] and metadata[0]['source'] == 'exec'
        else:
            spawn = metadata[0]['source']['subagent']['thread_spawn']
            assert spawn['parent_thread_id'] == proof['session'] and spawn['depth'] == 1
            assert metadata[0]['forked_from_id'] == proof['session']
        paths[name] = str(matches[0])
        # Completed native items represent actual operations, including tools
        # invoked inside code-mode exec cells. Raw response_item history can
        # include inherited parent calls and is not an execution ledger.
        for event in transcript:
            payload = event.get('payload', {})
            if event['type'] != 'event_msg' or payload.get('type') != 'item_completed':
                continue
            item = payload['item']
            kind = item['type']
            if kind == 'McpToolCall':
                assert item['server'] == 'gent' and item['status'] in {'completed', 'failed'}
                if item['status'] == 'failed':
                    assert name == 'child-a' and item['tool'] == 'gent_identity'
                    assert item['result']['isError'] and 'registration revoked' in fingerprint(item['result'])
                actual[signature(scope, item['tool'], item['arguments'])] += 1
            elif kind == 'SubAgentActivity':
                assert name == 'parent', 'unexpected grandchild activity'
                assert item['agent_thread_id'] in {proof['scopes']['child-a'], proof['scopes']['child-b']}
                activities.append(item)
            elif kind == 'CollabAgentToolCall':
                assert name == 'parent' and item['sender_thread_id'] == scope
                assert item['tool'] in {'spawn_agent', 'send_input', 'resume_agent', 'close_agent', 'wait'}
                assert set(item.get('receiver_thread_ids', [])) <= set(proof['scopes'].values())
            else:
                assert kind in {'AgentMessage', 'UserMessage', 'Reasoning'}, f'unexpected native action: {kind}'
    assert actual == observed, 'native Codex tool calls do not match MCP traffic'
    for name in ('child-a', 'child-b'):
        assert any(a['kind'] == 'started' and a['agent_thread_id'] == proof['scopes'][name] for a in activities)
    return {'rollouts': paths, 'native_child_scopes': [proof['scopes'][n] for n in ('child-a', 'child-b')]}


def claude_audit(root, proof, observed):
    scopes = {json.loads(scope)[1]: scope for scope in proof['scopes'].values()}
    assert len(scopes) == 3 and None in scopes
    assert all(json.loads(scope)[0] == proof['session'] for scope in scopes.values())
    children = set(scopes) - {None}
    events = rows(root / 'hooks.jsonl')
    hooks = {e['tool_use_id']: e for e in events if e['hook_event_name'] == 'PreToolUse'}
    for kind in ('SubagentStart', 'SubagentStop'):
        lifecycle = [e for e in events if e['hook_event_name'] == kind]
        assert {e['agent_id'] for e in lifecycle} == children
        assert all(e['session_id'] == proof['session'] and e['agent_type'] == 'gent-worker' for e in lifecycle)
        assert all(sum(e['agent_id'] == child for e in lifecycle) == 3 for child in children)
    actual, seen = Counter(), set()
    parent_calls = {None: None}
    for label in ('register', 'resume', 'revocation'):
        transcript = rows(root / f'{label}.jsonl')
        native, started, completed = {}, {}, set()
        for event in transcript:
            if event.get('type') == 'result':
                assert event['subtype'] == 'success' and not event.get('is_error')
            if event.get('type') == 'system' and event.get('subtype') == 'task_started':
                assert event['session_id'] == proof['session'] and event['task_id'] in children
                assert event['subagent_type'] == 'gent-worker' and event['spawn_depth'] == 1
                started[event['tool_use_id']] = event['task_id']
                parent_calls[event['tool_use_id']] = event['task_id']
            if event.get('type') == 'system' and event.get('subtype') == 'task_notification':
                assert event['status'] == 'completed' and event['task_id'] in children
                completed.add(event['task_id'])
            if event.get('type') != 'assistant':
                continue
            for block in event['message'].get('content', []):
                if block.get('type') != 'tool_use':
                    continue
                tool, call_id = block['name'], block['id']
                assert call_id not in seen, 'duplicate native tool call'
                seen.add(call_id)
                if tool.startswith('mcp__gent__'):
                    hook = hooks[call_id]
                    assert hook['tool_name'] == tool and hook['tool_input'] == block['input']
                    assert hook['session_id'] == proof['session'] and hook['agent_id'] in scopes
                    assert event['session_id'] == proof['session']
                    assert parent_calls[event.get('parent_tool_use_id')] == hook['agent_id'], 'native child and hook scope differ'
                    actual[signature(scopes[hook['agent_id']], tool.removeprefix('mcp__gent__'), block['input'])] += 1
                else:
                    assert not event.get('parent_tool_use_id'), 'child used native lifecycle tool'
                    assert tool in {'Agent', 'SendMessage', 'TaskOutput', 'TaskStop'}, f'unexpected native action: {tool}'
                    native[call_id] = block
        assert set(started.values()) == completed == children and len(started) == 2
        for call_id, child in started.items():
            block = native[call_id]
            if label == 'register':
                assert block['name'] == 'Agent' and block['input']['subagent_type'] == 'gent-worker'
                assert not block['input'].get('resume')
            else:
                assert ((block['name'] == 'SendMessage' and block['input'].get('to') == child)
                        or (block['name'] == 'Agent' and block['input'].get('resume') == child))
        assert all(block['name'] not in {'Agent', 'SendMessage'} or call_id in started for call_id, block in native.items())
    assert set(hooks) <= seen, 'hook lacks matching native tool call'
    assert actual == observed, 'native Claude tool calls do not match MCP traffic'
    return {'native_child_scopes': sorted(children), 'hook_calls': len(hooks)}


def audit(root, proof, calls):
    assert proof['phase'] == 4 and len(set(proof['ids'].values())) == len(set(proof['scopes'].values())) == 3
    phases = {label: json.loads((root / f'{label}-calls.json').read_text()) for label in ('register', 'resume', 'revocation')}
    assert calls == sum(phases.values(), []), 'phase evidence differs from MCP traffic'
    permitted = {
        'register': {'gent_register', 'gent_identity', 'gent_agents', 'gent_inbox'},
        'resume': {'gent_identity', 'gent_agents', 'gent_inbox', 'gent_ack', 'gent_request_ids', 'gent_reply'},
        'revocation': {'gent_identity', 'gent_inbox'},
    }
    for label, phase in phases.items():
        assert all(c['scope'] in proof['scopes'].values() and c['tool'] in permitted[label] for c in phase)
        errors = [c for c in phase if c['error']]
        if label == 'revocation':
            assert len(errors) == 1 and errors[0]['scope'] == proof['scopes']['child-a']
            assert errors[0]['tool'] == 'gent_identity' and 'registration revoked' in fingerprint(errors[0]['error'])
        else:
            assert not errors
    registrations = [c for c in phases['register'] if c['tool'] == 'gent_register']
    assert len(registrations) == 3
    for c in registrations:
        name = c['args']['name']
        assert c['scope'] == proof['scopes'][name] and c['value']['agent']['id'] == proof['ids'][name]
    peer_ids = set()
    for name, scope in proof['scopes'].items():
        for label, phase in phases.items():
            scoped = [c for c in phase if c['scope'] == scope]
            identity = [c for c in scoped if c['tool'] == 'gent_identity']
            assert identity, f'{name} lacks identity in {label}'
            if label == 'revocation' and name == 'child-a':
                assert len(scoped) == 1 and identity[0]['error']
                continue
            assert all(c['value']['agent']['id'] == proof['ids'][name] for c in identity)
            directories = [c['value'] for c in scoped if c['tool'] == 'gent_agents']
            if label in ('register', 'resume'):
                assert directories
                for directory in directories:
                    if label == 'register' or name == 'child-b':
                        assert directory == []
                    else:
                        assert len(directory) == 1 and directory[0]['name'] == 'fixture-peer'
                        peer_ids.add(directory[0]['id'])
            inboxes = [c['value'] for c in scoped if c['tool'] == 'gent_inbox']
            if label == 'resume' or name == 'child-b' or (label == 'register' and name == 'child-a'):
                assert inboxes
            messages = [m for inbox in inboxes for m in inbox]
            if label != 'resume' or name == 'child-b':
                assert not messages
                assert not any(c['tool'] in {'gent_ack', 'gent_reply'} for c in scoped)
                continue
            sent = proof['sent'][name]
            assert {m['id'] for m in messages} == {sent['id']}
            assert all(m['text'] == sent['marker'] and m['recipient'] == proof['ids'][name] for m in messages)
            peer_ids.update(m['sender'] for m in messages)
            issued, replies, acks = set(), [], []
            for c in scoped:
                if c['tool'] == 'gent_request_ids':
                    issued.update(c['value']['request_ids'])
                if c['tool'] == 'gent_reply':
                    assert c['args']['request_id'] in issued, 'reply ID not allocated to this scope before use'
                    replies.append(c)
                if c['tool'] == 'gent_ack':
                    acks.append(c)
            assert len(replies) == len(acks) == 1
            assert acks[0]['args']['message_id'] == sent['id'] and acks[0]['value']['acknowledged']
            assert replies[0]['args']['message_id'] == sent['id'] and replies[0]['args']['text'] == sent['marker']
            assert replies[0]['args']['files'] == messages[0]['files']
    assert len(peer_ids) == 1 and not (peer_ids & set(proof['ids'].values()))
    observed = Counter(signature(c['scope'], c['tool'], c['args']) for c in calls)
    provenance = codex_audit(root, proof, observed) if proof['host'] == 'codex' else claude_audit(root, proof, observed)
    result = dict(proof, result='passed', gent_calls=len(calls), provenance=provenance,
                  boundary='Gent identities, discovery and tool permissions; native parent/child context sharing remains host-controlled')
    (root / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
