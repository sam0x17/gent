"""Native file and image assertions for real Codex/Claude conversations.

Only owner setup and read-only verification use fixture access to Gent state.
Agents import, send, export, inspect, and forward through their own tools.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import uuid
from urllib.parse import unquote, urlsplit


def fixture(root, args, render):
    operation, *args = args
    if operation == 'render':
        color, side = args
        files = render(color, side, scale=8)
        result = []
        for item in files:
            content = base64.b64decode(item['data_base64'], validate=True)
            path = root / 'work' / item['name']
            path.write_bytes(content)
            result.append({'name': item['name'], 'media_type': item['media_type'], 'path': str(path),
                           'byte_length': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
        assert next(f['byte_length'] for f in result if f['name'] == 'card.png') > 1024 * 1024
        return {'files': result}
    assert operation == 'stage'
    name, destination = args
    assert name in ('card.svg', 'card.png')
    destination = Path(destination).resolve(strict=True)
    relative = destination.relative_to(root / 'state' / 'files')
    assert len(relative.parts) == 2 and relative.parts[1] == 'outbox'
    assert str(uuid.UUID(relative.parts[0])) == relative.parts[0]
    source = root / 'work' / name
    target = destination / name
    assert not source.is_symlink() and not target.is_symlink()
    shutil.copyfile(source, target)
    return {'staged': str(target), 'bytes': target.stat().st_size}


def exports(root):
    result = []
    for path in (root / 'state' / 'files').glob('*/inbox/*/*'):
        assert not path.is_symlink() and path.is_file()
        result.append({'path': str(path), 'byte_length': path.stat().st_size,
                       'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    return result


def audit(root, config, parse_tools):
    """Allow only Gent, the bounded fixture helper, and exported-image reads."""
    from prove_visual import settings
    assert settings(root).get('native_files')
    transcript = [json.loads(line) for path in sorted(root.glob('*.jsonl'))
                  for line in path.read_text().splitlines() if line.strip()]
    results = parse_tools(transcript, config['host'])
    export_paths = {entry['path'] for entry in results.get('gent_file_export', [])}
    imports = {entry['import_directory'] for entry in results.get('gent_file_paths', [])}
    helper = [config['python'], config['script'], 'native-files', str(root)]
    if config['host'] == 'codex':
        # Exec JSON currently omits ImageView. Read only this synthetic thread's
        # own rollout, selected by its exact recorded session ID.
        session = json.loads((root / 'register-result.json').read_text())['session']
        assert str(uuid.UUID(session)) == session
        sessions = Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')) / 'sessions'
        paths = list(sessions.rglob('*' + session + '*.jsonl'))
        assert len(paths) == 1, 'synthetic Codex rollout unavailable or ambiguous'
        raw = [json.loads(line) for line in paths[0].read_text().splitlines() if line.strip()]
        assert any(e['type'] == 'session_meta' and e['payload']['id'] == session for e in raw)
        kinds = {'AgentMessage': 'agent_message', 'UserMessage': 'user_message', 'Reasoning': 'reasoning',
                 'McpToolCall': 'mcp_tool_call', 'CommandExecution': 'command_execution', 'ImageView': 'image_view'}
        transcript = []
        for event in raw:
            payload = event.get('payload', {})
            if event['type'] == 'event_msg' and payload.get('type') == 'item_completed':
                item = payload['item']
                assert item['type'] in kinds, 'unexpected Codex thread action'
                transcript.append({'type': 'item.completed', 'item': dict(item, type=kinds[item['type']])})
        image_outputs = sum(part.get('type') == 'input_image'
            for e in raw if e['type'] == 'response_item' and e['payload'].get('type') == 'custom_tool_call_output'
            for part in e['payload'].get('output', []) if isinstance(part, dict))
        expected_views = sum(e['item']['type'] == 'image_view' for e in transcript)
        assert expected_views and image_outputs >= expected_views, 'native image bytes were not returned'

    commands, images, gent_calls = 0, 0, 0
    viewed_paths = set()
    pending_images, pending_commands = {}, {}
    denied_commands = 0

    def command(text):
        nonlocal commands
        parts = text if isinstance(text, list) else shlex.split(text)
        assert all(isinstance(part, str) for part in parts)
        if len(parts) == 3 and parts[1] in ('-c', '-lc'):
            parts = shlex.split(parts[2])
        assert parts[:4] == helper, 'host executed a command outside the native fixture'
        args = parts[4:]
        assert len(args) == 3
        if args[0] == 'render':
            assert args[1] in ('red', 'green', 'blue') and args[2] in ('left', 'right')
        else:
            assert args[0] == 'stage' and args[1] in ('card.png', 'card.svg') and args[2] in imports
        commands += 1

    def image(path):
        nonlocal images
        if path.startswith('file:'):
            uri = urlsplit(path)
            assert uri.scheme == 'file' and not uri.netloc and not uri.query and not uri.fragment
            path = unquote(uri.path, errors='strict')
        assert path in export_paths and Path(path).name == 'card.png', 'host read an unexported image'
        viewed_paths.add(path)
        images += 1

    for event in transcript:
        if config['host'] == 'codex':
            if event.get('type') != 'item.completed':
                continue
            item = event['item']
            kind = item['type']
            if kind == 'mcp_tool_call':
                assert item['server'] == 'gent' and item['tool'].startswith('gent_')
                gent_calls += 1
            elif kind == 'command_execution':
                assert item.get('exit_code') == 0
                command(item['command'])
            elif kind == 'image_view':
                image(item['path'])
            else:
                assert kind in ('agent_message', 'user_message', 'reasoning', 'todo_list'), f'unexpected native host action: {kind}'
        else:
            message = event.get('message', {})
            for block in message.get('content', []) if isinstance(message, dict) else []:
                if not isinstance(block, dict):
                    continue
                if block.get('type') == 'tool_result':
                    call_id = block['tool_use_id']
                    if call_id in pending_images:
                        assert not block.get('is_error'), 'native image read failed'
                        content = block['content']
                        assert isinstance(content, list) and any(b.get('type') == 'image' for b in content), 'native read returned no image'
                        image(pending_images.pop(call_id))
                    if call_id in pending_commands:
                        attempted = pending_commands.pop(call_id)
                        if block.get('is_error'):
                            assert isinstance(block.get('content'), str) and block['content'].startswith('Permission to use Bash has been denied'), 'native helper failed'
                            denied_commands += 1
                        else:
                            command(attempted)
                    continue
                if block.get('type') != 'tool_use':
                    continue
                name = block['name']
                if name.startswith('mcp__gent__gent_'):
                    gent_calls += 1
                elif name == 'Bash':
                    pending_commands[block['id']] = block['input']['command']
                elif name == 'Read':
                    pending_images[block['id']] = block['input']['file_path']
                else:
                    raise AssertionError(f'unexpected native host action: {name}')
    assert not pending_images and not pending_commands, "native tool result missing"
    assert commands and images and gent_calls
    assert viewed_paths == {p for p in export_paths if Path(p).name == 'card.png'}, 'host omitted an exported PNG view'
    result = {'result': 'passed', 'host': config['host'], 'gent_calls': gent_calls,
              'fixture_commands': commands, 'native_image_views': images, 'denied_shell_attempts': denied_commands}
    (root / 'tool-audit.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def exercise(aid, bid, local, remote, owner, local_state, remote_state, offline, restart, wait_for):
    marker = 'NATIVE_FILES_' + uuid.uuid4().hex

    def one(result, tool):
        values = result['tools'].get(tool, [])
        assert len(values) == 1, f'expected one {tool}, got {len(values)}'
        return values[0]

    def identity(result, expected):
        assert one(result, 'gent_identity')['agent']['id'] == expected

    def message(state, mid):
        return next((m for m in state()['messages'] if m['id'] == mid), None)

    def received(state, mid):
        def ready():
            snapshot = state()
            found = next((m for m in snapshot['messages'] if m['id'] == mid), None)
            if found and all(snapshot['objects'].get(f['id'], False) for f in found.get('attachments', [])):
                return found
        return wait_for(ready, 'native attachment delivery')

    def attachments(message, expected=None):
        assert message['files'] == [] and len(message['attachments']) == 2
        actual = sorted(message['attachments'], key=lambda f: f['name'])
        assert [f['name'] for f in actual] == ['card.png', 'card.svg']
        assert actual[0]['media_type'] == 'image/png' and actual[0]['byte_length'] > 1024 * 1024
        assert actual[1]['media_type'] == 'image/svg+xml'
        if expected is not None:
            before = sorted(expected, key=lambda f: f['name'])
            for a, b in zip(actual, before):
                assert a['id'] != b['id'], 'forwarding reused an encrypted object'
                assert {k: v for k, v in a.items() if k != 'id'} == {k: v for k, v in b.items() if k != 'id'}
        return actual

    def exported(result, state, files):
        outputs = result['tools'].get('gent_file_export', [])
        expected = {f['id']: f for f in files}
        assert {out['file']['id'] for out in outputs} == set(expected), 'host omitted a native export'
        actual = {f['path']: f for f in state()['exports']}
        for out in outputs:
            descriptor = expected[out['file']['id']]
            assert out['file'] == descriptor
            assert actual[out['path']]['sha256'] == descriptor['sha256']
            assert actual[out['path']]['byte_length'] == descriptor['byte_length']

    first = local('native-source',
        'Call gent_identity and gent_agents. Use the native fixture helper to render a red left card to disk. '
        'Call gent_file_paths, stage both actual files, and import them with gent_file_import, distinct UUIDv7s from gent_request_ids, '
        'and their correct media types. Send their file IDs to visual-reviewer with gent_send and a UUIDv7 from gent_request_ids. '
        f'Use exactly "{marker}: inspect these native files" as message text. Do not inline base64. Stop after sending.')
    identity(first, aid)
    imports = [result['file'] for result in first['tools']['gent_file_import']]
    assert len(imports) == 2
    first_id = one(first, 'gent_send')['message_id']
    initial = received(remote_state, first_id)
    assert initial['sender'] == aid and initial['recipient'] == bid
    first_files = attachments(initial, imports)
    print('Real host imported and sent a PNG larger than 1 MiB plus SVG through Gent', flush=True)
    offline()
    feedback = remote('native-feedback',
        'Call gent_identity and gent_inbox. Check and export both received attachments with gent_file_status and gent_file_export. '
        'Open the exported PNG with your native image tool and inspect it. The acceptance criteria are a green dot in the upper right and an unchanged blue panel. '
        'Acknowledge the message. Render a green right reference with the native helper, stage and import both files, '
        'then use gent_reply with the new file_ids and a UUIDv7 from gent_request_ids. Start text with "OBSERVED: COLOR SIDE" using the dot you actually see, '
        'and explain the needed correction. Do not inline base64. Stop after replying.')
    identity(feedback, bid)
    exported(feedback, remote_state, first_files)
    feedback_id = one(feedback, 'gent_reply')['message_id']
    answer = message(remote_state, feedback_id)
    assert answer['reply_to'] == first_id and answer['text'].lower().startswith('observed: red left')
    reference = attachments(answer, [f['file'] for f in feedback['tools']['gent_file_import']])
    restart()
    received(local_state, feedback_id)
    revision = local('native-revision',
        'Call gent_identity and gent_inbox. Export and open the feedback PNG with your native image tool; also export the SVG. '
        'Acknowledge that message. Use the native helper to render the requested revision to disk, stage and import both files, '
        'and reply to the feedback with gent_reply, UUIDv7 from gent_request_ids, file_ids, and a brief description of the change. Do not inline base64.')
    identity(revision, aid)
    exported(revision, local_state, reference)
    revision_id = one(revision, 'gent_reply')['message_id']
    revised = received(remote_state, revision_id)
    assert revised['reply_to'] == feedback_id
    revised_files = attachments(revised, [f['file'] for f in revision['tools']['gent_file_import']])
    approved = remote('native-approval',
        'Call gent_identity and gent_inbox. Export both revised attachments and open the PNG using your native image tool. '
        'Check your earlier acceptance criteria. Acknowledge it and reply with a UUIDv7 from gent_request_ids, no files, '
        'and exactly "APPROVED: green right" if the image passes. Otherwise describe its defect.')
    identity(approved, bid)
    exported(approved, remote_state, revised_files)
    approval_id = one(approved, 'gent_reply')['message_id']
    approval = received(local_state, approval_id)
    assert approval['reply_to'] == revision_id and approval['text'] == 'APPROVED: green right'
    print('Both real hosts exported and inspected images; visual revision survived both daemon restarts', flush=True)

    grant = owner('relay', 'grant', aid, bid, '--ttl-seconds', '3600')
    wait_for(lambda: local_state()['config']['applied_revision'] == grant['revision'], 'native relay grant')
    user_text = marker + '\nReview the revised files and return them unchanged.\nKeep  two spaces; tab\there.\n'
    forward = local('native-relay-forward',
        'Call gent_identity and acknowledge the final approval. I now want relay mode to visual-reviewer. Discover and attach '
        'using the supplied owner grant. Forward one new user turn using gent_relay_send and the file IDs you imported for your revision. '
        'Copy this JSON text value unchanged, including whitespace: ' + json.dumps(user_text) +
        '. Check the turn once and report pending. Do not resubmit or convert files to base64.')
    identity(forward, aid)
    turn_id = one(forward, 'gent_relay_send')['turn_id']
    request = received(remote_state, turn_id)
    assert request['text'] == user_text
    relay_files = attachments(request, revised_files)
    assert one(forward, 'gent_relay_turn_status')['state'] == 'pending'
    result_marker = 'NATIVE_RESPONSE_' + uuid.uuid4().hex
    response = remote('native-relay-response',
        'Call gent_identity and gent_relay_next. Export both request files and open the PNG with your native image tool. '
        'Acknowledge the request, then use gent_relay_respond with a complete outcome and a UUIDv7 from gent_request_ids. '
        'Return the same received file IDs in file_ids; do not reimport or inline their bytes. '
        'Use exactly "' + result_marker + ': COLOR SIDE" as the text, substituting the dot color and side you see.')
    identity(response, bid)
    exported(response, remote_state, relay_files)
    response_id = one(response, 'gent_relay_respond')['message_id']
    restart()
    final = received(local_state, response_id)
    final_files = attachments(final, relay_files)
    assert final['text'] == result_marker + ': green right'
    presentation = local('native-relay-present',
        'Call gent_identity and gent_relay_status. Retrieve the existing turn response, export both attachments for the user, '
        'and open the PNG with your native image tool. Acknowledge the response. Give exactly the target response text as your final answer. '
        'Do not summarize it, resend work, or inline base64. Then disengage relay mode with gent_relay_detach.')
    identity(presentation, aid)
    exported(presentation, local_state, final_files)
    assert presentation['final_text'] == final['text']
    assert not presentation['tools'].get('gent_relay_send')
    assert one(presentation, 'gent_relay_turn_status')['state'] == 'completed'
    assert one(presentation, 'gent_relay_detach')['state'] == 'detached'
    wait_for(lambda: message(remote_state, response_id)['acknowledged'], 'native relay receipt')
    ids = [first_id, feedback_id, revision_id, approval_id, turn_id, response_id]
    assert len(set(ids)) == 6
    for state in (local_state(), remote_state()):
        assert {m['id'] for m in state['messages']} == set(ids), 'unexpected native proof message'
    print('Real intermediary faithfully relayed private text and exported original file bytes after restart', flush=True)
    return {'result': 'passed', 'scenario': 'native-files', 'marker': marker, 'response_marker': result_marker,
            'builder_agent': aid, 'reviewer_agent': bid, 'message_ids': ids,
            'png_bytes': first_files[0]['byte_length'], 'file_ids': [f['id'] for fs in (first_files, reference, revised_files, relay_files, final_files) for f in fs]}
