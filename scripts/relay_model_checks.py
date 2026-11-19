"""Real-host relay assertions, driven by prove_visual.py --relay-turns.

Only the user's initial text/files enter the intermediary's prompt. The target's
private response markers must reach it through Gent. No fixture calls agent RPCs
on behalf of either host. Owner setup and read-only verification stay outside
model context.
"""
import json
import uuid


def exercise_relay(aid, bid, local, remote, owner, local_state, remote_state,
                   offline, restart, files, wait_for):
    source_marker = 'USER_' + uuid.uuid4().hex
    progress_marker = 'PROGRESS_' + uuid.uuid4().hex
    final_marker = 'FINAL_' + uuid.uuid4().hex
    cancel_marker = 'CANCELLED_' + uuid.uuid4().hex
    user_text = f'{source_marker}\nPlease inspect the attached graphic and report the dot color and side. Return the original files.\nKeep this whitespace:  two spaces; tab\there; unicode café →.\n'

    def sent(result, tool):
        values = result['tools'].get(tool, [])
        assert len(values) == 1, f'expected one {tool}, got {len(values)}'
        return values[0]

    def at(state, mid):
        return next((message for message in state()['messages'] if message['id'] == mid), None)

    def verify_identity(result, expected):
        assert sent(result, 'gent_identity')['agent']['id'] == expected

    def unchanged(message):
        assert message['files'] == files, 'file bytes, metadata, or ordering changed'

    def observed(message, marker):
        assert message['text'].startswith(marker + ': ')
        assert message['text'][len(marker) + 2:].lower() == 'red left', 'target misidentified the image'

    def status(result, turn_id, state):
        values = result['tools'].get('gent_relay_turn_status', [])
        assert values and all(value['turn_id'] == turn_id for value in values)
        assert values[-1]['state'] == state, values[-1]['state']
        assert not result['tools'].get('gent_relay_send_non_blocking'), 'checking status submitted new work'
        return values[-1]

    def faithful(result, turn_id, response, state):
        value = status(result, turn_id, state)
        assert value['responses'] == [response], 'new response was omitted or a previous response was repeated'
        assert result['final_text'] == response['text'], 'intermediary rewrote the target response'
        assert sent(result, 'gent_ack')['acknowledged'] is True
        unchanged(value['responses'][0])

    initial = local('relay-forward',
        'Call gent_identity. I want this conversation to act as a relay to visual-reviewer. '
        'Discover that agent, attach using the existing messaging permissions, and forward exactly one user turn below. '
        'The JSON text value is the exact message, including whitespace, and files contains actual user-provided bytes. '
        'Copy those values unchanged. Check the turn once; the target is currently idle, so report pending and stop. '
        'USER_TURN_JSON: ' + json.dumps({'text': user_text, 'files': files}, ensure_ascii=False))
    verify_identity(initial, aid)
    attachment = sent(initial, 'gent_relay_attach')['attachment']
    assert attachment['target'] == bid and attachment['security_mode'] == 'encrypted_daemon_link'
    first = sent(initial, 'gent_relay_send_non_blocking')['turn_id']
    assert initial['tools']['gent_relay_turn_status'][-1]['state'] == 'pending'
    message = wait_for(lambda: at(remote_state, first), 'forwarded user turn')
    assert message['sender'] == aid and message['recipient'] == bid and message['text'] == user_text
    assert message['relay']['attachment_id'] == attachment['id']
    unchanged(message)
    pending = local('relay-pending', 'Call gent_identity. Is there a reply yet? Only check the existing relay turn; do not resend or create work. Stop after that check.')
    verify_identity(pending, aid)
    status(pending, first, 'pending')
    assert any(word in pending['final_text'].lower() for word in ['pending', 'waiting', 'awaiting', 'no reply', 'no response'])
    assert len(local_state()['messages']) == 1, 'pending check duplicated work'
    print('Real intermediary forwarded exact user text/files and checked pending without resending', flush=True)

    offline()
    progress = remote('relay-progress',
        'Call gent_identity and gent_relay_next. Inspect the actual PNG from the current turn, and acknowledge its request. '
        'Report progress, keeping the turn unfinished. Use exactly "' + progress_marker + ': COLOR SIDE" as the response text, '
        'substituting the dot color and side you see in the PNG. Include the original SVG/PNG files unchanged. Do nothing else.')
    verify_identity(progress, bid)
    progress_id = sent(progress, 'gent_relay_respond')['message_id']
    progress_message = at(remote_state, progress_id)
    observed(progress_message, progress_marker)
    assert progress_message['relay']['kind'] == 'progress'
    unchanged(progress_message)
    restart()
    received = wait_for(lambda: at(local_state, progress_id), 'progress after both daemon restarts')
    relay_progress = local('relay-present-progress',
        'Call gent_identity, gent_relay_status, and gent_relay_turns to recover state after restart. '
        'Check the existing pending turn and relay the new target response faithfully, with no summarization or added commentary. '
        'Retrieve its files and acknowledge that response. Your final answer must be exactly the target response text. Submit no new work.')
    verify_identity(relay_progress, aid)
    assert sent(relay_progress, 'gent_relay_status')['attachment']['id'] == attachment['id']
    assert sent(relay_progress, 'gent_relay_turns')['turns'][0]['turn_id'] == first
    faithful(relay_progress, first, received, 'pending')

    finished = remote('relay-complete',
        'Call gent_identity and gent_relay_next to recover your unfinished turn. Finish it now with a complete outcome. '
        'Use exactly "' + final_marker + ': COLOR SIDE" as response text, substituting the color and side from the original image. '
        'Include both original files unchanged. Do not submit any new work.')
    verify_identity(finished, bid)
    assert sent(finished, 'gent_relay_next')['request']['id'] == first
    final_id = sent(finished, 'gent_relay_respond')['message_id']
    final_message = wait_for(lambda: at(local_state, final_id), 'final target response')
    observed(final_message, final_marker)
    assert final_message['relay']['kind'] == 'complete'
    unchanged(final_message)
    presented = local('relay-present-final',
        'Call gent_identity. Check for new responses to the existing relay turn, using after_message_id set to the response you already relayed. '
        'Retrieve the new response and its files, acknowledge it, and give exactly its text as your final answer. Do not replay the earlier progress or submit work.')
    verify_identity(presented, aid)
    faithful(presented, first, final_message, 'completed')
    print('Real intermediary resumed and relayed private target progress/final text and exact files', flush=True)

    followup_text = 'FOLLOWUP_' + uuid.uuid4().hex + ': wait for further instructions; do not start external work.'
    followup = local('relay-followup',
        'Call gent_identity. Forward one new user turn to the currently attached target, with this exact text and no files: '
        + json.dumps(followup_text) + '. Check it once and return pending.')
    verify_identity(followup, aid)
    second = sent(followup, 'gent_relay_send_non_blocking')['turn_id']
    second_message = wait_for(lambda: at(remote_state, second), 'follow-up turn')
    assert second != first and second_message['text'] == followup_text
    assert second_message['relay']['attachment_id'] == attachment['id']
    cancelled = local('relay-cancel-detach',
        'Call gent_identity. Cancel the most recent pending relay turn, then disengage relay mode. '
        'Do not send another work turn. A cancellation request does not prove target execution has stopped.')
    verify_identity(cancelled, aid)
    cancel_id = sent(cancelled, 'gent_relay_cancel')['message_id']
    assert sent(cancelled, 'gent_relay_detach')['state'] == 'detached'
    assert not cancelled['tools'].get('gent_relay_send_non_blocking')
    wait_for(lambda: at(remote_state, cancel_id), 'cancellation request')
    accepted = remote('relay-cancelled',
        'Call gent_identity and gent_relay_next. Handle the cancellation of the current turn without starting its requested work. '
        'Acknowledge the request and send a cancelled outcome with exactly "' + cancel_marker + ': cancellation handled" as text and no files.')
    verify_identity(accepted, bid)
    assert sent(accepted, 'gent_relay_next')['request']['id'] == second
    assert sent(accepted, 'gent_relay_next')['cancel_requested'] is True
    cancelled_id = sent(accepted, 'gent_relay_respond')['message_id']
    cancellation = wait_for(lambda: at(local_state, cancelled_id), 'target cancellation outcome')
    assert cancellation['relay']['kind'] == 'cancelled'
    assert cancellation['text'] == cancel_marker + ': cancellation handled'
    last = local('relay-after-detach',
        'Call gent_identity and gent_relay_status to confirm relay mode is disengaged. Use gent_relay_turns to recover the most recent turn '
        'and check its final cancellation response without attaching again. Retrieve and acknowledge that response; give exactly its text as your final answer. Do not send work.')
    verify_identity(last, aid)
    assert sent(last, 'gent_relay_status') is None
    assert not last['tools'].get('gent_relay_attach')
    result = status(last, second, 'completed')
    assert result['responses'] == [cancellation]
    assert last['final_text'] == cancellation['text']
    assert sent(last, 'gent_ack')['acknowledged'] is True
    ids = {first, progress_id, final_id, second, cancel_id, cancelled_id}
    assert len(ids) == 6
    wait_for(lambda: all(m['acknowledged'] for m in remote_state()['messages'] if m['id'] in [progress_id, final_id, cancelled_id]), 'reply acknowledgments')
    assert {m['id'] for m in local_state()['messages']} == {m['id'] for m in remote_state()['messages']} == ids
    return {'result': 'passed', 'scenario': 'relay-turns', 'intermediary_agent': aid, 'target_agent': bid,
            'attachment_id': attachment['id'], 'turn_ids': [first, second],
            'message_ids': sorted(ids), 'source_marker': source_marker,
            'progress_text': progress_message['text'], 'final_text': final_message['text'],
            'cancelled_text': cancellation['text']}
