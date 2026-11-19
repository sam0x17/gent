"""Group membership checks shared by native and physical CLI/MCP proofs."""


def exercise_groups(a, b, aid, bid, owner, restart, wait_for):
    group = 'group-proof'
    assert owner('group', 'new', group)['state'] == 'applied'
    assert group in owner('groups')
    assert owner('group', 'member', 'add', group, aid)['state'] == 'applied'
    owner('permission', 'deny', 'group:' + group, '*', '--permission', 'send')
    grant = owner('group', 'admin', 'grant', aid, group, '*', '--action', 'add', 'remove')['grant_id']
    wait_for(lambda: any(g['grant_id'] == grant for g in a.call('gent_group_admin_scopes')[0]['grants']))
    assert b.call('gent_group_admin_scopes')[0]['grants'] == []
    assert [m['id'] for m in a.call('gent_group_members', {'group': group})[0]['members']] == [aid]
    wait_for(lambda: not a.call('gent_permission_check', {'peer': bid})[0]['policy']['send_unsolicited']['allowed'])
    change = dict(grant_id=grant, group=group, member=aid, action='remove')
    request = {'request_id': a.request_id(), 'changes': [change]}
    preview = a.call('gent_group_preview', {'changes': [change]})[0]
    assert preview['changes'] == [change] and not {'members', 'revision', 'total'} & preview.keys()
    b.call('gent_group_apply', request, error=True)
    a.call('gent_group_apply', dict(request, administrator=bid), error=True)
    a.call('gent_group_apply', request)
    wait_for(lambda: a.call('gent_group_request', {'request_id': request['request_id']})[0]['state'] == 'applied')
    result = a.call('gent_group_request', {'request_id': request['request_id']})[0]
    assert not {'revision', 'writer', 'config_saved', 'config_error'} & result.keys()
    b.call('gent_group_request', {'request_id': request['request_id']}, error=True)
    a.call('gent_permission_apply', {'request_id': request['request_id'], 'changes': []}, error=True)
    restart()
    assert a.call('gent_group_apply', request)[0] == result
    wait_for(lambda: a.call('gent_permission_check', {'peer': bid})[0]['policy']['send_unsolicited']['allowed'])
    sent = a.call('gent_send_non_blocking', {'request_id': a.request_id(), 'recipient': bid, 'text': 'group membership enabled delivery'})[0]
    wait_for(lambda: any(m['id'] == sent['message_id'] for m in b.call('gent_inbox')[0]))
    b.call('gent_ack', {'message_id': sent['message_id']})
    for action in ('add', 'remove'):
        changed = {'request_id': a.request_id(), 'changes': [dict(change, action=action)]}
        a.call('gent_group_apply', changed)
        wait_for(lambda: a.call('gent_group_request', {'request_id': changed['request_id']})[0]['state'] == 'applied')
        wait_for(lambda: a.call('gent_permission_check', {'peer': bid})[0]['policy']['send_unsolicited']['allowed'] == (action == 'remove'))
    assert owner('group', 'show', group)['members'] == []
    owner('group', 'admin', 'revoke', grant)
    wait_for(lambda: a.call('gent_group_admin_scopes')[0]['grants'] == [])
    assert a.call('gent_group_apply', request)[0] == result
    a.call('gent_group_apply', dict(request, request_id=a.request_id()), error=True)
    a.call('gent_group_members', {'group': group}, error=True)
    assert grant in owner('group', 'admin', 'list')['retired']
    audit = owner('group', 'admin', 'history', '--agent', aid)['entries']
    assert len(audit) == 3 and all(r['state'] == 'applied' and r['group_membership'] and r['changes'] and r['revision'] for r in audit)
    assert 'cannot delete a group still referenced' in owner('group', 'delete', group, error=True)
    assert owner('group', 'new', 'unused-group')['state'] == 'applied'
    assert owner('group', 'delete', 'unused-group')['state'] == 'applied'
