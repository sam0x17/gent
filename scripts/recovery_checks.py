"""Signed checkpoint evidence across the physical pairing proof's two nodes."""
import os


SAVE = '''
import os,sys
with os.fdopen(os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600), 'w') as f:
    f.write(sys.stdin.read())
'''
READ = 'import pathlib,sys; sys.stdout.write(pathlib.Path(sys.argv[1]).read_text())'


def exercise(cli, owner, remote, folder, owner_home, restart, wait):
    local = folder / 'recovery-evidence'
    local.mkdir(mode=0o700)
    remote_root = owner_home + '/recovery-evidence'
    remote(['python3', '-c', 'import os,sys; os.mkdir(sys.argv[1], 0o700)', remote_root])
    challenge = local / 'challenge.json'
    local_report = local / 'local.json'
    owner_report = local / 'owner.json'
    remote_challenge = remote_root + '/challenge.json'
    remote_local = remote_root + '/local.json'
    remote_owner = remote_root + '/owner.json'

    def upload(source, target):
        remote(['python3', '-c', SAVE, target], source.read_text())

    def download(source, target):
        data = remote(['python3', '-c', READ, source]).stdout
        with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as f:
            f.write(data)

    def review(command, *paths, complete):
        result = command('recovery', 'inspect', *map(str, paths))
        assert result['all_match_baseline'] is complete, result
        assert not result['authorizes_owner_change']
        assert not result['proves_writer_stopped']
        assert not result['proves_global_freshness']
        assert len(result['missing_nodes']) == (0 if complete else 1)
        assert not result['conflicting_revisions']
        return result

    # A joined node holds no owner signing secret and can still produce a
    # baseline and a node-signed observation using its local owner RPC key.
    revision = owner('cluster')['authority']['revision']
    wait(lambda: cli('cluster')['authority']['revision'] == revision)
    before = cli('recovery', 'challenge', '--out', str(challenge))
    assert before['baseline']['revision'] == revision
    upload(challenge, remote_challenge)
    local_result = cli('recovery', 'witness', str(challenge), '--out', str(local_report))
    owner_result = owner('recovery', 'witness', remote_challenge, '--out', remote_owner)
    assert local_result['node'] != owner_result['node']
    assert local_result['checkpoint'] == owner_result['checkpoint'] == before['baseline']
    download(remote_owner, owner_report)
    upload(local_report, remote_local)
    review(cli, challenge, local_report, complete=False)
    left = review(cli, challenge, local_report, owner_report, complete=True)
    right = review(owner, remote_challenge, remote_local, remote_owner, complete=True)
    assert left == right
    restart()
    post_local = local / 'post-local.json'
    post_remote = remote_root + '/post-owner.json'
    assert cli('recovery', 'witness', str(challenge), '--out', str(post_local))['checkpoint'] == before['baseline']
    assert owner('recovery', 'witness', remote_challenge, '--out', post_remote)['checkpoint'] == before['baseline']
    download(post_remote, local / 'post-owner.json')
    review(cli, challenge, post_local, local / 'post-owner.json', complete=True)
    for path in local.iterdir():
        assert path.stat().st_mode & 0o077 == 0
    print('PASS: private signed recovery evidence on Linux/Mac, missing-node report, matching offline reviews, unchanged checkpoints after both restarts; no replacement authority')
