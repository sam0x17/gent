#!/usr/bin/env python3
"""Exercise plaintext quotas and interrupted exports through native CLI/MCP.

Only disposable state is modified. No model calls or permanent services.
"""
import json
import argparse
from pathlib import Path
import signal
import sqlite3
import subprocess
import tempfile
import time

from smoke_mcp import Client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', nargs='?', default='target/debug/gent')
    parser.add_argument('--size-mib', type=int, choices=(2, 32), default=2)
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    with tempfile.TemporaryDirectory(prefix='gent-handoffs-', dir='/tmp') as directory:
        home = Path(directory).resolve() / 'state'
        base = [binary, '--home', str(home)]
        daemon = None
        client = None

        def cli(*args, structured=True):
            output = subprocess.check_output(base + (['--json'] if structured else []) + list(args), text=True)
            return json.loads(output) if structured else output

        def sql(statement, values=()):
            with sqlite3.connect(home / 'state.sqlite3') as db:
                db.execute(statement, values)

        def start():
            nonlocal daemon
            daemon = subprocess.Popen(base + ['daemon', 'run'], stdout=subprocess.DEVNULL,
                                      stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 15
            while subprocess.run(base + ['daemon', 'status'], capture_output=True).returncode:
                assert daemon.poll() is None and time.monotonic() < deadline, 'daemon startup failed'
                time.sleep(.05)

        def stop(crash=False):
            nonlocal daemon
            if daemon and daemon.poll() is None:
                daemon.send_signal(signal.SIGKILL if crash else signal.SIGTERM)
                assert daemon.wait(timeout=10) == (-signal.SIGKILL if crash else 0)
            if daemon:
                daemon.stderr.close()
                daemon = None

        def exported(file_id, error=False):
            return client.call('gent_file_export', {'file_id': file_id}, error=error)

        try:
            cli('cluster', 'new', 'handoff-proof', '--local')
            start()
            client = Client(base + ['mcp', 'serve', '--binding', str(home / 'builder.key')])
            agent = client.call('gent_register', {'name': 'builder', 'provider': 'generic'})[0]['agent']['id']
            source = Path(client.call('gent_file_paths')[0]['import_directory']) / 'source.bin'
            content = bytes(range(256)) * (args.size_mib * 4096)
            source.write_bytes(content)
            request = {'request_id': client.request_id(), 'name': source.name, 'media_type': 'application/octet-stream'}
            file_id = client.call('gent_file_import', request)[0]['file']['id']
            sql("""CREATE TRIGGER fail_stage BEFORE UPDATE OF stamp ON file_exports
                BEGIN SELECT RAISE(ABORT,'proof stage failure'); END""")
            assert 'proof stage failure' in json.dumps(exported(file_id, error=True))
            report = cli('files')
            assert report['exports']['pending'] == 1
            temporary = Path(report['exports']['attention'][0]['temporary_path'])
            assert temporary.read_bytes() == content
            assert 'Pending exports: 1' in cli('files', structured=False)
            stop(crash=True)
            # Model the partial file left by an interrupted write, keeping its inode.
            temporary.write_bytes(content[:12345])
            inode = temporary.stat().st_ino
            sql('DROP TRIGGER fail_stage')
            start()
            output = Path(exported(file_id)[0]['path'])
            assert output.read_bytes() == content and output.stat().st_ino == inode
            assert not temporary.exists() and cli('files')['exports']['pending'] == 0
            usage = cli('files')['handoffs']
            assert usage['max_copies'] == 4096 and usage['max_bytes'] == 512 * 1024**2
            sql("""INSERT INTO file_exports(id,agent,object_id,name,digest,bytes,expires_at)
                VALUES('proof-fixture',?,'proof-fixture','fixture','',?,0)""",
                (agent, usage['max_bytes'] - usage['reserved_bytes']))
            assert client.call('gent_file_import', request)[0]['file']['id'] == file_id
            assert Path(exported(file_id)[0]['path']) == output
            output.unlink()
            assert 'plaintext handoff quota' in json.dumps(exported(file_id, error=True))
            assert not output.exists()
            sql("DELETE FROM file_exports WHERE id='proof-fixture'")
            sql("""CREATE TRIGGER fail_publish BEFORE INSERT ON file_handoffs WHEN NEW.slot<>''
                BEGIN SELECT RAISE(ABORT,'proof publication failure'); END""")
            assert 'proof publication failure' in json.dumps(exported(file_id, error=True))
            assert output.read_bytes() == content and cli('files')['exports']['pending'] == 1
            stop()
            start()
            sql('DROP TRIGGER fail_publish')
            assert Path(exported(file_id)[0]['path']) == output
            assert cli('files')['exports']['pending'] == 0
            output.unlink()
            sql("""CREATE TRIGGER fail_publish BEFORE INSERT ON file_handoffs WHEN NEW.slot<>''
                BEGIN SELECT RAISE(ABORT,'proof publication failure'); END""")
            assert 'proof publication failure' in json.dumps(exported(file_id, error=True))
            sql('UPDATE file_exports SET expires_at=1,next_attempt=0')
            assert cli('files', 'clean', '--dry-run')['exports']['removed'] == 1
            assert output.exists()
            assert cli('files', 'clean')['exports']['removed'] == 1
            assert not output.exists() and cli('files')['exports']['pending'] == 0
            with sqlite3.connect(home / 'state.sqlite3') as db:
                assert db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
                assert not db.execute('PRAGMA foreign_key_check').fetchall()
            print(f'PASS: {args.size_mib} MiB plaintext quota and CLI diagnostics, exact retries at capacity, failed publication recovery, partial-file fixture resumed after process kill, same inode, bounded cleanup')
        finally:
            if client:
                client.close()
            stop()


if __name__ == '__main__':
    main()
