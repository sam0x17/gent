"""Bearer download checks using the foreground gateway's real file fixtures."""
import hashlib
import sqlite3
import time
import urllib.error
import urllib.request


class DownloadChecks:
    def __init__(self, home, files):
        self.home, self.files = home, files
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.links = []
        self.expected = [files.image, files.bytes, b'']
        for file in files.files:
            linked, raw = files.call('gent_file_link', {'file_id': file['id']})
            assert linked['file'] == file and linked['access'] == 'bearer_url'
            assert time.time() - 1 < linked['expires_at'] <= time.time() + 300
            resource = raw['content'][1]
            assert resource == {'type': 'resource_link', 'uri': linked['download_url'],
                                'name': file['name'], 'mimeType': file['media_type'],
                                'size': file['byte_length']}
            self.links.append(linked['download_url'])
            files.call('gent_file_link', {'file_id': file['id']}, chat='two', error=True)
        files.call('gent_file_link', {'file_id': files.ids[0]}, error=True)
        files.call('gent_file_link', {'file_id': files.files[0]['id'], 'path': '/tmp'}, error=True)
        missing = files.rpc('tools/call', {'name': 'gent_file_link',
                           'arguments': {'file_id': files.files[0]['id']}}, files.token)
        assert missing['result']['isError']
        self.verify_bytes()
        headers, data = self.fetch(self.links[1], method='HEAD')
        assert not data and int(headers['Content-Length']) == len(files.bytes)
        self.fetch(self.links[1], headers={'Range': 'bytes=0-9'}, expected=416)
        self.fetch(self.links[0] + 'x', expected=404)
        self.fetch(self.links[0] + '?extra=1', expected=403)
        self.fetch(self.links[0], method='POST', expected=405)

    def fetch(self, url, method='GET', headers=None, expected=200):
        request = urllib.request.Request(url, method=method,
                                        headers=headers or {'Origin': 'https://host.example'})
        try:
            response = self.opener.open(request, timeout=40)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.code == expected, f'expected {expected}, got {response.code}'
            data = response.read(32 * 1024**2 + 1)
            if expected == 404:
                assert data == b'', 'failure exposed response bytes'
            return response.headers, data

    def verify_bytes(self):
        for url, data, file in zip(self.links, self.expected, self.files.files):
            headers, recovered = self.fetch(url)
            assert recovered == data and hashlib.sha256(recovered).hexdigest() == file['sha256']
            assert headers['Content-Type'] == file['media_type']
            assert headers['Cache-Control'] == 'no-store'
            assert headers['Referrer-Policy'] == 'no-referrer'
            assert headers['X-Content-Type-Options'] == 'nosniff'
            assert headers['Access-Control-Allow-Origin'] == '*'
            assert headers['Content-Disposition'].startswith('attachment;')
            assert 'sandbox' in headers['Content-Security-Policy']

    def after_restart(self):
        self.verify_bytes()
        # Corrupt a later chunk: the first verified chunk must not escape.
        file_id = self.files.files[1]['id']
        with sqlite3.connect(self.home / 'state.sqlite3', timeout=10) as db:
            ciphertext, = db.execute('SELECT ciphertext FROM file_chunks WHERE object_id=? AND position=1',
                                     (file_id,)).fetchone()
            db.execute('UPDATE file_chunks SET ciphertext=zeroblob(length(ciphertext)) WHERE object_id=? AND position=1',
                       (file_id,))
        try:
            self.fetch(self.links[1], expected=404)
        finally:
            with sqlite3.connect(self.home / 'state.sqlite3', timeout=10) as db:
                db.execute('UPDATE file_chunks SET ciphertext=? WHERE object_id=? AND position=1',
                           (ciphertext, file_id))
        # Failed verification must release its response capacity.
        assert self.fetch(self.links[1])[1] == self.files.bytes

    def after_permission_change(self):
        for link in self.links:
            self.fetch(link, expected=404)

    def check_logs(self, paths):
        for path in paths:
            text = path.read_text()
            for link in self.links:
                assert link not in text and link.split('/files/')[1] not in text
