"""Real CLI host-file inputs and bounded local binary import framing.

The public PNG is a synthetic host file, not a provider attachment. The binary
framing checks use only a disposable node and its own test agent credential.
"""
import base64
import hashlib
import json
import socket
import time
import urllib.request

from smoke_mcp import Client

ORIGIN = 'https://raw.githubusercontent.com'
URL = ORIGIN + '/github/explore/main/topics/rust/rust.png'


class InputChecks:
    def __init__(self, binary, home, cli, rpc, token):
        self.home, self.cli, self.rpc, self.token = home, cli, rpc, token
        initial = cli('files')
        self.args = {'request_id': self.call('gent_request_ids', {})['request_ids'][0],
                     'file': {'file_id': 'synthetic-public-png', 'file_name': 'rust.png',
                              'mime_type': 'image/png', 'download_url': URL}}
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(URL, timeout=15) as response:
            self.png = response.read(1024 * 1024 + 1)
            assert self.png.startswith(b'\x89PNG') and len(self.png) <= 1024 * 1024
        imported = self.call('gent_file_import_remote', self.args)
        self.file = imported['file']
        assert imported['duplicate'] is False
        assert self.file['sha256'] == hashlib.sha256(self.png).hexdigest()
        self.view()
        binding = home / 'binary-input.key'
        local = Client([str(binary), '--home', str(home), 'mcp', 'serve', '--binding', str(binding)])
        try:
            local.call('gent_register', {'name': 'binary-input', 'provider': 'generic'})
            self.credential = binding.read_text().strip()
            self.native_file = {'request_id': local.request_id(), 'source_id': 'a' * 64,
                                'name': 'large.bin', 'media_type': 'application/octet-stream'}
            self.bytes = bytes(range(256)) * (32 * 4096)
            # The source may send no body or the wrong size/hash. Nothing commits.
            for content, size, digest in [(b'', 1, hashlib.sha256(b'x').hexdigest()),
                                          (b'xx', 1, hashlib.sha256(b'x').hexdigest()),
                                          (b'x', 1, hashlib.sha256(b'y').hexdigest())]:
                assert self.binary(self.native_file, content, size=size, digest=digest) is None
            assert self.cli('files')['objects']['count'] == initial['objects']['count'] + 1
            assert self.binary(self.native_file, b'', size=32 * 1024**2 + 1, error=True)
            # Two stalled bodies occupy the two ingress slots; a third is refused.
            held = []
            try:
                for _ in range(2):
                    pending = dict(self.native_file, request_id=local.request_id())
                    connection, reader, check = self.open_binary(pending, 1, hashlib.sha256(b'x').hexdigest())
                    held.append((connection, reader))
                    assert check['status'] == 'ok' and check['data']['state'] == 'upload'
                assert self.binary(self.native_file, b'', error=True)['data'].startswith('file import busy')
            finally:
                for connection, reader in held:
                    reader.close()
                    connection.close()
            time.sleep(.1)
            created = self.binary(self.native_file, self.bytes)
            self.native_id = created['file']['id']
            assert created['duplicate'] is False
            duplicate = self.binary(self.native_file, self.bytes)
            assert duplicate['file'] == created['file'] and duplicate['duplicate'] is True
            # Completed IDs reject a different length/digest before reading a body.
            assert self.binary(self.native_file, b'changed', error=True)
            recovered = bytearray()
            for index in range(128):
                chunk = local.call('gent_file_read', {'file_id': self.native_id, 'chunk_index': index})[0]
                recovered.extend(base64.b64decode(chunk['data_base64'], validate=True))
            assert recovered == self.bytes
            assert self.cli('files')['handoffs']['reserved_copies'] == initial['handoffs']['reserved_copies']
        finally:
            local.close()

    def call(self, name, arguments):
        value = self.rpc('tools/call', {'name': name, 'arguments': arguments,
                         '_meta': {'test/conversation': 'one'}}, self.token)
        assert 'error' not in value and not value['result'].get('isError'), value
        return json.loads(value['result']['content'][0]['text'])

    def view(self):
        result = self.rpc('tools/call', {'name': 'gent_file_view', 'arguments': {'file_id': self.file['id']},
                          '_meta': {'test/conversation': 'one'}}, self.token)['result']
        assert not result.get('isError')
        assert base64.b64decode(result['content'][1]['data'], validate=True) == self.png

    def open_binary(self, file, size, digest):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(15)
        connection.connect(str(self.home / 'daemon.sock'))
        header = {'role': 'agent', 'credential': self.credential, 'action': {
            'op': 'file_receive', 'file': file, 'byte_length': size, 'sha256': digest}}
        connection.sendall(json.dumps(header).encode() + b'\n')
        reader = connection.makefile('rb')
        return connection, reader, json.loads(reader.readline())

    def binary(self, file, data, size=None, digest=None, error=False):
        connection, reader, check = self.open_binary(file, len(data) if size is None else size,
                                                      digest or hashlib.sha256(data).hexdigest())
        with connection:
            with reader:
                if error:
                    assert check['status'] == 'error', check
                    return check
                assert check['status'] == 'ok', check
                if check['data']['state'] == 'ready':
                    return check['data']
                assert check['data']['state'] == 'upload'
                connection.sendall(data)
                connection.shutdown(socket.SHUT_WR)
                response = reader.readline()
                if not response:
                    return None
                result = json.loads(response)
                assert result['status'] == 'ok', result
                return result['data']

    def after_restart(self):
        # This URL deliberately returns 404. A completed retry must avoid it.
        self.args['file']['download_url'] = ORIGIN + '/gent-proof-absent/private-expired-url'
        repeated = self.call('gent_file_import_remote', self.args)
        assert repeated['duplicate'] is True and repeated['file'] == self.file
        self.view()
        assert self.binary(self.native_file, self.bytes)['file']['id'] == self.native_id
