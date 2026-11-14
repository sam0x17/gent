"""Native MCP file checks shared with the foreground gateway proof.

Local stdio import and synthetic remote HTTP reads. No provider calls.
"""
import base64
import hashlib
import json
from pathlib import Path
import random
import struct
import zlib

from smoke_mcp import Client


def png():
    def chunk(kind, data):
        return (struct.pack('>I', len(data)) + kind + data
                + struct.pack('>I', zlib.crc32(kind + data)))
    rng = random.Random(73)
    pixels = b''.join(b'\0' + rng.randbytes(1024 * 3) for _ in range(1024))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', 1024, 1024, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(pixels)) + chunk(b'IEND', b''))


class FileChecks:
    def __init__(self, binary, home, cli, rpc, token, first, second):
        self.cli, self.rpc, self.token = cli, rpc, token
        self.first, self.second = first, second
        self.cluster = first['cluster_id']
        self.image = png()
        assert 1024**2 < len(self.image) < 4 * 1024**2
        self.bytes = bytes(range(256)) * (32 * 4096)
        self.ids = []
        self.local = Client([str(binary), '--home', str(home), 'mcp', 'serve',
                             '--binding', str(home / 'file-proof.key')])
        try:
            self.source = self.local.call('gent_register', {'name': 'file-source', 'provider': 'generic'})[0]['agent']['id']
            for actor, peer in [(self.source, first['agent']['id']),
                                (first['agent']['id'], self.source),
                                (first['agent']['id'], second['agent']['id']),
                                (second['agent']['id'], first['agent']['id'])]:
                cli('permission', 'allow', actor, peer, '--permission', 'enumerate', 'send', 'receive')
            folder = Path(self.local.call('gent_file_paths')[0]['import_directory'])
            for name, mime, data in [('source.png', 'image/png', self.image),
                                     ('source.bin', 'application/octet-stream', self.bytes),
                                     ('empty.bin', 'application/octet-stream', b'')]:
                (folder / name).write_bytes(data)
                file = self.local.call('gent_file_import', {
                    'name': name, 'media_type': mime, 'request_id': self.local.request_id(),
                })[0]['file']
                # The shared local tool surface works too, without exports.
                part = self.local.call('gent_file_read', {'file_id': file['id'], 'chunk_index': 0})[0]
                assert base64.b64decode(part['data_base64'], validate=True) == data[:256 * 1024]
                self.ids.append(file['id'])
            self.local.call('gent_send', {'recipient': first['agent']['id'],
                'request_id': self.local.request_id(), 'text': 'file read proof', 'file_ids': self.ids})
        finally:
            self.local.close()
        messages = self.call('gent_inbox', {})[0]
        self.files = messages[0]['attachments']
        self.call('gent_ack', {'message_id': messages[0]['id']})
        self.saved = self.call('gent_file_read', {'file_id': self.files[1]['id'], 'chunk_index': 0})[0]
        self.call('gent_register', {'name': 'outsider', 'provider': 'synthetic'}, chat='outsider')
        for name in ['gent_file_read', 'gent_file_view']:
            args = {'file_id': self.files[0]['id']}
            if name == 'gent_file_read':
                args['chunk_index'] = 0
            self.call(name, args, chat='two', error=True)
            self.call(name, args, chat='outsider', error=True)
            self.call(name, dict(args, file_id=self.ids[0]), error=True)
            self.call(name, dict(args, path='/etc/passwd'), error=True)
            result = rpc('tools/call', {'name': name, 'arguments': args}, token)
            assert result['result']['isError'] is True
        for index in [-1, 128, 2**32, 0.5, '0']:
            self.call('gent_file_read', {'file_id': self.files[0]['id'], 'chunk_index': index}, error=True)
        tools = rpc('tools/list', {}, token)['result']['tools']
        names = {tool['name'] for tool in tools}
        assert {'gent_file_read', 'gent_file_view'} <= names
        assert not names & {'gent_file_paths', 'gent_file_import', 'gent_file_export'}
        for name in ['gent_file_paths', 'gent_file_import', 'gent_file_export']:
            self.call(name, {}, error=True)

    def call(self, name, arguments, chat='one', error=False):
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments,
                         '_meta': {'test/conversation': chat}}, self.token)
        if error:
            assert 'error' in result or result.get('result', {}).get('isError'), result
            return result
        assert 'error' not in result and not result['result'].get('isError'), result
        return json.loads(result['result']['content'][0]['text']), result['result']

    def after_restart(self):
        assert self.call('gent_file_read', {'file_id': self.files[1]['id'], 'chunk_index': 0})[0] == self.saved
        for file, expected in zip(self.files, [self.image, self.bytes, b'']):
            recovered, index = bytearray(), 0
            while index is not None:
                part = self.call('gent_file_read', {'file_id': file['id'], 'chunk_index': index})[0]
                data = base64.b64decode(part['data_base64'], validate=True)
                assert part['file'] == file and part['chunk_index'] == index
                assert part['offset'] == len(recovered) and part['byte_length'] == len(data)
                assert len(data) <= 256 * 1024
                recovered.extend(data)
                index = part['next_chunk_index']
            assert recovered == expected and len(recovered) == file['byte_length']
            assert hashlib.sha256(recovered).hexdigest() == file['sha256']
        viewed, raw = self.call('gent_file_view', {'file_id': self.files[0]['id']})
        assert viewed == {'file': self.files[0]} and len(raw['content']) == 2
        assert raw['content'][1]['type'] == 'image' and raw['content'][1]['mimeType'] == 'image/png'
        assert base64.b64decode(raw['content'][1]['data'], validate=True) == self.image
        self.call('gent_file_view', {'file_id': self.files[1]['id']}, error=True)
        self.call('gent_file_view', {'file_id': self.files[2]['id']}, error=True)
        request = self.call('gent_request_ids', {})[0]['request_ids'][0]
        self.call('gent_send', {'recipient': self.second['agent']['id'], 'request_id': request,
                  'text': 'forwarded image', 'file_ids': [self.files[0]['id']]})
        incoming = self.call('gent_inbox', {}, chat='two')[0][0]['attachments'][0]
        assert incoming['id'] != self.files[0]['id']
        forwarded = self.call('gent_file_view', {'file_id': incoming['id']}, chat='two')[1]
        assert base64.b64decode(forwarded['content'][1]['data'], validate=True) == self.image
        self.cli('--cluster', self.cluster, 'permission', 'deny', self.first['agent']['id'],
                 self.source, '--permission', 'receive')
        for name, args in [('gent_file_read', {'chunk_index': 0}), ('gent_file_view', {})]:
            self.call(name, dict(args, file_id=self.files[0]['id']), error=True)
        self.cli('--cluster', self.cluster, 'agent', 'revoke', self.second['agent']['id'])
        self.call('gent_file_view', {'file_id': incoming['id']}, chat='two', error=True)

