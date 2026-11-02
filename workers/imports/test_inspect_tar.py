import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from inspect_archive import inspect, Rejected, MAX_ENTRY


def archive(items, format=tarfile.USTAR_FORMAT):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=format) as target:
        for name, content in items:
            member = name if isinstance(name, tarfile.TarInfo) else tarfile.TarInfo(name)
            member.size = len(content)
            target.addfile(member, io.BytesIO(content))
    return stream.getvalue()


def changed(data, start, value):
    result = bytearray(data)
    result[start:start+len(value)] = value
    result[148:156] = b'        '
    result[148:156] = f'{sum(result[:512]):06o}\0 '.encode('ascii')
    return bytes(result)


class TarTests(unittest.TestCase):
    def test_formats_bind_original_and_each_member(self):
        directory = tarfile.TarInfo('src/')
        directory.type = tarfile.DIRTYPE
        payload = b'{"dependencies":{"react":"synthetic-only"}}'
        source = archive([(directory, b''), ('package.json', payload), ('src/a.py', b'# inert')])
        for format, data in [('tar', source), ('tar.gz', gzip.compress(source, mtime=0))]:
            with self.subTest(format=format):
                result = inspect(data, 'untrusted-name.bin', format)
                self.assertEqual(result['input']['format'], format)
                self.assertEqual(result['input']['sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(result['expandedBytes'], len(payload) + 7)
                self.assertEqual(result['entries'][1]['sha256'], hashlib.sha256(payload).hexdigest())
                self.assertTrue(result['entries'][0]['directory'])
                self.assertIn('react', [t['name'] for t in result['technologies']])

    def test_empty_and_prefixed_long_paths(self):
        self.assertEqual(inspect(archive([]), format='tar')['entries'], [])
        path = 'parent/' * 20 + 'source.txt'
        self.assertEqual(inspect(archive([(path, b'x')]), format='tar')['entries'][0]['path'], path)

    def test_path_traversal_portable_and_prefix_collisions(self):
        for name in ['../escape', '/absolute', 'C:/escape', 'a\\b', 'a//b', './source', 'NUL.txt', 'a./file', 'a\n.txt']:
            with self.subTest(name=name), self.assertRaises(Rejected):
                inspect(archive([(name, b'x')]), format='tar')
        for names in [('a', 'A'), ('é', 'e\u0301'), ('a', 'a/file'), ('a/file', 'a')]:
            with self.subTest(names=names), self.assertRaises(Rejected):
                inspect(archive([(name, b'x') for name in names]), format='tar')
        with self.assertRaises(Rejected):
            inspect(changed(archive([('file', b'x')]), 345, b'../\0'), format='tar')

    def test_links_devices_extensions_and_sparse_rejected(self):
        data = archive([('object', b'')])
        for kind in [b'1', b'2', b'3', b'4', b'6', b'7', b'x', b'g', b'L', b'K', b'S']:
            with self.subTest(kind=kind), self.assertRaises(Rejected):
                inspect(changed(data, 156, kind), format='tar')
        for format in [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT]:
            member = tarfile.TarInfo('a')
            member.pax_headers = {'comment': 'synthetic-extension'}
            with self.assertRaises(Rejected):
                inspect(archive([(member, b'')], format=format), format='tar')

    def test_header_checksum_numeric_and_hidden_text(self):
        source = archive([('source', b'x')])
        cases = [source[:4] + b'X' + source[5:]]
        cases += [changed(source, start, value) for start, value in [
            (124, b'\x80'), (124, b'-0000000001\0'), (124, b'00000000009\0'),
            (6, b'\0hidden'), (257, b'notar'), (500, b'X'), (157, b'target'),
            (329, b'0000001\0'), (0, b'\xff')]]
        for data in cases:
            with self.assertRaises(Rejected):
                inspect(data, format='tar')

    def test_sizes_count_and_aggregate_bounded(self):
        source = archive([('source', b'x')])
        with self.assertRaises(Rejected):
            inspect(changed(source, 124, f'{MAX_ENTRY+1:011o}\0'.encode()), format='tar')
        with self.assertRaises(Rejected):
            inspect(archive([(str(i), b'') for i in range(513)]), format='tar')
        # Exercise the aggregate ceiling without allocating a large fixture in CI.
        with patch('inspect_archive.MAX_TOTAL', 7), self.assertRaises(Rejected):
            inspect(archive([('a', b'abcd'), ('b', b'efgh')]), format='tar')

    def test_directory_and_padding_consistency(self):
        source = archive([('source', b'x')])
        for data in [changed(source, 156, b'5'), changed(source, 0, b'a/\0\0\0\0'), source[:513] + b'X' + source[514:]]:
            with self.assertRaises(Rejected):
                inspect(data, format='tar')

    def test_truncation_end_blocks_and_trailing_data(self):
        source = archive([('source', b'x')])
        for data in [source[:512], source[:1024], source[:1536], source[:-1], source + b'X' * 512, source + source]:
            with self.assertRaises(Rejected):
                inspect(data, format='tar')

    def test_gzip_crc_truncation_concatenation_and_expansion(self):
        source = gzip.compress(archive([('source', b'x')]), mtime=0)
        for data in [source[:-1], source + source, source + b'extra', source[:-8] + b'\0' * 8,
                     gzip.compress(archive([('large', b'A' * 100000)]), mtime=0)]:
            with self.assertRaises(Rejected):
                inspect(data, format='tar.gz')
        with patch('inspect_archive.MAX_TAR_STREAM', 1024), self.assertRaises(Rejected):
            inspect(source, format='tar.gz')

    def test_declared_format_must_match_actual_bytes(self):
        source = archive([('a', b'x')])
        for format, data in [('zip', source), ('tar.gz', source), ('tar', gzip.compress(source)), ('rar', source)]:
            with self.assertRaises(Rejected):
                inspect(data, format=format)

    def test_nested_content_rejected_by_suffix_or_signature(self):
        for name, content in [('inner.tar', b'x'), ('inner.bin', archive([('a', b'x')])), ('inner.gz', b'\x1f\x8b')]:
            with self.assertRaises(Rejected):
                inspect(archive([(name, content)]), format='tar')

    def test_cli_explicit_format_preserves_original_and_creates_no_members(self):
        script = str(Path(__file__).with_name('inspect_archive.py'))
        source = archive([('source.py', b'# never executed')])
        for format, data in [('tar', source), ('tar.gz', gzip.compress(source, mtime=0))]:
            with tempfile.TemporaryDirectory() as root:
                path = Path(root) / 'input.archive'
                path.write_bytes(data)
                result = subprocess.run([sys.executable, '-I', '-B', script, '--consent', '--file', str(path), '--format', format], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['input']['format'], format)
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(list(Path(root).iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
