import binascii
import hashlib
import io
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from inspect_archive import inspect, Rejected, MAX_ENTRY
from fixture_project import fixture


def archive(items, compression=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(stream, 'w', compression) as output:
            for name, content in items:
                output.writestr(name, content)
    return stream.getvalue()


class ImportTests(unittest.TestCase):
    def test_positive_manifest_hashes_and_indicative_identification(self):
        data = fixture()
        result = inspect(data)
        self.assertTrue(result['quarantineOnly'])
        self.assertEqual(result['input']['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(len(result['entries']), 3)
        self.assertIn('react', [entry['name'] for entry in result['technologies']])
        self.assertIn('api', result['suggestedAnalyses'])
        self.assertTrue(all(e['confidence'] == 'indicative' for e in result['technologies']))

    def test_empty_stored_and_deflated_archives(self):
        self.assertEqual(inspect(archive([]))['entries'], [])
        for method in [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED]:
            self.assertEqual(inspect(archive([('hello.txt', 'hello')], method))['entries'][0]['bytes'], 5)

    def test_portable_path_rejections(self):
        for name in ['../escape', '/absolute', 'C:/escape', 'a\\b', 'a/../b', 'a//b', 'a./b', 'con.txt', 'a\x00b', 'a\n.txt']:
            with self.subTest(name=name), self.assertRaises(Rejected):
                # zipfile truncates NUL on writing; forge a literal NUL in both names instead.
                data = archive([(name if name not in ('a\x00b', 'a\\b') else 'aXb', 'data')])
                if name in ('a\x00b', 'a\\b'):
                    data = data.replace(b'aXb', name.encode())
                inspect(data)

    def test_duplicate_unicode_case_and_parent_collisions(self):
        for paths in [('a.txt', 'a.txt'), ('a.txt', 'A.txt'), ('é.txt', 'e\u0301.txt'), ('a', 'a/b.txt')]:
            with self.subTest(paths=paths), self.assertRaises(Rejected):
                inspect(archive([(path, 'small') for path in paths]))

    def test_symlink_and_special_members(self):
        for kind in [stat.S_IFLNK, stat.S_IFCHR, stat.S_IFIFO, stat.S_IFSOCK]:
            member = zipfile.ZipInfo('object')
            member.create_system = 3
            member.external_attr = (kind | 0o600) << 16
            with self.subTest(kind=kind), self.assertRaises(Rejected):
                inspect(archive([(member, 'destination')]))

    def test_ratio_and_entry_limits(self):
        for data in [archive([('bomb.txt', b'A' * 100000)]), archive([('large', b'A' * (MAX_ENTRY+1))], zipfile.ZIP_STORED), archive([(str(i), '') for i in range(513)])]:
            with self.assertRaises(Rejected):
                inspect(data)

    def test_nested_archives_by_signature_and_suffix(self):
        for path, content in [('nested.bin', fixture()), ('nested.tar', b'data'), ('a.gz', b'\x1f\x8b')]:
            with self.subTest(path=path), self.assertRaises(Rejected):
                inspect(archive([(path, content)]))

    def test_crc_and_truncation(self):
        data = archive([('a', b'hello')], zipfile.ZIP_STORED)
        for bad in [data[:-1], data + b'trailing', data.replace(b'hello', b'jello'), b'not zip']:
            with self.assertRaises(Rejected):
                inspect(bad)

    def test_false_uncompressed_size_does_not_hide_expansion(self):
        data = bytearray(archive([('a', b'hello-world')]))
        central = data.index(b'PK\x01\x02')
        struct.pack_into('<I', data, 22, 1)
        struct.pack_into('<I', data, central + 24, 1)
        with self.assertRaises(Rejected):
            inspect(bytes(data))

    def test_unsupported_flags_and_compression(self):
        for flag in [1, 8, 64]:
            data = bytearray(fixture())
            central = data.index(b'PK\x01\x02')
            struct.pack_into('<H', data, 6, flag)
            struct.pack_into('<H', data, central + 8, flag)
            with self.assertRaises(Rejected):
                inspect(bytes(data))
        with self.assertRaises(Rejected):
            inspect(archive([('a', 'text')], zipfile.ZIP_BZIP2))

    def test_local_central_mismatch(self):
        data = bytearray(fixture())
        data[30] = ord('X')
        with self.assertRaises(Rejected):
            inspect(bytes(data))

    def test_cli_requires_consent_preserves_input_and_creates_no_members(self):
        script = str(Path(__file__).with_name('inspect_archive.py'))
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'input.zip'
            path.write_bytes(fixture())
            original = path.read_bytes()
            denied = subprocess.run([sys.executable, '-I', '-B', script, '--file', str(path)], capture_output=True)
            self.assertNotEqual(denied.returncode, 0)
            result = subprocess.run([sys.executable, '-I', '-B', script, '--consent', '--file', str(path)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(list(Path(root).iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
