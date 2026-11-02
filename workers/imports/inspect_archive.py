"""Bounded offline ZIP and USTAR inspection. Never extracts or executes archive members."""
import argparse
import binascii
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import struct
import unicodedata
import zipfile
import zlib

MAX_INPUT = 16 * 1024 * 1024
MAX_ENTRY = 8 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_ENTRIES = 512
MAX_RATIO = 100
MAX_TAR_STREAM = MAX_TOTAL + MAX_ENTRIES * 1024 + 10240


class Rejected(ValueError):
    pass


def safe_path(name):
    if not name or len(name) > 512 or '\\' in name or ':' in name or name.startswith('/'):
        raise Rejected('Unsafe member path')
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise Rejected('Control character in member path')
    parts = name.rstrip('/').split('/')
    reserved = re.compile(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', re.I)
    if any(p in ('', '.', '..') or p.endswith((' ', '.')) or reserved.match(p) for p in parts):
        raise Rejected('Unsafe portable member path')
    return unicodedata.normalize('NFC', name.rstrip('/')).casefold()


def observe(path, content, directory, entries, technologies, suggestions):
    if content[257:262] == b'ustar' or content.startswith((b'PK\x03\x04', b'PK\x05\x06', b'\x1f\x8b', b'7z\xbc\xaf\x27\x1c', b'Rar!')) or path.lower().endswith(('.zip', '.tar', '.tar.gz', '.tgz', '.gz', '.7z', '.rar', '.apk', '.aab', '.ipa', '.jar', '.war')):
        raise Rejected('Nested archives are not supported')
    entries.append({'path': path, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'directory': directory})
    base = path.rsplit('/', 1)[-1].lower()
    language = {'package.json': 'JavaScript/TypeScript', 'pyproject.toml': 'Python', 'requirements.txt': 'Python', 'cargo.toml': 'Rust', 'go.mod': 'Go', 'pom.xml': 'Java'}.get(base)
    if language:
        technologies.append({'name': language, 'basis': path, 'confidence': 'indicative'})
        suggestions.add('securebuild')
    if base in ('package-lock.json', 'bom.json'):
        suggestions.add('dependency')
    if base in ('openapi.json', 'swagger.json'):
        suggestions.add('api')
    if base == 'package.json' and len(content) <= 65536:
        try:
            package = json.loads(content)
            for group in ('dependencies', 'devDependencies'):
                dependencies = package.get(group, {}) if isinstance(package, dict) else {}
                if isinstance(dependencies, dict):
                    for framework in ('react', 'vite', 'next', 'fastify', 'express'):
                        if framework in dependencies:
                            technologies.append({'name': framework, 'basis': path, 'confidence': 'indicative'})
        except (ValueError, RecursionError, UnicodeError):
            pass


def check_collisions(seen):
    for key in seen:
        parts = key.split('/')
        for i in range(1, len(parts)):
            if '/'.join(parts[:i]) in seen and not seen['/'.join(parts[:i])]:
                raise Rejected('File/directory collision')


def make_report(data, name, format, entries, technologies, suggestions, total):
    return {'schemaVersion': '1.0', 'engine': 'Sentinel Import Inspector', 'engineVersion': '1.1.0',
            'input': {'name': name, 'format': format, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data), 'unchanged': True},
            'quarantineOnly': True, 'entries': entries, 'expandedBytes': total, 'technologies': technologies,
            'suggestedAnalyses': sorted(suggestions), 'limitations': [
                ('ZIP armazenado ou deflate, sem volumes, ZIP64 ou descritores.' if format == 'zip' else
                 'USTAR UTF-8 regular/diretório, sem PAX, extensões GNU, sparse ou metadados binários. Gzip: um único membro.'),
                'Links, dispositivos, arquivos especiais e arquivos compactados internos são rejeitados.',
                'Identificação por nomes de manifests e dependências declaradas: indícios, sem execução nem confirmação de versões.',
                'Nenhum arquivo extraído, iniciado ou enviado à rede. Quarentena não equivale a isolamento de máquina virtual.',
                'Sugestões não executam análises. Importação não demonstra ausência de malware ou vulnerabilidades.'
            ]}


def inspect_zip(data, name):
    if not data or len(data) > MAX_INPUT:
        raise Rejected('ZIP input limit exceeded')
    end = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if end < 0 or len(data) - end < 22:
        raise Rejected('ZIP end record missing')
    _, disk, directory_disk, disk_count, count, directory_size, directory_start, comment_size = struct.unpack_from('<4s4H2IH', data, end)
    if disk or directory_disk or disk_count != count or count > MAX_ENTRIES or directory_start + directory_size != end or end + 22 + comment_size != len(data):
        raise Rejected('Unsupported multi-volume, ZIP64 or noncanonical directory')
    entries, technologies, suggestions, seen, total, offset = [], [], set(), {}, 0, 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) != count:
                raise Rejected('Directory count mismatch')
            for member in sorted(infos, key=lambda item: item.header_offset):
                path = member.orig_filename
                key = safe_path(path)
                if key in seen:
                    raise Rejected('Duplicate or colliding member paths')
                seen[key] = member.is_dir()
                mode = member.external_attr >> 16
                if member.create_system == 3 and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise Rejected('Links and special files are not supported')
                if bool(stat.S_ISDIR(mode)) and not member.is_dir():
                    raise Rejected('Inconsistent directory metadata')
                if member.flag_bits & ~0x800 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or member.extract_version > 20:
                    raise Rejected('Encrypted, descriptor, ZIP64 or unsupported compression')
                if member.file_size > MAX_ENTRY or total + member.file_size > MAX_TOTAL or member.file_size > max(1, member.compress_size) * MAX_RATIO:
                    raise Rejected('Expansion limit exceeded')
                if member.header_offset != offset or offset + 30 > directory_start:
                    raise Rejected('Overlapping, prefixed or gapped local records')
                header = struct.unpack_from('<4s5H3I2H', data, offset)
                signature, version, flags, compression, _, _, crc, compressed, expanded, name_len, extra_len = header
                start = offset + 30 + name_len + extra_len
                if signature != b'PK\x03\x04' or version > 20 or flags != member.flag_bits or compression != member.compress_type or crc != member.CRC or compressed != member.compress_size or expanded != member.file_size or start + compressed > directory_start:
                    raise Rejected('Local record mismatch')
                decoded = data[offset+30:offset+30+name_len].decode('utf-8' if flags & 0x800 else 'cp437')
                if decoded != path:
                    raise Rejected('Filename mismatch')
                raw = data[start:start+compressed]
                if compression == zipfile.ZIP_DEFLATED:
                    decoder = zlib.decompressobj(-15)
                    content = decoder.decompress(raw, MAX_ENTRY + 1)
                    if len(content) > MAX_ENTRY or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                        raise Rejected('Invalid or oversized compressed stream')
                else:
                    content = raw
                if len(content) != expanded or binascii.crc32(content) & 0xffffffff != crc:
                    raise Rejected('Member size or CRC mismatch')
                if member.is_dir() and content:
                    raise Rejected('Directory has content')
                observe(path, content, member.is_dir(), entries, technologies, suggestions)
                total += len(content)
                offset = start + compressed
            if offset != directory_start:
                raise Rejected('Unexpected data before directory')
            check_collisions(seen)
    except (zipfile.BadZipFile, struct.error, UnicodeError, zlib.error) as error:
        raise Rejected('Invalid ZIP structure') from error
    return make_report(data, name, 'zip', entries, technologies, suggestions, total)


def tar_number(field):
    # Accept only ASCII octal. GNU base-256 and signs are deliberately unsupported.
    value = field.strip(b'\x00 ')
    if value and not re.fullmatch(b'[0-7]+', value):
        raise Rejected('Unsupported TAR numeric field')
    return int(value, 8) if value else 0


def tar_text(field):
    head, marker, tail = field.partition(b'\x00')
    if marker and any(tail):
        raise Rejected('Noncanonical TAR text field')
    return head.decode('utf-8', errors='strict')


def inspect_tar(data, name, format):
    stream = data
    try:
        if format == 'tar.gz':
            decoder = zlib.decompressobj(31)
            limit = min(MAX_TAR_STREAM, len(data) * MAX_RATIO)
            stream = decoder.decompress(data, limit + 1)
            if len(stream) > limit or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise Rejected('Invalid, concatenated or oversized gzip stream')
        if len(stream) < 1024 or len(stream) % 512 or len(stream) > MAX_TAR_STREAM:
            raise Rejected('TAR framing or size limit')
        entries, technologies, suggestions, seen, total, offset = [], [], set(), {}, 0, 0
        while offset + 512 <= len(stream):
            header = stream[offset:offset+512]
            if not any(header):
                if len(stream) - offset < 1024 or any(stream[offset:]):
                    raise Rejected('TAR end blocks or trailing data invalid')
                check_collisions(seen)
                return make_report(data, name, format, entries, technologies, suggestions, total)
            if len(entries) >= MAX_ENTRIES:
                raise Rejected('TAR entry limit exceeded')
            if header[257:265] != b'ustar\x0000' or any(header[500:]):
                raise Rejected('Only POSIX USTAR headers supported')
            if tar_number(header[148:156]) != sum(header[:148]) + 8 * 32 + sum(header[156:]):
                raise Rejected('TAR header checksum mismatch')
            kind = header[156:157]
            if kind not in (b'0', b'\x00', b'5') or any(header[157:257]):
                raise Rejected('Links, extensions and special files unsupported')
            for first, last in [(100, 108), (108, 116), (116, 124), (136, 148)]:
                tar_number(header[first:last])
            if tar_number(header[329:337]) or tar_number(header[337:345]):
                raise Rejected('Device metadata unsupported')
            name_part, prefix = tar_text(header[:100]), tar_text(header[345:500])
            if not name_part:
                raise Rejected('Empty TAR name')
            path = prefix + '/' + name_part if prefix else name_part
            directory = kind == b'5'
            if not directory and path.endswith('/'):
                raise Rejected('Inconsistent TAR directory metadata')
            key = safe_path(path)
            if key in seen:
                raise Rejected('Duplicate or colliding member paths')
            seen[key] = directory
            size = tar_number(header[124:136])
            if size > MAX_ENTRY or total + size > MAX_TOTAL or (directory and size):
                raise Rejected('TAR expansion or directory limit')
            start = offset + 512
            padded_end = start + ((size + 511) // 512) * 512
            if padded_end > len(stream) or any(stream[start+size:padded_end]):
                raise Rejected('Truncated TAR content or nonzero padding')
            content = stream[start:start+size]
            observe(path, content, directory, entries, technologies, suggestions)
            total += size
            offset = padded_end
        raise Rejected('TAR end blocks missing')
    except (UnicodeError, zlib.error) as error:
        raise Rejected('Invalid TAR or gzip structure') from error


def inspect(data, name='archive.zip', format='zip'):
    if not data or len(data) > MAX_INPUT:
        raise Rejected('Archive input limit exceeded')
    if format == 'zip':
        return inspect_zip(data, name)
    if format in ('tar', 'tar.gz'):
        return inspect_tar(data, name, format)
    raise Rejected('Unsupported archive format')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--consent', action='store_true', required=True)
    parser.add_argument('--file', required=True)
    parser.add_argument('--format', choices=('zip', 'tar', 'tar.gz'), default='zip')
    args = parser.parse_args()
    path = Path(args.file)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
            raise Rejected('Input must be a bounded regular file')
        with path.open('rb') as source:
            data = source.read(MAX_INPUT + 1)
        report = inspect(data, path.name, args.format)
        with path.open('rb') as source:
            after = source.read(MAX_INPUT + 1)
        if hashlib.sha256(after).hexdigest() != report['input']['sha256']:
            raise Rejected('Input changed during inspection')
        print(json.dumps(report, ensure_ascii=True, separators=(',', ':')))
    except (OSError, ValueError) as error:
        parser.exit(2, f'Import inspection rejected: {type(error).__name__}\n')


if __name__ == '__main__':
    main()
