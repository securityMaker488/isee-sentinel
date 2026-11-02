"""Generate a synthetic source project, never execute its contents."""
import base64
import io
import gzip
import tarfile
import sys
import zipfile


def fixture(format='zip'):
    if format in ('tar', 'tar.gz'):
        stream = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(fixture())) as source, tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as target:
            for item in source.infolist():
                data = source.read(item)
                member = tarfile.TarInfo(item.filename)
                member.size = len(data)
                target.addfile(member, io.BytesIO(data))
        return gzip.compress(stream.getvalue(), mtime=0) if format == 'tar.gz' else stream.getvalue()
    if format != 'zip':
        raise ValueError('Unsupported fixture format')
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path, text in [('package.json', '{"name":"sentinel-synthetic-fixture","private":true,"dependencies":{"react":"test-only"}}'),
                           ('src/index.js', '// Synthetic inert source for import tests.\n'),
                           ('openapi.json', '{"openapi":"3.1.0","info":{"title":"Synthetic","version":"1"},"paths":{}}')]:
            info = zipfile.ZipInfo(path, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text)
    return data.getvalue()


if __name__ == '__main__':
    print(base64.b64encode(fixture(sys.argv[1] if len(sys.argv) > 1 else 'zip')).decode('ascii'))
