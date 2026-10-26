"""Generate a synthetic source project, never execute its contents."""
import base64
import io
import zipfile


def fixture():
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
    print(base64.b64encode(fixture()).decode('ascii'))
