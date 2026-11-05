"""Install the generated module ZIP in an isolated cache before live conformance."""
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
MODULE = 'github.com/vicotrbb/positron/sdk/go'

def archive():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_STORED) as package:
        for path in sorted((ROOT / 'sdk/go').rglob('*')):
            if path.is_file():
                info = zipfile.ZipInfo(f'{MODULE}@v0.0.0/{path.relative_to(ROOT / "sdk/go").as_posix()}')
                package.writestr(info, path.read_bytes())
    return output.getvalue()

with tempfile.TemporaryDirectory(prefix='positron-go-live-') as directory:
    root = pathlib.Path(directory)
    proxy = root / 'proxy' / MODULE / '@v'
    proxy.mkdir(parents=True)
    first, second = archive(), archive()
    assert first == second
    (proxy / 'v0.0.0.zip').write_bytes(first)
    (proxy / 'v0.0.0.mod').write_bytes((ROOT / 'sdk/go/go.mod').read_bytes())
    (proxy / 'v0.0.0.info').write_text(json.dumps(dict(Version='v0.0.0', Time='2023-11-14T22:13:20Z')))
    consumer = root / 'consumer'
    consumer.mkdir()
    (consumer / 'go.mod').write_text(f'module consumer\n\ngo 1.24.0\n\nrequire {MODULE} v0.0.0\n')
    (consumer / 'main.go').write_bytes((ROOT / 'sdk/tests/go/live/main.go').read_bytes())
    env = dict(os.environ, GOPROXY=(root / 'proxy').as_uri(), GOSUMDB='off', GOMODCACHE=str(root / 'cache'), GOTOOLCHAIN='local', GOMAXPROCS='2', GOFLAGS='-mod=mod -modcacherw')
    subprocess.run(['go', 'mod', 'download', MODULE + '@v0.0.0'], cwd=consumer, env=env, check=True, capture_output=True)
    result = subprocess.run(['go', 'run', '-p', '1', '.'], cwd=consumer, env=env, input=sys.stdin.buffer.read(), capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.exit(result.returncode)
