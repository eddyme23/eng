"""Explicit real-engine integration test; does not access public resolvers."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', required=True)
    parser.add_argument('--server', type=Path, required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('build', ROOT / 'dnstt-build.py')
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    with tempfile.TemporaryDirectory(prefix='eng-dnstt-tls-') as directory:
        path = Path(directory)
        build.source_into(path)
        shutil.copyfile(ROOT / 'tests/dnstt_transport_smoke.go', path / 'dnstt-client/eng_transport_test.go')
        env = dict(os.environ, ENG_DNSTT_TEST_SERVER=str(args.server.resolve()), GOTOOLCHAIN='local',
                   CGO_ENABLED='0', GOOS='', GOARCH='', GOARM='', GOFLAGS='', GOWORK='off', GOPROXY='off')
        subprocess.run([str(Path(shutil.which(args.go) or args.go).resolve()), 'test', '-mod=vendor',
                        '-run', '^TestEngEncryptedTransports$', '-count=1', '-timeout=60s', '-v', './dnstt-client'],
                       cwd=path, env=env, check=True, timeout=180)
