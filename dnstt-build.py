#!/usr/bin/env python3
"""Build the explicitly selected, pinned upstream DNSTT source without downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_into(destination):
    pin = json.loads((ROOT / 'dnstt-source/pin.json').read_text())
    archive = ROOT / 'dnstt-source/upstream-20260501.tar.gz'
    if sha(archive) != pin['archive_sha256']:
        raise ValueError('DNSTT source archive checksum mismatch')
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if len(set(names)) != len(names):
            raise ValueError('Duplicate source path')
        for member in members:
            path = PurePosixPath(member.name)
            if not member.isfile() or path.is_absolute() or '..' in path.parts or '\\' in member.name:
                raise ValueError('Unsafe source member')
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(tar.extractfile(member).read())
    manifest = json.loads((destination / 'ENG-SOURCE-MANIFEST.json').read_text())
    actual = {p.relative_to(destination).as_posix(): sha(p) for p in destination.rglob('*')
              if p.is_file() and p.name != 'ENG-SOURCE-MANIFEST.json'}
    if manifest != actual or len(actual) != pin['source_files']:
        raise ValueError('Source file manifest mismatch')
    return pin


def build(go, output, target, test=True):
    go = str(Path(shutil.which(go) or go).resolve())
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', GOWORK='off',
               CGO_ENABLED='0', GOFLAGS='', GOOS='', GOARCH='', GOARM='')
    version = subprocess.check_output([go, 'version'], text=True, env=env, timeout=15).strip()
    parsed = re.search(r'go(\d+)\.(\d+)', version)
    if not parsed or (int(parsed[1]), int(parsed[2])) < (1, 21):
        raise ValueError('Select Go 1.21 or newer explicitly; automatic toolchain downloads are disabled')
    osname, arch = ('windows' if os.name == 'nt' else platform.system().lower(), platform.machine().lower())
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
    if target != 'host':
        osname, arch = target.split('-')
    with tempfile.TemporaryDirectory(prefix='eng-dnstt-source-') as directory:
        source = Path(directory)
        pin = source_into(source)
        def call(*args, timeout=600):
            subprocess.run([go, *args], cwd=source, env=env, check=True, timeout=timeout)
        if test:
            call('test', '-mod=vendor', './...')
        env.update(GOOS=osname, GOARCH=arch)
        binaries = {}
        for name in ('dnstt-server', 'dnstt-client'):
            filename = name + ('.exe' if osname == 'windows' else '')
            path = output / filename
            temporary = output / (filename + '.new')
            call('build', '-mod=vendor', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
                 '-o', str(temporary), './' + name)
            temporary.chmod(0o755)
            os.replace(temporary, path)
            binaries[filename] = sha(path)
        provenance = dict(pin, go=version, target=osname + '-' + arch, binaries=binaries,
                          tests='host upstream tests passed' if test else 'not run')
        (output / 'build.json').write_text(json.dumps(provenance, indent=2) + '\n')
        shutil.copyfile(source / 'COPYING', output / 'COPYING')
    print(json.dumps(provenance, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--implementation', choices=('upstream-20260501',), required=True)
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', choices=('host', 'linux-amd64', 'linux-arm64'), default='host')
    parser.add_argument('--skip-tests', action='store_true')
    args = parser.parse_args()
    build(args.go, args.output, args.target, not args.skip_tests)
