#!/usr/bin/env python3
"""Transactional opt-in upgrade of installed ENG HCR or SlowDNS servers."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
BACKUPS = Path('/var/backups/frimps-v6/epro')
UNIT_DIR = Path('/etc/systemd/system')
HASHES = {'hcr': 'd752aba7081672cc54ec97e4e21d5fe21ec33a2f4872c753e2638aec5beee124',
          'slowdns': 'a9d19e39ae23261628e8f21dac79548b31dceb45f959017bc50300e7ebfcad7d'}
BINARIES = {'hcr': ['/opt/frimps-hcr/hcr-server', '/opt/frimps-hcr-tls/hcr-server'],
            'slowdns': ['/etc/slowdns/sldns-server']}
UNITS = {'hcr': ['frimps-hcr.service', 'frimps-hcr-tls.service'],
         'slowdns': ['frimps-slowdns.service']}
NETWORK_FILES = ['/etc/frimps-v6/slowdns-network.json',
                 '/etc/systemd/system/frimps-slowdns.service.d/70-frimps-slowdns-network.conf']


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), check=True, timeout=kwargs.pop('timeout', 30), **kwargs)


def settings_module():
    spec = importlib.util.spec_from_file_location('hcr_settings', ROOT / 'hcr-settings.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render_hcr(text, binary):
    lines = re.findall(r'^ExecStart=(.*)$', text, re.M)
    if len(lines) != 1:
        raise ValueError('Expected exactly one managed ExecStart')
    args = shlex.split(lines[0])
    if args[0] not in BINARIES['hcr'] or len(args[1:]) % 2:
        raise ValueError('Unrecognized managed HCR command')
    old = dict(zip(args[1::2], args[2::2]))
    if old.get('--target') != '127.0.0.1:22' or old.get('--transport') not in ('plain', 'tls'):
        raise ValueError('Unrecognized HCR target or transport')
    keep = ['--listen', '--target', '--transport', '--tls-cert', '--tls-key']
    if set(old) - set(keep) - {'--max-download-frame', '--download-poll-timeout', '--diagnostics-interval',
                              '--session-stats-interval', '--max-connections', '--max-sessions', '--max-sessions-per-ip'}:
        raise ValueError('Unknown HCR options; refusing to discard them')
    result = [args[0]]
    for key in keep:
        if key in old:
            if not re.fullmatch(r'[-A-Za-z0-9_./:\[\]]+', old[key]):
                raise ValueError('Unsafe unit argument')
            result += [key, old[key]]
    result += settings_module().options(binary, old)
    return text.replace('ExecStart=' + lines[0], 'ExecStart=' + ' '.join(result))


def save_backup(paths, units):
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-', time.gmtime()), dir=BACKUPS))
    os.chmod(backup, 0o700)
    missing = []
    for path in paths:
        if not path.exists():
            missing.append(str(path))
            continue
        destination = backup / path.relative_to(path.anchor)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    (backup / 'manifest.json').write_text(json.dumps({'paths': list(map(str, paths)), 'units': units, 'missing': missing}))
    return backup


def replace_file(source, destination):
    staged = destination.with_name(destination.name + '.epro-new')
    shutil.copy2(source, staged)
    os.replace(staged, destination)


def restore(backup):
    backup = backup.resolve()
    if not backup.is_relative_to(BACKUPS.resolve()) or backup == BACKUPS.resolve():
        raise ValueError('Rollback directory must be inside ' + str(BACKUPS))
    manifest = json.loads((backup / 'manifest.json').read_text())
    allowed = set(sum(BINARIES.values(), []) + NETWORK_FILES) | {str(UNIT_DIR / u) for us in UNITS.values() for u in us}
    paths = manifest['paths']
    units = manifest['units']
    missing = manifest.get('missing', [])
    if not set(missing) <= set(paths):
        raise ValueError('Invalid missing-file manifest')
    if not paths or not set(paths) <= allowed or not units or not set(units) <= set(sum(UNITS.values(), [])):
        raise ValueError('Invalid rollback manifest')
    for path in paths:
        if path in missing:
            continue
        saved = backup / Path(path).relative_to(Path(path).anchor)
        if not saved.is_file() or saved.is_symlink():
            raise ValueError('Missing or unsafe backup file')
    for unit in units:
        run('systemctl', 'stop', unit)
    for path in paths:
        if path in missing:
            Path(path).unlink(missing_ok=True)
        else:
            replace_file(backup / Path(path).relative_to(Path(path).anchor), Path(path))
    run('systemctl', 'daemon-reload')
    for unit in units:
        run('systemctl', 'reset-failed', unit)
        run('systemctl', 'start', unit)
        run('systemctl', 'is-active', '--quiet', unit)
    print('Restored binaries and units from ' + str(backup))


def verify_unit(unit):
    run('systemctl', 'is-active', '--quiet', unit)
    if unit == 'frimps-slowdns.service':
        run('bash', ROOT / 'slowdns-audit.sh', '--local', timeout=45)
        return
    text = (UNIT_DIR / unit).read_text()
    command = shlex.split(re.search(r'^ExecStart=(.*)$', text, re.M)[1])
    values = dict(zip(command[1::2], command[2::2]))
    port = int(values['--listen'].rsplit(':', 1)[1])
    pid = run('systemctl', 'show', unit, '-p', 'MainPID', '--value', capture_output=True, text=True).stdout.strip()
    sockets = run('ss', '-H', '-ltnp', f'sport = :{port}', capture_output=True, text=True).stdout
    if not pid.isdigit() or int(pid) == 0 or not re.search(r'pid=' + pid + r'[,)]', sockets):
        raise ValueError(unit + ' does not own its listener')
    if values['--transport'] == 'tls':
        state = Path(os.environ.get('V6_STATE_DIR', '/etc/frimps-v6'))
        domain = json.loads((state / 'routes.json').read_text())['primaryDomain']
        run('openssl', 's_client', '-connect', f'127.0.0.1:{port}', '-servername', domain,
            '-verify_hostname', domain, '-verify_return_error', '-CApath', '/etc/ssl/certs', '-brief',
            input=b'', stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=12)


def upgrade(kind):
    candidate = ROOT / 'releases/epro-20261029' / ('hcr-server' if kind == 'hcr' else 'slowdns')
    if hashlib.sha256(candidate.read_bytes()).hexdigest() != HASHES[kind]:
        raise ValueError('Release binary checksum mismatch')
    units, paths, changes = [], [], {}
    for unit, binary in zip(UNITS[kind], BINARIES[kind]):
        path = UNIT_DIR / unit
        if not path.exists():
            continue
        if path.is_symlink() or Path(binary).is_symlink() or not Path(binary).is_file():
            raise ValueError('Expected regular managed unit and binary')
        run('systemctl', 'is-active', '--quiet', unit)
        run('systemctl', 'is-enabled', '--quiet', unit)
        effective = run('systemctl', 'cat', unit, capture_output=True, text=True).stdout
        if len(re.findall(r'^ExecStart=', effective, re.M)) != 1:
            raise ValueError('ExecStart override present; review it before binary upgrade')
        text = path.read_text()
        if kind == 'hcr':
            text = render_hcr(text, candidate)
        elif not re.search(r'^ExecStart=/etc/slowdns/sldns-server .*127\.0\.0\.1:22$', text, re.M):
            raise ValueError('Unrecognized managed SlowDNS unit')
        changes[path] = text
        units.append(unit)
        paths.extend([path, Path(binary)])
    if not units:
        raise ValueError('Install the existing ENG service first')
    with tempfile.TemporaryDirectory(prefix='frimps-epro-') as directory:
        executable = Path(directory) / candidate.name
        shutil.copyfile(candidate, executable)
        executable.chmod(0o700)
        help_result = run(executable, '--help', capture_output=True, text=True, timeout=10)
        help_text = help_result.stdout + help_result.stderr
        required = ('listen', 'target', 'transport', 'max-download-frame') if kind == 'hcr' else ('udp', 'privkey-file', 'mtu')
        for flag in required:
            if not re.search(r'(?m)^\s*-{1,2}' + re.escape(flag) + r'(?:\s|=|$)', help_text):
                raise ValueError('Candidate does not advertise required option: ' + flag)
        for path, text in changes.items():
            staged = Path(directory) / path.name
            staged.write_text(text)
            run('systemd-analyze', 'verify', staged)
        backup = save_backup(paths, units)
        print('Upgrade disconnects existing ' + kind + ' sessions. Backup: ' + str(backup), flush=True)
        try:
            for unit in units:
                run('systemctl', 'stop', unit)
            for path in paths:
                if str(path) in BINARIES[kind]:
                    replace_file(executable, path)
            for path, text in changes.items():
                staged = Path(directory) / path.name
                staged.chmod(0o644)
                replace_file(staged, path)
            run('systemctl', 'daemon-reload')
            for unit in units:
                run('systemctl', 'reset-failed', unit)
                run('systemctl', 'start', unit)
            time.sleep(2)
            for unit in units:
                verify_unit(unit)
        except BaseException:
            print('Upgrade failed; restoring previous binaries and units.', file=sys.stderr)
            restore(backup)
            raise
    print('Upgrade passed local checks. Test client login, repeated reconnects and browsing.')
    print('Rollback: bash ./apply-epro-updates.sh --rollback ' + str(backup))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('protocol', nargs='?', choices=('hcr', 'slowdns'))
    parser.add_argument('--rollback', type=Path)
    args = parser.parse_args()
    if bool(args.protocol) == bool(args.rollback):
        parser.error('Choose hcr, slowdns, or --rollback DIRECTORY')
    if sys.platform != 'linux' or os.geteuid() != 0 or os.uname().machine != 'x86_64':
        parser.error('Run as root on Linux amd64')
    import fcntl
    lockdir = Path('/run/lock')
    with (lockdir / 'frimps-epro.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.umask(0o077)
        if args.rollback:
            restore(args.rollback)
        else:
            upgrade(args.protocol)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
