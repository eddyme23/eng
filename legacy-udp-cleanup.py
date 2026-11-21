#!/usr/bin/env python3
"""Remove only the historical port-only ENG UDP-Custom catch-all."""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import time

TOOLS = ('iptables', 'iptables-nft', 'iptables-legacy', 'ip6tables', 'ip6tables-nft', 'ip6tables-legacy')
PERSISTED = tuple(Path(p) for p in ('/etc/iptables/rules.v4', '/etc/iptables/rules.v6',
    '/etc/iptables/rules.v4.legacy', '/etc/iptables/rules.v6.legacy', '/etc/iptables.rules', '/etc/ip6tables.rules'))
BACKUPS = Path('/var/backups/frimps-v6/legacy-udp-persistence')


def obsolete(line, iface):
    try:
        args = shlex.split(line)
    except ValueError:
        return False
    if args and re.fullmatch(r'\[\d+:\d+\]', args[0]):
        args = args[1:]
    if args[:2] != ['-A', 'PREROUTING']:
        return False
    aliases = {'--in-interface': '-i', '--protocol': '-p', '--destination-port': '--dport',
               '--jump': '-j'}
    values = {}
    rest = args[2:]
    if len(rest) % 2:
        return False
    for key, value in zip(rest[::2], rest[1::2]):
        key = aliases.get(key, key)
        if key not in ('-i', '-p', '--dport', '-j', '--to-destination', '-m') or key in values:
            return False
        values[key] = value
    module = values.pop('-m', 'udp')
    return module == 'udp' and values == {'-i': iface, '-p': 'udp', '--dport': '1:65535',
                                         '-j': 'DNAT', '--to-destination': ':36717'}


def filter_saved(text, iface):
    table = None
    kept, removed = [], 0
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith('*'):
            table = stripped[1:]
        elif stripped == 'COMMIT':
            table = None
        if table == 'nat' and obsolete(stripped, iface):
            removed += 1
        else:
            kept.append(line)
    return ''.join(kept), removed


def clean_saved(path, iface):
    if not path.exists() and not path.is_symlink():
        return 0
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f'Refusing non-regular persistent firewall file: {path}')
    before = path.read_bytes()
    after, count = filter_saved(before.decode('utf-8', errors='surrogateescape'), iface)
    if not count:
        return 0
    original = path.stat()
    BACKUPS.mkdir(parents=True, mode=0o700, exist_ok=True)
    if BACKUPS.is_symlink() or BACKUPS.stat().st_mode & 0o077:
        raise ValueError('Persistence backup directory must be private and not a symlink')
    fd, saved = tempfile.mkstemp(prefix=path.name + '-', dir=BACKUPS)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(before)
        stream.flush(); os.fsync(stream.fileno())
    fd, temporary = tempfile.mkstemp(prefix='.frimps-udp-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(after.encode('utf-8', errors='surrogateescape'))
            os.fchmod(stream.fileno(), stat.S_IMODE(original.st_mode))
            os.fchown(stream.fileno(), original.st_uid, original.st_gid)
            stream.flush(); os.fsync(stream.fileno())
        if path.is_symlink() or path.read_bytes() != before or path.stat().st_ino != original.st_ino:
            raise ValueError('Persistent firewall file changed during cleanup; retry')
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    print(f'Removed {count} obsolete catch-all(s) from {path}; backup: {saved}')
    return count


def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=10)


def clean_runtime(iface):
    removed = 0
    inspected = 0
    for name in TOOLS:
        tool = shutil.which(name)
        if not tool:
            continue
        result = run([tool, '-w', '5', '-t', 'nat', '-S', 'PREROUTING'])
        if result.returncode:
            # An installed IPv6/legacy frontend need not have a NAT table.
            if re.search(r'Table does not exist|Address family not supported|Protocol not supported', result.stderr, re.I):
                print(f'[SKIP] {name}: NAT table unavailable')
                continue
            raise ValueError(f'{name}: cannot inspect NAT rules (exit {result.returncode}): {result.stderr.strip()}')
        inspected += 1
        for line in result.stdout.splitlines():
            if not obsolete(line, iface):
                continue
            tokens = shlex.split(line)
            if re.fullmatch(r'\[\d+:\d+\]', tokens[0]):
                tokens = tokens[1:]
            result = run([tool, '-w', '5', '-t', 'nat', '-D', *tokens[1:]])
            if result.returncode:
                raise ValueError(f'{name}: exact catch-all deletion failed (exit {result.returncode}): {result.stderr.strip()}')
            removed += 1
            print(f'Removed obsolete UDP Custom catch-all via {name} on {iface}')
    if not inspected:
        print('[SKIP] No inspectable iptables backend; legacy runtime state is unverified')
    return removed


def wait_udp():
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        pid = run(['systemctl', 'show', 'frimps-udp-custom.service', '-p', 'MainPID', '--value'])
        sockets = run(['ss', '-H', '-lunp', 'sport = :36717'])
        if pid.returncode == sockets.returncode == 0 and re.fullmatch(r'[1-9]\d*', pid.stdout.strip()):
            if re.search(r'pid=' + re.escape(pid.stdout.strip()) + r'[,)]', sockets.stdout):
                return
        time.sleep(.2)
    raise ValueError('UDP Custom did not acquire its UDP 36717 listener; startup cleanup could not be verified')


def native_ready(if_ready):
    native = run(['nft', 'list', 'table', 'ip', 'frimps_v6_udp'])
    if native.returncode:
        if if_ready and re.search(r'No such file or directory|does not exist', native.stderr, re.I):
            print('[SKIP] Native ENG UDP policy not ready; ordered migration will run after it starts')
            return False
        raise ValueError('Native ENG UDP policy must be readable before catch-all cleanup: ' + native.stderr.strip())
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--if-ready', action='store_true')
    parser.add_argument('--wait-udp', action='store_true')
    parser.add_argument('--check', action='store_true', help='Read-only detection of live obsolete rules')
    args = parser.parse_args()
    import fcntl
    if os.geteuid() != 0 or not re.fullmatch(r'[A-Za-z0-9_.:-]+', args.interface):
        raise ValueError('Run as root with a valid public interface')
    if not native_ready(args.if_ready):
        return
    os.umask(0o077)
    lockdir = Path('/run/frimps-firewall')
    lockdir.mkdir(mode=0o700, exist_ok=True)
    info = lockdir.stat()
    if lockdir.is_symlink() or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('Unsafe firewall lock directory')
    descriptor = os.open(lockdir / 'cleanup.lock', os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        deadline = time.monotonic() + 30
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError('Firewall cleanup lock busy; retry')
                time.sleep(.1)
        if args.wait_udp:
            wait_udp()
        if args.check:
            found = []
            inspected = 0
            for name in TOOLS:
                tool = shutil.which(name)
                if not tool:
                    continue
                result = run([tool, '-w', '5', '-t', 'nat', '-S', 'PREROUTING'])
                if result.returncode and not re.search(r'Table does not exist|Address family not supported|Protocol not supported', result.stderr, re.I):
                    raise ValueError(f'{name}: NAT inspection failed')
                if result.returncode == 0:
                    inspected += 1
                found.extend(name for line in result.stdout.splitlines() if obsolete(line, args.interface))
            if found:
                raise ValueError('Obsolete UDP Custom catch-all present: ' + ', '.join(found))
            if not inspected:
                print('[SKIP] No inspectable iptables backend; legacy runtime state is unverified')
                raise SystemExit(2)
            print('[OK] No obsolete ENG catch-all in available iptables backends')
            return
        for path in PERSISTED:
            clean_saved(path, args.interface)
        count = clean_runtime(args.interface)
        print(f'ENG catch-all cleanup complete ({count} live rule(s) removed); unrelated rules retained.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error))
