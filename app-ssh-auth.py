#!/usr/bin/env python3
"""Operator-approved device SSH certificates alongside existing password accounts."""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tempfile
import uuid

AUTH = Path('/etc/frimps-app-auth')
STATE = Path(os.environ.get('V6_STATE_DIR', '/etc/frimps-v6'))
KEYGEN = 'ssh-keygen'
MARKER = 'frimps-app-device:'


def run(*args):
    return subprocess.run(list(map(str, args)), check=True, capture_output=True,
                          text=True, timeout=30, env=dict(os.environ, TZ='UTC'))


def atomic(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.app-auth-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_db():
    path = AUTH / 'devices.json'
    db = json.loads(path.read_text()) if path.exists() else {'version': 1, 'devices': []}
    if not isinstance(db, dict) or db.get('version') != 1 or not isinstance(db.get('devices'), list):
        raise ValueError('Unsupported or invalid device database')
    return db


def save_db(db):
    atomic(AUTH / 'devices.json', (json.dumps(db, indent=2) + '\n').encode())


def identifier(value):
    if not re.fullmatch(r'[a-z0-9_][a-z0-9_-]{0,31}', value):
        raise ValueError('Use 1–32 lowercase letters, numbers, underscores or hyphens')
    return value


def public_key(value):
    if len(value.strip().splitlines()) != 1:
        raise ValueError('Supply exactly one SSH public key')
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] not in ('ssh-ed25519', 'ecdsa-sha2-nistp256'):
        raise ValueError('Supply an Ed25519 or ECDSA P-256 public key, never a private key/certificate')
    try:
        raw = base64.b64decode(fields[1], validate=True)
        size = struct.unpack('>I', raw[:4])[0]
        if raw[4:4 + size].decode() != fields[0]:
            raise ValueError('Key type mismatch')
    except (ValueError, UnicodeError, struct.error) as error:
        raise ValueError('Invalid SSH public key') from error
    return ' '.join(fields[:2])


def account(name):
    import pwd
    identifier(name)
    entries = json.loads((STATE / 'ssh-users.json').read_text())
    matches = [entry for entry in entries if entry['name'] == name]
    if len(matches) != 1:
        raise ValueError('Create this managed SSH account first in SSH Account Management')
    user = pwd.getpwnam(name)  # Numeric names are names, never UIDs.
    if user.pw_uid < 1000 or user.pw_uid == 65534:
        raise ValueError('Root/system accounts cannot receive app certificates')
    # Conservative midnight cap: never sign beyond the recorded OS expiry date.
    expiry = datetime.strptime(matches[0]['expiresAt'], '%Y-%m-%d').replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise ValueError('Renew the expired SSH account first')
    return user, expiry


def backend_policy(user, key_type=None):
    """Fail before enrollment if the deployed SSH config cannot read our key file."""
    configs = [Path('/etc/ssh/sshd_config')]
    backend = STATE / 'sshd-backend.conf'
    if backend.exists():
        configs.append(backend)
    result = []
    for config in configs:
        text = run('/usr/sbin/sshd', '-T', '-f', config, '-C',
                   f'user={user.pw_name},host=localhost,addr=127.0.0.1').stdout
        settings = dict(line.split(' ', 1) for line in text.splitlines() if ' ' in line)
        paths = settings.get('authorizedkeysfile', '').split()
        expected = str(Path(user.pw_dir) / '.ssh/authorized_keys')
        expanded = [p.replace('%h', user.pw_dir).replace('%u', user.pw_name) for p in paths]
        if settings.get('pubkeyauthentication') != 'yes' or not any(
                p == '.ssh/authorized_keys' or p == expected for p in expanded):
            raise ValueError(f'{config} must enable public keys and the normal .ssh/authorized_keys path')
        if not set(settings.get('authenticationmethods', 'any').split()) & {'any', 'publickey'}:
            raise ValueError(f'{config} requires another authentication step; certificate-only login is unavailable')
        types = (key_type,) if key_type else ('ssh-ed25519', 'ecdsa-sha2-nistp256')
        accepted = settings.get('pubkeyacceptedalgorithms', '').split(',')
        if not any(t + '-cert-v01@openssh.com' in accepted for t in types):
            raise ValueError(f'{config} does not accept the requested OpenSSH certificate algorithm')
        if 'casignaturealgorithms' in settings and 'ssh-ed25519' not in settings['casignaturealgorithms'].split(','):
            raise ValueError(f'{config} does not accept this CA signature algorithm')
        if settings.get('disableforwarding') == 'yes' or settings.get('allowtcpforwarding') not in ('yes', 'all', 'local'):
            raise ValueError(f'{config} does not permit the app TCP forwarding path')
        result.append(str(config))
    return result


def transport_policy():
    checked = []
    for unit in ('frimps-v6-tlsmux', 'frimps-v6-payloadgate', 'frimps-v6-sshws',
                 'frimps-hcr', 'frimps-hcr-tls', 'frimps-bhttp', 'frimps-slowdns'):
        result = subprocess.run(['systemctl', 'show', unit, '--no-pager', '-p', 'ExecStart', '-p', 'LoadState'],
                                capture_output=True, text=True, timeout=30)
        text = result.stdout
        if 'LoadState=not-found' in text:
            continue
        if result.returncode:
            raise ValueError('Unable to inspect ' + unit)
        if not text.strip():
            continue
        if unit.startswith('frimps-v6-'):
            match = re.search(r'-ssh-target\s+(127\.0\.0\.1:\d+)', text)
            if not match or match[1] not in ('127.0.0.1:22', '127.0.0.1:2222'):
                raise ValueError(unit + ': select the dedicated OpenSSH backend with apply-ssh-capacity-fix.sh first')
        else:
            if not re.search(r'127\.0\.0\.1:(?:22|2222)(?:\s|;|$)', text):
                raise ValueError(unit + ': unrecognized SSH backend; review routing before enrollment')
        checked.append(unit)
    return checked


def authority():
    private, public = AUTH / 'ca', AUTH / 'ca.pub'
    if private.exists() != public.exists():
        raise ValueError('Incomplete CA pair; restore its backup, do not rotate it automatically')
    if not private.exists():
        if read_db()['devices']:
            raise ValueError('Existing devices but missing CA; restore the signing key backup')
        with tempfile.TemporaryDirectory(dir=AUTH) as directory:
            key = Path(directory) / 'ca'
            run(KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-C', 'ENG app SSH CA', '-f', key)
            atomic(private, key.read_bytes())
            atomic(public, key.with_suffix('.pub').read_bytes())
    if private.is_symlink() or public.is_symlink() or not private.is_file() or not public.is_file() or private.stat().st_mode & 0o077 or private.stat().st_uid != 0:
        raise ValueError('CA must be a regular root-private key pair')
    actual = public_key(run(KEYGEN, '-y', '-f', private).stdout)
    if actual != public_key(public.read_text()):
        raise ValueError('CA key pair mismatch')
    return actual


def entry(record, ca):
    return (f'cert-authority,principals="{record["principal"]}",restrict,port-forwarding,'
            f'command="/bin/false" {ca} {MARKER}{record["id"]}\n').encode()


def edit_lines(before, device, replacement=None):
    token = (MARKER + device).encode()
    lines = [line for line in before.splitlines(keepends=True) if line.rstrip().split()[-1:] != [token]]
    data = b''.join(lines)
    if replacement:
        if data and not data.endswith(b'\n'):
            data += b'\n'
        data += replacement
    return data


@contextmanager
def authorized_file(user):
    """Use no-follow directory descriptors; never root-write through a user's symlink."""
    home = Path(user.pw_dir)
    if not home.is_absolute() or home.resolve() != home:
        raise ValueError('Account home must be an absolute path without symlinks')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with_home = os.open(home, flags)
    ssh = None
    try:
        info = os.fstat(with_home)
        if info.st_uid != user.pw_uid or info.st_mode & 0o022:
            raise ValueError('Account home must be owned by the managed account and not writable by others')
        owner, group = user.pw_uid, user.pw_gid
        try:
            os.mkdir('.ssh', 0o700, dir_fd=with_home)
            os.chown('.ssh', user.pw_uid, user.pw_gid, dir_fd=with_home, follow_symlinks=False)
        except FileExistsError:
            pass
        ssh = os.open('.ssh', flags, dir_fd=with_home)
        for fd in (with_home, ssh):
            info = os.fstat(fd)
            if info.st_uid not in (0, user.pw_uid) or info.st_mode & 0o022:
                raise ValueError('Home/.ssh ownership or write permissions are unsafe')
        try:
            fd = os.open('authorized_keys', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=ssh)
        except FileNotFoundError:
            before = b''
        else:
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (0, user.pw_uid) or info.st_mode & 0o022:
                    raise ValueError('Unsafe authorized_keys file')
                owner, group = info.st_uid, info.st_gid
                before = stream.read(1024 * 1024 + 1)
                if len(before) > 1024 * 1024:
                    raise ValueError('Oversized authorized_keys file')
        def write(data):
            name = '.eng-app-' + uuid.uuid4().hex
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=ssh)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    os.fchown(stream.fileno(), owner, group)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(name, 'authorized_keys', src_dir_fd=ssh, dst_dir_fd=ssh)
            finally:
                try:
                    os.unlink(name, dir_fd=ssh)
                except FileNotFoundError:
                    pass
        yield before, write
    finally:
        if ssh is not None:
            os.close(ssh)
        os.close(with_home)


def enroll(args):
    user, account_expiry = account(args.username)
    identifier(args.device)
    if not 1 <= args.days <= 90:
        raise ValueError('Certificate validity must be 1–90 days, capped by account expiry')
    db = read_db()
    if any(d['username'] == args.username and d['device'] == args.device for d in db['devices']):
        raise ValueError('Device label already exists; revoke it and use a new label for replacement')
    fd = os.open(args.public_key, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) |
                 getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Public key must be a regular file')
        data = stream.read(16385)
    if len(data) > 16384:
        raise ValueError('Oversized public key')
    public = public_key(data.decode('ascii'))
    backend_policy(user, public.split()[0])
    transport_policy()
    ca = authority()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    end = min(now + timedelta(days=args.days), account_expiry)
    start = now - timedelta(minutes=2)
    identity = uuid.uuid4().hex
    record = dict(id=identity, username=args.username, device=args.device,
                  principal='eng-app-' + identity, status='active', publicKey=public,
                  validAfter=start.isoformat(), validBefore=end.isoformat())
    with tempfile.TemporaryDirectory(dir=AUTH) as directory:
        key = Path(directory) / 'device.pub'
        key.write_text(public + '\n')
        run(KEYGEN, '-l', '-f', key)  # Check the complete public-key structure.
        run(KEYGEN, '-q', '-s', AUTH / 'ca', '-I', 'eng-app:' + identity,
            '-n', record['principal'], '-V', start.strftime('%Y%m%d%H%M%S') + ':' + end.strftime('%Y%m%d%H%M%S'),
            '-z', str(int(identity[:15], 16)), '-O', 'clear', '-O', 'permit-port-forwarding',
            '-O', 'force-command=/bin/false', key)
        record['certificate'] = (Path(directory) / 'device-cert.pub').read_text().strip()
    db['devices'].append(record)
    with authorized_file(user) as (before, write):
        write(edit_lines(before, identity, entry(record, ca)))
        try:
            save_db(db)
        except BaseException:
            write(before)
            raise
    return package(record, ca)


def package(record, ca):
    return dict(schema=1, type='eng-ssh-device-certificate', authMethod='openssh-user-certificate',
                username=record['username'], deviceId=record['id'], deviceLabel=record['device'],
                publicKey=record['publicKey'], certificate=record['certificate'], caPublicKey=ca,
                validAfter=record['validAfter'], validBefore=record['validBefore'],
                privateKeyIncluded=False)


def revoke(args):
    db = read_db()
    matches = [d for d in db['devices'] if d['username'] == args.username and d['device'] == args.device]
    if len(matches) != 1:
        raise ValueError('Device not found')
    record = matches[0]
    # Revocation remains possible even after the account expires.
    import pwd
    try:
        user = pwd.getpwnam(identifier(args.username))
    except KeyError:
        user = None
    if user is not None and (user.pw_uid < 1000 or user.pw_uid == 65534):
        raise ValueError('Refusing a root/system account')
    record['status'] = 'revoked'
    record['revokedAt'] = datetime.now(timezone.utc).isoformat()
    if user is None:
        save_db(db)
    else:
        with authorized_file(user) as (before, write):
            write(edit_lines(before, record['id']))
            try:
                save_db(db)
            except BaseException:
                write(before)
                raise
    print('Device revoked for new SSH logins. Existing sessions are not terminated.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    approve = commands.add_parser('enroll')
    approve.add_argument('username')
    approve.add_argument('device')
    approve.add_argument('public_key', type=Path)
    approve.add_argument('--days', type=int, default=7)
    cancel = commands.add_parser('revoke')
    cancel.add_argument('username')
    cancel.add_argument('device')
    commands.add_parser('list')
    audit = commands.add_parser('audit')
    audit.add_argument('username')
    export = commands.add_parser('export')
    export.add_argument('username')
    export.add_argument('device')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Run as root on the Linux VPS')
    import fcntl
    os.umask(0o077)
    if AUTH.is_symlink():
        raise ValueError('Auth directory cannot be a symlink')
    AUTH.mkdir(mode=0o700, exist_ok=True)
    if AUTH.stat().st_uid != 0 or AUTH.stat().st_mode & 0o077:
        raise ValueError('Auth directory must be root-owned mode 0700')
    with (STATE / '.ssh-accounts.lock').open('a') as accounts_lock, (AUTH / 'lock').open('a') as lock:
        fcntl.flock(accounts_lock, fcntl.LOCK_EX)
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'enroll':
            print(json.dumps(enroll(args), indent=2))
        elif args.action == 'revoke':
            revoke(args)
        elif args.action == 'list':
            for d in read_db()['devices']:
                print(d['username'], d['device'], d['status'], d['validBefore'], sep='\t')
        elif args.action == 'audit':
            user, _ = account(args.username)
            print(json.dumps(dict(sshConfigs=backend_policy(user), transports=transport_policy(),
                                  loginAndBrowsing='not tested', passwords='configuration unchanged'), indent=2))
        else:
            user, _ = account(args.username)
            del user
            matches = [d for d in read_db()['devices'] if d['username'] == args.username and d['device'] == args.device and d['status'] == 'active']
            if len(matches) != 1:
                raise ValueError('Active device not found')
            print(json.dumps(package(matches[0], authority()), indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
