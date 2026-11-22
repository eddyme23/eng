#!/usr/bin/env python3
"""Operator-approved device SSH certificates alongside existing password accounts."""
import argparse
import base64
import hashlib
import importlib.util
from contextlib import contextmanager, ExitStack
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
import tempfile
import uuid
from types import SimpleNamespace

AUTH = Path('/etc/frimps-app-auth')
STATE = Path(os.environ.get('V6_STATE_DIR', '/etc/frimps-v6'))
KEYGEN = 'ssh-keygen'
MARKER = 'frimps-app-device:'


def policy_module():
    spec = importlib.util.spec_from_file_location('app_policy', Path(__file__).with_name('app-ssh-policy.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manager():
    return SimpleNamespace(**globals())


def fingerprint(key):
    raw = base64.b64decode(key.split()[1], validate=True)
    return 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')


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
        raise ValueError('Use 1â€“32 lowercase letters, numbers, underscores or hyphens')
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
        central = str(policy_module().KEYS / user.pw_name)
        expanded = [p.replace('%h', user.pw_dir).replace('%u', user.pw_name) for p in paths]
        if settings.get('pubkeyauthentication') != 'yes' or not any(
                p == '.ssh/authorized_keys' or p == expected or p == central for p in expanded):
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
        if any(not d.get('shared') for d in read_db()['devices']):
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
    expiry = ''
    if record.get('shared'):
        end = datetime.fromisoformat(record['validBefore']).astimezone(timezone.utc)
        expiry = 'expiry-time="' + end.strftime('%Y%m%d%H%M%SZ') + '",'
    return (expiry + f'cert-authority,principals="{record["principal"]}",restrict,port-forwarding,'
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
    if not 1 <= args.days <= (3650 if getattr(args, 'generated_bundle', False) else 90):
        raise ValueError('Certificate validity must be 1â€“90 days, capped by account expiry')
    db = read_db()
    previous_db = json.loads(json.dumps(db))
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
    record = sign_device(args.username, args.device, public, args.days, account_expiry)
    record['caPublicKey'] = ca
    identity = record['id']
    db['devices'].append(record)
    with authorized_file(user) as (before, write):
        write(edit_lines(before, identity, entry(record, ca)))
        try:
            save_db(db)
            policy_module().sync(manager(), db, args.username)
        except BaseException:
            write(before)
            save_db(previous_db)
            raise
    return package(record, ca)


def sign_device(username, label, public, days, not_after, identity=None):
    """Shared signer; callers authorize enrollment and commit trust separately."""
    if not 1 <= days <= 3650:
        raise ValueError('Invalid certificate validity')
    identifier(username)
    identifier(label)
    public = public_key(public)
    identity = identity or uuid.uuid4().hex
    if not re.fullmatch(r'[a-f0-9]{32}', identity):
        raise ValueError('Invalid device identity')
    now = datetime.now(timezone.utc).replace(microsecond=0)
    end = min(now + timedelta(days=days), not_after)
    if end <= now:
        raise ValueError('Account or plan expired')
    start = now - timedelta(minutes=2)
    record = dict(id=identity, username=username, device=label,
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
    return record


def package(record, ca):
    return dict(schema=1, type='eng-ssh-device-certificate', authMethod='openssh-user-certificate',
                username=record['username'], deviceId=record['id'], deviceLabel=record['device'],
                publicKey=record['publicKey'], certificate=record['certificate'], caPublicKey=ca,
                validAfter=record['validAfter'], validBefore=record['validBefore'],
                privateKeyIncluded=False, caFingerprint=fingerprint(ca))


def revoke(args):
    db = read_db()
    previous_db = json.loads(json.dumps(db))
    matches = [d for d in db['devices'] if d['username'] == args.username and d['device'] == args.device]
    identity = getattr(args, 'identity', None)
    if identity:
        matches = [d for d in matches if d['id'] == identity]
    elif len(matches) > 1:
        local = [d for d in matches if not d.get('shared')]
        if len(local) == 1:
            matches = local
    if len(matches) != 1:
        raise ValueError('Select one certificate identity with --identity (see bundle-list)')
    record = matches[0]
    # Revocation remains possible even after the account expires.
    import pwd
    try:
        user = pwd.getpwnam(identifier(args.username))
    except KeyError:
        user = None
    if user is not None and not Path(user.pw_dir).exists():
        user = None
    if user is not None and (user.pw_uid < 1000 or user.pw_uid == 65534):
        raise ValueError('Refusing a root/system account')
    if user is not None and record['device'] == 'certificate-account' and not record.get('shared'):
        disable_udp_password(args.username)
    record['status'] = 'revoked'
    record['revokedAt'] = datetime.now(timezone.utc).isoformat()
    if user is None:
        save_db(db)
        policy_module().sync(manager(), db, args.username)
    else:
        with authorized_file(user) as (before, write):
            write(edit_lines(before, record['id']))
            try:
                save_db(db)
                policy_module().sync(manager(), db, args.username)
            except BaseException:
                write(before)
                save_db(previous_db)
                raise
    path = bundle_path(args.username)
    if path.exists() and not path.is_symlink():
        if json.loads(path.read_text()).get('deviceId') == record['id']:
            path.unlink()
    print('Device revoked for new SSH logins. Existing sessions are not terminated.')


def pin_policy(username, host_key):
    user, _ = account(username)
    backend_policy(user)
    transport_policy()
    allowed = []
    for config in (Path('/etc/ssh/sshd_config'), STATE / 'sshd-backend.conf'):
        if config.exists():
            text = run('/usr/sbin/sshd', '-T', '-f', config).stdout
            configured = [Path(line.split(' ', 1)[1] + '.pub') for line in text.splitlines() if line.startswith('hostkey ')]
            if host_key not in configured:
                raise ValueError(f'{host_key} is not a configured host key for {config}')
            allowed.extend(map(str, configured))
    fields = host_key.read_text().split()
    if len(fields) < 2:
        raise ValueError('Invalid host public key')
    ca = authority()
    return dict(username=username, genPolicy=dict(SSHAuthMethod='device_certificate',
                SSHCertificateCA=fingerprint(ca), SSHHostKeyPin=fingerprint(' '.join(fields[:2]))),
                hostKeyAlgorithm=fields[0], configuredHostPublicKeys=sorted(set(allowed)),
                note='Pin must match the actually negotiated SSH host key; this is not a TLS or user CA host pin.')


def purge_account(username):
    identifier(username)
    records = [d for d in read_db()['devices'] if d['username'] == username and d['status'] == 'active']
    for record in records:
        revoke(SimpleNamespace(username=username, device=record['device'], identity=record['id']))
    # Even an empty/stale database must remove any surviving central trust file.
    path = policy_module().KEYS / username
    if path.exists():
        if path.is_symlink():
            raise ValueError('Unsafe central trust path')
        atomic(path, b'')
        path.chmod(0o644)


def bundle_path(username):
    return AUTH / ('bundle-' + identifier(username) + '.json')


def read_bundle(username):
    path = bundle_path(username)
    if path.is_symlink():
        raise ValueError('Unsafe bundle path')
    if not path.exists():
        raise ValueError('No local private bundle. Shared accounts are renewed/exported on their issuing VPS.')
    data = json.loads(path.read_text())
    matches = [d for d in read_db()['devices'] if d['username'] == username and
               d['id'] == data['deviceId'] and d['status'] == 'active']
    if len(matches) != 1:
        raise ValueError('Certificate account has been revoked or removed')
    return data, matches[0]


def read_pasted_bundle(stream):
    chunks = []
    size = 0
    while True:
        line = stream.readline(65537)
        if not line or line.strip() == 'END':
            break
        size += len(line.encode('utf-8'))
        if size > 65536:
            raise ValueError('Pasted bundle exceeds 64 KiB')
        chunks.append(line)
    data = json.loads(''.join(chunks))
    if (not isinstance(data, dict) or data.get('schema') != 1 or
            data.get('type') != 'eng-ssh-account-bundle' or
            data.get('authMethod') != 'openssh-user-certificate' or
            data.get('privateKeyIncluded') is not True or
            not isinstance(data.get('privateKey'), str) or
            not isinstance(data.get('publicKey'), str)):
        raise ValueError('Paste a complete ENG account bundle including its matching private key')
    if public_key(data['publicKey']).split()[0] != 'ecdsa-sha2-nistp256':
        raise ValueError('Imported account keys must be P-256')
    return data


def disable_udp_password(username):
    # Account revocation must also invalidate the UDP password carried in JSON.
    run('usermod', '-L', identifier(username))


def configure_udp_password(username):
    password = secrets.token_urlsafe(36)
    # No plaintext secret in process arguments or public account output.
    result = subprocess.run(['openssl', 'passwd', '-6', '-stdin'], input=password + '\n',
                            capture_output=True, text=True, check=True, timeout=30)
    hashed = result.stdout.strip()
    if not re.fullmatch(r'\$6\$[^\s:]+', hashed):
        raise ValueError('Failed to generate UDP password hash')
    run('usermod', '-p', hashed, identifier(username))
    return dict(authMethod='password', username=username, password=password,
                portRange='50001-65535')


def create_bundle(args):
    # Caller explicitly requests certificate-only policy for this managed identity.
    account(args.username)
    if not 1 <= args.days <= 3650:
        raise ValueError('Certificate validity must be 1-3650 days')
    if any(d['username'] == args.username for d in read_db()['devices']):
        raise ValueError('Account already has credentials; renew or use a new account name')
    if bundle_path(args.username).exists() or bundle_path(args.username).is_symlink():
        raise ValueError('Bundle already exists')
    pins = pin_policy(args.username, args.host_key)
    pins['genPolicy']['SSHAuthMethod'] = 'account_certificate'
    with tempfile.TemporaryDirectory(dir=AUTH) as directory:
        key = Path(directory) / 'account'
        imported = getattr(args, 'bundle_data', None)
        if imported is None:
            run(KEYGEN, '-q', '-t', 'ecdsa', '-b', '256', '-N', '', '-f', key)
        else:
            atomic(key, imported['privateKey'].replace('\r\n', '\n').encode())
            actual = public_key(run(KEYGEN, '-y', '-P', '', '-f', key).stdout)
            if actual != public_key(imported['publicKey']):
                raise ValueError('Imported private and public keys do not match')
            # Foreign CAs are never trusted. Root explicitly imports the key;
            # ENG issues a NEW local certificate with the selected name/expiry.
            atomic(Path(str(key) + '.pub'), (actual + '\n').encode())
        result = enroll(SimpleNamespace(username=args.username, device='certificate-account',
                         public_key=Path(str(key) + '.pub'), days=args.days, generated_bundle=True))
        try:
            policy_module().set_mode(manager(), args.username, 'certificates-only')
            result.update(type='eng-ssh-account-bundle', privateKeyIncluded=True,
                          privateKey=key.read_text(), genPolicy=pins['genPolicy'])
            result['udpCustom'] = configure_udp_password(args.username)
            atomic(bundle_path(args.username), (json.dumps(result, indent=2) + '\n').encode())
        except BaseException:
            revoke(SimpleNamespace(username=args.username, device='certificate-account'))
            raise
    return bundle_path(args.username)


def renew_bundle(args):
    data, old = read_bundle(args.username)
    user, expiry = account(args.username)
    backend_policy(user, old['publicKey'].split()[0])
    transport_policy()
    # Preserve the key and identity so Gen can replace the credential predictably.
    record = sign_device(args.username, old['device'], old['publicKey'], args.days, expiry, old['id'])
    record['caPublicKey'] = authority()
    db = read_db()
    previous = json.loads(json.dumps(db))
    db['devices'] = [record if d['id'] == old['id'] else d for d in db['devices']]
    data.update(package(record, authority()))
    data.update(type='eng-ssh-account-bundle', privateKeyIncluded=True)
    with authorized_file(user) as (before, write):
        try:
            write(edit_lines(before, record['id'], entry(record, authority())))
            save_db(db)
            policy_module().sync(manager(), db, args.username)
            if 'udpCustom' not in data:
                data['udpCustom'] = configure_udp_password(args.username)
            atomic(bundle_path(args.username), (json.dumps(data, indent=2) + '\n').encode())
        except BaseException:
            write(before)
            save_db(previous)
            policy_module().sync(manager(), previous, args.username)
            raise
    return bundle_path(args.username)


def export_bundle(username, host_pin=None):
    account(username)
    data, _ = read_bundle(username)
    if datetime.fromisoformat(data['validBefore']) <= datetime.now(timezone.utc):
        raise ValueError('Certificate expired; renew first')
    if host_pin:
        if not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', host_pin):
            raise ValueError('Expected a verified SHA256 OpenSSH host fingerprint')
        data['genPolicy']['SSHHostKeyPin'] = host_pin
    return data


def shared_export(username, identity=None):
    """Public authorization only: never export a Gen bundle to another VPS."""
    account(username)
    records = [d for d in read_db()['devices'] if d['username'] == username and
               d['device'] == 'certificate-account' and d['status'] == 'active']
    if identity:
        records = [d for d in records if d['id'] == identity]
    elif len(records) > 1:
        local = [d for d in records if not d.get('shared')]
        if len(local) == 1:
            records = local
    if len(records) != 1:
        raise ValueError('Select one active certificate with --identity (see bundle-list)')
    record = records[0]
    data = dict(schema=1, type='eng-shared-ssh-authorization', username=username,
                deviceId=record['id'], publicKey=record['publicKey'],
                caPublicKey=record.get('caPublicKey') or authority(),
                validBefore=record['validBefore'])
    validate_shared(data)
    return data


def validate_shared(data):
    fields = {'schema', 'type', 'username', 'deviceId', 'publicKey', 'caPublicKey', 'validBefore'}
    if not isinstance(data, dict) or set(data) != fields or data['schema'] != 1 or data['type'] != 'eng-shared-ssh-authorization':
        raise ValueError('Expected public ENG shared authorization JSON, not a private Gen bundle')
    if any(not isinstance(data[key], str) for key in fields - {'schema'}):
        raise ValueError('Shared authorization fields must be strings')
    identifier(data['username'])
    if not isinstance(data['deviceId'], str) or not re.fullmatch(r'[a-f0-9]{32}', data['deviceId']):
        raise ValueError('Invalid shared certificate identity')
    data = dict(data)
    for key in ('publicKey', 'caPublicKey'):
        data[key] = public_key(data[key])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'key.pub'
            path.write_text(data[key] + '\n')
            run(KEYGEN, '-l', '-f', path)
    if not data['caPublicKey'].startswith('ssh-ed25519 '):
        raise ValueError('Expected an ENG Ed25519 certificate authority')
    expiry = datetime.fromisoformat(data['validBefore'])
    now = datetime.now(timezone.utc)
    if expiry.tzinfo is None or not now < expiry <= now + timedelta(days=3651):
        raise ValueError('Shared authorization is expired or has invalid expiry')
    data['validBefore'] = expiry.astimezone(timezone.utc).isoformat()
    return data


def shared_import(data, new_account=False):
    data = validate_shared(data)
    username = data['username']
    user, expiry = account(username)
    end = min(datetime.fromisoformat(data['validBefore']), expiry)
    db = read_db()
    previous = json.loads(json.dumps(db))
    records = [d for d in db['devices'] if d['username'] == username]
    matches = [d for d in records if d['id'] == data['deviceId']]
    if any(d['id'] == data['deviceId'] and d['username'] != username for d in db['devices']):
        raise ValueError('Certificate identity already belongs to another username')
    if matches:
        if len(matches) != 1 or matches[0]['status'] != 'active':
            raise ValueError('Refusing to restore a revoked certificate identity')
        old = matches[0]
        ca = old.get('caPublicKey') or authority()
        if ca != data['caPublicKey'] or old['publicKey'] != data['publicKey']:
            raise ValueError('Certificate identity key or CA changed; use a new identity')
        if not old.get('shared'):
            print('This VPS already owns the original certificate:', username)
            return
    elif not new_account and not any(d['device'] == 'certificate-account' and
                                     d['status'] == 'active' for d in records):
        raise ValueError('Refusing to convert an existing password account; create a certificate account first')
    backend_policy(user, data['publicKey'].split()[0])
    transport_policy()
    record = dict(id=data['deviceId'], username=username, device='certificate-account',
                  principal='eng-app-' + data['deviceId'], status='active', shared=True,
                  publicKey=data['publicKey'], caPublicKey=data['caPublicKey'],
                  validAfter=datetime.now(timezone.utc).isoformat(), validBefore=end.isoformat())
    db['devices'] = [d for d in db['devices'] if not (d['username'] == username and d['id'] == record['id'])] + [record]
    with authorized_file(user) as (before, write):
        try:
            write(edit_lines(before, record['id'], entry(record, record['caPublicKey'])))
            save_db(db)
            policy_module().set_mode(manager(), username, 'certificates-only')
        except BaseException:
            write(before)
            save_db(previous)
            policy_module().sync(manager(), previous, username)
            raise
    print('Shared certificate authorized:', username, 'identity:', record['id'])
    print('Local authorization expires:', record['validBefore'])
    print('No private keys, UDP credentials or host keys imported. Revoke on each VPS separately.')


def list_certificate_accounts():
    now = datetime.now(timezone.utc)
    rows = []
    for record in read_db()['devices']:
        if record['device'] != 'certificate-account':
            continue
        status = record['status']
        if status == 'active' and datetime.fromisoformat(record['validBefore']) <= now:
            status = 'expired'
        rows.append((record['username'], status, record['validBefore'], record.get('id', '-'),
                     'shared' if record.get('shared') else 'local'))
    if not rows:
        print('No certificate accounts found.')
        return
    print('ACCOUNT\tSTATUS\tCERTIFICATE EXPIRY (UTC)\tIDENTITY\tORIGIN')
    for row in rows:
        print(*row, sep='\t')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('bundle-create', 'bundle-import', 'bundle-renew', 'bundle-export', 'bundle-check'):
        bundle = commands.add_parser(action)
        bundle.add_argument('username')
        bundle.add_argument('--host-pin', help='Verified destination host fingerprint; export only')
        bundle.add_argument('--days', type=int, default=30)
        bundle.add_argument('--host-key', type=Path, default=Path('/etc/ssh/ssh_host_ed25519_key.pub'))
    approve = commands.add_parser('enroll')
    approve.add_argument('username')
    approve.add_argument('device')
    approve.add_argument('public_key', type=Path)
    approve.add_argument('--days', type=int, default=7)
    cancel = commands.add_parser('revoke')
    cancel.add_argument('username')
    cancel.add_argument('device')
    cancel.add_argument('--identity', help='Revoke only this identity; otherwise prefer the local certificate')
    commands.add_parser('list')
    commands.add_parser('bundle-list')
    shared = commands.add_parser('shared-export')
    shared.add_argument('username')
    shared.add_argument('--identity', help='Export this identity; otherwise prefer the local certificate')
    shared = commands.add_parser('shared-import')
    shared.add_argument('file', type=Path)
    audit = commands.add_parser('audit')
    audit.add_argument('username')
    pins = commands.add_parser('pins')
    pins.add_argument('username')
    pins.add_argument('--host-key', type=Path, default=Path('/etc/ssh/ssh_host_ed25519_key.pub'))
    policy = commands.add_parser('policy')
    policy.add_argument('username')
    policy.add_argument('--mode', choices=('mixed', 'certificates-only'), required=True)
    purge = commands.add_parser('purge', help=argparse.SUPPRESS)
    purge.add_argument('username')
    purge.add_argument('--from-account-manager', action='store_true', help=argparse.SUPPRESS)
    export = commands.add_parser('export')
    export.add_argument('username')
    export.add_argument('device')
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Run as root on the Linux VPS')
    if getattr(args, 'host_pin', None) and args.action != 'bundle-export':
        parser.error('--host-pin is only available for bundle-export')
    if args.action == 'bundle-import':
        print('Paste ENG JSON, then END on its own line. A new local certificate will be issued.', file=sys.stderr)
        args.bundle_data = read_pasted_bundle(sys.stdin)
    if args.action == 'shared-import':
        import pwd
        with args.file.open('rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('Public authorization must be a regular JSON file')
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise ValueError('Oversized public authorization package')
        args.shared_data = validate_shared(json.loads(raw))
        name = args.shared_data['username']
        try:
            pwd.getpwnam(name)
        except KeyError:
            days = (datetime.fromisoformat(args.shared_data['validBefore']) - datetime.now(timezone.utc)).days + 2
            run('bash', Path(__file__).with_name('ssh-accounts.sh'), 'create-certificate', name, str(days))
            args.shared_new_account = True
    import fcntl
    os.umask(0o077)
    if AUTH.is_symlink():
        raise ValueError('Auth directory cannot be a symlink')
    AUTH.mkdir(mode=0o700, exist_ok=True)
    if AUTH.stat().st_uid != 0 or AUTH.stat().st_mode & 0o077:
        raise ValueError('Auth directory must be root-owned mode 0700')
    with ExitStack() as stack:
        if args.action == 'purge' and args.from_account_manager:
            inherited, expected = os.fstat(9), (STATE / '.ssh-accounts.lock').stat()
            if (inherited.st_dev, inherited.st_ino) != (expected.st_dev, expected.st_ino):
                raise ValueError('Expected inherited SSH account-manager lock')
            fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            accounts_lock = stack.enter_context((STATE / '.ssh-accounts.lock').open('a'))
            fcntl.flock(accounts_lock, fcntl.LOCK_EX)
        lock = stack.enter_context((AUTH / 'lock').open('a'))
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action in ('bundle-create', 'bundle-import'):
            print('Private Gen bundle saved:', create_bundle(args))
        elif args.action == 'bundle-renew':
            print('Renewed private Gen bundle saved:', renew_bundle(args))
        elif args.action == 'bundle-check':
            read_bundle(args.username)
        elif args.action == 'bundle-export':
            print(json.dumps(export_bundle(args.username, args.host_pin), indent=2))
        elif args.action == 'enroll':
            print(json.dumps(enroll(args), indent=2))
        elif args.action == 'revoke':
            revoke(args)
        elif args.action == 'shared-export':
            print(json.dumps(shared_export(args.username, args.identity), indent=2))
        elif args.action == 'shared-import':
            shared_import(args.shared_data, getattr(args, 'shared_new_account', False))
        elif args.action == 'bundle-list':
            list_certificate_accounts()
        elif args.action == 'list':
            for d in read_db()['devices']:
                print(d['username'], d['device'], d['status'], d['validBefore'], sep='\t')
        elif args.action == 'policy':
            policy_module().set_mode(manager(), args.username, args.mode)
        elif args.action == 'pins':
            print(json.dumps(pin_policy(args.username, args.host_key), indent=2))
        elif args.action == 'purge':
            purge_account(args.username)
        elif args.action == 'audit':
            user, _ = account(args.username)
            print(json.dumps(dict(sshConfigs=backend_policy(user), transports=transport_policy(),
                                  loginAndBrowsing='not tested',
                                  accountPolicy=policy_module().modes(manager()).get(args.username, 'mixed'),
                                  otherAccounts='configuration unchanged'), indent=2))
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
