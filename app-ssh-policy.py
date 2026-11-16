#!/usr/bin/env python3
"""Scoped OpenSSH certificate-only account policy; no global password changes."""
import base64
import json
import glob
import shlex
from pathlib import Path
import subprocess
import tempfile

POLICY = Path('/etc/ssh/frimps-app-policy.conf')
KEYS = Path('/etc/ssh/frimps-app-keys')
ADMIN = Path('/etc/ssh/sshd_config')
BACKUPS = Path('/var/backups/frimps-v6/app-ssh-policy')


def modes(m):
    path = m.AUTH / 'account-policy.json'
    return json.loads(path.read_text()) if path.exists() else {}


def render(accounts):
    names = sorted(accounts)
    for name in names:
        if accounts[name] != 'certificates-only':
            raise ValueError('Unsupported account policy')
    if not names:
        return '# ENG app account policy; no certificate-only accounts\n'
    return ('# ENG app account policy\nMatch all\nMatch User ' + ','.join(names) + '\n'
            '    AuthenticationMethods publickey\n    PasswordAuthentication no\n'
            '    KbdInteractiveAuthentication no\n    PubkeyAuthentication yes\n'
            f'    AuthorizedKeysFile {KEYS}/%u\n'
            '    PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com\n'
            'Match all\n')


def sync(m, db, username):
    if modes(m).get(username) != 'certificates-only':
        return
    ca = m.public_key((m.AUTH / 'ca.pub').read_text())
    data = b''.join(m.entry(d, ca) for d in db['devices'] if d['username'] == username and d['status'] == 'active')
    m.atomic(KEYS / username, data)
    (KEYS / username).chmod(0o644)


def append_include(text):
    marker = '# ENG app certificate policy include'
    if marker in text:
        expected = marker + '\nMatch all\nInclude ' + str(POLICY) + '\n'
        if not text.endswith(expected):
            raise ValueError('Managed policy include was modified or is not at end of SSH config')
        return text
    return text.rstrip() + '\n\n' + marker + '\nMatch all\nInclude ' + str(POLICY) + '\n'


def prepare_keys():
    KEYS.mkdir(parents=True, exist_ok=True, mode=0o755)
    if KEYS.stat().st_uid != 0 or KEYS.stat().st_mode & 0o022:
        raise ValueError('Managed public keys directory must be root-owned and not writable by others')
    KEYS.chmod(0o755)


def check_existing_matches(config, seen=None):
    # A localhost -T check alone cannot rule out an earlier address-specific
    # password exception. Require review of custom conditional rules first.
    seen = set() if seen is None else seen
    config = config.resolve()
    if config in seen or config == POLICY.resolve():
        return
    seen.add(config)
    if len(seen) > 100:
        raise ValueError('Too many SSH includes; review policy manually')
    text = config.read_text().split('# ENG app certificate policy include', 1)[0]
    for line in text.splitlines():
        fields = shlex.split(line, comments=True)
        if not fields:
            continue
        if fields[0].lower() == 'match' and [x.lower() for x in fields[1:]] != ['all']:
            raise ValueError(f'Custom SSH Match rule in {config}; review before enabling account policy')
        if fields[0].lower() == 'include':
            for pattern in fields[1:]:
                pattern = Path(pattern)
                if not pattern.is_absolute():
                    pattern = ADMIN.parent / pattern
                for path in glob.glob(str(pattern)):
                    check_existing_matches(Path(path), seen)


def set_mode(m, username, mode):
    user, _ = m.account(username)
    m.transport_policy()
    current = modes(m)
    updated = dict(current)
    if mode == 'certificates-only':
        from datetime import datetime, timezone
        if not any(d['username'] == username and d['status'] == 'active' and
                   datetime.fromisoformat(d['validBefore']) > datetime.now(timezone.utc)
                   for d in m.read_db()['devices']):
            raise ValueError('Enroll an unexpired device before making this account certificate-only')
        updated[username] = mode
    else:
        updated.pop(username, None)
    for name in updated:
        m.identifier(name)
    configs = [ADMIN]
    backend = m.STATE / 'sshd-backend.conf'
    if backend.exists():
        configs.append(backend)
    for path in [*configs, POLICY, KEYS, KEYS / username]:
        if path.is_symlink():
            raise ValueError('Refusing symlink in managed SSH policy paths')
    for path in configs:
        if POLICY.exists() and not POLICY.read_text().startswith('# ENG app account policy'):
            raise ValueError('Unmanaged policy file; no change applied')
        if not path.is_file():
            raise ValueError('Expected an installed OpenSSH config')
        check_existing_matches(path)
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = Path(tempfile.mkdtemp(dir=BACKUPS))
    paths = [*configs, POLICY, KEYS / username, m.AUTH / 'account-policy.json']
    saved = {str(p): {'data': base64.b64encode(p.read_bytes()).decode(), 'mode': p.stat().st_mode & 0o777}
             if p.exists() else None for p in paths}
    m.atomic(backup / 'files.json', json.dumps(saved, indent=2).encode())
    services = ['ssh.service'] + (['frimps-v6-ssh-backend.service'] if backend.exists() else [])
    def reload():
        for service in services:
            # HUP re-reads sshd configuration without terminating authenticated sessions.
            m.run('systemctl', 'kill', '--kill-who=main', '--signal=HUP', service)
    try:
        prepare_keys()
        m.atomic(m.AUTH / 'account-policy.json', json.dumps(updated, indent=2).encode())
        sync(m, m.read_db(), username)
        m.atomic(POLICY, render(updated).encode())
        for config in configs:
            m.atomic(config, append_include(config.read_text()).encode())
            config.chmod(saved[str(config)]['mode'])
            m.run('/usr/sbin/sshd', '-t', '-f', config)
        m.backend_policy(user)
        # Verify the effective Match result, not merely that syntax is accepted.
        for config in configs:
            settings = dict(line.split(' ', 1) for line in m.run('/usr/sbin/sshd', '-T', '-f', config,
                '-C', f'user={username},host=localhost,addr=127.0.0.1').stdout.splitlines() if ' ' in line)
            if mode == 'certificates-only' and (settings.get('passwordauthentication') != 'no' or
                    settings.get('kbdinteractiveauthentication') != 'no' or
                    settings.get('authenticationmethods') != 'publickey' or
                    settings.get('authorizedkeysfile') != str(KEYS / '%u')):
                raise ValueError('An earlier SSH Match rule overrides the certificate-only policy')
        reload()
    except BaseException:
        for path, item in saved.items():
            path = Path(path)
            if item is None:
                path.unlink(missing_ok=True)
            else:
                m.atomic(path, base64.b64decode(item['data']))
                path.chmod(item['mode'])
        try:
            reload()
        except subprocess.SubprocessError:
            print('Automatic reload of restored config failed; inspect SSH from the existing admin session.', file=__import__('sys').stderr)
        raise
    print(f'Account {username}: {mode}. Other accounts retain their existing policy. Backup: {backup}')
