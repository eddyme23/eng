#!/usr/bin/env python3
"""Install/update the optional panel without restarting any VPN service."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess

ROOT = Path('/usr/local/lib/frimps-v6')
STATE = Path('/etc/frimps-panel')
HERE = Path(__file__).resolve().parent
ROUTES = Path('/etc/frimps-v6/routes.json')
CERTIFICATES = Path('/etc/letsencrypt/live')
UNITS = Path('/etc/systemd/system')
HOOKS = Path('/etc/letsencrypt/renewal-hooks/deploy')
DATA = Path('/var/lib/frimps-panel')
CF_CREDENTIALS = Path('/etc/letsencrypt/cloudflare.ini')


def units():
    helper = '''[Unit]
Description=ENG restricted panel account helper
After=network.target
[Service]
Type=simple
RuntimeDirectory=frimps-panel
RuntimeDirectoryMode=0750
Group=frimps-panel
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/lib/frimps-v6/panel-helper.py
Restart=on-failure
RestartSec=3
PrivateTmp=true
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
'''
    web = '''[Unit]
Description=ENG optional HTTPS administration panel
Requires=frimps-panel-helper.service
After=network.target frimps-panel-helper.service
[Service]
Type=simple
User=frimps-panel
Group=frimps-panel
UMask=0077
ExecStart=/usr/bin/python3 /usr/local/lib/frimps-v6/panel-server.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
LockPersonality=true
[Install]
WantedBy=multi-user.target
'''
    return helper, web


def call(*args):
    subprocess.run(args, check=True)


def write(path, text, mode=0o644):
    tmp = path.with_name(path.name + '.new')
    tmp.write_text(text, encoding='utf-8')
    tmp.chmod(mode)
    tmp.replace(path)


def main():
    import pwd
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', help='Hostname covered by an existing TLS certificate')
    parser.add_argument('--port', type=int, default=None)
    parser.add_argument('--bind', choices=('0.0.0.0', '127.0.0.1'), default=None)
    parser.add_argument('--reset-password', action='store_true')
    parser.add_argument('--central', action='store_true', help='Enable central management with administrator two-factor login')
    parser.add_argument('--local-name', help='Display name for this VPS in the central server selector')
    parser.add_argument('--reset-2fa', action='store_true', help='Set up a replacement administrator authenticator secret')
    parser.add_argument('--issue-certificate', action='store_true', help='Issue a missing hostname certificate using the existing ENG Cloudflare credentials')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run as root')
    if not ROUTES.is_file():
        raise SystemExit('Install ENG first')
    old = json.loads((STATE / 'web.json').read_text()) if (STATE / 'web.json').exists() else {}
    domain = args.domain or old.get('domain') or json.loads(ROUTES.read_text())['primaryDomain']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,251}[A-Za-z0-9]', domain):
        raise SystemExit('Invalid hostname')
    port = args.port or old.get('port', 8445)
    if not 1024 <= port <= 65535:
        raise SystemExit('Choose a port between 1024 and 65535')
    bind = args.bind or old.get('bind', '0.0.0.0')
    # Validate existing cert/key before changing an installed panel.
    cert = CERTIFICATES / domain / 'fullchain.pem'
    key = cert.with_name('privkey.pem')
    if not cert.is_file() and args.issue_certificate:
        if not CF_CREDENTIALS.is_file() or not shutil.which('certbot'):
            raise SystemExit('Existing ENG certbot and /etc/letsencrypt/cloudflare.ini are required to issue the panel certificate')
        call('certbot', 'certonly', '--non-interactive', '--dns-cloudflare',
             '--dns-cloudflare-credentials', str(CF_CREDENTIALS),
             '--dns-cloudflare-propagation-seconds', '60', '--keep-until-expiring',
             '--cert-name', domain, '-d', domain)
    if not cert.is_file() and not args.issue_certificate:
        # load_cert_chain below remains the final cryptographic validation.
        print('TLS certificate required for:', domain)
        print('Use --issue-certificate to reuse the existing ENG Cloudflare DNS credentials.')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    if not old or port != old.get('port') or bind != old.get('bind'):
        with socket.socket() as probe:
            probe.bind((bind, port))
    if not old or args.reset_password:
        username = input('Panel administrator name [admin]: ').strip() or 'admin'
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', username):
            raise SystemExit('Invalid administrator name')
        password = getpass.getpass('Panel password (at least 3 characters): ')
        if len(password) < 3 or len(password) > 256 or password != getpass.getpass('Repeat password: '):
            raise SystemExit('Passwords must match and contain 3-256 characters')
        import importlib.util
        spec = importlib.util.spec_from_file_location('eng_panel', HERE / 'panel-server.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        salt = secrets.token_hex(16)
        old.update(username=username, salt=salt, passwordHash=module.password_hash(password, salt))
    central = args.central or old.get('central', False)
    if args.reset_2fa and not central:
        raise SystemExit('--reset-2fa applies to central management')
    if central and (not old.get('totpSecret') or args.reset_2fa):
        from panel_totp import new_secret, verify
        from urllib.parse import quote
        secret = new_secret()
        print('Add this account to your authenticator app. Keep the setup key private.')
        print('Account:', old['username'] + '@' + domain)
        print('Setup key:', secret)
        print('Authenticator URI: otpauth://totp/' + quote('ENG:' + old['username'] + '@' + domain, safe='') +
              '?secret=' + secret + '&issuer=ENG&algorithm=SHA1&digits=6&period=30')
        if verify(secret, getpass.getpass('Enter the current six-digit authenticator code: ').strip()) is None:
            raise SystemExit('Authenticator code did not match; no panel configuration changed')
        old['totpSecret'] = secret
    try:
        account = pwd.getpwnam('frimps-panel')
        if account.pw_uid == 0 or account.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
            raise SystemExit('frimps-panel must be a dedicated non-login service user')
    except KeyError:
        call('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'frimps-panel')
    ROOT.mkdir(parents=True, exist_ok=True)
    # Runtime remains root-owned; the web user cannot change executable helpers.
    for source in HERE.iterdir():
        if source.suffix in ('.sh', '.py') or source.name in ('panel.html', 'panel.css', 'panel.js'):
            target = ROOT / source.name
            if source.resolve() != target.resolve():
                shutil.copyfile(source, target)
            target.chmod(0o755 if source.suffix in ('.sh', '.py') else 0o644)
            os.chown(target, 0, 0)
    STATE.mkdir(mode=0o750, parents=True, exist_ok=True)
    import grp
    gid = grp.getgrnam('frimps-panel').gr_gid
    if central:
        DATA.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(DATA, pwd.getpwnam('frimps-panel').pw_uid, gid)
        DATA.chmod(0o700)
    os.chown(STATE, 0, gid)
    STATE.chmod(0o750)
    old.update(domain=domain, bind=bind, port=port, origin=f'https://{domain}:{port}',
               cert='/run/credentials/frimps-panel.service/tls.crt',
               key='/run/credentials/frimps-panel.service/tls.key')
    if central:
        label = args.local_name or old.get('localName') or json.loads(ROUTES.read_text())['primaryDomain']
        if not re.fullmatch(r'[\w .()-]{1,48}', label, re.UNICODE):
            raise SystemExit('Invalid local server name')
        old.update(central=True, dataDir=str(DATA), localName=label)
    write(STATE / 'web.json', json.dumps(old, indent=2) + '\n', 0o640)
    os.chown(STATE / 'web.json', 0, gid)
    helper, web = units()
    web = web.replace('[Service]\n', f'[Service]\nLoadCredential=tls.crt:{cert}\nLoadCredential=tls.key:{key}\n')
    if central:
        web = web.replace('[Service]\n', f'[Service]\nReadWritePaths={DATA}\n')
    write(UNITS / 'frimps-panel-helper.service', helper)
    write(UNITS / 'frimps-panel.service', web)
    # Certificate renewal refreshes systemd credentials without touching VPNs.
    hooks = HOOKS
    hooks.mkdir(parents=True, exist_ok=True)
    write(hooks / 'eng-panel', '#!/bin/sh\nif systemctl is-active --quiet frimps-panel.service; then systemctl restart frimps-panel.service; fi\n', 0o755)
    call('systemctl', 'daemon-reload')
    call('systemctl', 'enable', 'frimps-panel-helper.service', 'frimps-panel.service')
    call('systemctl', 'restart', 'frimps-panel-helper.service', 'frimps-panel.service')
    call('systemctl', 'is-active', '--quiet', 'frimps-panel-helper.service', 'frimps-panel.service')
    print(f'ENG panel: https://{domain}:{port}')
    if central:
        print('Central management enabled. Sign in with your administrator password and authenticator code.')
        print('This VPS is available locally. Add other servers using one-time pairing codes in the panel.')
    if central:
        print(f'Allow inbound TCP {port} from your administrator and remote VPS IP addresses. Use a DNS-only hostname.')
    else:
        print(f'Allow inbound TCP {port} only from your administrator IP where possible. Use a DNS-only hostname.')
    print('VPN services, account stores, DNS keys and routing were not changed.')


if __name__ == '__main__':
    main()
