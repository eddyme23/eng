#!/usr/bin/env python3
"""ENG-owned Xray accounts, configuration and gateway overlay.

No Linux SSH accounts, DNS keys, UDP firewall rules or credentials are changed.
"""
import argparse
import base64
import contextlib
import copy
import datetime as dt
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import uuid
from urllib.parse import urlencode, quote

PROTOCOLS = ('vless', 'vmess', 'trojan')
# One internal listener per transport. TLS is supplied by the existing gateway.
TRANSPORTS = (
    ('vless', 'ws', '/vless-ws', 13101),
    ('vless', 'httpupgrade', '/vless-upgrade', 13102),
    ('vless', 'xhttp', '/vless-xhttp', 13103),
    ('vmess', 'ws', '/vmess-ws', 13104),
    ('vmess', 'httpupgrade', '/vmess-upgrade', 13105),
    ('trojan', 'ws', '/trojan-ws', 13106),
)
BEGIN, END = '# BEGIN ENG XRAY', '# END ENG XRAY'


def load(path, default=None):
    return json.loads(path.read_text()) if path.exists() else copy.deepcopy(default)


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(value if isinstance(value, str) else json.dumps(value, indent=2) + '\n')
        os.chmod(temp, 0o600)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def hostname(value):
    if not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9]+(?:[.-][a-zA-Z0-9]+)*', value):
        raise ValueError('Invalid hostname')
    return value.lower()


def active(user, today=None):
    return user['expiresAt'] >= (today or dt.datetime.now(dt.timezone.utc).date().isoformat())


def configuration(settings, accounts):
    inbounds = []
    for protocol, network, path, port in TRANSPORTS:
        users = [dict(email=u['name'], **({'password': u['password']} if protocol == 'trojan'
                 else {'id': u['uuid'], **({'alterId': 0} if protocol == 'vmess' else {})}))
                 for u in accounts[protocol] if active(u)]
        stream = {'network': network, 'security': 'none',
                  {'ws': 'wsSettings', 'httpupgrade': 'httpupgradeSettings', 'xhttp': 'xhttpSettings'}[network]:
                  {'path': path, **({'mode': 'auto'} if network == 'xhttp' else {})}}
        inbounds.append({'tag': protocol + '-' + network, 'listen': '127.0.0.1', 'port': port,
                         'protocol': protocol, 'settings': {'clients': users, **({'decryption': 'none'} if protocol == 'vless' else {})},
                         'streamSettings': stream})
    r = settings['reality']
    inbounds.append({'tag': 'vless-reality', 'listen': '127.0.0.1', 'port': 13107, 'protocol': 'vless',
                     'settings': {'decryption': 'none', 'clients': [dict(id=u['uuid'], email=u['name'], flow='xtls-rprx-vision')
                                  for u in accounts['vless'] if active(u)]},
                     'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                         'show': False, 'target': r['target'], 'xver': 0,
                         'serverNames': [r['serverName']], 'privateKey': r['privateKey'], 'shortIds': [r['shortId']]}}})
    return {'log': {'loglevel': 'warning'}, 'inbounds': inbounds,
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}, {'protocol': 'blackhole', 'tag': 'blocked'}],
            'routing': {'rules': [{'type': 'field', 'ip': ['127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12',
                         '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '::1/128', 'fc00::/7', 'fe80::/10'],
                         'outboundTag': 'blocked'}]}}


def accounts_at(state):
    return load(state / 'xray-users.json', {p: [] for p in PROTOCOLS})


def validate_config(binary, config, directory):
    with tempfile.TemporaryDirectory(dir=directory) as tmp:
        candidate = Path(tmp) / 'config.json'
        atomic(candidate, config)
        subprocess.run([binary, 'run', '-test', '-config', str(candidate)], check=True, capture_output=True)


def render(state, binary):
    settings = load(state / 'xray-settings.json')
    config = configuration(settings, accounts_at(state))
    validate_config(binary, config, state)
    atomic(state / 'xray.json', config)
    atomic(state / 'xray-routes.json', {path: f'127.0.0.1:{port}' for _, _, path, port in TRANSPORTS})


def strip_overlay(text):
    return re.sub(r'(?m)^\s*# BEGIN ENG XRAY\n.*?^\s*# END ENG XRAY\n', '', text, flags=re.S)


def overlay_haproxy(text, settings):
    text = strip_overlay(text)
    r = settings['reality']
    # The client connects to realityDomain but sends target serverName as SNI.
    # A DNS alias cannot be distinguished on the wire; route using target SNI.
    block = (f'    {BEGIN}\n    tcp-request inspect-delay 5s\n'
             '    tcp-request content accept if { req.ssl_hello_type 1 }\n'
             f'    use_backend eng_xray_reality if {{ req.ssl_sni -i {r["serverName"]} }}\n    {END}\n')
    marker = 'frontend public_tcp_443\n    bind :443\n'
    if text.count(marker) != 1:
        raise ValueError('Unrecognized ENG HAProxy listener; refusing to replace it')
    text = text.replace(marker, marker + block)
    text += f'\n{BEGIN}\nbackend eng_xray_reality\n    server xray_reality 127.0.0.1:13107\n{END}\n'
    return text


def overlay_nginx(text):
    text = strip_overlay(text)
    lines = []
    for _, _, path, port in TRANSPORTS:
        locations = [f'= {path}'] + ([f'^~ {path}/'] if path == '/vless-xhttp' else [])
        for location in locations:
            lines.append(f'''    location {location} {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        client_max_body_size 0;
    }}''')
    block = f'    {BEGIN}\n' + '\n'.join(lines) + f'\n    {END}\n'
    # Only insert into existing ENG HTTP servers, leaving other sites alone.
    updated, count = re.subn(r'(?m)^(    server_name [^;]+;\n)', lambda m: m[0] + block, text)
    if count != 2:
        raise ValueError('Unrecognized ENG nginx configuration; expected two local servers')
    return updated


def decorate(state):
    if not (state / 'xray-settings.json').exists():
        return
    settings = load(state / 'xray-settings.json')
    atomic(state / 'haproxy-443.cfg', overlay_haproxy((state / 'haproxy-443.cfg').read_text(), settings))
    atomic(state / 'nginx-main-tls.conf', overlay_nginx((state / 'nginx-main-tls.conf').read_text()))
    metadata(state)


def metadata(state):
    if not (state / 'xray-settings.json').exists() or not (state / 'backends.json').exists():
        return
    data = load(state / 'backends.json')
    rows = [r for r in data['publicRoutes'] if r.get('owner') != 'eng-xray']
    for protocol, network, path, port in TRANSPORTS:
        for tls in ([True] if protocol == 'trojan' else [False, True]):
            rows.append(dict(owner='eng-xray', transport='tls-http' if tls else 'plain-http',
                             path=path, backend=f'xray-{protocol}-{network}:{port}', publicPort=443 if tls else 80))
    data['publicRoutes'] = rows
    data['xrayReality'] = {'publicPort': 443, 'backend': '127.0.0.1:13107',
                           'serverName': load(state / 'xray-settings.json')['reality']['serverName']}
    atomic(state / 'backends.json', data)


def links(settings, protocol, user):
    for proto, network, path, _ in TRANSPORTS:
        if proto != protocol:
            continue
        for tls in ([True] if protocol == 'trojan' else [False, True]):
            host = settings.get('tlsDomain', settings['domain']) if tls else settings['domain']
            port = 443 if tls else 80
            label = f'ENG-{user["name"]}-{protocol}-{network}-' + ('TLS' if tls else 'NTLS')
            if protocol == 'vmess':
                data = dict(v='2', ps=label, add=host, port=str(port), id=user['uuid'], aid='0', scy='auto',
                            net=network, type='none', host=host, path=path, tls='tls' if tls else '', sni=host if tls else '')
                if tls:
                    data.update(alpn='http/1.1', fp='chrome')
                yield 'vmess://' + base64.b64encode(json.dumps(data, separators=(',', ':')).encode()).decode()
            else:
                query = dict(type=network, security='tls' if tls else 'none', host=host, path=path)
                if protocol == 'vless':
                    query['encryption'] = 'none'
                if tls:
                    query.update(sni=host, fp='chrome', alpn='http/1.1' if network != 'xhttp' else 'h2,http/1.1')
                if network == 'xhttp':
                    query['mode'] = 'auto'
                credential = user['password'] if protocol == 'trojan' else user['uuid']
                yield f'{protocol}://{quote(credential, safe="")}@{host}:{port}?{urlencode(query)}#{quote(label)}'
    if protocol == 'vless':
        r = settings['reality']
        query = dict(type='tcp', security='reality', encryption='none', flow='xtls-rprx-vision',
                     sni=r['serverName'], fp='chrome', pbk=r['publicKey'], sid=r['shortId'], spx='/')
        yield f'vless://{user["uuid"]}@{r["domain"]}:443?{urlencode(query)}#ENG-{quote(user["name"])}-REALITY'


def change(state, binary, protocol, action, name='', days=30):
    old = accounts_at(state)
    users = copy.deepcopy(old)
    rows = users[protocol]
    matches = [u for u in rows if u['name'] == name]
    if action in ('create', 'renew'):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}', name) or not 1 <= days <= 3650:
            raise ValueError('Use a 1-32 character account name and 1-3650 days')
        expiry = (dt.datetime.now(dt.timezone.utc).date() + dt.timedelta(days=days)).isoformat()
        if action == 'create':
            if matches:
                raise ValueError('Account already exists; renew it or delete it first')
            rows.append(dict(name=name, expiresAt=expiry, **({'password': secrets.token_urlsafe(32)}
                        if protocol == 'trojan' else {'uuid': str(uuid.uuid4())})))
        else:
            if not matches:
                raise ValueError('Account not found')
            matches[0]['expiresAt'] = expiry
    elif action == 'delete':
        if not matches:
            raise ValueError('Account not found')
        users[protocol] = [u for u in rows if u['name'] != name]
    elif action == 'cleanup':
        for p in PROTOCOLS:
            users[p] = [u for u in users[p] if active(u)]
        if users == old:
            return
    settings = load(state / 'xray-settings.json')
    config = configuration(settings, users)
    validate_config(binary, config, state)
    old_config = (state / 'xray.json').read_text()
    try:
        atomic(state / 'xray-users.json', users)
        atomic(state / 'xray.json', config)
        subprocess.run(['systemctl', 'restart', 'frimps-xray.service'], check=True)
        subprocess.run(['systemctl', 'is-active', '--quiet', 'frimps-xray.service'], check=True)
    except Exception:
        atomic(state / 'xray-users.json', old)
        atomic(state / 'xray.json', old_config)
        subprocess.run(['systemctl', 'restart', 'frimps-xray.service'], check=False)
        raise


@contextlib.contextmanager
def locked(state, account_operation=False):
    import fcntl
    with contextlib.ExitStack() as stack:
        if account_operation:
            installer = stack.enter_context((state / 'xray-install.lock').open('a'))
            fcntl.flock(installer, fcntl.LOCK_EX)
        stream = stack.enter_context((state / 'xray.lock').open('a'))
        os.chmod(stream.name, 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['init', 'render', 'decorate', 'metadata', 'create', 'renew', 'delete', 'list', 'links', 'cleanup'])
    parser.add_argument('protocol', nargs='?', choices=PROTOCOLS, default='vless')
    parser.add_argument('name', nargs='?', default='')
    parser.add_argument('days', nargs='?', type=int, default=30)
    parser.add_argument('--domain')
    parser.add_argument('--reality-domain')
    parser.add_argument('--reality-sni', default='www.apple.com')
    parser.add_argument('--binary', default='/usr/local/libexec/frimps-xray')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run as root')
    state = Path(os.environ.get('V6_STATE_DIR', '/etc/frimps-v6'))
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    with locked(state, args.action not in ('init', 'render', 'decorate', 'metadata')):
        if args.action == 'init':
            if not (state / 'xray-settings.json').exists():
                primary = hostname(load(state / 'routes.json')['primaryDomain'])
                domain = hostname(args.domain or primary)
                sni = hostname(args.reality_sni)
                if sni in (domain, primary):
                    raise ValueError('REALITY target SNI must differ from the normal TLS domain')
                output = subprocess.check_output([args.binary, 'x25519'], text=True)
                fields = dict(line.split(':', 1) for line in output.splitlines() if ':' in line)
                private = fields.get('PrivateKey', fields.get('Private key', '')).strip()
                public = fields.get('Password (PublicKey)', fields.get('Password', fields.get('Public key', fields.get('PublicKey', '')))).strip()
                if not re.fullmatch(r'[\w-]{43}', private) or not re.fullmatch(r'[\w-]{43}', public):
                    raise ValueError('Cannot read Xray X25519 keys')
                atomic(state / 'xray-settings.json', dict(schema=1, domain=domain, tlsDomain=primary, reality=dict(
                    domain=hostname(args.reality_domain or 'reality.' + domain), serverName=sni,
                    target=sni + ':443', privateKey=private, publicKey=public, shortId=secrets.token_hex(8))))
            if not (state / 'xray-users.json').exists():
                atomic(state / 'xray-users.json', {p: [] for p in PROTOCOLS})
            render(state, args.binary)
        elif args.action == 'render':
            render(state, args.binary)
        elif args.action == 'decorate':
            decorate(state)
        elif args.action == 'metadata':
            metadata(state)
        elif args.action == 'list':
            for u in accounts_at(state)[args.protocol]:
                print(u['name'], u['expiresAt'], 'active' if active(u) else 'expired', sep='\t')
        elif args.action == 'links':
            user = next((u for u in accounts_at(state)[args.protocol] if u['name'] == args.name), None)
            if not user or not active(user):
                raise ValueError('Active account not found')
            print('Private connection links. Expiry (UTC, inclusive):', user['expiresAt'])
            print('\n'.join(links(load(state / 'xray-settings.json'), args.protocol, user)))
        else:
            change(state, args.binary, args.protocol, args.action, args.name, args.days)
            print('Xray account update applied. Existing Xray sessions were disconnected.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, 'stderr', None)
        if isinstance(detail, bytes):
            detail = detail.decode(errors='replace')
        raise SystemExit('ENG Xray: ' + str(error) + ('\n' + detail if detail else ''))
