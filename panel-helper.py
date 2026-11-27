#!/usr/bin/env python3
"""Root-only, bounded Unix-socket bridge to ENG's existing account tools."""
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess

ROOT = Path('/usr/local/lib/frimps-v6')
SOCKET = '/run/frimps-panel/control.sock'
STATE = Path('/etc/frimps-v6')
LIMIT = 65536
PROTOCOLS = ('ssh', 'certificate', 'udp-custom', 'hysteria1', 'hysteria2',
             'zivpn', 'openvpn', 'wireguard', 'vless', 'vmess', 'trojan',
             'shadowsocks', 'combined')
XRAY = PROTOCOLS[-5:]
SERVICES = ('ssh', 'nginx', 'haproxy', 'frimps-v6-ssh-backend',
            'frimps-v6-sshws', 'frimps-v6-payloadgate', 'frimps-v6-tlsmux',
            'frimps-slowdns', 'frimps-udp-custom', 'frimps-socksip',
            'frimps-socksip-network', 'frimps-hcr', 'frimps-hcr-tls',
            'frimps-bhttp', 'hysteria1-server', 'hysteria2-server',
            'zivpn', 'wg-quick@wg0', 'frimps-openvpn-udp',
            'frimps-openvpn-tcp', 'frimps-xray')


def run(argv, stdin=''):
    # Never accept shell text, caller-selected paths or environment variables.
    env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
           'HOME': '/root', 'TERM': 'dumb', 'SYSTEMD_PAGER': 'cat', 'PAGER': 'cat',
           'LANG': 'C.UTF-8'}
    routes = STATE / 'routes.json'
    if routes.exists():
        domain = json.loads(routes.read_text())['primaryDomain']
        if not isinstance(domain, str) or not re.fullmatch(r'[A-Za-z0-9.-]+', domain):
            raise ValueError('Invalid saved primary domain')
        env['V6_DOMAIN'] = domain
    result = subprocess.run(argv, input=stdin, text=True, encoding='utf-8',
                            errors='replace', capture_output=True, timeout=120, env=env)
    output = (result.stdout + result.stderr)[:262144]
    if result.returncode:
        raise ValueError(output or 'ENG operation failed')
    return output


def script(name, *args, stdin=''):
    return run(['/bin/bash', str(ROOT / name), *map(str, args)], stdin)


def dispatch(req):
    if not isinstance(req, dict) or set(req) - {'protocol', 'action', 'name', 'days', 'password'}:
        raise ValueError('Invalid request fields')
    action = req.get('action')
    if action == 'status':
        return run(['/usr/bin/systemctl', 'show', *SERVICES, '--no-pager',
                    '-p', 'Id', '-p', 'LoadState', '-p', 'ActiveState', '-p', 'UnitFileState'])
    protocol = req.get('protocol')
    if protocol not in PROTOCOLS or action not in ('list', 'create', 'renew', 'delete', 'export', 'share'):
        raise ValueError('Unsupported protocol or operation')
    name = req.get('name', '')
    if action != 'list' and (not isinstance(name, str) or not re.fullmatch(r'[a-z0-9_][a-z0-9_-]{0,31}', name)):
        raise ValueError('Use 1-32 lowercase letters, digits, underscores or hyphens')
    days = req.get('days', 30)
    if action in ('create', 'renew') and (type(days) is not int or not 1 <= days <= 3650):
        raise ValueError('Validity must be 1-3650 days')
    password = req.get('password', '')
    if not isinstance(password, str) or len(password) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in password):
        raise ValueError('Invalid password')
    if protocol in XRAY:
        if action == 'share':
            raise ValueError('Shared authorization applies to SSH certificates')
        return script('xray-accounts.sh', 'links' if action == 'export' else action,
                      protocol, name, days)
    if protocol == 'certificate':
        if action in ('create', 'renew'):
            return script('certificate-accounts.sh', action, name, days)
        mapping = {'list': ('bundle-list',), 'export': ('bundle-export', name),
                   'share': ('shared-export', name)}
        if action in mapping:
            return script('app-ssh-auth.sh', *mapping[action])
        return script('ssh-accounts.sh', 'delete-certificate', name)
    if action == 'share':
        raise ValueError('Shared authorization applies to SSH certificates')
    if protocol == 'udp-custom':
        protocol = 'ssh'  # Same password account, never a second store.
    if protocol == 'ssh':
        if action == 'export':
            raise ValueError('SSH passwords cannot be recovered. Use the creation output; SSH accounts also serve WS, SSL, BHTTP, HCR, DNSTT and SocksIP.')
        if action == 'create' and not password:
            raise ValueError('Enter the SSH account password')
        return script('ssh-accounts.sh', action, name, days, stdin=password + '\n')
    if action == 'export':
        if protocol == 'wireguard':
            return script('wireguard-accounts.sh', 'config', name)
        if protocol == 'hysteria2':
            return script('hysteria2-accounts.sh', 'uri', name)
        paths = {'openvpn': Path('/etc/openvpn/clients') / (name + '-udp.ovpn')}
        if protocol in paths:
            return paths[protocol].read_text(encoding='utf-8')
        if protocol in ('hysteria1', 'zivpn'):
            users = json.loads((STATE / (protocol + '-users.json')).read_text())
            field = 'password' if protocol == 'zivpn' else 'name'
            matches = [u for u in users if u[field] == name]
            if len(matches) != 1:
                raise ValueError('Account not found')
            config_path = Path('/etc/hysteria1/config.json' if protocol == 'hysteria1' else '/etc/zivpn/config.json')
            config = json.loads(config_path.read_text())
            obfs = config['inbounds'][0].get('obfs', '') if protocol == 'hysteria1' else config.get('obfs', '')
            return json.dumps(dict(protocol=protocol, host=json.loads((STATE / 'routes.json').read_text())['primaryDomain'],
                                   portRange='20000-50000' if protocol == 'hysteria1' else '6000-19999',
                                   account=matches[0], obfs=obfs), indent=2)
        raise ValueError('Export not supported')
    if protocol == 'zivpn' and action == 'create':
        # Its identifier IS its password; do not silently use a different field.
        if password and password != name:
            raise ValueError('For ZiVPN, account name is the password; leave the password box empty')
    stdin = password + '\n' if protocol == 'openvpn' else ''
    if protocol == 'openvpn' and action == 'create' and not password:
        raise ValueError('Enter the OpenVPN password')
    return script(protocol + '-accounts.sh', action, name, days, stdin=stdin)


def serve():
    import pwd
    import grp
    if os.geteuid() != 0:
        raise SystemExit('Run helper as root')
    uid = pwd.getpwnam('frimps-panel').pw_uid
    gid = grp.getgrnam('frimps-panel').gr_gid
    path = Path(SOCKET)
    path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(SOCKET)
        os.chown(SOCKET, 0, gid)
        os.chmod(SOCKET, 0o660)
        server.listen(8)
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(5)
                peer = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                if peer != uid:
                    continue
                try:
                    data = bytearray()
                    while b'\n' not in data and len(data) <= LIMIT:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data.extend(chunk)
                    if len(data) > LIMIT or not data.endswith(b'\n'):
                        raise ValueError('Invalid request size')
                    req = json.loads(data)
                    # Audit metadata only: never log names/passwords or exports.
                    print(json.dumps({'action': str(req.get('action'))[:20],
                                      'protocol': str(req.get('protocol'))[:20]}), flush=True)
                    response = {'ok': True, 'output': dispatch(req)}
                except Exception as exc:
                    response = {'ok': False, 'output': str(exc)[:4096]}
                try:
                    conn.sendall(json.dumps(response).encode() + b'\n')
                except OSError:
                    pass


if __name__ == '__main__':
    serve()
