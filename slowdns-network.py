#!/usr/bin/env python3
"""SlowDNS listener ownership checks and optional native nftables NOTRACK."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

CONFIG = Path('/etc/frimps-v6/slowdns-network.json')
TABLE = 'frimps_slowdns_notrack'


def command(*args):
    return subprocess.check_output(args, text=True, timeout=10, stderr=subprocess.PIPE)


def assigned():
    return [(ipaddress.ip_address(a['local']), row['ifname'].split('@')[0])
            for row in json.loads(command('ip', '-j', 'address', 'show', 'scope', 'global'))
            for a in row.get('addr_info', [])
            if a.get('scope') == 'global' and not a.get('tentative') and not a.get('dadfailed')]


def endpoint():
    text = command('systemctl', 'show', 'frimps-slowdns.service', '-p', 'ExecStart', '--value')
    match = re.search(r'(?:^|\s)-udp\s+(\S+)', text)
    if not match:
        raise ValueError('Cannot determine the running SlowDNS endpoint')
    return match[1]


def selected(address):
    host, port = address.rsplit(':', 1)
    host = host.strip('[]')
    if port != '53':
        raise ValueError('Managed SlowDNS listener must use UDP 53')
    if host in ('', '::', '0.0.0.0'):
        rows = assigned()
        return [(ip, iface) for ip, iface in rows if host != '0.0.0.0' or ip.version == 4]
    ip = ipaddress.ip_address(host)
    rows = [(a, iface) for a, iface in assigned() if a == ip]
    if not rows:
        raise ValueError('Listener address is not assigned to this server')
    return rows


def covers(local, flags, ip):
    host = local.rsplit(':', 1)[0].strip('[]')
    if host == str(ip):
        return True
    if host == '0.0.0.0':
        return ip.version == 4
    if host in ('*', '::'):
        return ip.version == 6 or bool(re.search(r'v6only:0(?:\s|$)', flags))
    return False


def inspect(address, preflight=False):
    targets = selected(address)
    if not targets:
        raise ValueError('No global listener addresses found')
    if address == ':53' and not {4, 6} <= {ip.version for ip, _ in targets}:
        raise ValueError('Dual-stack mode requires assigned global IPv4 and IPv6 addresses')
    try:
        pid = command('systemctl', 'show', 'frimps-slowdns.service', '-p', 'MainPID', '--value').strip()
    except subprocess.CalledProcessError:
        if not preflight:
            raise
        pid = '0'  # Fresh install: no managed unit exists yet.
    rows = command('ss', '-H', '-O', '-lunpe', 'sport = :53').splitlines()
    owned = []
    for row in rows:
        fields = row.split()
        if len(fields) < 5 or fields[0] != 'UNCONN':
            continue
        owners = set(re.findall(r'pid=(\d+)', row))
        ours = owners == {pid} and pid != '0'
        if preflight:
            host = address.rsplit(':', 1)[0].strip('[]')
            overlaps = not host or host in ('0.0.0.0', '::') or any(covers(fields[3], row, ip) for ip, _ in targets)
            if overlaps and not ours:
                raise ValueError('UDP 53 is occupied by another or unidentified process: ' + fields[3])
        elif ours:
            owned.append((fields[3], row))
    if not preflight:
        for ip, _ in targets:
            if not any(covers(local, flags, ip) for local, flags in owned):
                raise ValueError('SlowDNS MainPID does not own a UDP 53 listener for ' + str(ip))
    print('[OK] SlowDNS listener ownership and selected IP families' + (' preflight' if preflight else ''))


def nft_apply(text):
    subprocess.run(['nft', '-c', '-f', '-'], input=text, text=True, check=True, timeout=10)
    subprocess.run(['nft', '-f', '-'], input=text, text=True, check=True, timeout=10)


def notrack_rules(targets):
    lines = [f'table inet {TABLE} {{', 'chain ingress { type filter hook prerouting priority raw; policy accept;']
    for ip, iface in targets:
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+', iface):
            raise ValueError('Invalid interface')
        family = 'ip' if ip.version == 4 else 'ip6'
        lines.append(f'iifname "{iface}" {family} daddr {ip} udp dport 53 notrack')
    lines += ['}', 'chain egress { type filter hook output priority raw; policy accept;']
    for ip, _ in targets:
        family = 'ip' if ip.version == 4 else 'ip6'
        lines.append(f'{family} saddr {ip} udp sport 53 notrack')
    return '\n'.join(lines + ['}', '}']) + '\n'


def network(action):
    exists = subprocess.run(['nft', 'list', 'table', 'inet', TABLE], capture_output=True, timeout=10).returncode == 0
    delete = f'delete table inet {TABLE}\n' if exists else ''
    if action == 'stop' or not CONFIG.exists():
        if delete:
            nft_apply(delete)
        return
    config = json.loads(CONFIG.read_text())
    if not config.get('notrack', False):
        if delete:
            nft_apply(delete)
        return
    targets = selected(config['endpoint'])
    if not targets:
        raise ValueError('No NOTRACK addresses')
    nft_apply(delete + notrack_rules(targets))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'check', 'start', 'stop'))
    parser.add_argument('address', nargs='?')
    args = parser.parse_args()
    try:
        if args.action in ('start', 'stop'):
            if os.geteuid() != 0:
                raise ValueError('Run as root')
            network(args.action)
        else:
            inspect(args.address or endpoint(), args.action == 'preflight')
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit('[FAIL] ' + str(error))
