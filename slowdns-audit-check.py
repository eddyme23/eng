#!/usr/bin/env python3
"""Bounded, non-mutating SlowDNS stream and DNS-address checks."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
BUILDS = (Path('/var/cache/frimps-dnstt/upstream-20260501'), Path('/opt/frimps-dnstt-ssh-test'))


class Unavailable(Exception):
    pass


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=8)


def verified_client():
    pin = json.loads((ROOT / 'dnstt-source/pin.json').read_text())
    for build in BUILDS:
        client, metadata = build / 'dnstt-client', build / 'build.json'
        if not client.is_file() or not metadata.is_file():
            continue
        record = json.loads(metadata.read_text())
        if any(record.get(field) != pin[field] for field in ('implementation', 'revision', 'archive_sha256')):
            raise ValueError('Cached DNSTT client source pin mismatch; encrypted check not run')
        if hashlib.sha256(client.read_bytes()).hexdigest() != record.get('binaries', {}).get('dnstt-client'):
            raise ValueError('Cached DNSTT client checksum mismatch; encrypted check not run')
        if not os.access(client, os.X_OK):
            raise ValueError('Cached DNSTT client is not executable')
        return client
    raise Unavailable('Verified DNSTT client cache unavailable; encrypted check skipped (no rebuild or restart)')


def running_config(text):
    listener = re.search(r'(?:^|\s)-udp\s+(\S+)', text)
    tail = re.search(r'-privkey-file\s+(\S+)\s+([A-Za-z0-9.-]+)\s+(127\.0\.0\.1:22)(?:\s|$)', text)
    if not listener or not tail or tail[1] != '/etc/slowdns/server.key':
        raise ValueError('Unrecognized running SlowDNS configuration; encrypted check not run')
    address = listener[1]
    host, port = address.rsplit(':', 1)
    if port != '53':
        raise ValueError('Unexpected SlowDNS port')
    if host.strip('[]') in ('', '0.0.0.0', '::'):
        choices = module('slowdns-network').selected(address)
        ipv4 = [ip for ip, _ in choices if ip.version == 4]
        if not ipv4:
            raise Unavailable('No assigned IPv4 endpoint for the local DNSTT client check')
        address = str(ipv4[0]) + ':53'
    else:
        ipaddress.ip_address(host.strip('[]'))
    return address, tail[2], tail[3]


def stream_check(expected_domain=None):
    client = verified_client()
    text = command('systemctl', 'show', 'frimps-slowdns.service', '-p', 'ExecStart', '--value')
    address, domain, backend = running_config(text)
    if expected_domain and domain.rstrip('.').lower() != expected_domain.rstrip('.').lower():
        raise ValueError('Configured tunnel domain differs from the running SlowDNS domain')
    result = module('dnstt-probe').probe(client, domain=domain, keys=Path('/etc/slowdns'),
        resolver=address, ssh_target=backend, transport='udp', timeout=12)
    print('[OK] Encrypted DNSTT stream reached OpenSSH through the running UDP 53 listener '
          f"({result['first_verified_stream_seconds']:.3f}s)")


def addresses_check(text):
    addresses = set()
    for line in text.splitlines():
        try:
            address = ipaddress.ip_address(line.strip())
        except ValueError:
            continue  # dig +short may also include CNAMEs.
        if address.version == 4:
            addresses.add(address)
    if not addresses:
        raise ValueError('Delegated NS target has no IPv4 address')
    local = {ip for ip, _ in module('slowdns-network').assigned() if ip.version == 4}
    if not addresses <= local:
        # NATed VPSes can publish an unassigned egress address. Try to confirm it;
        # inability to discover it is reported as unverified, never as DNS success.
        try:
            public = ipaddress.ip_address(command('curl', '-4fsS', '--connect-timeout', '2',
                                                 '--max-time', '4', 'https://api.ipify.org').strip())
        except (OSError, ValueError, subprocess.SubprocessError):
            raise Unavailable('NS IPv4 differs from assigned addresses; public/NAT address could not be confirmed')
        local.add(public)
    if not addresses <= local:
        raise ValueError('Delegated NS target includes IPv4 address(es) that do not match this VPS: '
                         + ', '.join(sorted(map(str, addresses - local))))
    print('[OK] Delegated NS IPv4 addresses match this VPS (external reachability not measured)')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stream', 'addresses'))
    parser.add_argument('--domain', help='Expected configured tunnel domain')
    args = parser.parse_args()
    try:
        if args.action == 'stream':
            stream_check(args.domain)
        else:
            addresses_check(sys.stdin.read())
    except Unavailable as error:
        print('[SKIP] ' + str(error))
        sys.exit(2)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('[FAIL] ' + str(error), file=sys.stderr)
        sys.exit(1)
