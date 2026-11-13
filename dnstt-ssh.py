#!/usr/bin/env python3
"""Isolated DNSTT-to-SSH candidate with explicit production activation/rollback."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
LAB = Path('/opt/frimps-dnstt-ssh-test')
UNIT = Path('/etc/systemd/system/frimps-dnstt-ssh-test.service')
PROD_UNIT = Path('/etc/systemd/system/frimps-slowdns.service')
PROD_BINARY = Path('/etc/slowdns/sldns-server')
PROD_KEYS = Path('/etc/slowdns')
RECORD = Path('/etc/frimps-v6/dnstt-backend.json')
BACKUPS = Path('/var/backups/frimps-v6/dnstt')
LAB_UNIT = 'frimps-dnstt-ssh-test.service'
PROD_SERVICE = 'frimps-slowdns.service'


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), timeout=kwargs.pop('timeout', 30), check=True, **kwargs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reset_failed(service):
    # A new unit may exist on disk without a loaded failed-state entry yet.
    subprocess.run(['systemctl', 'reset-failed', service], capture_output=True, timeout=30)


def domain(value):
    labels = value.rstrip('.').split('.')
    if len(value) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', s) for s in labels):
        raise ValueError('Invalid tunnel domain')
    return '.'.join(labels).lower()


def current_domain():
    text = Path('/etc/frimps-v6/service-options.env').read_text()
    match = re.search(r'^V6_SLOWDNS_NS=([A-Za-z0-9.-]+)$', text, re.M)
    if not match:
        raise ValueError('Specify --domain or configure the existing SlowDNS nameserver')
    return domain(match[1])


def endpoint(value):
    host, port = value.rsplit(':', 1)
    host = ipaddress.ip_address(host.strip('[]'))
    if host.version == 6 and not value.startswith('['):
        raise ValueError('Use [IPv6]:PORT for an IPv6 listener')
    if not port.isdecimal() or not 1 <= int(port) <= 65535 or host.is_unspecified or host.is_multicast:
        raise ValueError('Use a specific assigned IP and UDP port')
    # Nonstandard public UDP ports belong to other ENG range protocols.
    if not host.is_loopback and int(port) != 53:
        raise ValueError('Public candidate must use a free assigned IP on port 53; use loopback for other ports')
    return host, int(port)


def port_check(value, own_pid='0', require_owner=False):
    address, port = endpoint(value)
    if not address.is_loopback:
        assigned = module('slowdns-network').assigned()
        if address not in {a for a, _ in assigned}:
            raise ValueError('Candidate listener address is not assigned on this VPS')
    rows = run('ss', '-H', '-O', '-lunpe', f'sport = :{port}', capture_output=True, text=True).stdout
    owned = False
    for row in rows.splitlines():
        fields = row.split()
        if len(fields) < 5:
            continue
        host = fields[3].rsplit(':', 1)[0].strip('[]')
        overlap = host in ('*', '::') or host == str(address) or (host == '0.0.0.0' and address.version == 4)
        owners = set(re.findall(r'pid=(\d+)', row))
        if overlap and not (own_pid != '0' and owners == {own_pid}):
            raise ValueError('UDP listener conflicts with an existing/unidentified service: ' + fields[3])
        if overlap:
            owned = True
    if require_owner and not owned:
        raise ValueError('Test service does not own its configured UDP listener')


def validate_keys(directory):
    secret = bytes.fromhex((directory / 'server.key').read_text().strip())
    public = bytes.fromhex((directory / 'server.pub').read_text().strip())
    if len(secret) != 32 or len(public) != 32:
        raise ValueError('Invalid key lengths; existing keys will not be replaced')
    result = run('openssl', 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER',
                 input=bytes.fromhex('302e020100300506032b656e04220420') + secret, capture_output=True)
    if result.stdout != bytes.fromhex('302a300506032b656e032100') + public:
        raise ValueError('Private/public key pair does not match')


def verified_build(build):
    pin = json.loads((ROOT / 'dnstt-source/pin.json').read_text())
    metadata = json.loads((build / 'build.json').read_text())
    machine = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(os.uname().machine, os.uname().machine)
    if metadata['archive_sha256'] != pin['archive_sha256'] or metadata['target'] != 'linux-' + machine:
        raise ValueError('Build source pin or Linux architecture does not match')
    for name in ('dnstt-server', 'dnstt-client'):
        path = build / name
        if not path.is_file() or path.is_symlink() or digest(path) != metadata['binaries'].get(name):
            raise ValueError('Build binary checksum mismatch: ' + name)
    return metadata


def atomic(source, destination, mode=None):
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.dnstt-', dir=destination.parent)
    os.close(fd)
    try:
        shutil.copy2(source, temporary)
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)


def allowed(service):
    if service == PROD_SERVICE:
        return {PROD_UNIT, PROD_BINARY, RECORD}
    if service == LAB_UNIT:
        return {UNIT} | {LAB / name for name in
                ('dnstt-server', 'dnstt-client', 'server.key', 'server.pub', 'test.json', 'build.json')}
    raise ValueError('Unexpected managed service')


def backup(paths, service):
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    destination = Path(tempfile.mkdtemp(prefix=time.strftime('%Y%m%dT%H%M%SZ-', time.gmtime()), dir=BACKUPS))
    enabled = subprocess.run(['systemctl', 'is-enabled', '--quiet', service], capture_output=True).returncode == 0
    active = subprocess.run(['systemctl', 'is-active', '--quiet', service], capture_output=True).returncode == 0
    manifest = {'service': service, 'enabled': enabled, 'active': active, 'paths': {}, 'hashes': {}}
    for path in paths:
        if path.is_symlink():
            raise ValueError('Refusing symlink configuration: ' + str(path))
        present = path.is_file()
        manifest['paths'][str(path)] = present
        if present:
            saved = destination / path.relative_to(path.anchor)
            saved.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, saved)
            manifest['hashes'][str(path)] = digest(saved)
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    return destination


def rollback(directory):
    directory = directory.resolve()
    if not directory.is_relative_to(BACKUPS.resolve()) or directory == BACKUPS.resolve():
        raise ValueError('Rollback must use a backup inside ' + str(BACKUPS))
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest['service'] not in (LAB_UNIT, PROD_SERVICE) or not manifest['paths']:
        raise ValueError('Invalid rollback service/paths')
    for name, present in manifest['paths'].items():
        path = Path(name)
        if path not in allowed(manifest['service']):
            raise ValueError('Unexpected rollback path')
        saved = directory / path.relative_to(path.anchor)
        if present and (not saved.is_file() or saved.is_symlink()):
            raise ValueError('Incomplete backup')
        if present and digest(saved) != manifest['hashes'].get(name):
            raise ValueError('Backup file checksum mismatch; refusing partial restore')
    service = manifest['service']
    # A failed first stage may have no loaded service yet.
    subprocess.run(['systemctl', 'stop', service], capture_output=True, timeout=30)
    subprocess.run(['systemctl', 'disable', service], capture_output=True, timeout=30)
    for name, present in manifest['paths'].items():
        path = Path(name)
        if present:
            atomic(directory / path.relative_to(path.anchor), path)
        else:
            path.unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    if manifest['enabled']:
        run('systemctl', 'enable', service)
    if manifest['active']:
        reset_failed(service)
        run('systemctl', 'start', service)
        run('systemctl', 'is-active', '--quiet', service)
    print('Restored previous files and service state: ' + str(directory))


def stage(args):
    metadata = verified_build(args.build)
    target = {'openssh': '127.0.0.1:22', 'gateway': '127.0.0.1:2222'}[args.ssh_backend]
    name = domain(args.domain) if args.domain else current_domain()
    endpoint(args.listen)
    own_pid = run('systemctl', 'show', LAB_UNIT, '-p', 'MainPID', '--value', capture_output=True, text=True).stdout.strip() \
        if UNIT.exists() else '0'
    port_check(args.listen, own_pid)
    if UNIT.exists() and not UNIT.read_text().startswith('# ENG isolated DNSTT SSH test\n'):
        raise ValueError('Existing test unit is not owned by this installer')
    with tempfile.TemporaryDirectory(prefix='eng-dnstt-stage-') as directory:
        temp = Path(directory)
        if args.identity == 'existing':
            source = PROD_KEYS
            validate_keys(source)
            for file in ('server.key', 'server.pub'):
                shutil.copyfile(source / file, temp / file)
        else:
            if LAB.exists() and (LAB / 'server.key').exists():
                validate_keys(LAB)
                for file in ('server.key', 'server.pub'):
                    shutil.copyfile(LAB / file, temp / file)
            else:
                run(args.build / 'dnstt-server', '-gen-key', '-privkey-file', temp / 'server.key',
                    '-pubkey-file', temp / 'server.pub', capture_output=True)
        validate_keys(temp)
        result = module('dnstt-probe').probe(args.build / 'dnstt-client', args.build / 'dnstt-server', name, temp, target)
        print('Preflight encrypted SSH stream: ' + json.dumps(result))
        config = dict(domain=name, listen=args.listen, ssh_target=target, identity=args.identity,
                      implementation=metadata['implementation'], candidate_sha256=metadata['binaries']['dnstt-server'])
        text = render_unit(args.listen, name, target)
        (temp / UNIT.name).write_text(text)
        # First install has no executable at LAB yet. Verify the same unit
        # against the already verified build before changing any installed files.
        verification = temp / 'verify'
        verification.mkdir()
        candidate_unit = text.replace('WorkingDirectory=' + str(LAB), 'WorkingDirectory=' + str(args.build))
        candidate_unit = candidate_unit.replace('ExecStart=' + str(LAB) + '/dnstt-server',
                                                'ExecStart=' + str(args.build) + '/dnstt-server')
        (verification / UNIT.name).write_text(candidate_unit)
        run('systemd-analyze', 'verify', verification / UNIT.name)
        paths = [UNIT] + [LAB / n for n in ('dnstt-server', 'dnstt-client', 'server.key', 'server.pub', 'test.json', 'build.json')]
        saved = backup(paths, LAB_UNIT)
        print('Test service backup: ' + str(saved), flush=True)
        try:
            if UNIT.exists():
                run('systemctl', 'stop', LAB_UNIT)
            LAB.mkdir(parents=True, exist_ok=True, mode=0o700)
            for file in ('dnstt-server', 'dnstt-client', 'build.json'):
                atomic(args.build / file, LAB / file, 0o700 if file.startswith('dnstt-') else 0o600)
            for file in ('server.key', 'server.pub'):
                atomic(temp / file, LAB / file, 0o600 if file.endswith('.key') else 0o644)
            (temp / 'test.json').write_text(json.dumps(config, indent=2))
            atomic(temp / 'test.json', LAB / 'test.json', 0o600)
            atomic(temp / UNIT.name, UNIT, 0o644)
            run('systemd-analyze', 'verify', UNIT)
            run('systemctl', 'daemon-reload')
            reset_failed(LAB_UNIT)
            if args.enable:
                run('systemctl', 'enable', LAB_UNIT)
            run('systemctl', 'start', LAB_UNIT)
            run('systemctl', 'is-active', '--quiet', LAB_UNIT)
            # Probe the installed candidate, not merely the private preflight process.
            result = module('dnstt-probe').probe(LAB / 'dnstt-client', domain=name, keys=LAB,
                                                resolver=args.listen, ssh_target=target)
            print('Installed test service: ' + json.dumps(result))
        except BaseException:
            rollback(saved)
            raise
    print('Production SlowDNS was not replaced. Test unit: ' + LAB_UNIT)
    print('Rollback: bash ./dnstt-ssh.sh rollback ' + str(saved))


def render_unit(listen, name, target):
    endpoint(listen)
    domain(name)
    if target not in ('127.0.0.1:22', '127.0.0.1:2222'):
        raise ValueError('Choose the OpenSSH or dedicated SSH backend')
    return f'''# ENG isolated DNSTT SSH test
[Unit]
Description=ENG opt-in upstream DNSTT to SSH test
Wants=network-online.target
After=network-online.target
[Service]
Type=exec
WorkingDirectory={LAB}
ExecStart={LAB}/dnstt-server -mtu 1232 -udp {listen} -privkey-file {LAB}/server.key {name} {target}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65536
TasksMax=256
[Install]
WantedBy=multi-user.target
'''


def activate(args):
    config = json.loads((LAB / 'test.json').read_text())
    verified_build(LAB)
    validate_keys(PROD_KEYS)
    if (LAB / 'server.pub').read_text().strip() != (PROD_KEYS / 'server.pub').read_text().strip():
        raise ValueError('Test identity differs from production; refusing key rotation')
    text = PROD_UNIT.read_text()
    command = re.search(r'^ExecStart=/etc/slowdns/sldns-server .* -privkey-file /etc/slowdns/server.key (\S+) (127\.0\.0\.1:(?:22|2222))$', text, re.M)
    if not command or command[1] != config['domain']:
        raise ValueError('Production domain/SSH unit differs from the staged test; refusing to rewrite it')
    run('systemctl', 'is-active', '--quiet', PROD_SERVICE)
    # Do not silently activate through unknown ExecStart overrides.
    effective = run('systemctl', 'cat', PROD_SERVICE, capture_output=True, text=True).stdout
    if len(re.findall(r'^ExecStart=', effective, re.M)) != 1:
        raise ValueError('Review existing SlowDNS ExecStart overrides before activation')
    probe = module('dnstt-probe')
    print(json.dumps(probe.probe(LAB / 'dnstt-client', LAB / 'dnstt-server', command[1],
                                  PROD_KEYS, command[2])))
    saved = backup([PROD_UNIT, PROD_BINARY, RECORD], PROD_SERVICE)
    print('Production activation disconnects SlowDNS sessions. Backup: ' + str(saved), flush=True)
    try:
        run('systemctl', 'stop', PROD_SERVICE)
        atomic(LAB / 'dnstt-server', PROD_BINARY, 0o700)
        reset_failed(PROD_SERVICE)
        run('systemctl', 'start', PROD_SERVICE)
        run('bash', ROOT / 'slowdns-audit.sh', '--local', timeout=45)
        listen = module('slowdns-network').endpoint()
        result = probe.probe(LAB / 'dnstt-client', domain=command[1], keys=PROD_KEYS,
                             resolver=listen, ssh_target=command[2])
        record = dict(implementation='upstream-20260501', binary_sha256=digest(PROD_BINARY), local_stream_test=result)
        temporary = saved / 'backend-new.json'
        temporary.write_text(json.dumps(record, indent=2))
        atomic(temporary, RECORD, 0o600)
        print(json.dumps(result, indent=2))
    except BaseException:
        rollback(saved)
        raise
    print('Production unit, keys, domain, MTU and SSH accounts preserved. Client login/browsing still need testing.')
    print('Rollback: bash ./dnstt-ssh.sh rollback ' + str(saved))


def delegation(name):
    print('Candidate DNS delegation: ' + name)
    if not shutil.which('dig'):
        print('[WARN] Install dnsutils to inspect delegation; no connection gate is imposed.')
        return
    parent = name.split('.', 1)[-1]
    authority = ''
    while '.' in parent and not authority:
        authority = run('dig', '+time=2', '+tries=1', '+short', 'NS', parent, capture_output=True, text=True).stdout.splitlines()
        authority = authority[0] if authority else ''
        parent = parent.split('.', 1)[-1]
    if not re.fullmatch(r'[A-Za-z0-9.-]+', authority):
        print('[WARN] Parent DNS authority could not be determined; external path is unverified.')
        return
    reply = run('dig', '+time=2', '+tries=1', '@' + authority, name, 'NS', '+norecurse',
                '+noall', '+answer', '+authority', capture_output=True, text=True).stdout
    targets = [line.split()[4] for line in reply.splitlines() if len(line.split()) >= 5 and line.split()[3] == 'NS']
    if not targets:
        print('[WARN] No parent NS delegation confirmed; a direct UDP test may still work while public DoH/DoT fails.')
    for target in targets:
        if re.fullmatch(r'[A-Za-z0-9.-]+', target):
            for kind in ('A', 'AAAA'):
                records = run('dig', '+time=2', '+tries=1', '+short', target, kind, capture_output=True, text=True).stdout.strip()
                print(target + ' ' + kind + ': ' + (records or 'no answer'))
    print('Compare NS addresses with this VPS public IP; DNS records alone do not establish reply delivery.')


def audit():
    for service, path in ((PROD_SERVICE, PROD_BINARY), (LAB_UNIT, LAB / 'dnstt-server')):
        if not path.exists():
            print(service + ': not installed')
            continue
        print(service + ' SHA256=' + digest(path))
        run('systemctl', 'show', service, '--no-pager', '-p', 'ExecStart', '-p', 'MainPID', '-p', 'ActiveState')
    if (LAB / 'test.json').exists():
        config = json.loads((LAB / 'test.json').read_text())
        print(json.dumps(config, indent=2))
        print('Candidate public key: ' + (LAB / 'server.pub').read_text().strip())
        validate_keys(LAB)
        pid = run('systemctl', 'show', LAB_UNIT, '-p', 'MainPID', '--value', capture_output=True, text=True).stdout.strip()
        port_check(config['listen'], pid, require_owner=True)
        delegation(config['domain'])
        run('journalctl', '-b', '-u', LAB_UNIT, '--since', '5 minutes ago', '-n', '40', '--no-pager')
    if PROD_UNIT.exists():
        run('bash', ROOT / 'slowdns-audit.sh', timeout=60)
    print('Public DoH/DoT end at recursive resolvers; this server normally remains on UDP 53.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    stage_parser = commands.add_parser('stage')
    stage_parser.add_argument('--implementation', choices=('upstream-20260501',), required=True)
    stage_parser.add_argument('--backend', choices=('ssh',), required=True)
    stage_parser.add_argument('--build', type=Path, required=True)
    stage_parser.add_argument('--domain')
    stage_parser.add_argument('--identity', choices=('existing', 'fresh'), default='existing')
    stage_parser.add_argument('--ssh-backend', choices=('openssh', 'gateway'), default='openssh')
    stage_parser.add_argument('--listen', default='127.0.0.1:15353')
    stage_parser.add_argument('--enable', action='store_true', help='Enable the isolated test service for boot')
    activation = commands.add_parser('activate')
    activation.add_argument('--implementation', choices=('upstream-20260501',), required=True)
    activation.add_argument('--backend', choices=('ssh',), required=True)
    commands.add_parser('audit')
    restore = commands.add_parser('rollback')
    restore.add_argument('directory', type=Path)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        parser.error('Run this management path as root on Linux')
    import fcntl
    with open('/run/lock/frimps-epro.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.umask(0o077)
        if args.action == 'stage':
            args.build = args.build.resolve()
            stage(args)
        elif args.action == 'activate':
            activate(args)
        elif args.action == 'audit':
            audit()
        else:
            rollback(args.directory)


if __name__ == '__main__':
    main()
