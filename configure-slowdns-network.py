#!/usr/bin/env python3
"""Opt-in SlowDNS dual-stack and scoped nftables NOTRACK, with rollback."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dual-stack', choices=('yes', 'no'), required=True)
    parser.add_argument('--notrack', choices=('yes', 'no'), required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.geteuid() != 0:
        parser.error('Run as root on Linux')
    import fcntl
    with open('/run/lock/frimps-epro.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.umask(0o077)
        upgrade = load('epro-upgrade')
        network = load('slowdns-network')
        unit = 'frimps-slowdns.service'
        upgrade.run('systemctl', 'is-active', '--quiet', unit)
        upgrade.run('systemctl', 'is-enabled', '--quiet', unit)
        text = Path('/etc/systemd/system', unit).read_text()
        line = re.search(r'^ExecStart=(/etc/slowdns/sldns-server .*127\.0\.0\.1:22)$', text, re.M)
        if not line:
            raise ValueError('Unrecognized managed SlowDNS unit')
        targets = network.assigned()
        original = re.search(r' -udp ([0-9.]+):53 ', line[1])
        ipv4 = original[1] if original else next((str(ip) for ip, _ in targets if ip.version == 4), None)
        if not ipv4:
            raise ValueError('An assigned global IPv4 address is required')
        address = ':53' if args.dual_stack == 'yes' else ipv4 + ':53'
        network.inspect(address, preflight=True)
        runtime = Path('/usr/local/lib/frimps-v6')
        runtime.mkdir(parents=True, exist_ok=True)
        helper = runtime / 'slowdns-network.py'
        if helper.resolve() != (ROOT / 'slowdns-network.py').resolve():
            upgrade.replace_file(ROOT / 'slowdns-network.py', helper)
        helper.chmod(0o755)
        config, dropin = map(Path, upgrade.NETWORK_FILES)
        effective = upgrade.run('systemctl', 'cat', unit, capture_output=True, text=True).stdout
        # Only our own existing override may be replaced.
        if len(re.findall(r'^ExecStart=', effective, re.M)) > (3 if dropin.exists() else 1):
            raise ValueError('Unexpected ExecStart overrides; review existing drop-ins')
        command = re.sub(r'(?<= -udp )\S+', address, line[1])
        if command == line[1] and address not in command:
            raise ValueError('Missing UDP listener argument')
        rendered = ('[Service]\nExecStart=\nExecStart=' + command + '\n'
                    'ExecStartPre=+/usr/bin/python3 ' + str(helper) + ' start\n'
                    'ExecStopPost=+/usr/bin/python3 ' + str(helper) + ' stop\n')
        # Validate the nftables rules without touching the running ruleset.
        if args.notrack == 'yes':
            import subprocess
            rules = network.notrack_rules(network.selected(address))
            exists = subprocess.run(['nft', 'list', 'table', 'inet', network.TABLE], capture_output=True).returncode == 0
            prefix = 'delete table inet ' + network.TABLE + '\n' if exists else ''
            subprocess.run(['nft', '-c', '-f', '-'], input=prefix + rules, text=True, check=True, timeout=10)
        backup = upgrade.save_backup([config, dropin], [unit])
        print('Network change disconnects SlowDNS sessions. Backup: ' + str(backup), flush=True)
        try:
            upgrade.run('systemctl', 'stop', unit)
            config.parent.mkdir(parents=True, exist_ok=True)
            dropin.parent.mkdir(parents=True, exist_ok=True)
            config.write_text(json.dumps({'endpoint': address, 'notrack': args.notrack == 'yes'}))
            config.chmod(0o600)
            dropin.write_text(rendered)
            dropin.chmod(0o644)
            upgrade.run('systemctl', 'daemon-reload')
            upgrade.run('systemctl', 'reset-failed', unit)
            upgrade.run('systemctl', 'start', unit)
            time.sleep(1)
            network.inspect(address)
            upgrade.verify_unit(unit)
        except BaseException:
            upgrade.restore(backup)
            raise
        print('Applied SlowDNS networking. Existing keys, MTU and other protocols were preserved.')
        print('Test app browsing. Rollback: bash ./apply-epro-updates.sh --rollback ' + str(backup))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        sys.exit(str(error))
