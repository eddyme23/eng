#!/usr/bin/env python3
"""Pair/update an ENG VPS as an outbound central-management agent."""
import argparse
import getpass
import importlib.util
import json
import os
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
ROOT = Path('/usr/local/lib/frimps-v6')
STATE = Path('/etc/frimps-panel-agent')
UNITS = Path('/etc/systemd/system')
ROUTES = Path('/etc/frimps-v6/routes.json')


def unit():
    return '''[Unit]
Description=ENG outbound central-management agent
Requires=frimps-panel-helper.service
After=network-online.target frimps-panel-helper.service
Wants=network-online.target
[Service]
Type=simple
User=frimps-panel
Group=frimps-panel
UMask=0077
StateDirectory=frimps-agent
StateDirectoryMode=0700
ExecStart=/usr/bin/python3 /usr/local/lib/frimps-v6/panel_agent.py
Restart=on-failure
RestartSec=5
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


def main():
    import pwd
    import grp
    from panel_agent import origin, send
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--central', help='HTTPS central URL, including its port')
    parser.add_argument('--re-pair', action='store_true', help='Replace this agent registration using a new pairing code')
    args = parser.parse_args()
    if os.geteuid() != 0 or not ROUTES.is_file():
        raise SystemExit('Run as root on an installed ENG VPS')
    old = json.loads((STATE / 'config.json').read_text()) if (STATE / 'config.json').exists() else None
    url = origin(args.central or (old or {}).get('central') or input('Central panel URL: ').strip())
    if old and old['central'] != url and not args.re_pair:
        raise SystemExit('Use --re-pair to change the central panel. Remove the old registration in that panel separately.')
    # Reuse the helper unit definition; never install a public web listener here.
    spec = importlib.util.spec_from_file_location('eng_panel_install', HERE / 'panel-install.py')
    install = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(install)
    try:
        account = pwd.getpwnam('frimps-panel')
        if account.pw_uid == 0 or account.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false'):
            raise SystemExit('frimps-panel must be a dedicated non-login service user')
    except KeyError:
        install.call('useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', 'frimps-panel')
    config = old
    if not old or args.re_pair:
        code = getpass.getpass('Single-use pairing code from the central panel: ').strip()
        result = send(url, '/api/agent/pair', {'code': code})
        import re
        if not re.fullmatch(r'[a-f0-9]{32}', str(result.get('nodeId', ''))) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', str(result.get('token', ''))):
            raise SystemExit('Invalid pairing response')
        config = {'central': url, 'nodeId': result['nodeId'], 'token': result['token'], 'label': result['label']}
    gid = grp.getgrnam('frimps-panel').gr_gid
    ROOT.mkdir(parents=True, exist_ok=True)
    for source in HERE.iterdir():
        if source.suffix in ('.sh', '.py'):
            target = ROOT / source.name
            if source.resolve() != target.resolve():
                shutil.copyfile(source, target)
            target.chmod(0o755)
            os.chown(target, 0, 0)
    STATE.mkdir(mode=0o750, parents=True, exist_ok=True)
    STATE.chmod(0o750)
    os.chown(STATE, 0, gid)
    install.write(STATE / 'config.json', json.dumps(config, indent=2) + '\n', 0o640)
    os.chown(STATE / 'config.json', 0, gid)
    install.write(UNITS / 'frimps-panel-helper.service', install.units()[0])
    install.write(UNITS / 'frimps-panel-agent.service', unit())
    install.call('systemctl', 'daemon-reload')
    install.call('systemctl', 'enable', 'frimps-panel-helper.service', 'frimps-panel-agent.service')
    install.call('systemctl', 'restart', 'frimps-panel-helper.service', 'frimps-panel-agent.service')
    install.call('systemctl', 'is-active', '--quiet', 'frimps-panel-helper.service', 'frimps-panel-agent.service')
    print('Paired server:', config['label'])
    print('Agent connects outward to:', url)
    print('No public management port was opened. VPN services and accounts were not changed.')


if __name__ == '__main__':
    main()
