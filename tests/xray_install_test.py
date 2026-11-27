"""Run the real deployment shell against a private filesystem and fake services.

This exercises rollback and fresh/upgrade persistence without touching a host's
services. Real Xray/transport validation lives in xray_stream_test.py.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
JQ = shutil.which('jq') or str(ROOT.parent / 'test-bin/jq.exe')


def bash_path(path):
    value = Path(path).as_posix()
    return '/' + value[0].lower() + value[2:] if os.name == 'nt' and value[1:3] == ':/' else value


@unittest.skipUnless(BASH and Path(JQ).exists(), 'Bash and jq required')
class InstallerTest(unittest.TestCase):
    def run_install(self, old=False, fail=False):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            f = bash_path(base)
            state = base / 'etc/frimps-v6'
            for directory in ['etc/frimps-v6', 'etc/haproxy', 'etc/nginx/conf.d', 'etc/systemd/system',
                              'usr/local/libexec', 'usr/local/lib/frimps-v6', 'commands', 'flags']:
                (base / directory).mkdir(parents=True, exist_ok=True)
            original_haproxy = 'EXISTING SSH 2222 / OPENVPN CONFIG\n'
            original_nginx = 'EXISTING NGINX CONFIG\n'
            (base / 'etc/haproxy/haproxy.cfg').write_text(original_haproxy)
            (base / 'etc/nginx/conf.d/frimps-v6-main.conf').write_text(original_nginx)
            (state / 'routes.json').write_text('{"primaryDomain":"example.test"}')
            (base / 'archive.zip').write_bytes(b'fixture-verified-release')
            digest = hashlib.sha256(b'fixture-verified-release').hexdigest()
            (base / 'release.json').write_text(json.dumps({'assets': [{'name': 'Xray-linux-64.zip', 'digest': 'sha256:' + digest}]}))
            if old:
                (state / 'xray-settings.json').write_text('OLD REALITY KEY AND SHORT ID')
                (state / 'xray-users.json').write_text('OLD UUID AND PASSWORD')
                (base / 'etc/systemd/system/frimps-xray.service').write_text('OLD UNIT')
                (base / 'flags/frimps-xray.service.active').touch()
                (base / 'flags/frimps-xray.service.enabled').touch()
            if fail:
                (base / 'flags/fail-nginx').touch()
            source = (ROOT / 'xray-install.sh').read_text(encoding='utf-8')
            source = source.replace("[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }", '')
            for prefix in ['/etc/', '/usr/local/', '/var/backups/']:
                source = source.replace(prefix, f + prefix)
            (base / 'commands/xray-install.sh').write_bytes(source.encode())
            for file in ['xray-manager.py', 'xray-accounts.sh', 'xray-menu.sh']:
                (base / 'commands' / file).write_text('fixture helper')
            harness = r'''
set -euo pipefail
export V6_STATE_DIR="$fixture/etc/frimps-v6"
flock() { :; }
chmod() { :; }
install() {
 local directory=0
 if [[ $1 == -d ]]; then directory=1; shift; fi
 if [[ $1 == -m ]]; then shift 2; fi
 if ((directory)); then mkdir -p -- "$@"; else command cp -- "$@"; fi
}
cp() {
 local arg; local -a arguments=()
 for arg in "$@"; do [[ $arg == -a ]] || arguments+=("$arg"); done
 command cp "${arguments[@]}"
}
uname() { echo x86_64; }
jq() { "$jq_binary" "$@" | tr -d '\r'; }
curl() {
 local output='' api=0
 while (($#)); do
  case "$1" in -o) output="$2"; shift 2;; *api.github.com*) api=1; shift;; *) shift;; esac
 done
 if ((api)); then cp "$fixture/release.json" "$output"; else cp "$fixture/archive.zip" "$output"; fi
}
unzip() { local destination="${@: -1}"; printf '#!/usr/bin/env bash\nexit 0\n' > "$destination/xray"; }
go() {
 while (($#)); do
  if [[ $1 == -o ]]; then printf '#!/usr/bin/env bash\nexit 0\n' > "$2"; return; fi
  shift
 done
}
python3() {
 case "$2" in
 init)
  [[ -f "$V6_STATE_DIR/xray-settings.json" ]] || echo 'NEW REALITY KEY' > "$V6_STATE_DIR/xray-settings.json"
  [[ -f "$V6_STATE_DIR/xray-users.json" ]] || echo '{}' > "$V6_STATE_DIR/xray-users.json"
  echo 'NEW CONFIG' > "$V6_STATE_DIR/xray.json"
  echo '{}' > "$V6_STATE_DIR/xray-routes.json";;
 decorate)
  echo '# XRAY ROUTES' >> "$V6_STATE_DIR/haproxy-443.cfg"
  echo '# XRAY ROUTES' >> "$V6_STATE_DIR/nginx-main-tls.conf";;
 esac
}
haproxy() { :; }
nginx() { if [[ -e "$fixture/flags/fail-nginx" ]]; then rm "$fixture/flags/fail-nginx"; return 1; fi; }
systemctl() {
 local unit="${@: -1}" item
 echo "$*" >> "$fixture/calls"
 case "$1" in
 is-active) [[ -f "$fixture/flags/$unit.active" ]];;
 is-enabled) [[ -f "$fixture/flags/$unit.enabled" ]];;
 enable) for item in "${@:2}"; do touch "$fixture/flags/$item.enabled"; done;;
 disable) rm -f "$fixture/flags/$unit.enabled";;
 start|restart) for item in "${@:2}"; do touch "$fixture/flags/$item.active"; done;;
 stop) for item in "${@:2}"; do rm -f "$fixture/flags/$item.active"; done;;
 *) return 0;;
 esac
}
source "$fixture/commands/xray-install.sh"
'''
            env = dict(os.environ, fixture=f, jq_binary=bash_path(JQ))
            result = subprocess.run([BASH, '-c', harness], env=env, capture_output=True, text=True, timeout=30)
            if fail:
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('restoring touched files', result.stderr)
                self.assertEqual((base / 'etc/haproxy/haproxy.cfg').read_text(), original_haproxy)
                self.assertEqual((base / 'etc/nginx/conf.d/frimps-v6-main.conf').read_text(), original_nginx)
                if old:
                    self.assertEqual((base / 'etc/systemd/system/frimps-xray.service').read_text(), 'OLD UNIT')
                    self.assertTrue((base / 'flags/frimps-xray.service.active').exists())
                else:
                    self.assertFalse((state / 'xray-settings.json').exists())
                    self.assertFalse((base / 'flags/frimps-xray.service.enabled').exists())
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(original_haproxy, (base / 'etc/haproxy/haproxy.cfg').read_text())
                for unit in ['frimps-xray.service', 'frimps-xray-cleanup.timer']:
                    self.assertTrue((base / ('flags/' + unit + '.active')).exists())
                    self.assertTrue((base / ('flags/' + unit + '.enabled')).exists())
            if old:
                self.assertEqual((state / 'xray-settings.json').read_text(), 'OLD REALITY KEY AND SHORT ID')
                self.assertEqual((state / 'xray-users.json').read_text(), 'OLD UUID AND PASSWORD')

    def test_fresh_installs_start_and_enable_service_and_expiry_timer(self):
        self.run_install()

    def test_upgrade_preserves_existing_keys_accounts_and_gateway(self):
        self.run_install(old=True)

    def test_failed_fresh_install_restores_gateway_and_removes_new_settings(self):
        self.run_install(fail=True)

    def test_failed_upgrade_restores_existing_service_keys_and_accounts(self):
        self.run_install(old=True, fail=True)


if __name__ == '__main__':
    unittest.main()
