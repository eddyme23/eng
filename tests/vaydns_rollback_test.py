import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')


class VaydnsRollbackTest(unittest.TestCase):
    def test_restores_endpoint_without_deleting_keys_or_other_overrides(self):
        source = (ROOT / 'rollback-vaydns.sh').read_text(encoding='utf-8')
        source = source.replace('[[ $EUID -eq 0 ]] || exit 1', ':')
        source = source.replace('/var/backups/frimps-v6/', '$root/backups/')
        source = source.replace('/etc/systemd/system/', '$root/units/')
        setup = r'''
set -euo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
mkdir -p "$root/backups/vaydns-test" "$root/units/frimps-slowdns.service.d" "$root/state" "$root/keys"
printf 'old unit' > "$root/backups/vaydns-test/slowdns.service"
printf '%s\n' "$root/state" > "$root/backups/vaydns-test/state-dir"
touch "$root/units/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf"
touch "$root/units/frimps-slowdns.service.d/unrelated.conf"
touch "$root/units/frimps-vaydns.service" "$root/units/frimps-dns-dispatch.service"
touch "$root/state/vaydns.env" "$root/state/dns-dispatch.json" "$root/keys/server.key"
systemctl() { printf '%s\n' "$*" >> "$root/calls"; }
set -- "$root/backups/vaydns-test"
'''
        assertions = r'''
test ! -f "$root/units/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf"
test ! -f "$root/units/frimps-vaydns.service"
test ! -f "$root/state/vaydns.env"
test -f "$root/units/frimps-slowdns.service.d/unrelated.conf"
test -f "$root/keys/server.key"
grep -q 'restart frimps-slowdns.service' "$root/calls"
'''
        result = subprocess.run([BASH, '-c', setup + source + assertions], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_installer_validates_before_live_switch_and_has_failure_trap(self):
        source = (ROOT / 'vaydns-install.sh').read_text(encoding='utf-8')
        self.assertLess(source.index('sha256sum -c -'), source.index('trap recover ERR'))
        self.assertLess(source.index('systemd-analyze verify'), source.index('trap recover ERR'))
        self.assertLess(source.index('trap recover ERR'), source.index('systemctl restart frimps-slowdns.service'))
        self.assertIn('rollback-vaydns.sh', source)


if __name__ == '__main__':
    unittest.main()
