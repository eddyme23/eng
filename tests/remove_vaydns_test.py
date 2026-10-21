import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
BASH = r"C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")

class RemoveVaydnsTest(unittest.TestCase):
    def run_removal(self, fail):
        source=(ROOT/"remove-vaydns.sh").read_text(encoding="utf-8")
        source=source.replace("[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }", ":")
        source=re.sub(r'^script_dir=.*$', 'script_dir="$root/scripts"', source, flags=re.M)
        for path in ['/etc/systemd/system','/var/backups/frimps-v6','/usr/local/libexec','/usr/local/lib/frimps-v6','/etc/frimps-vaydns']:
            source=source.replace(path,'$root'+path)
        setup=r"""
set -euo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
export V6_STATE_DIR="$root/state"
mkdir -p "$root/scripts" "$root/state" "$root/etc/systemd/system/frimps-slowdns.service.d" "$root/etc/frimps-vaydns" "$root/usr/local/libexec" "$root/usr/local/lib/frimps-v6"
printf 'ExecStart=/etc/slowdns/sldns-server -udp 1.2.3.4:53 -privkey-file /etc/slowdns/server.key ns.test 127.0.0.1:22\n' > "$root/etc/systemd/system/frimps-slowdns.service"
printf 'original override' > "$root/etc/systemd/system/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf"
touch "$root/etc/systemd/system/frimps-vaydns.service" "$root/etc/systemd/system/frimps-dns-dispatch.service"
printf 'key retained' > "$root/etc/frimps-vaydns/server.key"
touch "$root/state/vaydns.env" "$root/state/dns-dispatch.json" "$root/usr/local/libexec/frimps-vaydns"
printf '#!/bin/bash\nexit FAIL\n' > "$root/scripts/slowdns-audit.sh"
printf '#!/bin/bash\nexit 0\n' > "$root/scripts/refresh-menu-v6.sh"
install() { shift; if [[ ${1:-} == -m ]]; then shift 2; fi; mkdir -p "$@"; }
flock() { return 0; }
systemctl() { printf '%s\n' "$*" >> "$root/calls"; return 0; }
ss() { echo 'sldns-server'; }
set +e
(
set -e
""".replace('exit FAIL','exit '+('1' if fail else '0'))
        assertions = r"""
)
result=$?
set -e
"""
        if fail:
            assertions += r"""
test "$result" = 1
grep -q "start frimps-dns-dispatch.service" "$root/calls"
test -f "$root/state/vaydns.env"
grep -q 'original override' "$root/etc/systemd/system/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf"
grep -q 'key retained' "$root/etc/frimps-vaydns/server.key"
"""
        else:
            assertions += r"""
test "$result" = 0
test ! -f "$root/state/vaydns.env"
test ! -f "$root/etc/systemd/system/frimps-slowdns.service.d/85-frimps-dns-dispatch.conf"
test ! -f "$root/etc/systemd/system/frimps-vaydns.service"
test ! -f "$root/usr/local/libexec/frimps-vaydns"
grep -q 'key retained' "$root"/var/backups/frimps-v6/remove-vaydns-*/vaydns-keys/server.key
"""
        result=subprocess.run([BASH,'-c',setup+source+assertions],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_removal_and_key_backup(self):self.run_removal(False)
    def test_failed_slowdns_check_recovers_dispatcher_configuration(self):self.run_removal(True)
if __name__ == '__main__': unittest.main()
