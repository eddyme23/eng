import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"

class HealthMonitorTest(unittest.TestCase):
    def test_recovery_threshold_cooldown_failure_and_disabled(self):
        source = (ROOT / "service-health-v6.sh").read_text(encoding="utf-8")
        functions = source[source.index("listener() {"):source.index("# Check the protocol")]
        harness = r"""
set -eu
state=$(mktemp -d)
trap 'rm -rf "$state"' EXIT
now=10000
active=0; enabled=1; restarts=0; broken=0
systemctl() {
 case "$1" in
 is-enabled) test "$enabled" = 1;;
 is-active) test "$active" = 1;;
 restart) restarts=$((restarts+1)); test "$broken" = 0 || return 1; active=1;;
 esac
}
timeout() { shift; "$@"; }
listener() { test "$active" = 1; }
check example.service t 123
check example.service t 123
test "$restarts" = 0
check example.service t 123
test "$restarts" = 1
test ! -f "$state/example.service.fail"
active=0
check example.service t 123
check example.service t 123
check example.service t 123
test "$restarts" = 1
now=12000; broken=1
check example.service t 123
test "$restarts" = 2
test -f "$state/example.service.fail"
enabled=0; now=15000
check example.service t 123
test "$restarts" = 2
"""
        # Replace listener only in the harness, leaving recovery logic unchanged.
        result = subprocess.run([BASH, "-c", functions + harness], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_all_account_writers_lock_before_store_access(self):
        for protocol in ("ssh", "wireguard", "hysteria1", "hysteria2", "openvpn", "zivpn"):
            source = (ROOT / (protocol + "-accounts.sh")).read_text(encoding="utf-8")
            self.assertLess(source.index("flock -w 30 9"), source.index('store='))

    def test_wireguard_cleanup_does_not_reenter_locked_script(self):
        source = (ROOT / "wireguard-accounts.sh").read_text(encoding="utf-8")
        self.assertNotIn('"$0" delete', source)
        self.assertIn('delete_peer_account "$name"', source)

    def test_health_installer_does_not_copy_runtime_file_onto_itself(self):
        source = (ROOT / "install-health-monitor.sh").read_text(encoding="utf-8")
        start = source.index('if [[ ! "$script_dir/service-health-v6.sh"')
        block = source[start:source.index('fi\n', start)+3]
        # Substitute the runtime directory with the fixture, keeping the actual guard.
        block = block.replace('/usr/local/lib/frimps-v6/service-health-v6.sh', '$target')
        setup = r'''
set -eu
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
script_dir="$fixture"; target="$fixture/service-health-v6.sh"
touch "$target"
install() { echo copied >> "$fixture/copies"; }
'''
        result = subprocess.run([BASH, "-c", setup + block + '\ntest ! -f "$fixture/copies"'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

if __name__ == "__main__":
    unittest.main()
