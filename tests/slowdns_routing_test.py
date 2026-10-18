import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = r"C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")

@unittest.skipUnless(BASH, "bash required")
class LegacyUdpRetirementTest(unittest.TestCase):
    def run_retirement(self, native=True, rule_interface="eth0"):
        source = (ROOT / "retire-iptables-rules.sh").read_text(encoding="utf-8")
        source = source[source.index('iface="'):]
        mock = ('set -euo pipefail\nV6_PUBLIC_INTERFACE=eth0\ncount=0\n'
                + 'iptables-legacy() { return 1; }; ip6tables() { return 1; }; ip6tables-legacy() { return 1; };\n'
                + 'nft() { return ' + ('0' if native else '1') + '; };\n'
                + 'iptables() { if [[ $* == *"--dport 1:65535"* && $* == *"-i ' + rule_interface + ' "* ]]; then '
                + 'if [[ $* == *"-C PREROUTING"* ]]; then (( count < 2 )); return; fi; '
                + 'if [[ $* == *"-D PREROUTING"* ]]; then count=$((count+1)); printf "DELETE %s\\n" "$*"; return 0; fi; fi; return 1; };\n')
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "audit.sh"
            script.write_bytes((mock + source).encode("utf-8"))
            return subprocess.run([BASH, script.as_posix()], capture_output=True, timeout=5)

    def test_exact_duplicate_catch_all_rules_are_removed(self):
        result = self.run_retirement()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count(b"DELETE"), 2)
        self.assertNotIn(b"-F", result.stdout)
        self.assertIn(b"--to-destination :36717", result.stdout)

    def test_other_interface_is_preserved(self):
        result = self.run_retirement(rule_interface="eth1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"DELETE", result.stdout)

    def test_no_deletion_before_native_replacement_exists(self):
        result = self.run_retirement(native=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"DELETE", result.stdout)

    def test_response_size_remains_opt_in(self):
        install = (ROOT / "slowdns-install.sh").read_text(encoding="utf-8")
        self.assertIn('Environment=FRIMPS_SLOWDNS_MTU=1232', install)
        self.assertIn('EnvironmentFile=-$state_dir/slowdns.env', install)
        self.assertIn(r'-mtu \${FRIMPS_SLOWDNS_MTU}', install)
        updater = (ROOT / "apply-slowdns-mtu.sh").read_text(encoding="utf-8")
        python = re.search("<<'PY'\n(.*?)\nPY", updater, re.S).group(1)
        compile(python, 'mtu-updater', 'exec')
        # Exercise actual unit transformation for old and already-configured units.
        for command in ('-udp', '-mtu 900 -udp', '-mtu ${FRIMPS_SLOWDNS_MTU} -udp'):
            with tempfile.TemporaryDirectory() as directory:
                unit = Path(directory) / 'unit.service'
                unit.write_text('[Service]\nExecStart=/etc/slowdns/sldns-server ' + command + ' 1.2.3.4:53 -privkey-file /etc/slowdns/server.key ns.example.com 127.0.0.1:22\n', encoding='utf-8')
                code = python.replace("Path('/etc/systemd/system/frimps-slowdns.service')", 'Path(' + repr(str(unit)) + ')')
                previous = os.environ.get('V6_STATE_DIR')
                os.environ['V6_STATE_DIR'] = '/etc/frimps-v6'
                try:
                    exec(compile(code,'mtu-updater','exec'), {})
                finally:
                    if previous is None: os.environ.pop('V6_STATE_DIR', None)
                    else: os.environ['V6_STATE_DIR'] = previous
                rendered = unit.read_text(encoding='utf-8')
                self.assertEqual(rendered.count(' -mtu '), 1)
                self.assertIn('127.0.0.1:22', rendered)
                self.assertEqual(rendered.count('EnvironmentFile='), 1)
