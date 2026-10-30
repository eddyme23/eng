import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = r"C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")


@unittest.skipUnless(BASH, "bash required")
class FreshFirewallTest(unittest.TestCase):
    def run_shell(self, code):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "test.sh"
            script.write_bytes(code.encode("utf-8"))
            return subprocess.run([BASH, script.as_posix()], capture_output=True, timeout=10)

    def test_cleanup_runs_after_services_and_before_postflight(self):
        source = (ROOT / "install-frimps.sh").read_text(encoding="utf-8")
        start = source.index("note 'Enabling every installed Frimps service")
        end = source.index("\nrequired_units=", start)
        section = source[start:end]
        self.assertGreater(start, source.index('bash "$script_dir/udp-custom-install.sh"'))
        for cleanup_result in (0, 1):
            code = ('set -euo pipefail\nscript_dir=/scripts\nnote() { :; }\n'
                    'systemctl() { :; }\n'
                    'bash() { echo "RUN $1"; '
                    'if [[ $1 == */apply-legacy-udp-fix.sh ]]; then return '
                    + str(cleanup_result) + '; fi; }\n' + section)
            result = self.run_shell(code)
            output = result.stdout.decode()
            self.assertEqual(result.returncode, cleanup_result, result.stderr)
            self.assertLess(output.index("refresh-menu-v6.sh"), output.index("apply-legacy-udp-fix.sh"))
            if cleanup_result:
                self.assertNotIn("postflight-v6.sh", output)
            else:
                self.assertLess(output.index("apply-legacy-udp-fix.sh"), output.index("postflight-v6.sh"))

    def test_postflight_rejects_failed_slowdns_routing_audit(self):
        source = (ROOT / "postflight-v6.sh").read_text(encoding="utf-8")
        function = source[source.index("config_check() {"):source.index("\n\nfor unit")]
        tail = source[source.index('config_check bash "$script_dir/slowdns-audit.sh" --local'):]
        for audit_result in (0, 1):
            code = ('set -euo pipefail\nfailed=0\nscript_dir=/scripts\n'
                    'bash() { return ' + str(audit_result) + '; }\n'
                    'jq() { :; }\nsystemctl() { :; }\n' + function + '\n' + tail)
            result = self.run_shell(code)
            self.assertEqual(result.returncode, audit_result, result.stderr)
            self.assertEqual(b"post-install verification passed" in result.stdout, audit_result == 0)
