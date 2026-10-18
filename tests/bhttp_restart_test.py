import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = (r"C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))

@unittest.skipUnless(BASH and Path(BASH).exists(), "bash is required")
class BhttpRestartTest(unittest.TestCase):
    def run_restart(self, behavior=""):
        code = (ROOT / "restart-bhttp.sh").read_text(encoding="utf-8")
        code = code[:code.index('if [[ ${BASH_SOURCE[0]} == "$0" ]]')]
        code += '\nsystemctl() { ' + behavior + '; if [[ $1 == cat ]]; then return 0; fi; printf "%s\\n" "$*"; }; restart_bhttp\n'
        return subprocess.run([BASH, "-c", code], text=True, capture_output=True)

    def test_proxy_stops_before_socket_reopens(self):
        result = self.run_restart(":")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        self.assertLess(lines.index("stop frimps-bhttp-alt.socket frimps-bhttp-alt.service"), lines.index("restart frimps-bhttp.service"))
        self.assertLess(lines.index("restart frimps-bhttp.service"), lines.index("start frimps-bhttp-alt.socket"))

    def test_backend_only_install(self):
        result = self.run_restart('if [[ $1 == cat && $2 == frimps-bhttp-alt.socket ]]; then return 1; fi')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("start frimps-bhttp-alt.socket", result.stdout)

    def test_stop_failure_aborts_restart(self):
        result = self.run_restart('if [[ $1 == stop ]]; then return 1; fi')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("restart frimps-bhttp.service", result.stdout)
