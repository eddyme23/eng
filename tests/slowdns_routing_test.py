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
