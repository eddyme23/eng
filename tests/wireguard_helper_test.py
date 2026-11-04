import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')


@unittest.skipUnless(BASH, 'bash required')
class WireguardHelperTest(unittest.TestCase):
    def run_helper(self, action, local_ui=False, runtime_ui=False):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            libexec = fixture / 'libexec'
            runtime = fixture / 'runtime'
            clients = fixture / 'clients'
            state = fixture / 'state'
            for path in (libexec, runtime, clients, state):
                path.mkdir()
            config = fixture / 'wg0.conf'
            config.write_text('[Interface]\n')
            client = clients / 'eddy.conf'
            client.write_text('[Interface]\nDNS = 1.1.1.1\n')
            source = (ROOT / 'wireguard-accounts.sh').read_text(encoding='utf-8')
            # Exercise the whole installed helper with fixture paths and mocked
            # platform tools; Windows cannot supply Linux root or WireGuard.
            source = re.sub(r'^\[\[ .*EUID.*\n', '', source, flags=re.M)
            source = source.replace('client_dir="/etc/wireguard/clients"', 'client_dir="' + clients.as_posix() + '"')
            source = source.replace('config="/etc/wireguard/wg0.conf"', 'config="' + config.as_posix() + '"')
            source = source.replace('/usr/local/lib/frimps-v6/ui-v6.sh', (runtime / 'ui-v6.sh').as_posix())
            tools = ('install() { mkdir -p "${@: -1}"; }\n'
                     'flock() { :; }\nwg() { :; }\n'
                     'jq() { if [[ $1 == -r ]]; then printf "eddy\\t10.0.0.2\\t2027-11-04\\n"; fi; }\n')
            helper = libexec / 'frimps-v6-wireguard-accounts'
            helper.write_bytes((tools + source).encode('utf-8'))
            for destination, enabled in ((libexec, local_ui), (runtime, runtime_ui)):
                if enabled:
                    shutil.copyfile(ROOT / 'ui-v6.sh', destination / 'ui-v6.sh')
            env = dict(os.environ, V6_STATE_DIR=state.as_posix(), V6_WG_ENDPOINT='example.org')
            result = subprocess.run([BASH, helper.as_posix(), action], env=env, capture_output=True, timeout=10)
            return result, client.read_text()

    def test_migration_works_from_libexec_without_ui(self):
        result, contents = self.run_helper('migrate-dns')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('DNS = 1.1.1.1, 1.0.0.1', contents)

    def test_account_listing_uses_adjacent_or_runtime_formatter(self):
        for adjacent in (False, True):
            with self.subTest(adjacent=adjacent):
                result, _ = self.run_helper('list', local_ui=adjacent, runtime_ui=not adjacent)
                self.assertEqual(result.returncode, 0, result.stderr)
                for value in (b'NAME', b'ADDRESS', b'EXPIRES', b'eddy', b'10.0.0.2'):
                    self.assertIn(value, result.stdout)
