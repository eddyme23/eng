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
class SlowdnsKeysTest(unittest.TestCase):
    def run_keys(self, initial):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            keys = base / "keys"
            keys.mkdir()
            for name, value in initial.items():
                (keys / name).write_text(value, encoding="ascii")
            generator = base / "generator.sh"
            generator.write_bytes(b'#!/usr/bin/env bash\nset -eu\n[[ $1 == -gen-key && $2 == -privkey-file && $4 == -pubkey-file ]]\nprintf "%064d\\n" 1 > "$3"\nprintf "%064d\\n" 2 > "$5"\necho GENERATED\n')
            runner = ROOT / "slowdns-keys.sh"
            if os.name == "nt":
                # Windows ACLs cannot implement the Debian install/chmod modes.
                runner = base / "runner.sh"
                runner.write_bytes(b'install() { if [[ $1 == -d ]]; then mkdir -p "${@: -1}"; else cp "$3" "$4"; fi; }; chmod() { :; };\n' + (ROOT / "slowdns-keys.sh").read_bytes())
            result = subprocess.run([BASH, runner.as_posix(), keys.as_posix(), generator.as_posix()], capture_output=True)
            contents = {path.name: path.read_text(encoding="ascii") for path in keys.iterdir() if path.is_file()}
            return result, contents

    def test_first_install_generates_pair(self):
        result, contents = self.run_keys({})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(contents), {"server.key", "server.pub"})
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}\n", value) for value in contents.values()))
        self.assertNotIn(b"GENERATED", result.stdout)

    def test_reinstall_preserves_existing_pair(self):
        initial = {"server.key": "a" * 64 + "\n", "server.pub": "b" * 64 + "\n"}
        result, contents = self.run_keys(initial)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(contents, initial)

    def test_partial_or_invalid_pair_is_not_replaced(self):
        for initial in ({"server.key": "a" * 64 + "\n"},
                        {"server.pub": "b" * 64 + "\n"},
                        {"server.key": "invalid\n", "server.pub": "b" * 64 + "\n"}):
            result, contents = self.run_keys(initial)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(contents, initial)

    def test_installer_and_health_use_actual_keys_and_backend(self):
        install = (ROOT / "slowdns-install.sh").read_text(encoding="utf-8")
        self.assertNotIn("819d82813183", install)
        self.assertIn('bash "$script_dir/slowdns-keys.sh"', install)
        self.assertIn('systemctl enable --now frimps-slowdns.service', install)
        self.assertIn('Requires=ssh.service frimps-v6-udp-routing.service', install)
        self.assertIn('$ns 127.0.0.1:22', install)
        postflight = (ROOT / "postflight-v6.sh").read_text(encoding="utf-8")
        accounts = (ROOT / "ssh-accounts.sh").read_text(encoding="utf-8")
        self.assertNotIn("7fbd1f8aa0ab", postflight + accounts)
        self.assertIn('slowdns-audit.sh" --local', (ROOT / "protocol-health-v6.sh").read_text(encoding="utf-8"))

    def test_flow_probe_uses_runtime_listener_and_tunnel_domain(self):
        source = (ROOT / "slowdns-flow-audit.sh").read_text(encoding="utf-8")
        probe = source[source.index("if [[ $command_line =~"):source.index('echo "=== Account')]
        for domain, expected in (("ns-fr.vpnguruz.store", True), ("invalid;name", False)):
            code = ('command_line="ExecStart={ path=/etc/slowdns/sldns-server ; argv[]=/etc/slowdns/sldns-server -udp 81.17.97.202:53 -privkey-file /etc/slowdns/server.key '
                    + domain + ' 127.0.0.1:22 ; }"\n'
                    + 'dig() { printf "PROBE %s\\n" "$*"; };\n' + probe)
            result = subprocess.run([BASH, "-c", code], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            if expected:
                self.assertIn(b"@81.17.97.202 _eng-audit.ns-fr.vpnguruz.store TXT", result.stdout)
            else:
                self.assertNotIn(b"PROBE", result.stdout)
