import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')


def load():
    spec = importlib.util.spec_from_file_location('audit_checks', ROOT / 'slowdns-audit-check.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class AuditCheckTest(unittest.TestCase):
    def test_only_checksum_verified_pinned_client_is_executed(self):
        m = load()
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            client = base / 'dnstt-client'
            client.write_bytes(b'fixture-client')
            client.chmod(0o700)
            record = json.loads((ROOT / 'dnstt-source/pin.json').read_text())
            record['binaries'] = {'dnstt-client': hashlib.sha256(client.read_bytes()).hexdigest()}
            (base / 'build.json').write_text(json.dumps(record))
            with patch.object(m, 'BUILDS', (base,)), patch.object(m.os, 'access', return_value=True):
                self.assertEqual(m.verified_client(), client)
                client.write_bytes(b'tampered')
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    m.verified_client()
            with patch.object(m, 'BUILDS', (base / 'missing',)):
                with self.assertRaises(m.Unavailable):
                    m.verified_client()

    def test_running_endpoint_domain_and_backend_are_used(self):
        m = load()
        config = 'argv[]=/etc/slowdns/sldns-server -mtu 1232 -udp 192.0.2.10:53 -privkey-file /etc/slowdns/server.key ns.example.test 127.0.0.1:22 ;'
        probe = Mock(return_value={'first_verified_stream_seconds': .05})
        with patch.object(m, 'verified_client', return_value=Path('/verified/client')), patch.object(
                m, 'command', return_value=config), patch.object(m, 'module', return_value=SimpleNamespace(probe=probe)):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                m.stream_check()
            self.assertIn('[OK] Encrypted DNSTT stream', output.getvalue())
            self.assertEqual(probe.call_args.kwargs['domain'], 'ns.example.test')
            self.assertEqual(probe.call_args.kwargs['resolver'], '192.0.2.10:53')
            self.assertEqual(probe.call_args.kwargs['timeout'], 12)
            with self.assertRaisesRegex(ValueError, 'differs from the running'):
                m.stream_check('wrong.example.test')
        with self.assertRaises(ValueError):
            m.running_config(config.replace('127.0.0.1:22', 'example.test:22'))

    def test_wildcard_probe_selects_assigned_ipv4(self):
        m = load()
        network = SimpleNamespace(selected=lambda _: [(ipaddress.ip_address('192.0.2.10'), 'eth0')])
        with patch.object(m, 'module', return_value=network):
            self.assertEqual(m.running_config('-udp :53 -privkey-file /etc/slowdns/server.key ns.example.test 127.0.0.1:22')[0], '192.0.2.10:53')

    def test_dns_addresses_must_match_vps_or_confirmed_nat_address(self):
        m = load()
        network = SimpleNamespace(assigned=lambda: [(ipaddress.ip_address('192.0.2.10'), 'eth0')])
        with patch.object(m, 'module', return_value=network), contextlib.redirect_stdout(io.StringIO()):
            with patch.object(m, 'command') as external:
                m.addresses_check('alias.example.test.\n192.0.2.10\n')
                external.assert_not_called()
            with patch.object(m, 'command', return_value='198.51.100.20'):
                m.addresses_check('198.51.100.20')
                with self.assertRaisesRegex(ValueError, 'do not match'):
                    m.addresses_check('203.0.113.99')
            with patch.object(m, 'command', side_effect=OSError('network unavailable')):
                with self.assertRaises(m.Unavailable):
                    m.addresses_check('203.0.113.99')
            with self.assertRaisesRegex(ValueError, 'no IPv4'):
                m.addresses_check('alias.example.test.\n2001:db8::1')

    @unittest.skipUnless(BASH, 'bash required')
    def test_audit_summary_does_not_turn_skipped_or_failed_probe_into_success(self):
        source = (ROOT / 'slowdns-audit.sh').read_text()
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('[[ $EUID'))
        prefix = r"""
set -- --local
systemctl() { return 0; }
bash() { return 0; }
test() { return 0; }
grep() { [[ $* != *1-65535* ]]; }
timeout() { return 0; }
nft() { echo '53, 443, 1194, 4000'; }
journalctl() { echo 'begin session unrelated'; }
python3() {
 case "$1" in
  *slowdns-audit-check.py) echo PROBE; return PROBE_STATUS ;;
  *) cat >/dev/null; return 0 ;;
 esac
}
"""
        for status in (0, 1, 2):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'audit.sh'
                path.write_bytes((prefix.replace('PROBE_STATUS', str(status)) + source).encode())
                result = subprocess.run([BASH, path.as_posix()], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1 if status == 1 else 0, result.stderr)
                self.assertEqual('including an encrypted stream' in result.stdout, status == 0)
                self.assertEqual('encrypted stream check unavailable' in result.stdout, status == 2)
                self.assertNotIn('Use the displayed DNS public key', result.stdout)
