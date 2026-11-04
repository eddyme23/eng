import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')


class SlowdnsSummaryTest(unittest.TestCase):
    def summary(self, text):
        spec = importlib.util.spec_from_file_location('summary', ROOT / 'slowdns-log-summary.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            module.summarize(text)
        return output.getvalue()

    def test_repeated_rejections_do_not_identify_client_or_prove_browsing(self):
        log = 'FORMERR: requester payload size 512 is too small (minimum 1232)\n' * 10
        result = self.summary(log)
        self.assertIn('Repeated', result)
        self.assertIn('10 rejection(s)', result)
        self.assertIn('unrelated probe', result)
        self.assertIn('Keep the server MTU unchanged', result)
        self.assertIn('has not been verified', result)

    def test_stream_activity_is_not_reported_as_successful_login(self):
        result = self.summary('begin session abc\nbegin stream abc:3\n')
        self.assertNotIn('[WARN]', result)
        self.assertIn('does not prove SSH login or browsing', result)

    def test_empty_logs_do_not_imply_failure(self):
        result = self.summary('')
        self.assertNotIn('[WARN]', result)
        self.assertIn('has not been verified', result)


@unittest.skipUnless(BASH, 'bash required')
class FirewallDiagnosticTest(unittest.TestCase):
    def test_snapshot_identifies_backend_and_stops_on_failure(self):
        source = (ROOT / 'apply-legacy-udp-fix.sh').read_text(encoding='utf-8')
        function = source[source.index('snapshot() {'):source.index('snapshot nft ')]
        for status in (0, 2):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                fixture = Path(directory)
                script = fixture / 'test.sh'
                code = ('set -euo pipefail\nbackup="' + fixture.as_posix() + '"\n' + function
                        + 'iptables-save() { echo "XT target DNAT not found" >&2; echo snapshot; return ' + str(status) + '; }\n'
                        + 'snapshot iptables-save "$backup/saved.rules"\necho CONTINUED\n')
                script.write_bytes(code.encode('utf-8'))
                result = subprocess.run([BASH, script.as_posix()], capture_output=True, timeout=10)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertIn(f'[iptables-save snapshot, exit {status}]'.encode(), result.stderr)
                self.assertEqual(b'CONTINUED' in result.stdout, status == 0)
                self.assertEqual((fixture / 'saved.rules').read_text().strip(), 'snapshot')
                self.assertIn('DNAT not found', (fixture / 'saved.rules.stderr').read_text())

    def test_failed_firewall_change_keeps_error_status_and_backend_label(self):
        source = (ROOT / 'retire-iptables-rules.sh').read_text(encoding='utf-8')
        function = source[source.index('firewall_change() {'):source.index('# Native replacement')]
        code = ('set -euo pipefail\ntool=iptables-legacy\n'
                'iptables-legacy() { echo "DNAT failure" >&2; return 2; }\n'
                + function + '\nfirewall_change -t nat -D PREROUTING\n')
        result = subprocess.run([BASH, '-c', code], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b'iptables-legacy', result.stderr)
        self.assertIn(b'exit 2', result.stderr)
