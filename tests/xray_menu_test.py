import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')


@unittest.skipUnless(BASH, 'Bash required')
class XrayMenuTest(unittest.TestCase):
    def run_menu(self, data):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            (state / 'xray-settings.json').write_text('{}')
            script = state / 'menu.sh'
            script.write_text('''bash() { printf 'CALL %s\\n' "$*"; }
python3() { printf 'customer\\t2099-01-01\\tactive\\n'; }
systemctl() { printf 'SERVICE %s\\n' "$*"; }
''' + (ROOT / 'xray-menu.sh').read_text(), encoding='utf-8', newline='\n')
            result = subprocess.run([BASH, script.as_posix()], input=data.encode(), env=dict(os.environ, V6_STATE_DIR=state.as_posix()),
                                    capture_output=True, timeout=5)
            result.stdout = result.stdout.decode('utf-8')
            result.stderr = result.stderr.decode('utf-8')
            return result

    def test_back_and_eof_at_both_levels(self):
        for data in ['0\n', '00\n', '', '01\n00\n00\n', '02\n0\n0\n', '03\n']:
            result = self.run_menu(data)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('Invalid option', result.stdout)
            self.assertNotIn('CALL', result.stdout)

    def test_all_account_actions_dispatch_with_numbered_selection(self):
        for data, expected in [
            ('1\n1\n12345\n30\n\n0\n0\n', 'create vless 12345 30'),
            ('2\n2\n01\n60\n\n0\n0\n', 'renew vmess customer 60'),
            ('3\n3\n01\ny\n\n0\n0\n', 'delete trojan customer'),
            ('1\n4\n\n0\n0\n', 'list vless'),
            ('1\n5\n01\n\n0\n0\n', 'links vless customer'),
        ]:
            result = self.run_menu(data)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('xray-accounts.sh ' + expected, result.stdout)

    def test_cancel_invalid_selection_or_decline_delete_does_not_delete(self):
        for selection in ['0', '00', '99', 'no']:
            result = self.run_menu('1\n3\n' + selection + '\n\n0\n0\n')
            self.assertNotIn('xray-accounts.sh delete', result.stdout)
        result = self.run_menu('1\n3\n1\nn\n\n0\n0\n')
        self.assertNotIn('xray-accounts.sh delete', result.stdout)


if __name__ == '__main__':
    unittest.main()
