import os
import json
import shlex
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = r"C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash")
JQ = shutil.which("jq") or (str(ROOT.parent / "test-bin/jq.exe") if (ROOT.parent / "test-bin/jq.exe").exists() else None)

@unittest.skipUnless(BASH, "bash required")
class MenuServicesTest(unittest.TestCase):
    def test_main_menu_xray_is_seven_and_shifted_actions_still_dispatch(self):
        source = (ROOT / 'menu-v6.sh').read_text(encoding='utf-8')
        main = source[source.rindex('\nwhile true; do'):]
        harness = ('RED= GREEN= YELLOW= BLUE= CYAN= WHITE= BOLD= NC=\n' + self.menu_functions()
                   + '\nscript_dir=/fixture; load_runtime() { :; }; show_ports() { :; }; clear() { :; }; pause() { :; }; '
                   + 'maintenance_menu() { echo SERVICE_CONTROLS; }; utilities_menu() { echo UTILITIES; }; '
                   + 'settings_menu() { echo SETTINGS; }; reboot() { echo REBOOT; }; '
                   + 'bash() { printf "CALL %s\\n" "$*"; };\n' + main)
        for data, expected in [('07\n00\n', 'CALL /fixture/xray-menu.sh'),
                               ('08\n00\n', 'CALL /fixture/maintenance-v6.sh monitor'),
                               ('09\n00\n', 'SERVICE_CONTROLS'),
                               ('10\n00\n', 'CALL /fixture/maintenance-v6.sh backup'),
                               ('11\n00\n', 'UTILITIES'), ('12\n00\n', 'SETTINGS'),
                               ('13\ny\n00\n', 'REBOOT')]:
            with self.subTest(data=data):
                result = self.run_shell(harness, data)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertIn('[07] Xray Account Management', result.stdout)

    def run_shell(self, code, data=""):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "check.sh"
            script.write_bytes(code.encode("utf-8"))
            result = subprocess.run([BASH, script.as_posix()], input=data.encode("utf-8"),
                                    capture_output=True, timeout=8)
            result.stdout = result.stdout.decode("utf-8")
            result.stderr = result.stderr.decode("utf-8")
            return result

    def menu_functions(self):
        source = (ROOT / "menu-v6.sh").read_text(encoding="utf-8")
        return source[source.index("line() {"):source.rindex("\nwhile true; do")]

    def test_every_submenu_accepts_both_back_choices_and_eof(self):
        functions = self.menu_functions()
        menus = re.findall(r"^(\w+_menu)\(\) \{\n  while true; do", functions, re.M)
        self.assertEqual(len(menus), 10)
        for menu in menus:
            for data in ("0\n", "00\n", ""):
                with self.subTest(menu=menu, data=data):
                    result = self.run_shell("set -u\nRED= GREEN= YELLOW= BLUE= CYAN= WHITE= BOLD= NC=\n"
                        + functions + "\nclear() { :; }; " + menu + "; echo RETURNED", data)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertNotIn("Invalid option", result.stdout)
                    self.assertIn("RETURNED", result.stdout)

    def test_certificate_menu_dispatches_all_handlers_and_returns_after_failure(self):
        cases = [
            ('01\ncustomer1\n30\n00\n', 'certificate-accounts.sh create customer1 30'),
            ('02\n01\n30\n00\n', 'certificate-accounts.sh renew customer1 30'),
            ('03\n01\n00\n', 'app-ssh-auth.sh revoke customer1 certificate-account --identity ' + 'a' * 32),
            ('04\n00\n', 'app-ssh-auth.sh bundle-list'),
            ('05\n01\n00\n', 'app-ssh-auth.sh bundle-export customer1'),
            ('06\n01\n00\n', 'certificate-details.sh customer1'),
            ('07\n01\n00\n', 'app-ssh-auth.sh shared-export customer1 --identity ' + 'a' * 32),
            ('08\n00\n', 'app-ssh-auth.sh shared-import --paste'),
            ('09\n01\n00\n', 'app-ssh-auth.sh revoke customer1 certificate-account --identity ' + 'a' * 32),
            ('10\n01\ny\n00\n', 'ssh-accounts.sh delete-certificate customer1'),
            ('11\n00\n', 'app-ssh-auth.sh proxy-export'),
            ('12\n00\n', 'app-ssh-auth.sh proxy-save'),
        ]
        for data, expected in cases:
            for exit_code in (0, 1):
                with self.subTest(action=expected, status=exit_code):
                    code = ('set -u\nRED= GREEN= YELLOW= BLUE= CYAN= WHITE= BOLD= NC=\n'
                            + self.menu_functions()
                            + '\nscript_dir=/fixture; clear() { :; }; pause() { :; }; '
                            + 'pick_certificate() { read -r selection; account=customer1; identity=' + 'a' * 32 + '; selected_local=true; }; '
                            + 'pick_ssh_account() { read -r selection; account=customer1; }; '
                            + 'bash() { printf "CALL %s\\n" "$*"; return ' + str(exit_code) + '; }; '
                            + 'app_cert_menu; echo RETURNED')
                    result = self.run_shell(code, data)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('CALL /fixture/' + expected, result.stdout)
                    self.assertIn('RETURNED', result.stdout)
                    self.assertNotIn('Invalid option', result.stdout)

    def test_private_import_is_not_in_certificate_menu(self):
        code = ('set -u\nRED= GREEN= YELLOW= BLUE= CYAN= WHITE= BOLD= NC=\n' + self.menu_functions()
                + '\nclear() { :; }; app_cert_menu')
        result = self.run_shell(code, '00\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('Import existing certificate JSON', result.stdout)
        self.assertIn('[06] Show certificate connection details', result.stdout)
        self.assertEqual(len(re.findall(r'^  \[\d{2}\]', result.stdout, re.M)), 13)

    @unittest.skipUnless(JQ, 'jq required')
    def test_numbered_picker_accepts_padded_choice_and_cancels_safely(self):
        rows = [dict(account='eddy',identity='a'*32,local=True,label='eddy | local'),
                dict(account='eddy',identity='b'*32,local=False,label='eddy | shared')]
        jq_function = 'jq() { ' + shlex.quote(Path(JQ).as_posix()) + ' "$@" | tr -d \'\\r\'; };\n'
        code = ('set -u\nRED= GREEN= YELLOW= BLUE= CYAN= WHITE= BOLD= NC=\n' + self.menu_functions() + '\n' + jq_function
                + 'if pick_account_rows ' + shlex.quote(json.dumps(rows)) + ' Certificate; then printf "SELECTED %s %s %s" "$account" "$identity" "$selected_local"; else echo CANCELLED; fi')
        result = self.run_shell(code, '02\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SELECTED eddy ' + 'b'*32 + ' false', result.stdout)
        for data in ('0\n','00\n','99\n','bad\n','999999999999999\n',''):
            result = self.run_shell(code, data)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('CANCELLED', result.stdout)
            self.assertNotIn('SELECTED eddy', result.stdout)
        empty = self.run_shell(code.replace(shlex.quote(json.dumps(rows)), "'[]'"), '1\n')
        self.assertIn('No Certificate accounts available', empty.stdout)

    @unittest.skipUnless(JQ, 'jq required')
    def test_certificate_picker_cancellation_never_calls_handler_or_pause(self):
        rows = json.dumps([dict(account='eddy',identity='b'*32,local=False,label='eddy | shared')])
        jq_function = 'jq() { ' + shlex.quote(Path(JQ).as_posix()) + ' "$@" | tr -d \'\\r\'; };\n'
        for option in ('2','3','5','6','7','9'):
            for selection in ('0','00','99','bad'):
                code = ('set -u\nRED= GREEN= YELLOW= BLUE= CYAN= WHITE= BOLD= NC=\n' + self.menu_functions() + '\n' + jq_function
                    + 'script_dir=/fixture; clear() { :; }; pause() { echo PAUSED; }; '
                    + 'bash() { if [[ $2 == choices ]]; then printf "%s" ' + shlex.quote(rows)
                    + '; else echo MUTATION; fi; }; app_cert_menu; echo RETURNED')
                result = self.run_shell(code, option + '\n' + selection + '\n00\n')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('RETURNED', result.stdout)
                self.assertNotIn('MUTATION', result.stdout)
                self.assertNotIn('PAUSED', result.stdout)

    @unittest.skipUnless(JQ, 'jq required')
    def test_empty_or_failed_renewal_list_keeps_explanation_visible(self):
        jq_function = 'jq() { ' + shlex.quote(Path(JQ).as_posix()) + ' "$@" | tr -d \'\\r\'; };\n'
        prefix = ('set -u\nRED= GREEN= YELLOW= BLUE= CYAN= WHITE= BOLD= NC=\n' + self.menu_functions() + '\n' + jq_function
                  + 'script_dir=/fixture; pause() { echo PAUSED; }; ')
        empty = self.run_shell(prefix + 'bash() { echo "[]"; }; pick_certificate renew; echo RETURNED')
        self.assertIn('No locally issued certificate bundles', empty.stdout)
        self.assertIn('VPS that issued', empty.stdout)
        self.assertIn('PAUSED', empty.stdout)
        self.assertIn('RETURNED', empty.stdout)
        failed = self.run_shell(prefix + 'bash() { echo "fixture error" >&2; return 1; }; pick_certificate renew; echo RETURNED')
        self.assertIn('Could not load certificate accounts', failed.stdout)
        self.assertIn('PAUSED', failed.stdout)
        self.assertIn('fixture error', failed.stderr)

    def test_certificate_details_prints_endpoints_without_private_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'bhttp.env').write_bytes(b'BHTTP_PORTS="90 8180 8081"\n')
            (folder / 'hcr.env').write_bytes(b'HCR_PORT=8881\n')
            (folder / 'hcr-tls.env').write_bytes(b'HCR_TLS_PORT=8444\n')
            (folder / 'service-options.env').write_bytes(b'V6_SLOWDNS_NS=ns.example.test\n')
            source = (ROOT / 'certificate-details.sh').read_text(encoding='utf-8')
            source = '\n'.join(line for line in source.splitlines() if not line.startswith('[[ $EUID'))
            mocks = ("export V6_STATE_DIR='" + folder.as_posix() + "'\n"
                     + r"""
bash() { return 0; }
curl() { printf '192.0.2.5'; }
jq() {
 case "$*" in
  *primaryDomain*) printf example.test ;;
  *validBefore*) printf '2030-01-01T00:00:00+00:00' ;;
  *udpCustom.password*) return 0 ;;
  *) return 1 ;;
 esac
}
set -- account1
""")
            result = self.run_shell(mocks + source)
            self.assertEqual(result.returncode, 0, result.stderr)
            for expected in ('account1', 'example.test', '192.0.2.5', '90, 8180, 8081',
                             '8881', '8444', '50001-65535', 'ns.example.test', 'Certificate'):
                self.assertIn(expected, result.stdout)
            self.assertNotIn('PRIVATE KEY', result.stdout)
            self.assertNotIn('SocksIP', result.stdout)
            self.assertNotIn('Dropbear', result.stdout)

    def test_padded_choices_are_decimal_and_invalid_input_is_literal(self):
        for value, expected in (("0", "0"), ("00", "0"), ("01", "1"),
                                ("08", "8"), ("09", "9"), ("10", "10"),
                                ("no", "no"), ("999999999999999999999", "999999999999999999999")):
            result = self.run_shell(self.menu_functions() + '\nread_menu_option x ""; printf "%s" "$x"', value + "\n")
            self.assertEqual(result.stdout, expected, result.stderr)

    def enable_script(self):
        source = (ROOT / "enable-frimps-services.sh").read_text(encoding="utf-8")
        return "set -euo pipefail\n" + source[source.index("units='"):]

    def test_enabler_checks_every_fresh_install_required_unit(self):
        fresh = (ROOT / "install-frimps.sh").read_text(encoding="utf-8")
        required = re.search(r"required_units='([^']+)'", fresh).group(1).split()
        enabled = re.search(r"units='([^']+)'", self.enable_script()).group(1).split()
        self.assertFalse(set(required) - set(enabled))
        for optional in ("frimps-hcr", "frimps-hcr-tls", "frimps-bhttp", "frimps-bhttp-alt.socket"):
            self.assertIn(optional, enabled)
        # The proxy service is socket-activated, and cleanup is timer-activated.
        self.assertNotIn("frimps-bhttp-alt.service", enabled)
        self.assertNotIn("frimps-account-cleanup.service", enabled)

    def test_start_or_boot_enable_failure_is_not_reported_as_success(self):
        for fail_command in ("enable", "is-enabled", "is-active"):
            mock = 'systemctl() { if [[ $1 == ' + fail_command + ' && $* == *nginx* ]]; then return 1; fi; return 0; };\n'
            result = self.run_shell(mock + self.enable_script())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("nginx", result.stderr)
            self.assertNotIn("active and enabled for boot", result.stdout)

    def test_enabler_success(self):
        result = self.run_shell('systemctl() { return 0; };\n' + self.enable_script())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("active and enabled for boot", result.stdout)
