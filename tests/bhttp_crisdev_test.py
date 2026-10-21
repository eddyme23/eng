import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')


class BhttpPortsTest(unittest.TestCase):
    def run_selection(self, sockets='', main='42', proxy='0', socket_active=False):
        source = (ROOT / 'bhttp-ports.sh').read_text(encoding='utf-8')
        setup = f'''
ss() {{ if [[ $* == *':90 )'* ]]; then printf '%s\\n' '{sockets}'; fi; }}
systemctl() {{
 if [[ $1 == is-active ]]; then return {0 if socket_active else 1}; fi
 if [[ $* == *' -p Listen '* ]]; then echo '0.0.0.0:8180 (Stream)'; return; fi
 if [[ $2 == frimps-bhttp.service ]]; then echo {main}; else echo {proxy}; fi
}}
'''
        return subprocess.run([BASH, '-c', source + setup + '\nbhttp_select_ports; echo "${BHTTP_SELECTED_PORTS[*]}"'], capture_output=True, text=True)

    def test_free_ports(self):
        self.assertEqual(self.run_selection().stdout.strip(), '90 8180 8081')

    def test_reuses_owned_listener(self):
        result = self.run_selection('LISTEN 0 10 0.0.0.0:90 *:* users:(("bhttp",pid=42,fd=3))')
        self.assertEqual(result.stdout.strip(), '90 8180 8081')

    def test_unrelated_or_hidden_owner_skipped(self):
        for row in ['LISTEN 0 10 0.0.0.0:90 *:* users:(("other",pid=99,fd=3))', 'LISTEN 0 10 0.0.0.0:90 *:*']:
            result = self.run_selection(row)
            self.assertEqual(result.stdout.strip(), '8180 8081')
            self.assertIn('Skipping TCP 90', result.stderr)

    def test_pid_one_is_not_accepted_for_non_socket_port(self):
        result = self.run_selection('LISTEN 0 10 0.0.0.0:90 *:* users:(("systemd",pid=1,fd=3))', socket_active=True)
        self.assertEqual(result.stdout.strip(), '8180 8081')

    def test_no_available_ports_aborts(self):
        source = (ROOT / 'bhttp-ports.sh').read_text(encoding='utf-8')
        result = subprocess.run([BASH, '-c', source + "\nbhttp_port_available() { return 1; }; bhttp_select_ports"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('No requested BHTTP port', result.stderr)

    def test_native_health_checks_every_selected_listener(self):
        source = (ROOT / 'service-health-v6.sh').read_text(encoding='utf-8')
        function = source[source.index('listener() {'):source.index('check() {')]
        code = function + r'''
BHTTP_ENGINE=crisdev; BHTTP_PORTS="90 8180 8081"
listener_one() { echo "$3"; [[ $3 != 8081 ]]; }
listener frimps-bhttp.service t 90
'''
        result = subprocess.run([BASH, '-c', code], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.splitlines(), ['90', '8180', '8081'])


class CrisdevMigrationTest(unittest.TestCase):
    def test_activation_failure_restores_legacy_engine_and_socket(self):
        source = (ROOT / 'apply-bhttp-crisdev.sh').read_text(encoding='utf-8')
        source = source[source.index('restore() {'):]
        source = source.replace('install -d -m 700 /opt/frimps-bhttp', 'install -d -m 700 "$root/opt/frimps-bhttp"')
        policy = (ROOT / 'bhttp-policy.sh').read_text(encoding='utf-8')
        setup = r'''
set -euo pipefail
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
script_dir="$root/scripts"; state_dir="$root/state"; base="$root/backups"
unit="$root/unit"; binary="$root/binary"; socket_unit="$root/socket"; proxy_unit="$root/proxy"
files=("$unit" "$binary" "$state_dir/bhttp.env" "$socket_unit" "$proxy_unit")
units=(frimps-bhttp.service frimps-bhttp-alt.socket frimps-bhttp-alt.service)
mkdir -p "$script_dir" "$state_dir"
printf 'ExecStart=/opt/frimps-bhttp/bhttp-server --port 90\n' > "$unit"
printf 'legacy engine' > "$binary"
printf 'Description=Frimps BHTTP alternate port socket\nlegacy socket' > "$socket_unit"
printf 'Description=Frimps BHTTP alternate port proxy\nlegacy proxy' > "$proxy_unit"
printf 'BHTTP_PORT=90\nBHTTP_PORTS="90 8180"\n' > "$state_dir/bhttp.env"
printf 'bhttp_select_ports() { BHTTP_SELECTED_PORTS=(90 8180 8081); }\n' > "$script_dir/bhttp-ports.sh"
install() {
 if [[ $1 == -d ]]; then shift; [[ ${1:-} != -m ]] || shift 2; mkdir -p "$@"
 else [[ ${1:-} != -m ]] || shift 2; cp "$@"; fi
}
systemctl() {
 if [[ $1 == restart && ! -f $root/attempted ]]; then touch "$root/attempted"; return 1; fi
 printf '%s\n' "$*" >> "$root/calls"; return 0
}
ss() { echo 'LISTEN'; }
uname() { echo x86_64; }
awk() { echo 2048; }
curl() { while (($#)); do if [[ $1 == -o ]]; then printf '#!/bin/bash\nexit 0\n' > "$2"; return; fi; shift; done; }
sha256sum() { cat >/dev/null; }
python3() { return 0; }
systemd-analyze() { return 0; }
'''
        setup += '\ncat > "$script_dir/bhttp-policy.sh" <<\'POLICY\'\n' + policy + '\nPOLICY\nset +e\n( set -e\n'
        assertions = r'''
)
result=$?
set -e
test "$result" = 1
test -f "$root/attempted"
test "$(cat "$binary")" = 'legacy engine'
grep -q 'legacy socket' "$socket_unit"
grep -q 'legacy proxy' "$proxy_unit"
grep -q 'BHTTP_PORTS="90 8180"' "$state_dir/bhttp.env"
grep -q 'start frimps-bhttp-alt.socket' "$root/calls"
'''
        result = subprocess.run([BASH, '-c', setup + source + assertions], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
