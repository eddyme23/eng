import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')


@unittest.skipUnless(BASH, 'bash required')
class SlowdnsDefaultTest(unittest.TestCase):
    def installer(self, existing=False, build_ok=True):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = base / 'etc/frimps-v6'
            state.mkdir(parents=True)
            (state / 'service-options.env').write_text('V6_SLOWDNS_NS=ns.example.org\n')
            (base / 'etc/systemd/system').mkdir(parents=True)
            binary = base / 'etc/slowdns/sldns-server'
            if existing:
                binary.parent.mkdir()
                binary.write_text('previous engine')
                binary.chmod(0o755)
                (base / 'etc/systemd/system/frimps-slowdns.service').write_text('existing unit')
            source = (ROOT / 'slowdns-install.sh').read_text()
            source = source.replace("[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }", ':')
            source = source.replace('/etc/', base.as_posix() + '/etc/').replace('/var/cache/', base.as_posix() + '/cache/')
            if os.name == 'nt':
                source = source.replace('&& -x ', '&& -s ')  # Fixture text is not a Windows executable.
            prefix = '''
uname() { echo x86_64; }
ip() { if [[ $* == *route* ]]; then echo 'default via 192.0.2.1 dev eth0'; else echo '2: eth0 inet 192.0.2.2/24 scope global'; fi; }
python3() { :; }
systemctl() { printf 'SYSTEMCTL %s\\n' "$*"; }
ss() { echo sldns-server; }
install() { if [[ $1 == -d ]]; then mkdir -p "${@: -1}"; else cp "$3" "$4"; fi; }
bash() {
  case "$1" in
    */slowdns-build.sh)
      BUILD_RESULT
      mkdir -p 'BASE/cache/frimps-dnstt/upstream-20260501'
      printf 'tested engine' > 'BASE/cache/frimps-dnstt/upstream-20260501/dnstt-server'
      printf '{}' > 'BASE/cache/frimps-dnstt/upstream-20260501/build.json';;
    */slowdns-keys.sh) echo KEYGEN; printf public > "$2/server.pub"; printf private > "$2/server.key";;
    */dnstt-ssh.sh) printf 'MIGRATE %s\\n' "$*";;
  esac
}
'''.replace('BASE', base.as_posix()).replace('BUILD_RESULT', ':' if build_ok else 'return 9')
            script = base / 'install.sh'
            script.write_bytes((prefix + source).encode())
            env = dict(os.environ, V6_STATE_DIR=state.as_posix())
            result = subprocess.run([BASH, script.as_posix()], capture_output=True, env=env, timeout=15)
            return result, binary.read_text() if binary.exists() else None

    def test_fresh_install_uses_built_engine_and_enables_production_only(self):
        result, binary = self.installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(binary, 'tested engine')
        self.assertIn(b'enable --now frimps-slowdns.service', result.stdout)
        self.assertNotIn(b'MIGRATE ', result.stdout)

    def test_existing_install_uses_transactional_activation(self):
        result, binary = self.installer(existing=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'stage --implementation upstream-20260501', result.stdout)
        self.assertIn(b'activate --implementation upstream-20260501', result.stdout)
        self.assertNotIn(b'KEYGEN', result.stdout)
        self.assertEqual(binary, 'previous engine')  # Only mocked activation may replace it.

    def test_build_failure_leaves_existing_engine_and_keys_alone(self):
        result, binary = self.installer(existing=True, build_ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(binary, 'previous engine')
        self.assertNotIn(b'KEYGEN', result.stdout)
        self.assertNotIn(b'MIGRATE', result.stdout)

    def helper(self, checksum_ok):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).as_posix()
            source = (ROOT / 'slowdns-build.sh').read_text()
            source = source.replace("[[ $EUID -eq 0 ]] || { echo 'run as root' >&2; exit 1; }", ': # privilege check bypassed only in fixture')
            source = source.replace('/opt/', base + '/').replace('/var/cache/', base + '/')
            prefix = '''
uname() { echo x86_64; }
curl() { printf archive > "$6"; }
sha256sum() { cat >/dev/null; return CHECKSUM; }
tar() { mkdir -p "$4/go/bin"; printf compiler > "$4/go/bin/go"; chmod +x "$4/go/bin/go"; }
python3() { printf 'BUILD %s\\n' "$*"; }
'''.replace('CHECKSUM', '0' if checksum_ok else '1')
            # curl's output filename follows -o, independent of option count.
            prefix = prefix.replace('printf archive > "$6"', 'while [[ $1 != -o ]]; do shift; done; printf archive > "$2"')
            script = Path(directory) / 'build.sh'
            script.write_bytes((prefix + source).encode())
            return subprocess.run([BASH, script.as_posix()], capture_output=True, timeout=15)

    def test_compiler_checksum_failure_stops_before_build(self):
        result = self.helper(False)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'BUILD ', result.stdout)

    def test_verified_compiler_runs_pinned_source_builder(self):
        result = self.helper(True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--implementation upstream-20260501', result.stdout)
        self.assertIn(b'--target linux-amd64', result.stdout)

