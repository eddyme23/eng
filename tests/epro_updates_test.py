import hashlib
import importlib.util
import os
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EproUpdatesTest(unittest.TestCase):
    def setUp(self):
        self.settings = load('hcr-settings')
        self.network = load('slowdns-network')
        self.upgrade = load('epro-upgrade')

    def test_pinned_release_integrity(self):
        for kind, name in [('hcr', 'hcr-server'), ('slowdns', 'slowdns')]:
            data = (ROOT / 'releases/epro-20261029' / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), self.upgrade.HASHES[kind])
            self.assertEqual(data[:4], b'\x7fELF')

    def test_default_and_existing_hcr_settings_are_preserved(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.settings.options('unused'), ['--max-download-frame', '6144', '--download-poll-timeout', '8s'])
            existing = {'--max-download-frame': '8192', '--download-poll-timeout': '5s'}
            self.assertEqual(self.settings.options('unused', existing), ['--max-download-frame', '8192', '--download-poll-timeout', '5s'])

    def test_invalid_limits_durations_and_frames_are_rejected(self):
        for key, value in [('MAX_SESSIONS', '-1'), ('MAX_CONNECTIONS', '1;echo'),
                           ('DIAGNOSTICS_INTERVAL', '9s'), ('DIAGNOSTICS_INTERVAL', '6m'),
                           ('DOWNLOAD_POLL_TIMEOUT', '0s'), ('MAX_DOWNLOAD_FRAME', '262141'),
                           ('MAX_DOWNLOAD_FRAME', '16385')]:
            with self.subTest(key=key, value=value), patch.dict(os.environ, {'HCR_' + key: value}, clear=True):
                with self.assertRaises(ValueError):
                    self.settings.options('unused')

    def test_large_frames_and_diagnostics_require_binary_support(self):
        env = {'HCR_MAX_DOWNLOAD_FRAME': '262140', 'HCR_ALLOW_LARGE_FRAMES': 'YES',
               'HCR_DIAGNOSTICS_INTERVAL': '10s', 'HCR_MAX_SESSIONS': '32'}
        supported = subprocess.CompletedProcess([], 0, ' frame range: 1-262140\n -diagnostics-interval duration\n -max-sessions int\n', '')
        unsupported = subprocess.CompletedProcess([], 0, 'legacy help', '')
        with patch.dict(os.environ, env, clear=True), patch.object(self.settings.subprocess, 'run', return_value=supported):
            args = self.settings.options('candidate')
            self.assertIn('--diagnostics-interval', args)
            self.assertIn('262140', args)
        with patch.dict(os.environ, env, clear=True), patch.object(self.settings.subprocess, 'run', return_value=unsupported):
            with self.assertRaises(ValueError):
                self.settings.options('candidate')

    def test_hcr_render_preserves_tls_and_service_protection(self):
        text = ('[Service]\nExecStart=/opt/frimps-hcr-tls/hcr-server --listen :8444 --target 127.0.0.1:22 '
                '--transport tls --tls-cert /etc/live/cert.pem --tls-key /etc/live/key.pem '
                '--max-download-frame 6144 --download-poll-timeout 8s\nMemoryMax=384M\nNoNewPrivileges=true\n')
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.upgrade.render_hcr(text, 'unused'), text)
        with self.assertRaises(ValueError):
            self.upgrade.render_hcr(text.replace('127.0.0.1:22', 'other:22'), 'unused')

    def fake_command(self, sockets):
        def command(*args):
            if args[0] == 'ip':
                return '[{"ifname":"eth0","addr_info":[{"local":"192.0.2.2","scope":"global"},{"local":"2001:db8::2","scope":"global"}]}]'
            if args[0] == 'systemctl':
                return '123\n'
            if args[0] == 'ss':
                return sockets
            self.fail(args)
        return command

    def test_listener_preflight_rejects_foreign_and_unidentified_owners(self):
        for owner in ('users:(("dns",pid=999,fd=1))', ''):
            sockets = 'UNCONN 0 0 0.0.0.0:53 0.0.0.0:* ' + owner
            with patch.object(self.network, 'command', self.fake_command(sockets)):
                with self.assertRaises(ValueError):
                    self.network.inspect('192.0.2.2:53', True)
        with patch.object(self.network, 'command', self.fake_command('UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("dns",pid=999,fd=1))')):
            self.network.inspect('192.0.2.2:53', True)
            with self.assertRaises(ValueError):
                self.network.inspect(':53', True)

    def test_dual_stack_requires_proven_coverage_by_main_pid(self):
        sockets = 'UNCONN 0 0 [::]:53 [::]:* users:(("sldns",pid=123,fd=1)) v6only:1'
        with patch.object(self.network, 'command', self.fake_command(sockets)):
            with self.assertRaises(ValueError):
                self.network.inspect(':53')
        with patch.object(self.network, 'command', self.fake_command(sockets.replace('v6only:1', 'v6only:0'))):
            self.network.inspect(':53')

    def test_first_install_preflight_allows_absent_unit(self):
        normal = self.fake_command('')
        def command(*args):
            if args[0] == 'systemctl':
                raise subprocess.CalledProcessError(1, args)
            return normal(*args)
        with patch.object(self.network, 'command', command):
            self.network.inspect('192.0.2.2:53', True)
            with self.assertRaises(subprocess.CalledProcessError):
                self.network.inspect('192.0.2.2:53')

    def test_notrack_is_scoped_and_has_no_nat_or_firewall_allow_rules(self):
        with patch.object(self.network, 'command', self.fake_command('')):
            rules = self.network.notrack_rules(self.network.selected(':53'))
        self.assertIn('ip daddr 192.0.2.2 udp dport 53 notrack', rules)
        self.assertIn('ip6 saddr 2001:db8::2 udp sport 53 notrack', rules)
        self.assertIn('priority raw', rules)
        self.assertNotIn('dnat', rules)
        self.assertNotIn('iptables', rules)
        self.assertNotIn('flush ruleset', rules)

    def test_rollback_restores_files_and_removes_previously_absent_config(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            binary = base / 'binary'
            missing = base / 'network.json'
            binary.write_bytes(b'old engine')
            with patch.object(self.upgrade, 'BACKUPS', base / 'backups'), \
                 patch.object(self.upgrade, 'BINARIES', {'hcr': [str(binary)], 'slowdns': []}), \
                 patch.object(self.upgrade, 'NETWORK_FILES', [str(missing)]), \
                 patch.object(self.upgrade, 'run') as run:
                backup = self.upgrade.save_backup([binary, missing], ['frimps-hcr.service'])
                binary.write_bytes(b'new engine')
                missing.write_text('new config')
                self.upgrade.restore(backup)
                self.assertEqual(binary.read_bytes(), b'old engine')
                self.assertFalse(missing.exists())
                self.assertIn(('systemctl', 'start', 'frimps-hcr.service'), [call.args for call in run.call_args_list])

    def test_failed_activation_restores_all_hcr_services(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            unit_dir = base / 'units'
            unit_dir.mkdir()
            release = base / 'releases/epro-20261029'
            release.mkdir(parents=True)
            (release / 'hcr-server').write_bytes(b'candidate engine')
            binaries, originals = [], {}
            for unit in self.upgrade.UNITS['hcr']:
                binary = base / (unit + '.binary')
                binary.write_bytes(b'previous engine')
                binaries.append(str(binary))
                text = ('[Service]\nExecStart=' + shlex.quote(str(binary)) + ' --listen :8881 --target 127.0.0.1:22 '
                        '--transport plain --max-download-frame 6144 --download-poll-timeout 8s\nNoNewPrivileges=true\n')
                (unit_dir / unit).write_text(text)
                originals[unit] = text
            def run(*args, **kwargs):
                output = ' -listen string\n -target string\n -transport string\n -max-download-frame int\n'
                if args[:2] == ('systemctl', 'cat'):
                    output = originals[args[2]]
                return subprocess.CompletedProcess(args, 0, output, '')
            with patch.object(self.upgrade, 'ROOT', base), \
                 patch.object(self.upgrade, 'UNIT_DIR', unit_dir), \
                 patch.object(self.upgrade, 'BACKUPS', base / 'backups'), \
                 patch.object(self.upgrade, 'BINARIES', {'hcr': binaries, 'slowdns': []}), \
                 patch.dict(self.upgrade.HASHES, {'hcr': hashlib.sha256(b'candidate engine').hexdigest()}), \
                 patch.object(self.upgrade, 'run', side_effect=run), \
                 patch.object(self.upgrade, 'settings_module', return_value=self.settings), \
                 patch.object(self.upgrade.time, 'sleep'), \
                 patch.object(self.upgrade, 'verify_unit', side_effect=ValueError('TLS activation failed')), \
                 patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, 'TLS activation failed'):
                    self.upgrade.upgrade('hcr')
            for binary in binaries:
                self.assertEqual(Path(binary).read_bytes(), b'previous engine')
            for unit, text in originals.items():
                self.assertEqual((unit_dir / unit).read_text(), text)
