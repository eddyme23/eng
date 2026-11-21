import importlib.util
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
RULE = '-A PREROUTING -i eth0 -p udp -m udp --dport 1:65535 -j DNAT --to-destination :36717'


def load():
    spec = importlib.util.spec_from_file_location('legacy_udp', ROOT / 'legacy-udp-cleanup.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class LegacyCleanupTest(unittest.TestCase):
    def test_only_exact_owned_catchall_is_selected(self):
        m = load()
        self.assertTrue(m.obsolete(RULE, 'eth0'))
        self.assertTrue(m.obsolete(RULE.replace('-m udp ', ''), 'eth0'))
        self.assertTrue(m.obsolete('[123:456] ' + RULE, 'eth0'))
        for other in (RULE.replace('eth0', 'eth1'), RULE.replace(':36717', ':6000'),
                      RULE.replace('1:65535', '50001:65535'), RULE.replace('-p udp', '-p tcp'),
                      RULE.replace('PREROUTING', 'CUSTOM'), RULE + ' -s 192.0.2.0/24',
                      RULE + ' -m comment --comment unrelated', RULE.replace(':36717', '192.0.2.1:36717')):
            with self.subTest(rule=other):
                self.assertFalse(m.obsolete(other, 'eth0'))

    def test_all_nft_legacy_ipv4_ipv6_frontends_and_duplicates_are_idempotent(self):
        m = load()
        unrelated = RULE.replace('1:65535', '50001:65535')
        databases = {name: [RULE, RULE, unrelated] for name in m.TOOLS}
        def run(args):
            name = args[0]
            if '-S' in args:
                return SimpleNamespace(returncode=0, stdout='\n'.join(databases[name]), stderr='')
            self.assertIn('-D', args)
            self.assertIn('5', args)  # Wait for the xtables lock.
            reconstructed = '-A ' + ' '.join(args[args.index('-D') + 1:])
            self.assertEqual(reconstructed, RULE)
            databases[name].remove(reconstructed)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(m.shutil, 'which', side_effect=lambda name: name), patch.object(m, 'run', side_effect=run):
            self.assertEqual(m.clean_runtime('eth0'), 12)
            self.assertEqual(m.clean_runtime('eth0'), 0)
        self.assertTrue(all(values == [unrelated] for values in databases.values()))

    def test_inspection_and_delete_errors_cannot_be_reported_as_clean(self):
        m = load()
        with patch.object(m.shutil, 'which', return_value='iptables'), patch.object(m, 'run', return_value=SimpleNamespace(returncode=4, stderr='Permission denied', stdout='')):
            with self.assertRaisesRegex(ValueError, 'cannot inspect'):
                m.clean_runtime('eth0')
        responses = [SimpleNamespace(returncode=0, stdout=RULE, stderr=''), SimpleNamespace(returncode=1, stdout='', stderr='delete failed')]
        with patch.object(m.shutil, 'which', return_value='iptables'), patch.object(m, 'run', side_effect=responses):
            with self.assertRaisesRegex(ValueError, 'deletion failed'):
                m.clean_runtime('eth0')

    def test_persisted_restores_keep_every_unrelated_byte_and_table(self):
        m = load()
        keep = RULE.replace('1:65535', '50001:65535')
        before = '*filter\r\n' + RULE + '\r\nCOMMIT\r\n*nat\r\n# comment\r\n' + RULE + '\r\n' + keep + '\r\n' + RULE + '\r\nCOMMIT\r\n'
        expected = '*filter\r\n' + RULE + '\r\nCOMMIT\r\n*nat\r\n# comment\r\n' + keep + '\r\nCOMMIT\r\n'
        after, count = m.filter_saved(before, 'eth0')
        self.assertEqual(count, 2)
        self.assertEqual(after, expected)
        self.assertEqual(m.filter_saved(after, 'eth0'), (after, 0))
        # Reboot/reload consumes sanitized persistent state, never the catch-all.
        restored_nat = after.split('*nat', 1)[1]
        self.assertNotIn('--dport 1:65535 ', restored_nat)
        self.assertIn('50001:65535', restored_nat)

    def test_saved_file_backup_atomic_replacement_and_repeat(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            path = base / 'rules.v4'
            original = ('*nat\n' + RULE + '\nCOMMIT\n').encode()
            path.write_bytes(original); path.chmod(0o640)
            m.BACKUPS = base / 'backup'
            with ExitStack() as stack:
                if os.name == 'nt':
                    # Exercise atomic file edits on Windows; Linux mode/UID calls
                    # are mocked here and require verification on the VPS.
                    original_stat = Path.stat
                    def fixture_stat(value, *args, **kwargs):
                        result = original_stat(value, *args, **kwargs)
                        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700) if value == m.BACKUPS else result
                    stack.enter_context(patch.object(Path, 'stat', fixture_stat))
                    stack.enter_context(patch.object(m.os, 'fchmod', create=True))
                    stack.enter_context(patch.object(m.os, 'fchown', create=True))
                self.assertEqual(m.clean_saved(path, 'eth0'), 1)
            self.assertEqual(path.read_bytes(), b'*nat\nCOMMIT\n')
            if os.name != 'nt':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual(next(m.BACKUPS.iterdir()).read_bytes(), original)
            self.assertEqual(m.clean_saved(path, 'eth0'), 0)
            self.assertEqual(len(list(m.BACKUPS.iterdir())), 1)

    def test_native_policy_is_required_but_socksip_is_not(self):
        m = load()
        with patch.object(m, 'run', return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as run:
            self.assertTrue(m.native_ready(False))
            run.assert_called_once_with(['nft', 'list', 'table', 'ip', 'frimps_v6_udp'])
        with patch.object(m, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr='No such file or directory')):
            self.assertFalse(m.native_ready(True))
            with self.assertRaises(ValueError):
                m.native_ready(False)
        with patch.object(m, 'run', return_value=SimpleNamespace(returncode=1, stdout='', stderr='Operation not permitted')):
            with self.assertRaises(ValueError):
                m.native_ready(True)

    def test_upgrade_restart_and_reboot_restore_cannot_keep_the_catchall(self):
        m = load()
        good = RULE.replace('1:65535', '50001:65535')
        saved, count = m.filter_saved('*nat\n' + RULE + '\n' + good + '\nCOMMIT\n', 'eth0')
        self.assertEqual(count, 1)
        state = [RULE, good]
        def command(args):
            if '-S' in args:
                return SimpleNamespace(returncode=0, stdout='\n'.join(state), stderr='')
            state.remove(RULE)
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.object(m, 'TOOLS', ('iptables-nft',)), patch.object(m.shutil, 'which', return_value='iptables-nft'), patch.object(m, 'run', side_effect=command):
            # Existing VPS migration.
            m.clean_runtime('eth0'); self.assertEqual(state, [good])
            # Upstream startup recreates its old catch-all; post-start hook removes it.
            state.append(RULE)
            m.clean_runtime('eth0'); self.assertEqual(state, [good])
            # Reboot restore reads sanitized saved rules; later UDP startup is cleaned too.
            state[:] = [line for line in saved.splitlines() if line.startswith('-A')]
            self.assertEqual(state, [good])
            state.append(RULE)
            m.clean_runtime('eth0'); self.assertEqual(state, [good])

    def test_symlink_persistence_is_never_followed(self):
        m = load()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'target'
            target.write_text('*nat\n' + RULE + '\nCOMMIT\n')
            link = Path(directory) / 'rules.v4'
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest('symlink creation unavailable')
            with self.assertRaisesRegex(ValueError, 'non-regular'):
                m.clean_saved(link, 'eth0')
            self.assertIn(RULE, target.read_text())

    def test_post_start_waits_for_the_managed_udp_pid_before_cleanup(self):
        m = load()
        answers = [SimpleNamespace(returncode=0, stdout='123\n'), SimpleNamespace(returncode=0, stdout='UNCONN users:(("udp-custom",pid=999,fd=3))'),
                   SimpleNamespace(returncode=0, stdout='123\n'), SimpleNamespace(returncode=0, stdout='UNCONN users:(("udp-custom",pid=123,fd=3))')]
        with patch.object(m, 'run', side_effect=answers), patch.object(m.time, 'sleep') as sleep:
            m.wait_udp()
            sleep.assert_called_once()

    @unittest.skipUnless(BASH, 'bash required')
    def test_guard_installer_replaces_stale_hooks_and_orders_boot_without_socksip(self):
        source = (ROOT / 'install-firewall-guard.sh').read_text()
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('[[ $EUID'))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source = source.replace('/etc/', base.as_posix() + '/etc/').replace('/usr/local/', base.as_posix() + '/usr/local/')
            prefix = 'install() { if [[ $1 == -d ]]; then mkdir -p "${@: -1}"; else :; fi; }; systemctl() { printf "SYSTEMCTL %s\\n" "$*"; };\n'
            script = base / 'install.sh'; script.write_bytes((prefix + source).encode())
            for _ in range(2):
                result = subprocess.run([BASH, script.as_posix()], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('SYSTEMCTL restart', result.stdout)
            units = base / 'etc/systemd/system'
            migration = (units / 'frimps-firewall-migration.service').read_text()
            self.assertNotIn('socksip', migration)
            self.assertIn('Before=frimps-slowdns.service', migration)
            # Check the generated ordering graph, including original service
            # dependencies, rather than assuming added hooks are cycle-free.
            import graphlib
            before = {}
            service_text = {name: (units / name).read_text() for name in ('frimps-firewall-migration.service',)}
            for folder in units.glob('*.service.d'):
                service_text[folder.name[:-2]] = '\n'.join(p.read_text() for p in folder.glob('*.conf'))
            service_text['frimps-slowdns.service'] = 'After=network-online.target ssh.service frimps-v6-udp-routing.service'
            for name, text in service_text.items():
                before.setdefault(name, set())
                for line in text.splitlines():
                    if line.startswith('After='):
                        before[name].update(line.split('=', 1)[1].split())
                    if line.startswith('Before='):
                        for target in line.split('=', 1)[1].split():
                            before.setdefault(target, set()).add(name)
            list(graphlib.TopologicalSorter(before).static_order())
            udp = (units / 'frimps-udp-custom.service.d/60-frimps-firewall-guard.conf').read_text()
            self.assertEqual(udp.count('ExecStartPre='), 1)
            self.assertEqual(udp.count('ExecStartPost='), 1)
            self.assertIn('--wait-udp', udp)
            self.assertIn('CapabilityBoundingSet=~CAP_NET_ADMIN', udp)
            self.assertIn('ExecStartPost=+', udp)
            self.assertIn('ExecStopPost=', udp)
            routing = (units / 'frimps-v6-udp-routing.service.d/60-frimps-firewall-guard.conf').read_text()
            self.assertIn('After=netfilter-persistent.service nftables.service', routing)
            for firewall in ('netfilter-persistent', 'nftables', 'iptables', 'ip6tables'):
                self.assertIn('--if-ready', (units / (firewall + '.service.d/60-frimps-firewall-guard.conf')).read_text())

    @unittest.skipUnless(BASH, 'bash required')
    def test_existing_vps_update_backs_up_before_cleanup_without_restarting_vpns(self):
        source = (ROOT / 'apply-legacy-udp-fix.sh').read_text()
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('[[ $EUID'))
        for snapshot_status in (0, 2):
            with self.subTest(snapshot=snapshot_status), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                units = base / 'etc/systemd/system'
                units.mkdir(parents=True)
                (units / 'frimps-firewall-migration.service').write_text('previous migration')
                code = source.replace('/etc/', base.as_posix() + '/etc/').replace('/var/backups/', base.as_posix() + '/backups/')
                mocks = r"""
install() { if [[ $1 == -d ]]; then mkdir -p "${@: -1}"; else return 1; fi; }
nft() { if [[ $* == 'list ruleset' ]]; then echo SNAPSHOT; return SNAPSHOT_STATUS; fi; return 0; }
iptables-save() { echo SAVED; }; iptables-nft-save() { echo SAVED; }; iptables-legacy-save() { echo SAVED; }
ip6tables-save() { echo SAVED; }; ip6tables-nft-save() { echo SAVED; }; ip6tables-legacy-save() { echo SAVED; }
bash() { echo "INSTALL $1"; }
systemctl() { echo "SYSTEMCTL $*"; }
""".replace('SNAPSHOT_STATUS', str(snapshot_status))
                script = base / 'update.sh'; script.write_bytes((mocks + code).encode())
                result = subprocess.run([BASH, script.as_posix()], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, snapshot_status, result.stderr)
                if snapshot_status:
                    self.assertNotIn('INSTALL ', result.stdout)
                else:
                    backups = list((base / 'backups/frimps-v6').glob('legacy-udp-*'))
                    self.assertEqual(len(backups), 1)
                    self.assertEqual((backups[0] / 'frimps-firewall-migration.service').read_text(), 'previous migration')
                    self.assertIn('install-firewall-guard.sh', result.stdout)
                    self.assertIn('SYSTEMCTL restart frimps-firewall-migration.service', result.stdout)
                    for forbidden in ('restart frimps-udp-custom', 'restart frimps-slowdns', 'restart ssh'):
                        self.assertNotIn(forbidden, result.stdout)

    def test_fresh_install_upgrade_refresh_and_recovery_use_the_shared_guard(self):
        self.assertIn('install-firewall-guard.sh', (ROOT / 'udp-custom-install.sh').read_text())
        self.assertIn('install-firewall-guard.sh', (ROOT / 'apply-legacy-udp-fix.sh').read_text())
        self.assertIn('install-firewall-guard.sh', (ROOT / 'refresh-menu-v6.sh').read_text())
        guard = (ROOT / 'install-firewall-guard.sh').read_text()
        for companion in ('apply-udp-updates.sh', 'refresh-menu-v6.sh', 'service-health-v6.sh'):
            self.assertIn(companion, guard)
        self.assertIn('apply-legacy-udp-fix.sh', (ROOT / 'apply-udp-updates.sh').read_text())
        self.assertNotIn('cat >/etc/systemd/system/frimps-firewall-migration.service', (ROOT / 'apply-udp-updates.sh').read_text())
        self.assertIn('frimps-retire-iptables-rules --if-ready', (ROOT / 'service-health-v6.sh').read_text())
