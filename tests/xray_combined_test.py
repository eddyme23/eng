import copy
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from xray_manager_test import x, SETTINGS, USERS


class CombinedAccountsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        x.atomic(self.state / 'xray-settings.json', SETTINGS)
        x.atomic(self.state / 'xray-users.json', USERS)
        x.atomic(self.state / 'xray.json', {'old': True})

    def change(self, action, name='all123', days=30):
        with patch.object(x, 'validate_config'), patch.object(x.subprocess, 'run') as run:
            x.change(self.state, 'unused', 'combined', action, name, days)
            return run.call_args_list

    def test_creation_exports_all_protocols_with_one_expiry_and_one_restart(self):
        calls = self.change('create')
        users = x.accounts_at(self.state)
        rows, identity = x.combined_rows(users, 'all123')
        self.assertEqual(len(identity), 32)
        self.assertEqual(len({group[0]['expiresAt'] for group in rows.values()}), 1)
        self.assertEqual(len({group[0].get('uuid', group[0].get('password')) for group in rows.values()}), 4)
        self.assertEqual([c.args[0] for c in calls], [['systemctl', 'restart', 'frimps-xray.service'],
                                                   ['systemctl', 'is-active', '--quiet', 'frimps-xray.service']])
        output = x.combined_links(SETTINGS, users, 'all123')
        uris = [line for line in output.splitlines() if line.startswith(('vless://', 'vmess://', 'trojan://', 'ss://'))]
        self.assertEqual(len(uris), 16)
        self.assertEqual(list(x.combined_list(users))[0][0], 'all123')
        self.assertEqual(list(x.combined_list(users))[0][2], 'active')
        for p in x.PROTOCOLS:
            self.assertIn(USERS[p][0], users[p])

    def test_renewal_preserves_all_credentials_and_delete_keeps_unrelated_accounts(self):
        self.change('create')
        before = x.accounts_at(self.state)
        self.change('renew', days=90)
        renewed = x.accounts_at(self.state)
        for p in x.PROTOCOLS:
            old = next(u for u in before[p] if u['name'] == 'all123')
            new = next(u for u in renewed[p] if u['name'] == 'all123')
            self.assertEqual({k: v for k, v in old.items() if k != 'expiresAt'},
                             {k: v for k, v in new.items() if k != 'expiresAt'})
            self.assertNotEqual(old['expiresAt'], new['expiresAt'])
        self.change('delete')
        self.assertEqual(x.accounts_at(self.state), USERS)

    def test_existing_names_and_individual_mutations_are_not_adopted(self):
        with self.assertRaises(ValueError):
            self.change('create', name='customer')
        self.assertEqual(x.accounts_at(self.state), USERS)
        self.change('create')
        before = x.accounts_at(self.state)
        for p in x.PROTOCOLS:
            for action in ['renew', 'delete']:
                with self.assertRaisesRegex(ValueError, 'Combined'):
                    x.change(self.state, 'unused', p, action, 'all123', 90)
        self.assertEqual(x.accounts_at(self.state), before)

    def test_failed_restart_rolls_back_every_member(self):
        with patch.object(x, 'validate_config'), patch.object(x.subprocess, 'run', side_effect=[
                subprocess.CalledProcessError(1, 'systemctl'), subprocess.CompletedProcess([], 0)]):
            with self.assertRaises(subprocess.CalledProcessError):
                x.change(self.state, 'unused', 'combined', 'create', 'all123', 30)
        self.assertEqual(x.accounts_at(self.state), USERS)
        self.assertEqual(x.load(self.state / 'xray.json'), {'old': True})

    def test_failed_validation_never_writes_partial_accounts(self):
        with patch.object(x, 'validate_config', side_effect=ValueError('Rejected configuration')), \
                patch.object(x.subprocess, 'run') as run:
            with self.assertRaises(ValueError):
                x.change(self.state, 'unused', 'combined', 'create', 'all123', 30)
        run.assert_not_called()
        self.assertEqual(x.accounts_at(self.state), USERS)
        self.assertEqual(x.load(self.state / 'xray.json'), {'old': True})

    def test_cleanup_expires_entire_group_and_partial_group_can_be_deleted(self):
        self.change('create')
        users = x.accounts_at(self.state)
        for p in x.PROTOCOLS:
            next(u for u in users[p] if u['name'] == 'all123')['expiresAt'] = '2000-01-01'
        x.atomic(self.state / 'xray-users.json', users)
        with self.assertRaises(ValueError):
            x.combined_links(SETTINGS, users, 'all123')
        self.change('cleanup')
        self.assertEqual(x.accounts_at(self.state), USERS)
        self.change('create')
        users = x.accounts_at(self.state)
        users['vmess'] = [u for u in users['vmess'] if u['name'] != 'all123']
        foreign = x.new_account('vmess', 'all123', '2099-01-01')
        users['vmess'].append(foreign)
        x.atomic(self.state / 'xray-users.json', users)
        self.assertEqual(list(x.combined_list(users))[0][2], 'incomplete')
        with self.assertRaises(ValueError):
            self.change('renew')
        self.change('delete')
        expected = copy.deepcopy(USERS)
        expected['vmess'].append(foreign)
        self.assertEqual(x.accounts_at(self.state), expected)

    def test_combined_cli_list_and_export_use_same_account(self):
        self.change('create')
        for action in ['list', 'links']:
            output = io.StringIO()
            argv = ['xray-manager.py', action, 'combined'] + (['all123'] if action == 'links' else [])
            with patch.dict(os.environ, V6_STATE_DIR=str(self.state)), patch.object(x.os, 'geteuid', return_value=0, create=True), \
                    patch.object(x, 'locked', return_value=contextlib.nullcontext()), patch('sys.argv', argv), contextlib.redirect_stdout(output):
                x.main()
            self.assertIn('all123', output.getvalue())
            if action == 'links':
                for scheme in ['vless://', 'vmess://', 'trojan://', 'ss://']:
                    self.assertIn(scheme, output.getvalue())

    @unittest.skipUnless(os.environ.get('XRAY_TEST_BINARY'), 'set XRAY_TEST_BINARY for real core validation')
    def test_real_core_accepts_generated_combined_credentials(self):
        self.change('create')
        settings = copy.deepcopy(SETTINGS)
        binary = os.environ['XRAY_TEST_BINARY']
        values = dict(line.split(':', 1) for line in subprocess.check_output([binary, 'x25519'], text=True).splitlines() if ':' in line)
        settings['reality']['privateKey'] = values['PrivateKey'].strip()
        x.validate_config(binary, x.configuration(settings, x.accounts_at(self.state)), self.state)


if __name__ == '__main__':
    unittest.main()
