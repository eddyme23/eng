import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = r'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else shutil.which('bash')
JQ = shutil.which('jq') or (str(ROOT.parent / 'test-bin/jq.exe') if (ROOT.parent / 'test-bin/jq.exe').exists() else None)


class AccountTypesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = self.root / 'ssh-users.json'
        self.auth = self.root / 'auth'; self.auth.mkdir()
        spec = importlib.util.spec_from_file_location('account_types', ROOT / 'ssh-account-types.py')
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)

    def test_legacy_new_revoked_and_incomplete_accounts(self):
        rows = [dict(name=n, expiresAt='2030-01-01', **extra) for n, extra in (
            ('ordinary', {}), ('local', {}), ('shared', {}), ('revoked', {}),
            ('incomplete', {'accountType': 'certificate'}), ('pinned', {}), ('bundleonly', {}), ('mixedphone', {}))]
        self.store.write_text(json.dumps(rows))
        (self.auth / 'devices.json').write_text(json.dumps({'version': 1, 'devices': [
            dict(username=n, device='certificate-account', status=status) for n, status in
            [('local', 'active'), ('shared', 'active'), ('revoked', 'revoked')]] +
            [dict(username='mixedphone', device='phone1', status='active')]}))
        (self.auth / 'account-policy.json').write_text('{"pinned":"certificates-only"}')
        (self.auth / 'bundle-bundleonly.json').write_text('{}')
        kinds = {r['name']: r['accountType'] for r in self.m.classify(self.store, self.auth)}
        self.assertEqual(kinds.pop('ordinary'), 'password')
        self.assertEqual(kinds.pop('mixedphone'), 'password')
        self.assertEqual(set(kinds.values()), {'certificate'})
        self.assertEqual(json.loads(self.store.read_text()), rows)

    def test_corrupt_metadata_fails_closed(self):
        self.store.write_text('[{"name":"normal"}]')
        (self.auth / 'devices.json').write_text('{broken')
        with self.assertRaises(ValueError): self.m.classify(self.store, self.auth)

    def test_deleted_certificate_name_is_reserved(self):
        self.store.write_text('[]')
        (self.auth / 'account-policy.json').write_text('{"eddy":"certificates-only"}')
        self.assertEqual(self.m.classify(self.store, self.auth, name='eddy')[0]['accountType'], 'certificate')


@unittest.skipUnless(BASH and JQ, 'Bash and jq required')
class AccountDispatchTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'; self.state.mkdir()
        self.auth = self.root / 'auth'; self.auth.mkdir()
        self.log = self.root / 'mutations'
        self.store = self.state / 'ssh-users.json'
        self.store.write_text(json.dumps([dict(name='normal', expiresAt='2030-01-01'), dict(name='cert', expiresAt='2030-01-01')]))
        (self.auth / 'devices.json').write_text('{"version":1,"devices":[{"username":"cert","device":"certificate-account","status":"active"}]}')
        helper = (ROOT / 'ssh-account-types.py').read_text().replace("Path('/etc/frimps-app-auth')", 'Path(' + repr(self.auth.as_posix()) + ')')
        (self.root / 'ssh-account-types.py').write_bytes(helper.encode())
        source = (ROOT / 'ssh-accounts.sh').read_text(encoding='utf-8')
        source = '\n'.join(line for line in source.splitlines() if not line.startswith('[[ $EUID') and not line.startswith('[[ "${EUID}"'))
        start, end = source.index('account_uid_by_name()'), source.index('create_system_account()')
        source = source[:start] + 'account_uid_by_name() { echo 1001; }\n' + source[end:]
        start, end = source.index('retire_app_credentials()'), source.index('delete_system_account()')
        source = source[:start] + 'retire_app_credentials() { echo purge >> "$MUTATIONS"; }\n' + source[end:]
        self.script = self.root / 'ssh-accounts.sh'; self.script.write_bytes(source.encode()); self.script.chmod(0o755)
        self.driver = self.root / 'run.sh'
        lines = ['#!/usr/bin/env bash', 'set -eu',
            'python3() { ' + shlex.quote(Path(sys.executable).as_posix()) + ' "$@"; }',
            'jq() { ' + shlex.quote(Path(JQ).as_posix()) + ' "$@" | tr -d \'\\r\'; }',
            *[name + '() { echo ' + name + ' >> "$MUTATIONS"; }' for name in ('usermod','chage','userdel','pkill')],
            'pgrep() { return 1; }', 'install() { :; }', 'chmod() { :; }', 'flock() { :; }',
            'export -f python3 jq usermod chage userdel pkill pgrep install chmod flock',
            'exec ' + shlex.quote(Path(BASH).as_posix()) + ' ' + shlex.quote(self.script.as_posix()) + ' "$@"']
        self.driver.write_bytes('\n'.join(lines).encode())

    def run_action(self, *args, data=''):
        return subprocess.run([BASH, self.driver.as_posix(), *args], input=data, capture_output=True,
            text=True, timeout=15, env=dict(os.environ, V6_STATE_DIR=self.state.as_posix(), MUTATIONS=self.log.as_posix()))

    def test_lists_and_choosers_separate_existing_accounts(self):
        for action, visible, hidden in [('list','normal','cert'), ('list-certificate','cert','normal'),
            ('choose-delete','normal','cert'), ('choose-delete-certificate','cert','normal')]:
            result = self.run_action(action, data='00\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(visible, result.stdout); self.assertNotIn(hidden, result.stdout)
        self.assertFalse(self.log.exists())

    def test_ordinary_delete_and_renew_refuse_certificate_before_mutation(self):
        for action in ('delete', 'renew'):
            result = self.run_action(action, 'cert', '30')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('use App Certificate Accounts', result.stderr)
            self.assertFalse(self.log.exists())
        self.assertEqual(len(json.loads(self.store.read_text())), 2)

    def test_explicit_certificate_delete_purges_and_removes_only_cert(self):
        result = self.run_action('delete-certificate', 'cert')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('purge', self.log.read_text()); self.assertIn('userdel', self.log.read_text())
        self.assertEqual([r['name'] for r in json.loads(self.store.read_text())], ['normal'])

    def test_certificate_delete_refuses_password_user_and_cancel_is_safe(self):
        result = self.run_action('delete-certificate', 'normal')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not a certificate account', result.stderr)
        result = self.run_action('choose-delete-certificate', data='1\nn\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log.exists())

    def test_password_delete_still_works_and_preserves_certificate_account(self):
        result = self.run_action('delete', 'normal')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([r['name'] for r in json.loads(self.store.read_text())], ['cert'])

    def test_renew_routes_are_separate(self):
        for action, name in [('renew','normal'), ('renew-certificate','cert')]:
            result = self.run_action(action, name, '1')
            self.assertEqual(result.returncode, 0, result.stderr)
        rows = json.loads(self.store.read_text())
        self.assertTrue(all(row['expiresAt'] > '2030-01-01' for row in rows))
        self.assertNotIn('userdel', self.log.read_text())

    def test_automatic_expiry_cleanup_still_covers_both_types(self):
        rows = json.loads(self.store.read_text())
        for row in rows: row['expiresAt'] = '2000-01-01'
        self.store.write_text(json.dumps(rows))
        result = self.run_action('cleanup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.store.read_text()), [])
        self.assertEqual(self.log.read_text().count('userdel'), 2)
