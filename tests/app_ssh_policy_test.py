import base64
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AppSshPolicyTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.m, self.p = load('app-ssh-auth'), load('app-ssh-policy')
        self.m.AUTH = self.root / 'auth'
        self.m.AUTH.mkdir()
        self.m.STATE = self.root / 'state'
        self.m.STATE.mkdir()
        self.p.POLICY = self.root / 'policy.conf'
        self.p.KEYS = self.root / 'keys'
        self.p.KEYS.mkdir()
        self.p.ADMIN = self.root / 'sshd_config'
        self.p.ADMIN.write_text('Port 22\nPasswordAuthentication yes\n')
        self.p.BACKUPS = self.root / 'backups'
        self.original = self.p.ADMIN.read_bytes()
        self.user = SimpleNamespace(pw_name='appuser', pw_dir='/home/appuser')
        self.m.account = Mock(return_value=(self.user, datetime.now(timezone.utc) + timedelta(days=30)))
        self.m.backend_policy = Mock()
        self.m.transport_policy = Mock()
        self.m.policy_module = lambda: self.p
        self.p.prepare_keys = Mock()
        raw = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'a' * 32
        (self.m.AUTH / 'ca.pub').write_text('ssh-ed25519 ' + base64.b64encode(raw).decode())
        self.device = dict(username='appuser', status='active', id='a' * 32, principal='eng-app-' + 'a' * 32,
                           validBefore=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat())
        self.m.save_db({'version': 1, 'devices': [self.device]})
        self.calls = []
        def run(*args):
            self.calls.append(args)
            if '-T' in args:
                return SimpleNamespace(stdout='passwordauthentication no\nkbdinteractiveauthentication no\n'
                    'authenticationmethods publickey\nauthorizedkeysfile ' + str(self.p.KEYS / '%u') + '\n')
            return SimpleNamespace(stdout='')
        self.m.run = Mock(side_effect=run)

    def test_policy_scopes_password_restriction_to_named_account_and_syncs_trust(self):
        self.p.set_mode(self.m, 'appuser', 'certificates-only')
        text = self.p.POLICY.read_text()
        self.assertIn('Match User appuser\n', text)
        self.assertNotIn('Match User *', text)
        self.assertIn('cert-v01@openssh.com', text)
        self.assertIn('cert-authority,principals="eng-app-', (self.p.KEYS / 'appuser').read_text())
        self.assertIn('PasswordAuthentication yes', self.p.ADMIN.read_text())
        self.assertEqual(self.p.modes(self.m), {'appuser': 'certificates-only'})
        self.assertTrue(any('--signal=HUP' in args for args in self.calls))

    def test_syntax_failure_restores_config_and_policy_metadata(self):
        self.m.run.side_effect = subprocess.CalledProcessError(1, 'sshd -t')
        with self.assertRaises(subprocess.CalledProcessError):
            self.p.set_mode(self.m, 'appuser', 'certificates-only')
        self.assertEqual(self.p.ADMIN.read_bytes(), self.original)
        self.assertFalse(self.p.POLICY.exists())
        self.assertEqual(self.p.modes(self.m), {})
        self.assertFalse((self.p.KEYS / 'appuser').exists())

    def test_prior_match_override_is_detected_and_rolled_back(self):
        self.m.run.return_value = SimpleNamespace(stdout='passwordauthentication yes\n')
        self.m.run.side_effect = None
        with self.assertRaisesRegex(ValueError, 'earlier SSH Match'):
            self.p.set_mode(self.m, 'appuser', 'certificates-only')
        self.assertEqual(self.p.ADMIN.read_bytes(), self.original)

    def test_no_certificate_means_no_login_policy_mutation(self):
        self.m.save_db({'version': 1, 'devices': []})
        with self.assertRaisesRegex(ValueError, 'Enroll'):
            self.p.set_mode(self.m, 'appuser', 'certificates-only')
        self.assertEqual(self.p.ADMIN.read_bytes(), self.original)
        self.assertFalse(self.p.BACKUPS.exists())

    def test_include_is_idempotent_and_rejects_modified_footer(self):
        text = self.p.append_include(self.original.decode())
        self.assertEqual(text, self.p.append_include(text))
        with self.assertRaises(ValueError):
            self.p.append_include(text + '# later edit\n')

    def test_address_specific_password_exception_requires_review_before_mutation(self):
        dropin = self.root / 'custom.conf'
        dropin.write_text('Match Address 192.0.2.1\n PasswordAuthentication yes\n')
        self.p.ADMIN.write_text('Include ' + dropin.as_posix() + '\nPort 22\n')
        original = self.p.ADMIN.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Custom SSH Match'):
            self.p.set_mode(self.m, 'appuser', 'certificates-only')
        self.assertEqual(self.p.ADMIN.read_bytes(), original)
        self.assertFalse(self.p.BACKUPS.exists())

    def test_revocation_sync_removes_central_trust(self):
        self.p.set_mode(self.m, 'appuser', 'certificates-only')
        self.device['status'] = 'revoked'
        self.p.sync(self.m, {'devices': [self.device]}, 'appuser')
        self.assertEqual((self.p.KEYS / 'appuser').read_bytes(), b'')

    def test_fingerprint_is_compatible_with_tg_sha256_format(self):
        key = (self.m.AUTH / 'ca.pub').read_text()
        pin = self.m.fingerprint(key)
        self.assertRegex(pin, r'^SHA256:[A-Za-z0-9+/]{43}$')

    def test_mixed_removes_only_selected_account_policy(self):
        self.m.atomic(self.m.AUTH / 'account-policy.json', json.dumps({'appuser': 'certificates-only', 'otherapp': 'certificates-only'}).encode())
        self.p.set_mode(self.m, 'appuser', 'mixed')
        self.assertEqual(self.p.modes(self.m), {'otherapp': 'certificates-only'})
        self.assertIn('Match User otherapp\n', self.p.POLICY.read_text())
        self.assertNotIn('appuser', self.p.POLICY.read_text())

    def test_foreign_shared_ca_survives_sync_without_local_signing_ca(self):
        ca = (self.m.AUTH / 'ca.pub').read_text()
        (self.m.AUTH / 'ca.pub').unlink()
        self.device.update(shared=True, caPublicKey=ca)
        self.m.save_db({'version': 1, 'devices': [self.device]})
        self.p.set_mode(self.m, 'appuser', 'certificates-only')
        text = (self.p.KEYS / 'appuser').read_text()
        self.assertIn(ca, text)
        self.assertIn('expiry-time=', text)
        self.device['status'] = 'revoked'
        self.m.save_db({'version': 1, 'devices': [self.device]})
        self.p.sync(self.m, self.m.read_db(), 'appuser')
        self.assertEqual((self.p.KEYS / 'appuser').read_text(), '')

    def test_three_identities_keep_their_own_ca_and_revoking_one_preserves_two(self):
        local = dict(self.device)
        local['caPublicKey'] = (self.m.AUTH / 'ca.pub').read_text()
        foreign = []
        for letter in ('b', 'c'):
            raw = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + letter.encode() * 32
            ca = 'ssh-ed25519 ' + base64.b64encode(raw).decode()
            foreign.append(dict(local, id=letter * 32, principal='eng-app-' + letter * 32, shared=True, caPublicKey=ca))
        db = {'version': 1, 'devices': [local, *foreign]}
        self.m.save_db(db)
        self.p.set_mode(self.m, 'appuser', 'certificates-only')
        text = (self.p.KEYS / 'appuser').read_text()
        for record in db['devices']:
            self.assertIn(record['caPublicKey'], text)
            self.assertIn(record['principal'], text)
        self.assertEqual(text.count('cert-authority'), 3)
        foreign[0]['status'] = 'revoked'
        self.p.sync(self.m, db, 'appuser')
        text = (self.p.KEYS / 'appuser').read_text()
        self.assertNotIn(foreign[0]['principal'], text)
        self.assertIn(local['principal'], text)
        self.assertIn(foreign[1]['principal'], text)
        self.assertEqual(text.count('cert-authority'), 2)
