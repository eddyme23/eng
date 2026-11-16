import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
KEYGEN = shutil.which('ssh-keygen')


def load():
    spec = importlib.util.spec_from_file_location('app_auth', ROOT / 'app-ssh-auth.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(KEYGEN, 'OpenSSH ssh-keygen required')
class AppSshAuthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory()
        cls.base = Path(cls.keys.name)
        for name in ('device',):
            subprocess.run([KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', str(cls.base / name)],
                           check=True, capture_output=True)
        subprocess.run([KEYGEN, '-q', '-t', 'ecdsa', '-b', '256', '-N', '', '-f', str(cls.base / 'device-ecdsa')],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.m = load()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.auth = Path(self.temp.name)
        self.m.AUTH = self.auth
        self.m.KEYGEN = KEYGEN
        subprocess.run([KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', str(self.auth / 'ca')],
                       check=True, capture_output=True)
        self.public = self.m.public_key((self.auth / 'ca.pub').read_text())
        self.expiry = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=2)
        self.user = SimpleNamespace(pw_name='eddy', pw_dir=str(self.auth / 'home'), pw_uid=1001, pw_gid=1001)
        Path(self.user.pw_dir).mkdir()
        self.content = b'# existing\nssh-ed25519 unrelated-key old-client\n'
        self.before = self.content
        self.args = argparse.Namespace(username='eddy', device='phone1', days=7, public_key=self.base / 'device.pub')

    @contextmanager
    def authorized(self, user):
        def write(data):
            self.content = data
        yield self.content, write

    def patches(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.object(self.m, 'account', return_value=(self.user, self.expiry)))
        stack.enter_context(patch.object(self.m, 'backend_policy'))
        stack.enter_context(patch.object(self.m, 'transport_policy'))
        stack.enter_context(patch.object(self.m, 'authority', return_value=self.public))
        stack.enter_context(patch.object(self.m, 'authorized_file', self.authorized))
        return stack

    def test_real_certificate_signing_expiry_and_restricted_forwarding(self):
        with self.patches():
            result = self.m.enroll(self.args)
        cert = self.auth / 'verify-cert.pub'
        cert.write_text(result['certificate'] + '\n')
        output = subprocess.check_output([KEYGEN, '-L', '-f', str(cert)], text=True)
        self.assertIn('eng-app-' + result['deviceId'], output)
        self.assertIn('force-command /bin/false', output)
        self.assertIn('permit-port-forwarding', output)
        self.assertNotIn('permit-pty', output)
        self.assertNotIn('permit-agent-forwarding', output)
        fingerprint = subprocess.check_output([KEYGEN, '-l', '-f', str(self.auth / 'ca.pub')], text=True).split()[1]
        self.assertIn(fingerprint, output)
        self.assertEqual(result['caFingerprint'], fingerprint)
        self.assertEqual(datetime.fromisoformat(result['validBefore']), self.expiry)
        self.assertFalse(result['privateKeyIncluded'])
        self.assertNotIn('password', result)
        self.assertTrue(self.content.startswith(self.before))
        self.assertIn(b'cert-authority,principals="eng-app-', self.content)

    def test_real_p256_certificate_for_keystore_compatible_public_key(self):
        self.args.public_key = self.base / 'device-ecdsa.pub'
        with self.patches():
            result = self.m.enroll(self.args)
        self.assertTrue(result['certificate'].startswith('ecdsa-sha2-nistp256-cert-v01@openssh.com '))

    def test_duplicate_device_cannot_silently_replace_existing_credential(self):
        with self.patches():
            self.m.enroll(self.args)
            old = self.content
            with self.assertRaisesRegex(ValueError, 'already exists'):
                self.m.enroll(self.args)
        self.assertEqual(self.content, old)

    def test_database_failure_restores_original_authorized_keys(self):
        with self.patches(), patch.object(self.m, 'save_db', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.m.enroll(self.args)
        self.assertEqual(self.content, self.before)

    def test_revoke_only_removes_selected_device(self):
        with self.patches():
            first = self.m.enroll(self.args)
            self.args.device = 'phone2'
            second = self.m.enroll(self.args)
            with patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: self.user)}):
                self.m.revoke(argparse.Namespace(username='eddy', device='phone1'))
        self.assertNotIn(first['deviceId'].encode(), self.content)
        self.assertIn(second['deviceId'].encode(), self.content)
        self.assertTrue(self.content.startswith(self.before))
        self.assertEqual(self.m.read_db()['devices'][0]['status'], 'revoked')

    def test_account_purge_revokes_devices_and_clears_only_its_central_trust(self):
        module = self.m.policy_module()
        module.KEYS = self.auth / 'central'
        module.KEYS.mkdir()
        (module.KEYS / 'eddy').write_text('old device trust')
        (module.KEYS / 'other').write_text('other account trust')
        with self.patches(), patch.object(self.m, 'policy_module', return_value=module):
            result = self.m.enroll(self.args)
            with patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: self.user)}):
                self.m.purge_account('eddy')
        self.assertEqual((module.KEYS / 'eddy').read_bytes(), b'')
        self.assertEqual((module.KEYS / 'other').read_text(), 'other account trust')
        self.assertEqual(self.m.read_db()['devices'][0]['status'], 'revoked')
        self.assertNotIn(result['deviceId'].encode(), self.content)

    def test_invalid_validity_and_private_key_are_rejected(self):
        for days in (0, -1, 91):
            self.args.days = days
            with self.patches(), self.assertRaises(ValueError):
                self.m.enroll(self.args)
        for value in ('-----BEGIN OPENSSH PRIVATE KEY-----', 'ssh-ed25519 invalid',
                      (self.base / 'device.pub').read_text() + 'another key\n'):
            with self.assertRaises(ValueError):
                self.m.public_key(value)
        self.assertEqual(self.content, self.before)

    def test_ssh_policy_rejects_password_required_after_publickey(self):
        settings = 'pubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\nauthenticationmethods publickey,password\nallowtcpforwarding yes\n'
        self.m.STATE = self.auth
        with patch.object(self.m, 'run', return_value=SimpleNamespace(stdout=settings)):
            with self.assertRaisesRegex(ValueError, 'another authentication'):
                self.m.backend_policy(self.user)

    def test_ssh_policy_preserves_password_and_requires_certificate_algorithm(self):
        settings = ('passwordauthentication yes\npubkeyauthentication yes\n'
                    'authorizedkeysfile .ssh/authorized_keys\nauthenticationmethods any\n'
                    'allowtcpforwarding yes\npubkeyacceptedalgorithms ssh-ed25519-cert-v01@openssh.com\n')
        self.m.STATE = self.auth
        with patch.object(self.m, 'run', return_value=SimpleNamespace(stdout=settings)):
            self.m.backend_policy(self.user, 'ssh-ed25519')
            with self.assertRaisesRegex(ValueError, 'certificate algorithm'):
                self.m.backend_policy(self.user, 'ecdsa-sha2-nistp256')

    def test_incomplete_ca_is_never_silently_rotated(self):
        original = (self.auth / 'ca').read_bytes()
        (self.auth / 'ca.pub').unlink()
        with self.assertRaisesRegex(ValueError, 'Incomplete CA'):
            self.m.authority()
        self.assertEqual((self.auth / 'ca').read_bytes(), original)

    def test_missing_ca_with_existing_devices_requires_restore(self):
        (self.auth / 'ca').unlink()
        (self.auth / 'ca.pub').unlink()
        self.m.save_db({'version': 1, 'devices': [{'id': 'existing'}]})
        with self.assertRaisesRegex(ValueError, 'missing CA'):
            self.m.authority()
        self.assertFalse((self.auth / 'ca').exists())

    def test_signing_failure_does_not_authorize_device(self):
        with self.patches(), patch.object(self.m, 'run', side_effect=subprocess.CalledProcessError(1, 'ssh-keygen')):
            with self.assertRaises(subprocess.CalledProcessError):
                self.m.enroll(self.args)
        self.assertEqual(self.content, self.before)
        self.assertFalse((self.auth / 'devices.json').exists())

    def test_dropbear_routing_is_not_reported_as_certificate_ready(self):
        result = SimpleNamespace(returncode=0, stdout='LoadState=loaded\nExecStart=-ssh-target 127.0.0.1:143\n')
        with patch.object(self.m.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(ValueError, 'OpenSSH backend'):
                self.m.transport_policy()

    def test_native_account_expiry_and_root_rejection(self):
        self.m.STATE = self.auth
        (self.auth / 'ssh-users.json').write_text(json.dumps([{'name': '12345', 'expiresAt': '2000-01-01'}]))
        pwd = SimpleNamespace(getpwnam=lambda _: self.user)
        with patch.dict(sys.modules, {'pwd': pwd}):
            with self.assertRaisesRegex(ValueError, 'expired'):
                self.m.account('12345')
            self.user.pw_uid = 0
            with self.assertRaisesRegex(ValueError, 'system accounts'):
                self.m.account('12345')

    @unittest.skipUnless(sys.platform == 'linux', 'Linux no-follow descriptor semantics')
    def test_symlinked_authorized_keys_is_rejected_without_writing_target(self):
        home = Path(self.user.pw_dir)
        (home / '.ssh').mkdir(parents=True, mode=0o700)
        home.chmod(0o700)
        self.user.pw_uid, self.user.pw_gid = os.getuid(), os.getgid()
        target = self.auth / 'unrelated'
        target.write_text('unchanged')
        (home / '.ssh/authorized_keys').symlink_to(target)
        with self.assertRaises(OSError):
            with self.m.authorized_file(self.user):
                self.fail('Symlink should be rejected')
        self.assertEqual(target.read_text(), 'unchanged')
