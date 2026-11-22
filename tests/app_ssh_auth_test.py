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
        stack.enter_context(patch.object(self.m, 'configure_udp_password', return_value=dict(
            authMethod='password', username='eddy', password='synthetic-udp-secret', portRange='50001-65535')))
        stack.enter_context(patch.object(self.m, 'disable_udp_password'))
        stack.enter_context(patch.object(self.m, 'authority', return_value=self.public))
        stack.enter_context(patch.object(self.m, 'authorized_file', self.authorized))
        return stack

    def bundle_args(self):
        return argparse.Namespace(username='eddy', days=365, host_key=self.base / 'device.pub')

    def test_generated_bundle_has_matching_private_key_and_restricted_signed_certificate(self):
        with self.patches(), patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: self.user)}), patch.object(self.m, 'policy_module') as policy, patch.object(
                self.m, 'pin_policy', return_value={'genPolicy': {'SSHAuthMethod': 'device_certificate'}}):
            path = self.m.create_bundle(self.bundle_args())
            data = json.loads(path.read_text())
            policy.return_value.set_mode.assert_called_once()
            self.assertTrue(data['privateKeyIncluded'])
            self.assertEqual(data['type'], 'eng-ssh-account-bundle')
            self.assertEqual(data['genPolicy']['SSHAuthMethod'], 'account_certificate')
            self.assertNotIn('PRIVATE KEY', json.dumps(self.m.read_db()))
            self.assertNotIn('synthetic-udp-secret', json.dumps(self.m.read_db()))
            self.assertEqual(data['udpCustom']['password'], 'synthetic-udp-secret')
            private = self.auth / 'check-key'
            private.write_bytes(data['privateKey'].encode())
            if os.name != 'nt':
                private.chmod(0o600)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            from cryptography.hazmat.primitives import serialization
            key = serialization.load_ssh_private_key(data['privateKey'].encode(), password=None)
            public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                   serialization.PublicFormat.OpenSSH).decode()
            self.assertEqual(self.m.public_key(public), data['publicKey'])
            cert = self.auth / 'check-cert.pub'
            cert.write_text(data['certificate'])
            detail = subprocess.run([KEYGEN, '-L', '-f', str(cert)], check=True,
                                   capture_output=True, text=True).stdout
            self.assertIn('force-command /bin/false', detail)
            self.assertIn('permit-port-forwarding', detail)
            self.assertNotIn('permit-pty', detail)
            self.assertLessEqual(datetime.fromisoformat(data['validBefore']), self.expiry)
            self.assertNotEqual(data['privateKey'], (self.auth / 'ca').read_text())
            self.m.revoke(argparse.Namespace(username='eddy', device='certificate-account'))
            self.assertFalse(path.exists())
            self.m.disable_udp_password.assert_called_once_with('eddy')
            with self.assertRaises((ValueError, FileNotFoundError)):
                self.m.read_bundle('eddy')

    def test_bundle_renewal_preserves_identity_key_and_rejects_revocation(self):
        with self.patches(), patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: self.user)}), patch.object(self.m, 'policy_module'), patch.object(
                self.m, 'pin_policy', return_value={'genPolicy': {}}):
            args = self.bundle_args()
            args.days = 1
            path = self.m.create_bundle(args)
            old = json.loads(path.read_text())
            args.days = 2
            self.m.renew_bundle(args)
            new = json.loads(path.read_text())
            self.assertEqual(new['privateKey'], old['privateKey'])
            self.assertEqual(new['deviceId'], old['deviceId'])
            self.assertGreater(new['validBefore'], old['validBefore'])
            self.assertEqual(len(self.m.read_db()['devices']), 1)
            self.m.revoke(argparse.Namespace(username='eddy', device='certificate-account'))
            with self.assertRaises((ValueError, FileNotFoundError)):
                self.m.renew_bundle(args)

    def test_bundle_policy_failure_leaves_no_usable_credential(self):
        with self.patches(), patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: self.user)}), patch.object(self.m, 'policy_module') as policy, patch.object(
                self.m, 'pin_policy', return_value={'genPolicy': {}}):
            policy.return_value.set_mode.side_effect = ValueError('sshd validation failed')
            with self.assertRaisesRegex(ValueError, 'sshd validation'):
                self.m.create_bundle(self.bundle_args())
            self.assertFalse(self.m.bundle_path('eddy').exists())
            self.assertEqual(self.m.read_db()['devices'][0]['status'], 'revoked')
            self.assertEqual(self.content, self.before)

    def test_bundle_renewal_write_failure_restores_trust_and_old_export(self):
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(
                self.m, 'pin_policy', return_value={'genPolicy': {}}):
            args = self.bundle_args()
            args.days = 1
            path = self.m.create_bundle(args)
            previous_file, previous_db, previous_keys = path.read_bytes(), self.m.read_db(), self.content
            atomic = self.m.atomic
            def fail_bundle(target, data):
                if Path(target) == path:
                    raise OSError('disk full')
                return atomic(target, data)
            args.days = 2
            with patch.object(self.m, 'atomic', side_effect=fail_bundle), self.assertRaises(OSError):
                self.m.renew_bundle(args)
            self.assertEqual(path.read_bytes(), previous_file)
            self.assertEqual(self.m.read_db(), previous_db)
            self.assertEqual(self.content, previous_keys)

    def test_certificate_account_list_filters_phone_keys_and_marks_expiry(self):
        import io
        from contextlib import redirect_stdout
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        future = self.expiry.isoformat()
        self.m.save_db({'version': 1, 'devices': [
            dict(username='old-phone', device='phone1', status='active', validBefore=future),
            dict(username='active', device='certificate-account', status='active', validBefore=future),
            dict(username='expired', device='certificate-account', status='active', validBefore=past),
            dict(username='revoked', device='certificate-account', status='revoked', validBefore=future)]})
        output = io.StringIO()
        with redirect_stdout(output):
            self.m.list_certificate_accounts()
        self.assertNotIn('old-phone', output.getvalue())
        self.assertIn('active\tactive', output.getvalue())
        self.assertIn('expired\texpired', output.getvalue())
        self.assertIn('revoked\trevoked', output.getvalue())

    def test_pasted_bundle_validation_requires_private_key_and_rejects_oversize(self):
        import io
        data = dict(schema=1, type='eng-ssh-account-bundle', authMethod='openssh-user-certificate',
                    privateKeyIncluded=True, privateKey='test-fixture',
                    publicKey=self.m.public_key((self.base / 'device-ecdsa.pub').read_text()))
        self.assertEqual(self.m.read_pasted_bundle(io.StringIO(json.dumps(data) + '\nEND\n')), data)
        for changed in (dict(data, privateKeyIncluded=False), dict(data, type='wrong')):
            with self.assertRaises(ValueError):
                self.m.read_pasted_bundle(io.StringIO(json.dumps(changed)))
        with self.assertRaises(ValueError):
            self.m.read_pasted_bundle(io.StringIO('x' * 65537))

    @unittest.skipIf(os.name == 'nt', 'native Windows OpenSSH rejects imported fixture file ACLs')
    def test_pasted_bundle_reuses_key_but_gets_local_identity_and_ca(self):
        args = self.bundle_args()
        args.bundle_data = dict(privateKey=(self.base / 'device-ecdsa').read_text(),
                                publicKey=(self.base / 'device-ecdsa.pub').read_text())
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(
                self.m, 'pin_policy', return_value={'genPolicy': {}}):
            path = self.m.create_bundle(args)
            data = json.loads(path.read_text())
            self.assertEqual(data['publicKey'], self.m.public_key(args.bundle_data['publicKey']))
            self.assertEqual(data['caPublicKey'], self.public)
            self.assertEqual(data['username'], 'eddy')
            self.assertEqual(data['udpCustom']['username'], 'eddy')

    def test_pasted_mismatched_key_never_authorizes_a_certificate(self):
        args = self.bundle_args()
        args.bundle_data = dict(privateKey='fixture', publicKey=(self.base / 'device-ecdsa.pub').read_text())
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(
                self.m, 'pin_policy', return_value={'genPolicy': {}}), patch.object(
                self.m, 'run', return_value=SimpleNamespace(stdout=(self.base / 'device.pub').read_text())):
            with self.assertRaisesRegex(ValueError, 'do not match'):
                self.m.create_bundle(args)
            self.assertEqual(self.m.read_db()['devices'], [])
            self.assertFalse(self.m.bundle_path('eddy').exists())

    def test_udp_secret_is_hashed_without_plaintext_process_arguments(self):
        with patch.object(self.m.subprocess, 'run', return_value=SimpleNamespace(stdout='$6$salt$hash')) as execute, patch.object(self.m, 'run') as run:
            value = self.m.configure_udp_password('eddy')
            self.assertGreaterEqual(len(value['password']), 40)
            self.assertEqual(execute.call_args.kwargs['input'], value['password'] + '\n')
            self.assertNotIn(value['password'], str(execute.call_args.args))
            run.assert_called_once_with('usermod', '-p', '$6$salt$hash', 'eddy')

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

    def shared_fixture(self):
        return dict(schema=1, type='eng-shared-ssh-authorization', username='eddy',
                    deviceId='a' * 32, publicKey=self.m.public_key((self.base / 'device-ecdsa.pub').read_text()),
                    caPublicKey=self.public, validBefore=(self.expiry - timedelta(hours=1)).isoformat())

    def test_shared_export_contains_no_private_or_udp_credentials(self):
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(self.m, 'pin_policy', return_value={'genPolicy': {}}):
            original = json.loads(self.m.create_bundle(self.bundle_args()).read_text())
            shared = self.m.shared_export('eddy')
            self.assertEqual(shared['deviceId'], original['deviceId'])
            self.assertEqual(shared['caPublicKey'], original['caPublicKey'])
            self.assertEqual(shared['validBefore'], original['validBefore'])
            self.assertNotIn('privateKey', shared)
            self.assertNotIn('udpCustom', shared)
            self.assertNotIn('PRIVATE KEY', json.dumps(shared))

    def test_shared_import_preserves_foreign_ca_and_identity_and_is_idempotent(self):
        data = self.shared_fixture()
        (self.auth / 'ca.pub').unlink()
        (self.auth / 'ca').unlink()
        with self.patches(), patch.object(self.m, 'policy_module') as policy:
            self.m.shared_import(data, new_account=True)
            self.m.shared_import(data)
            record = self.m.read_db()['devices'][0]
            self.assertEqual(len(self.m.read_db()['devices']), 1)
            self.assertEqual(record['principal'], 'eng-app-' + data['deviceId'])
            self.assertEqual(record['caPublicKey'], data['caPublicKey'])
            self.assertEqual(record['validBefore'], data['validBefore'])
            self.assertIn(b'expiry-time=', self.content)
            self.assertIn(data['caPublicKey'].encode(), self.content)
            self.assertIn(b'unrelated-key old-client', self.content)
            self.assertFalse(self.m.bundle_path('eddy').exists())
            self.m.configure_udp_password.assert_not_called()
            self.m.authority.assert_not_called()
            self.assertEqual(policy.return_value.set_mode.call_count, 2)

    def test_shared_import_refuses_password_account_conflicts_revocation_and_expiry(self):
        data = self.shared_fixture()
        with self.patches(), patch.object(self.m, 'policy_module'):
            with self.assertRaisesRegex(ValueError, 'password account'):
                self.m.shared_import(data)
            self.m.shared_import(data, new_account=True)
            changed = dict(data, deviceId='b' * 32)
            self.m.shared_import(changed)
            self.assertEqual(len(self.m.read_db()['devices']), 2)
            db = self.m.read_db();db['devices'][0]['status'] = 'revoked';self.m.save_db(db)
            with self.assertRaisesRegex(ValueError, 'revoked'):
                self.m.shared_import(data)
            with self.assertRaisesRegex(ValueError, 'expired'):
                self.m.validate_shared(dict(data, validBefore='2000-01-01T00:00:00+00:00'))
            with self.assertRaises(ValueError):
                self.m.validate_shared(dict(data, privateKey='secret'))

    def test_shared_import_policy_failure_restores_trust_and_database(self):
        with self.patches(), patch.object(self.m, 'policy_module') as policy:
            policy.return_value.set_mode.side_effect = ValueError('syntax failure')
            with self.assertRaisesRegex(ValueError, 'syntax failure'):
                self.m.shared_import(self.shared_fixture(), new_account=True)
            self.assertEqual(self.content, self.before)
            self.assertEqual(self.m.read_db()['devices'], [])

    def test_shared_import_is_bounded_by_local_account_expiry(self):
        with self.patches():
            with patch.object(self.m, 'policy_module'):
                self.m.shared_import(dict(self.shared_fixture(), validBefore=(self.expiry + timedelta(days=1)).isoformat()), new_account=True)
            self.assertEqual(self.m.read_db()['devices'][0]['validBefore'], self.expiry.isoformat())

    def test_destination_bundle_export_changes_only_pin_and_not_saved_credential(self):
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(self.m, 'pin_policy', return_value={'genPolicy': {'SSHHostKeyPin': 'original'}}):
            path = self.m.create_bundle(self.bundle_args())
            original = path.read_bytes()
            pin = 'SHA256:' + 'A' * 43
            exported = self.m.export_bundle('eddy', pin)
            self.assertEqual(exported['genPolicy']['SSHHostKeyPin'], pin)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(exported['certificate'], json.loads(original)['certificate'])
            self.assertEqual(exported['privateKey'], json.loads(original)['privateKey'])
            with self.assertRaisesRegex(ValueError, 'fingerprint'):
                self.m.export_bundle('eddy', 'invalid')

    def test_three_ca_identities_coexist_renew_and_revoke_independently(self):
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(self.m, 'pin_policy', return_value={'genPolicy': {}}), patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: self.user)}):
            self.m.policy_module().KEYS = self.auth / 'central'
            args = self.bundle_args()
            path = self.m.create_bundle(args)
            original = path.read_bytes()
            local = json.loads(original)
            foreign_b = dict(self.shared_fixture(), caPublicKey=self.m.public_key((self.base / 'device.pub').read_text()))
            ca_c = self.auth / 'foreign-c'
            subprocess.run([KEYGEN, '-q', '-t', 'ed25519', '-N', '', '-f', str(ca_c)], check=True, capture_output=True)
            foreign_c = dict(self.shared_fixture(), deviceId='c' * 32, caPublicKey=self.m.public_key(ca_c.with_suffix('.pub').read_text()))
            self.m.shared_import(foreign_b)
            self.m.shared_import(foreign_c)
            self.m.shared_import(foreign_b)
            self.assertEqual(len(self.m.read_db()['devices']), 3)
            self.assertEqual(path.read_bytes(), original)
            for data in (local, foreign_b, foreign_c):
                self.assertIn(data['caPublicKey'].encode(), self.content)
                self.assertIn(('eng-app-' + data['deviceId']).encode(), self.content)
            self.assertEqual(self.m.shared_export('eddy')['deviceId'], local['deviceId'])
            self.assertEqual(self.m.shared_export('eddy', foreign_b['deviceId'])['caPublicKey'], foreign_b['caPublicKey'])
            self.m.shared_import(self.m.shared_export('eddy'))
            self.assertEqual(len(self.m.read_db()['devices']), 3)
            self.m.renew_bundle(args)
            self.assertEqual(len(self.m.read_db()['devices']), 3)
            renewed = path.read_bytes()
            self.m.revoke(SimpleNamespace(username='eddy', device='certificate-account', identity=foreign_b['deviceId']))
            self.assertEqual(path.read_bytes(), renewed)
            self.m.disable_udp_password.assert_not_called()
            self.assertNotIn(foreign_b['caPublicKey'].encode(), self.content)
            self.assertIn(foreign_c['caPublicKey'].encode(), self.content)
            self.assertIn(local['caPublicKey'].encode(), self.content)
            with self.assertRaisesRegex(ValueError, 'revoked'):
                self.m.shared_import(foreign_b)
            self.m.revoke(SimpleNamespace(username='eddy', device='certificate-account'))
            self.assertFalse(path.exists())
            self.assertIn(foreign_c['caPublicKey'].encode(), self.content)
            self.m.disable_udp_password.assert_called_once_with('eddy')
            self.m.purge_account('eddy')
            self.assertFalse(any(d['status'] == 'active' for d in self.m.read_db()['devices']))

    def test_shared_import_rejects_identity_key_replacement_without_losing_others(self):
        with self.patches(), patch.object(self.m, 'policy_module'):
            data = self.shared_fixture()
            self.m.shared_import(data, new_account=True)
            before = self.content
            with self.assertRaisesRegex(ValueError, 'key or CA changed'):
                self.m.shared_import(dict(data, caPublicKey=self.m.public_key((self.base / 'device.pub').read_text())))
            self.assertEqual(self.content, before)

    def test_shared_import_failure_preserves_existing_local_bundle_and_foreign_trust(self):
        with self.patches(), patch.object(self.m, 'policy_module') as policy, patch.object(self.m, 'pin_policy', return_value={'genPolicy': {}}):
            path = self.m.create_bundle(self.bundle_args())
            self.m.shared_import(self.shared_fixture())
            before, bundle, db = self.content, path.read_bytes(), self.m.read_db()
            policy.return_value.set_mode.side_effect = ValueError('policy failed')
            with self.assertRaisesRegex(ValueError, 'policy failed'):
                self.m.shared_import(dict(self.shared_fixture(), deviceId='c' * 32))
            self.assertEqual(self.content, before)
            self.assertEqual(path.read_bytes(), bundle)
            self.assertEqual(self.m.read_db(), db)

    def test_pasted_shared_json_matches_file_import_and_stops_at_complete_object(self):
        from io import StringIO
        data = self.shared_fixture()
        source = StringIO(json.dumps(data, indent=2) + '\n00\n')
        pasted = self.m.read_shared_authorization(stream=source)
        self.assertEqual(pasted, self.m.validate_shared(data))
        self.assertEqual(source.read(), '00\n')
        path = self.auth / 'public.json'
        path.write_text(json.dumps(data))
        self.assertEqual(self.m.read_shared_authorization(file=path), pasted)

    def test_invalid_or_private_pasted_json_is_rejected_before_import(self):
        from io import StringIO
        for text in ('not json\nEND\n', '{}\nEND\n',
                     json.dumps(dict(self.shared_fixture(), privateKey='secret')) + '\nEND\n',
                     ' ' * 16385 + '\nEND\n'):
            with self.subTest(text=text[:30]):
                with self.assertRaises(ValueError):
                    self.m.read_shared_authorization(stream=StringIO(text))
        self.assertFalse((self.auth / 'devices.json').exists())
        self.assertEqual(self.content, self.before)

    def test_certificate_choices_filter_modes_and_keep_same_username_identities(self):
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(self.m, 'pin_policy', return_value={'genPolicy': {}}):
            self.m.STATE = self.auth
            (self.auth / 'ssh-users.json').write_text('[{"name":"eddy","expiresAt":"2030-01-01"}]')
            self.m.create_bundle(self.bundle_args())
            local = self.m.shared_export('eddy')
            self.m.shared_import(self.shared_fixture())
            for mode in ('renew', 'gen', 'revoke'):
                choices = self.m.certificate_choices(mode)
                self.assertEqual(len(choices), 1)
                self.assertEqual(choices[0]['identity'], local['deviceId'])
                self.assertTrue(choices[0]['local'])
            self.assertEqual(len(self.m.certificate_choices('details')), 2)
            self.assertEqual(len(self.m.certificate_choices('share')), 2)
            shared = self.m.certificate_choices('shared-revoke')
            self.assertEqual(len(shared), 1)
            self.assertEqual(shared[0]['identity'], 'a'*32)
            self.assertFalse(shared[0]['local'])
            self.assertNotIn('privateKey', json.dumps(shared))
            self.assertNotIn('udpCustom', json.dumps(shared))
            self.assertEqual(self.m.certificate_info('eddy', 'a'*32)['deviceId'], 'a'*32)
            db = self.m.read_db();db['devices'][1]['status'] = 'revoked';self.m.save_db(db)
            self.assertEqual(self.m.certificate_choices('shared-revoke'), [])
            with self.assertRaisesRegex(ValueError, 'not found'):
                self.m.certificate_info('eddy', 'a'*32)

    def test_compact_and_formatted_paste_finish_without_end_or_eof(self):
        from io import StringIO
        data = self.shared_fixture()
        data['publicKey'] += ' comment with } and { braces'
        for indent in (None, 2):
            source = StringIO(json.dumps(data, indent=indent) + '\nNEXT MENU INPUT\n')
            self.assertEqual(self.m.read_shared_authorization(stream=source), self.m.validate_shared(data))
            self.assertEqual(source.read(), 'NEXT MENU INPUT\n')

    def proxy_fixture(self):
        return dict(schema=1, type='eng-ssh-proxy-details', ipv4='8.8.8.8',
                    hostPublicKey=self.public, sshHostKeyPin=self.m.fingerprint(self.public))

    def test_proxy_export_needs_no_certificate_account_or_ca_private_key(self):
        real_run = self.m.run
        def run(*args):
            if args[0] == '/usr/sbin/sshd':
                return SimpleNamespace(stdout='hostkey ' + str(self.auth / 'ca') + '\n')
            if args[0] == 'curl':
                return SimpleNamespace(stdout='8.8.8.8\n')
            return real_run(*args)
        with patch.object(self.m, 'run', side_effect=run), patch.object(self.m, 'authority') as authority, patch.object(self.m, 'account') as account:
            self.m.STATE = self.auth
            (self.auth / 'sshd-backend.conf').write_text('# fixture SSH config\n')
            data = self.m.export_proxy('8.8.8.8', self.auth / 'ca.pub')
            self.assertEqual(data, self.proxy_fixture())
            self.assertEqual(self.m.export_proxy('', self.auth / 'ca.pub'), data)
            with self.assertRaisesRegex(ValueError, 'not a configured host key'):
                self.m.export_proxy('8.8.8.8', self.base / 'device.pub')
            authority.assert_not_called();account.assert_not_called()
            self.assertFalse((self.auth / 'devices.json').exists())
            self.assertNotIn('privateKey', data)
            self.assertNotIn('PRIVATE KEY', json.dumps(data))

    def test_saved_proxy_exports_change_only_pin_and_leave_direct_bundle_unchanged(self):
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(self.m, 'pin_policy', return_value={'genPolicy': {'SSHHostKeyPin': 'original-direct-pin'}}):
            path = self.m.create_bundle(self.bundle_args())
            before = path.read_bytes()
            proxy = self.proxy_fixture()
            self.m.save_proxy(proxy)
            exported = self.m.export_bundle('eddy', use_proxy=True)
            self.assertEqual(exported['genPolicy']['SSHHostKeyPin'], proxy['sshHostKeyPin'])
            self.assertEqual(self.m.export_bundle('eddy')['genPolicy']['SSHHostKeyPin'], 'original-direct-pin')
            self.assertEqual(path.read_bytes(), before)
            for field in ('certificate','privateKey','deviceId','username','caPublicKey','udpCustom'):
                self.assertEqual(exported[field], json.loads(before)[field])
            self.assertEqual(self.m.saved_proxy(), proxy)
            with self.assertRaisesRegex(ValueError, 'not both'):
                self.m.export_bundle('eddy', 'SHA256:' + 'A'*43, use_proxy=True)
            self.m.proxy_path().unlink()
            self.assertIsNone(self.m.saved_proxy())
            with self.assertRaisesRegex(ValueError, 'No saved proxy'):
                self.m.export_bundle('eddy', use_proxy=True)

    def test_proxy_paste_is_validated_and_cannot_overwrite_with_account_bundle(self):
        from io import StringIO
        proxy = self.proxy_fixture()
        self.m.save_proxy(proxy)
        before = self.m.proxy_path().read_bytes()
        stream = StringIO(json.dumps(proxy, indent=2) + '\nnext input\n')
        self.assertEqual(self.m.validate_proxy(self.m.read_public_json(stream)), proxy)
        self.assertEqual(stream.read(), 'next input\n')
        for invalid in (dict(proxy, sshHostKeyPin='SHA256:'+'A'*43), dict(proxy, ipv4='127.0.0.1'),
                        dict(proxy, ipv4='invalid'), dict(proxy, ipv4='224.0.0.1'), dict(proxy, privateKey='secret'),
                        dict(proxy, type='eng-ssh-account-bundle')):
            with self.assertRaises(ValueError): self.m.save_proxy(invalid)
            self.assertEqual(self.m.proxy_path().read_bytes(), before)

    def test_deleted_revoked_username_can_receive_fresh_bundle_without_reactivating_old_identity(self):
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(self.m, 'pin_policy', return_value={'genPolicy': {}}), patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwnam=lambda _: self.user)}):
            args = self.bundle_args()
            original = json.loads(self.m.create_bundle(args).read_text())
            old_public_authorization = self.m.shared_export('eddy')
            self.m.revoke(SimpleNamespace(username='eddy', device='certificate-account'))
            replacement = json.loads(self.m.create_bundle(args).read_text())
            self.assertNotEqual(replacement['deviceId'], original['deviceId'])
            self.assertNotEqual(replacement['privateKey'], original['privateKey'])
            self.assertNotEqual(replacement['publicKey'], original['publicKey'])
            records = self.m.read_db()['devices']
            self.assertEqual([r['status'] for r in records], ['revoked','active'])
            self.assertNotIn(('eng-app-' + original['deviceId']).encode(), self.content)
            self.assertIn(('eng-app-' + replacement['deviceId']).encode(), self.content)
            with self.assertRaisesRegex(ValueError, 'revoked'):
                self.m.shared_import(old_public_authorization)
            with self.assertRaisesRegex(ValueError, 'already has credentials'):
                self.m.create_bundle(args)
            # Default revocation must target the replacement, not the old tombstone.
            self.m.revoke(SimpleNamespace(username='eddy', device='certificate-account'))
            self.assertFalse(self.m.bundle_path('eddy').exists())
            self.assertTrue(all(r['status'] == 'revoked' for r in self.m.read_db()['devices']))
            third = json.loads(self.m.create_bundle(args).read_text())
            self.assertNotIn(third['deviceId'], [original['deviceId'], replacement['deviceId']])

    def test_combined_export_approves_direct_and_proxy_without_changing_account(self):
        direct = self.m.fingerprint(self.m.public_key((self.base / 'device.pub').read_text()))
        with self.patches(), patch.object(self.m, 'policy_module'), patch.object(self.m, 'pin_policy', return_value={'genPolicy': {'SSHHostKeyPin': direct}}):
            path = self.m.create_bundle(self.bundle_args())
            before = path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'No saved proxy'):
                self.m.export_bundle('eddy', combined=True)
            proxy = self.proxy_fixture();self.m.save_proxy(proxy)
            combined = self.m.export_bundle('eddy', combined=True)
            self.assertEqual(combined['schema'], 2)
            self.assertEqual(combined['genPolicy']['SSHHostKeyPin'], direct)
            self.assertEqual(combined['genPolicy']['SSHHostKeyPins'], [direct, proxy['sshHostKeyPin']])
            self.assertEqual(path.read_bytes(), before)
            for field in ('privateKey','certificate','username','deviceId','caPublicKey'):
                self.assertEqual(combined[field], json.loads(before)[field])
            for options in ({}, {'use_proxy':True}):
                legacy = self.m.export_bundle('eddy', **options)
                self.assertEqual(legacy['schema'], 1)
                self.assertNotIn('SSHHostKeyPins', legacy['genPolicy'])
            with self.assertRaisesRegex(ValueError, 'not more than one'):
                self.m.export_bundle('eddy', use_proxy=True, combined=True)
