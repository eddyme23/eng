import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class DnsttSshTest(unittest.TestCase):
    def setUp(self):
        self.manager = load('dnstt-ssh')

    def test_unit_uses_raw_ssh_and_only_requested_dns_listener(self):
        unit = self.manager.render_unit('127.0.0.1:15353', 'ns.example.com', '127.0.0.1:22')
        self.assertIn('-udp 127.0.0.1:15353', unit)
        self.assertIn('ns.example.com 127.0.0.1:22', unit)
        self.assertNotIn('socks', unit.lower())
        self.assertNotIn(':443', unit)
        self.assertNotIn(':853', unit)
        self.assertIn('NoNewPrivileges=true', unit)
        with self.assertRaises(ValueError):
            self.manager.render_unit('127.0.0.1:15353', 'example.org', '127.0.0.1:1080')

    def test_port_conflict_never_stops_another_service(self):
        for socket in ('UNCONN 0 0 0.0.0.0:15353 0.0.0.0:* users:(("other",pid=999,fd=1))',
                       'UNCONN 0 0 127.0.0.1:15353 0.0.0.0:*'):
            result = subprocess.CompletedProcess([], 0, socket, '')
            with patch.object(self.manager, 'run', return_value=result) as run:
                with self.assertRaises(ValueError):
                    self.manager.port_check('127.0.0.1:15353')
                self.assertEqual(len(run.call_args_list), 1)
                self.assertEqual(run.call_args.args[0], 'ss')

    def test_owned_listener_requires_matching_main_pid(self):
        result = subprocess.CompletedProcess([], 0, 'UNCONN 0 0 127.0.0.1:15353 0.0.0.0:* users:(("dnstt",pid=123,fd=1))', '')
        with patch.object(self.manager, 'run', return_value=result):
            self.manager.port_check('127.0.0.1:15353', '123', True)
            with self.assertRaises(ValueError):
                self.manager.port_check('127.0.0.1:15353', '999', True)

    def test_no_listener_is_not_healthy(self):
        with patch.object(self.manager, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):
            with self.assertRaises(ValueError):
                self.manager.port_check('127.0.0.1:15353', '123', True)

    def test_domain_and_endpoint_validation_preserve_other_protocol_ranges(self):
        for name in ('a;id.example', 'a b.example', '../x', 'a..example', '-a.example'):
            with self.assertRaises(ValueError):
                self.manager.domain(name)
        self.assertEqual(self.manager.domain('Ns.Example.com'), 'ns.example.com')
        with self.assertRaises(ValueError):
            self.manager.endpoint('192.0.2.1:20000')
        self.manager.endpoint('192.0.2.1:53')
        self.manager.endpoint('[2001:db8::1]:53')
        with self.assertRaises(ValueError):
            self.manager.endpoint('2001:db8::1:53')

    def test_failed_first_stage_removes_only_test_files(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            lab, unit, backups = fixture / 'lab', fixture / 'test.service', fixture / 'backups'
            build = fixture / 'build'
            build.mkdir()
            production = fixture / 'production'
            production.write_bytes(b'unchanged production engine')
            for name in ('dnstt-server', 'dnstt-client', 'build.json'):
                (build / name).write_text('candidate')
            verified = []
            def run(*args, **kwargs):
                if args[:2] == ('systemd-analyze', 'verify'):
                    checked = Path(args[2])
                    text = checked.read_text()
                    executable = text.split('ExecStart=', 1)[1].split(' ', 1)[0]
                    working = text.split('WorkingDirectory=', 1)[1].splitlines()[0]
                    self.assertTrue(Path(executable).is_file(), 'Verifier must use an existing executable')
                    self.assertTrue(Path(working).is_dir(), 'Verifier must use an existing working directory')
                    verified.append(checked == unit)
                if '-gen-key' in args:
                    Path(args[args.index('-privkey-file') + 1]).write_text('a' * 64)
                    Path(args[args.index('-pubkey-file') + 1]).write_text('b' * 64)
                if args[:3] == ('systemctl', 'start', self.manager.LAB_UNIT):
                    raise subprocess.CalledProcessError(1, args)
                return subprocess.CompletedProcess(args, 0, '', '')
            args = argparse.Namespace(build=build, ssh_backend='openssh', domain='ns.example.org',
                                      listen='127.0.0.1:15353', identity='fresh', enable=False)
            with patch.object(self.manager, 'LAB', lab), patch.object(self.manager, 'UNIT', unit), \
                 patch.object(self.manager, 'BACKUPS', backups), patch.object(self.manager, 'run', side_effect=run), \
                 patch.object(self.manager, 'verified_build', return_value={'implementation': 'upstream-20260501', 'binaries': {'dnstt-server': 'test'}}), \
                 patch.object(self.manager, 'port_check'), patch.object(self.manager, 'validate_keys'), \
                 patch.object(self.manager, 'module', return_value=Mock(probe=Mock(return_value={'stream': 'ok'}))), \
                 patch.object(self.manager.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.manager.stage(args)
            self.assertFalse(unit.exists())
            self.assertFalse((lab / 'server.key').exists())
            self.assertFalse((lab / 'dnstt-server').exists())
            self.assertEqual(production.read_bytes(), b'unchanged production engine')
            self.assertEqual(verified, [False, True])

    def test_activation_refuses_identity_change_before_stopping_production(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            lab, keys = fixture / 'lab', fixture / 'keys'
            lab.mkdir(); keys.mkdir()
            (lab / 'test.json').write_text('{}')
            (lab / 'server.pub').write_text('a' * 64)
            (keys / 'server.pub').write_text('b' * 64)
            with patch.object(self.manager, 'LAB', lab), patch.object(self.manager, 'PROD_KEYS', keys), \
                 patch.object(self.manager, 'verified_build'), patch.object(self.manager, 'validate_keys'), \
                 patch.object(self.manager, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'identity differs'):
                    self.manager.activate(argparse.Namespace())
                run.assert_not_called()

    def test_source_bundle_manifest_is_verified(self):
        build = load('dnstt-build')
        with tempfile.TemporaryDirectory() as directory:
            pin = build.source_into(Path(directory))
            self.assertEqual(pin['revision'], '0c5c52a57d899c05428c116898941761a2ed83c2')
            self.assertTrue((Path(directory) / 'COPYING').is_file())
            self.assertTrue((Path(directory) / 'vendor/modules.txt').is_file())

    def test_tampered_backup_is_rejected_before_service_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            binary, unit, record = fixture / 'binary', fixture / 'unit', fixture / 'record'
            binary.write_bytes(b'old engine')
            with patch.object(self.manager, 'PROD_BINARY', binary), patch.object(self.manager, 'PROD_UNIT', unit), \
                 patch.object(self.manager, 'RECORD', record), patch.object(self.manager, 'BACKUPS', fixture / 'backups'), \
                 patch.object(self.manager.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')) as run:
                saved = self.manager.backup([binary], self.manager.PROD_SERVICE)
                (saved / binary.relative_to(binary.anchor)).write_bytes(b'corrupted')
                before = run.call_count
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    self.manager.rollback(saved)
                self.assertEqual(run.call_count, before)
            self.assertEqual(binary.read_bytes(), b'old engine')

    def test_artifact_checksum_and_architecture_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            pin = json.loads((ROOT / 'dnstt-source/pin.json').read_text())
            metadata = dict(pin, target='linux-amd64', binaries={})
            for name in ('dnstt-server', 'dnstt-client'):
                (fixture / name).write_bytes(b'candidate')
                metadata['binaries'][name] = self.manager.digest(fixture / name)
            (fixture / 'build.json').write_text(json.dumps(metadata))
            with patch.object(self.manager.os, 'uname', return_value=Mock(machine='x86_64'), create=True):
                self.manager.verified_build(fixture)
                (fixture / 'dnstt-server').write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    self.manager.verified_build(fixture)
                metadata['target'] = 'windows-amd64'
                (fixture / 'build.json').write_text(json.dumps(metadata))
                with self.assertRaisesRegex(ValueError, 'architecture'):
                    self.manager.verified_build(fixture)

    def test_failed_activation_restores_binary_unit_and_previous_backend_record(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            lab, keys = fixture / 'lab', fixture / 'keys'
            lab.mkdir(); keys.mkdir()
            config = {'domain': 'ns.example.org'}
            (lab / 'test.json').write_text(json.dumps(config))
            (lab / 'dnstt-server').write_bytes(b'candidate')
            for parent in (lab, keys):
                (parent / 'server.pub').write_text('b' * 64)
            (keys / 'server.key').write_text('private stays private')
            binary, unit, record = fixture / 'engine', fixture / 'production.service', fixture / 'backend.json'
            binary.write_bytes(b'previous engine')
            original = ('[Service]\nExecStart=/etc/slowdns/sldns-server -mtu ${FRIMPS_SLOWDNS_MTU} '
                        '-udp 192.0.2.1:53 -privkey-file /etc/slowdns/server.key ns.example.org 127.0.0.1:22\n')
            unit.write_text(original)
            record.write_text('previous backend')
            probe = Mock(probe=Mock(side_effect=[{'preflight': 'ok'}, ValueError('live wire failure')]))
            def run(*args, **kwargs):
                return subprocess.CompletedProcess(args, 0, original if args[:2] == ('systemctl', 'cat') else '', '')
            with patch.object(self.manager, 'LAB', lab), patch.object(self.manager, 'PROD_KEYS', keys), \
                 patch.object(self.manager, 'PROD_BINARY', binary), patch.object(self.manager, 'PROD_UNIT', unit), \
                 patch.object(self.manager, 'RECORD', record), patch.object(self.manager, 'BACKUPS', fixture / 'backups'), \
                 patch.object(self.manager, 'verified_build'), patch.object(self.manager, 'validate_keys'), \
                 patch.object(self.manager, 'run', side_effect=run), \
                 patch.object(self.manager, 'module', side_effect=lambda name: probe if name == 'dnstt-probe' else Mock(endpoint=Mock(return_value='192.0.2.1:53'))), \
                 patch.object(self.manager.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')):
                with self.assertRaisesRegex(ValueError, 'live wire failure'):
                    self.manager.activate(argparse.Namespace())
            self.assertEqual(binary.read_bytes(), b'previous engine')
            self.assertEqual(unit.read_text(), original)
            self.assertEqual(record.read_text(), 'previous backend')
            self.assertEqual((keys / 'server.key').read_text(), 'private stays private')
