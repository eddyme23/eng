"""Real HTTP session checks and restricted bridge mappings; no VPN mutations."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import threading
import time
import tempfile
import ssl
import subprocess
import shutil
import contextlib
import io
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bridge = load('panel-helper')
web = load('panel-server')
installer = load('panel-install')


class BridgeTests(unittest.TestCase):
    def test_rejects_untrusted_commands_and_paths(self):
        for req in ({'protocol': 'ssh;id', 'action': 'list'},
                    {'protocol': 'ssh', 'action': 'restart'},
                    {'protocol': 'ssh', 'action': 'list', 'path': '/etc/shadow'},
                    {'protocol': 'ssh', 'action': 'delete', 'name': '../../root'},
                    {'protocol': 'ssh', 'action': 'create', 'name': '-root'},
                    {'protocol': 'ssh', 'action': 'create', 'name': 'user', 'password': 'x\ny'},
                    {'protocol': 'ssh', 'action': 'renew', 'name': 'user', 'days': True},
                    {'protocol': 'ssh', 'action': 'renew', 'name': 'user', 'days': 10000}):
            with self.subTest(req=req), patch.object(bridge, 'script') as script:
                with self.assertRaises(ValueError):
                    bridge.dispatch(req)
                script.assert_not_called()

    def test_shared_password_accounts(self):
        for protocol in ('ssh', 'udp-custom'):
            with patch.object(bridge, 'script', return_value='ok') as script:
                bridge.dispatch(dict(protocol=protocol, action='create', name='alice', days=45, password='pass;$(id)'))
                script.assert_called_once_with('ssh-accounts.sh', 'create', 'alice', 45, stdin='pass;$(id)\n')

    def test_all_xray_protocols_use_same_manager(self):
        for protocol in bridge.XRAY:
            for action in ('create', 'renew', 'delete', 'list', 'export'):
                with patch.object(bridge, 'script', return_value='ok') as script:
                    bridge.dispatch(dict(protocol=protocol, action=action, name='alice', days=45))
                    script.assert_called_once_with('xray-accounts.sh', 'links' if action == 'export' else action,
                                                   protocol, 'alice', 45)

    def test_certificate_separate_from_password_manager(self):
        for action in ('create', 'renew'):
            with patch.object(bridge, 'script') as script:
                bridge.dispatch(dict(protocol='certificate', action=action, name='alice', days=45))
                script.assert_called_once_with('certificate-accounts.sh', action, 'alice', 45)
        for action, expected in [('export', ('app-ssh-auth.sh', 'bundle-export', 'alice')),
                                 ('share', ('app-ssh-auth.sh', 'shared-export', 'alice')),
                                 ('delete', ('ssh-accounts.sh', 'delete-certificate', 'alice'))]:
            with patch.object(bridge, 'script') as script:
                bridge.dispatch(dict(protocol='certificate', action=action, name='alice'))
                script.assert_called_once_with(*expected)

    def test_native_protocol_mappings(self):
        for protocol in ('hysteria1', 'hysteria2', 'zivpn', 'openvpn', 'wireguard'):
            for action in ('create', 'renew', 'delete', 'list'):
                with patch.object(bridge, 'script', return_value='ok') as script:
                    bridge.dispatch(dict(protocol=protocol, action=action, name='alice', days=30,
                                         password='secret' if protocol == 'openvpn' else ''))
                    script.assert_called_once_with(protocol + '-accounts.sh', action, 'alice', 30,
                                                   stdin='secret\n' if protocol == 'openvpn' else '')

    def test_subprocess_failure_is_not_success(self):
        import subprocess
        with patch.object(bridge.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'failed')):
            with self.assertRaisesRegex(ValueError, 'failed'):
                bridge.run(['/bin/false'])

    def test_export_and_status_allowlist(self):
        for protocol, command in [('hysteria2', 'uri'), ('wireguard', 'config')]:
            with patch.object(bridge, 'script') as script:
                bridge.dispatch(dict(protocol=protocol, action='export', name='alice'))
                script.assert_called_once_with(protocol + '-accounts.sh', command, 'alice')
        with patch.object(bridge, 'run', return_value='active') as run:
            self.assertEqual('active', bridge.dispatch({'action': 'status'}))
            args = run.call_args[0][0]
            self.assertIn('frimps-slowdns', args)
            self.assertNotIn('restart', args)

    def test_units_separate_privileges_and_leave_gateways_alone(self):
        helper, webunit = installer.units()
        self.assertIn('User=frimps-panel', webunit)
        self.assertIn('ProtectSystem=strict', webunit)
        self.assertIn('CapabilityBoundingSet=\n', webunit)
        self.assertNotIn('User=frimps-panel', helper)
        self.assertIn('RuntimeDirectoryMode=0750', helper)
        source = (ROOT / 'panel-install.py').read_text()
        self.assertNotIn("call('systemctl', 'restart', 'nginx'", source)
        self.assertNotIn('iptables', source)
        self.assertIn('LoadCredential=tls.key:', source)

    def test_saved_domain_is_supplied_without_inheriting_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'routes.json').write_text(json.dumps({'primaryDomain':'vpn.example.com'}))
            with patch.object(bridge, 'STATE', state), patch.object(bridge.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'ok', '')) as run:
                bridge.run(['/bin/true'])
                env = run.call_args.kwargs['env']
                self.assertEqual('vpn.example.com', env['V6_DOMAIN'])
                self.assertNotIn('PYTHONPATH', env)
                self.assertNotIn('LD_PRELOAD', env)

    def test_hysteria1_export_uses_real_store_and_runtime_obfs(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / 'routes.json').write_text(json.dumps({'primaryDomain':'vpn.example.com'}))
            (state / 'hysteria1-users.json').write_text(json.dumps([dict(name='alice',password='generated',expiresAt='2027-01-01')]))
            original = Path.read_text
            def read(path, *args, **kwargs):
                if str(path).replace('\\', '/') == '/etc/hysteria1/config.json':
                    return json.dumps({'inbounds':[{'obfs':'saved-obfs'}]})
                return original(path, *args, **kwargs)
            with patch.object(bridge, 'STATE', state), patch.object(Path, 'read_text', read):
                result = json.loads(bridge.dispatch(dict(protocol='hysteria1', action='export', name='alice')))
                self.assertEqual('saved-obfs', result['obfs'])
                self.assertEqual('generated', result['account']['password'])


class InstallTests(unittest.TestCase):
    def test_fresh_install_upgrade_and_reset_preserve_vpn_state(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            base = Path(directory)
            for attr, name in [('ROOT','runtime'),('STATE','state'),('UNITS','units'),('HOOKS','hooks'),('CERTIFICATES','certs')]:
                path = base / name
                path.mkdir()
                stack.enter_context(patch.object(installer, attr, path))
            routes = base / 'routes.json'
            routes.write_text('{"primaryDomain":"vpn.example.com","socksipRanges":["1195-3999"]}')
            before = routes.read_bytes()
            stack.enter_context(patch.object(installer, 'ROUTES', routes))
            stack.enter_context(patch.dict('sys.modules', {
                'pwd':types.SimpleNamespace(getpwnam=lambda _:types.SimpleNamespace(pw_uid=995,pw_shell='/usr/sbin/nologin')),
                'grp':types.SimpleNamespace(getgrnam=lambda _:types.SimpleNamespace(gr_gid=995))}))
            stack.enter_context(patch.object(os, 'geteuid', return_value=0, create=True))
            stack.enter_context(patch.object(os, 'chown', create=True))
            stack.enter_context(patch.object(installer.ssl, 'SSLContext'))
            stack.enter_context(patch.object(installer.socket, 'socket'))
            calls = stack.enter_context(patch.object(installer, 'call'))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch('sys.argv', ['panel-install.py']))
            with patch('builtins.input', return_value='admin'), patch.object(installer.getpass, 'getpass', return_value='a-good-password-123'):
                installer.main()
            config = json.loads((installer.STATE / 'web.json').read_text())
            self.assertEqual('https://vpn.example.com:8445', config['origin'])
            self.assertEqual('0.0.0.0', config['bind'])
            self.assertTrue((installer.ROOT / 'panel.html').is_file())
            self.assertIn('LoadCredential=tls.key:', (installer.UNITS / 'frimps-panel.service').read_text())
            self.assertTrue((installer.HOOKS / 'eng-panel').is_file())
            with patch('builtins.input', side_effect=AssertionError('upgrade must not prompt')), patch.object(installer.getpass, 'getpass', side_effect=AssertionError('upgrade must keep password')):
                installer.main()
            self.assertEqual(config, json.loads((installer.STATE / 'web.json').read_text()))
            self.assertEqual(before, routes.read_bytes())
            for call in calls.call_args_list:
                if 'restart' in call.args:
                    self.assertEqual(('systemctl','restart','frimps-panel-helper.service','frimps-panel.service'), call.args)
            with patch('sys.argv', ['panel-install.py','--reset-password']), patch('builtins.input', return_value='newadmin'), patch.object(installer.getpass, 'getpass', return_value='a-different-password-123'):
                installer.main()
            reset = json.loads((installer.STATE / 'web.json').read_text())
            self.assertEqual('newadmin', reset['username'])
            self.assertNotEqual(config['passwordHash'], reset['passwordHash'])
            self.assertEqual(config['origin'], reset['origin'])


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = dict(origin='https://panel.example:8445', username='admin', salt='ab'*16,
                      passwordHash=web.password_hash('test-password-123', 'ab'*16))
        cls.calls = []
        def fake(req):
            cls.calls.append(req)
            return {'ok': True, 'output': '<script>not HTML</script>'}
        cls.server = web.Panel(('127.0.0.1', 0), config, fake)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.sessions.clear()
        self.server.failures.clear()
        self.calls.clear()

    def request(self, path, data=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        all_headers = {'Host':'panel.example:8445', 'Origin':'https://panel.example:8445', 'Content-Type':'application/json'}
        all_headers.update(headers or {})
        conn.request('GET' if data is None else 'POST', path, None if data is None else json.dumps(data), all_headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def login(self):
        status, headers, body = self.request('/api/login', {'username':'admin', 'password':'test-password-123'})
        self.assertEqual(200, status)
        return {'Cookie': headers['Set-Cookie'].split(';')[0], 'X-CSRF-Token': json.loads(body)['csrf']}

    def test_unauthenticated_operations_blocked(self):
        self.assertEqual(401, self.request('/api/action', {'action':'status'})[0])
        self.assertEqual([], self.calls)

    def test_login_operation_logout(self):
        headers = self.login()
        status, response_headers, body = self.request('/api/action', {'action':'status'}, headers)
        self.assertEqual(200, status)
        self.assertEqual('no-store', response_headers['Cache-Control'])
        self.assertEqual('<script>not HTML</script>', json.loads(body)['output'])
        self.assertEqual([{'action':'status'}], self.calls)
        self.assertEqual(200, self.request('/api/logout', {}, headers)[0])
        self.assertEqual(401, self.request('/api/action', {'action':'status'}, headers)[0])

    def test_csrf_host_and_origin(self):
        headers = self.login()
        for changes in ({'X-CSRF-Token':'bad'}, {'Host':'evil.example'}, {'Origin':'https://evil.example'}):
            self.assertIn(self.request('/api/action', {'action':'status'}, {**headers, **changes})[0], (400,403))
        self.assertEqual([], self.calls)

    def test_session_expiry(self):
        headers = self.login()
        for session in self.server.sessions.values():
            session['expires'] = time.monotonic() - 1
        self.assertEqual(401, self.request('/api/action', {'action':'status'}, headers)[0])

    def test_login_rate_limit_and_cookie_flags(self):
        _, headers, _ = self.request('/api/login', {'username':'admin','password':'test-password-123'})
        for flag in ('Secure', 'HttpOnly', 'SameSite=Strict'):
            self.assertIn(flag, headers['Set-Cookie'])
        self.server.failures.clear()
        for _ in range(5):
            self.assertEqual(401, self.request('/api/login', {'username':'admin', 'password':'wrong'})[0])
        self.assertEqual(429, self.request('/api/login', {'username':'admin', 'password':'wrong'})[0])

    def test_ui_and_script_do_not_render_untrusted_html(self):
        self.assertEqual(200, self.request('/')[0])
        source = (ROOT / 'panel.js').read_text()
        self.assertNotIn('innerHTML', source)
        self.assertIn('textContent=lastOutput', source)
        self.assertEqual(400, self.request('/', headers={'Host':'evil.example'})[0])

    def test_real_https_login(self):
        openssl = shutil.which('openssl')
        if not openssl and Path('C:/Program Files/Git/usr/bin/openssl.exe').exists():
            openssl = 'C:/Program Files/Git/usr/bin/openssl.exe'
        if not openssl:
            self.skipTest('OpenSSL required for ephemeral HTTPS test certificate')
        with tempfile.TemporaryDirectory() as directory:
            cert, key = str(Path(directory) / 'cert.pem'), str(Path(directory) / 'key.pem')
            subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=panel.example', '-keyout', key, '-out', cert],
                           check=True, capture_output=True)
            server = web.Panel(('127.0.0.1', 0), self.server.config, lambda req: {'ok':True,'output':'ok'})
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client_context = ssl.create_default_context(cafile=cert)
                client_context.check_hostname = False  # Connect to loopback, not public DNS.
                conn = http.client.HTTPSConnection('127.0.0.1', server.server_port, context=client_context, timeout=5)
                conn.request('POST', '/api/login', json.dumps({'username':'admin','password':'test-password-123'}),
                             {'Host':'panel.example:8445','Origin':'https://panel.example:8445','Content-Type':'application/json'})
                response = conn.getresponse()
                self.assertEqual(200, response.status)
                self.assertIn('csrf', json.loads(response.read()))
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == '__main__':
    unittest.main()
