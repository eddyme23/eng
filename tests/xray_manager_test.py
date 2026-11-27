import base64
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('eng_xray', ROOT / 'xray-manager.py')
x = importlib.util.module_from_spec(spec)
spec.loader.exec_module(x)
SETTINGS = dict(domain='direct.example.test', reality=dict(domain='reality.example.test',
                serverName='www.microsoft.com', target='www.microsoft.com:443',
                privateKey='A' * 43, publicKey='B' * 43, shortId='abcd1234'))
USERS = {p: [dict(name='customer', expiresAt='2099-01-01', uuid='11111111-1111-4111-8111-111111111111',
                  password='testing-only')] for p in x.PROTOCOLS}


class XrayManagerTest(unittest.TestCase):
    def test_all_transports_are_loopback_and_expired_users_excluded(self):
        users = copy.deepcopy(USERS)
        for rows in users.values():
            rows.append(dict(rows[0], name='expired', expiresAt='2000-01-01'))
        config = x.configuration(SETTINGS, users)
        self.assertEqual(len(config['inbounds']), 7)
        for inbound in config['inbounds']:
            self.assertEqual(inbound['listen'], '127.0.0.1')
            self.assertEqual([u['email'] for u in inbound['settings']['clients']], ['customer'])
        self.assertEqual(config['inbounds'][-1]['settings']['clients'][0]['flow'], 'xtls-rprx-vision')
        self.assertEqual(len({i['port'] for i in config['inbounds']}), 7)

    def test_links_match_paths_tls_and_credentials(self):
        for protocol, count in [('vless', 7), ('vmess', 4), ('trojan', 1)]:
            links = list(x.links(SETTINGS, protocol, USERS[protocol][0]))
            self.assertEqual(len(links), count)
            for link in links:
                if protocol == 'vmess':
                    data = json.loads(base64.b64decode(link[8:]))
                    self.assertEqual(data['aid'], '0')
                    self.assertEqual(data['net'], 'ws' if data['path'].endswith('-ws') else 'httpupgrade')
                    self.assertEqual(data['tls'], 'tls' if data['port'] == '443' else '')
                else:
                    uri = urlparse(link)
                    q = parse_qs(uri.query)
                    if protocol == 'trojan':
                        self.assertEqual(uri.port, 443)
                        self.assertEqual(q['security'], ['tls'])
                    if q['security'] == ['reality']:
                        self.assertEqual(q['sni'], ['www.microsoft.com'])
                        self.assertEqual(uri.hostname, 'reality.example.test')
                    else:
                        self.assertEqual(q['security'], ['tls'] if uri.port == 443 else ['none'])

    def test_ntls_alias_does_not_change_certificate_hostname(self):
        settings = dict(SETTINGS, tlsDomain='tls.example.test')
        links = list(x.links(settings, 'vless', USERS['vless'][0]))
        self.assertEqual(urlparse(links[0]).hostname, 'direct.example.test')
        self.assertEqual(urlparse(links[1]).hostname, 'tls.example.test')
        self.assertEqual(parse_qs(urlparse(links[1]).query)['sni'], ['tls.example.test'])

    def test_gateway_overlay_preserves_routes_and_is_idempotent(self):
        haproxy = 'frontend public_tcp_443\n    bind :443\n    default_backend main_tls_router\nbackend main_tls_router\n    server tls 127.0.0.1:9443\n'
        first = x.overlay_haproxy(haproxy, SETTINGS)
        self.assertIn('req.ssl_sni -i www.microsoft.com', first)
        self.assertNotIn('req.ssl_sni -i reality.example.test', first)
        self.assertIn('default_backend main_tls_router', first)
        self.assertEqual(x.overlay_haproxy(first, SETTINGS).strip(), first.strip())
        nginx = 'server {\n    server_name direct.example.test;\n    location = /openvpn { }\n}\n' * 2
        first = x.overlay_nginx(nginx)
        self.assertEqual(first.count('location ^~ /vless-xhttp/'), 2)
        self.assertEqual(first.count('location = /openvpn'), 2)
        self.assertEqual(x.overlay_nginx(first), first)
        self.assertIn('proxy_request_buffering off', first)

    def test_unrecognized_configs_are_not_replaced(self):
        with self.assertRaises(ValueError):
            x.overlay_haproxy('unknown', SETTINGS)
        with self.assertRaises(ValueError):
            x.overlay_nginx('unknown')

    def test_backend_metadata_preserves_existing_routes_without_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            x.atomic(state / 'xray-settings.json', SETTINGS)
            existing = dict(transport='plain-http', path='/openvpn', backend='openvpn-websocket:10081')
            x.atomic(state / 'backends.json', {'version': 2, 'publicRoutes': [existing]})
            x.metadata(state)
            first = x.load(state / 'backends.json')
            x.metadata(state)
            self.assertEqual(x.load(state / 'backends.json'), first)
            self.assertEqual(first['publicRoutes'][0], existing)
            self.assertEqual(len(first['publicRoutes']), 12)
            self.assertNotIn('privateKey', (state / 'backends.json').read_text())

    def test_upgrade_and_rerender_keep_existing_ssh_and_openvpn_routes(self):
        import re
        routing = (ROOT / 'render-routing.sh').read_text(encoding='utf-8')
        haproxy = re.search(r'haproxy-443.cfg" <<EOF\n(.*?)\nEOF', routing, re.S)[1]
        haproxy += '\n# Existing dedicated SSH target\n# 127.0.0.1:2222\n'
        nginx = re.search(r'nginx-main-tls.conf" <<EOF\n(.*?)\nEOF', routing, re.S)[1]
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            x.atomic(state / 'xray-settings.json', SETTINGS)
            x.atomic(state / 'haproxy-443.cfg', haproxy)
            x.atomic(state / 'nginx-main-tls.conf', nginx)
            x.decorate(state)
            once = [(state / f).read_text() for f in ['haproxy-443.cfg', 'nginx-main-tls.conf']]
            x.decorate(state)
            twice = [(state / f).read_text() for f in ['haproxy-443.cfg', 'nginx-main-tls.conf']]
            self.assertEqual([v.strip() for v in once], [v.strip() for v in twice])
            for port in [80, 443, 8080, 8880, 2082, 2086]:
                self.assertIn('bind :' + str(port) + '\n', twice[0])
            self.assertIn('# 127.0.0.1:2222', twice[0])
            self.assertIn('server ssh_http_gateway 127.0.0.1:3102', twice[0])
            self.assertEqual(twice[1].count('location = /openvpn'), 2)
            self.assertEqual(twice[1].count('location = / {'), 2)

    def test_failed_account_restart_restores_credentials_and_config(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            x.atomic(state / 'xray-users.json', USERS)
            x.atomic(state / 'xray-settings.json', SETTINGS)
            x.atomic(state / 'xray.json', {'old': True})
            with patch.object(x, 'validate_config'), patch.object(x.subprocess, 'run', side_effect=[
                    subprocess.CalledProcessError(1, 'systemctl'), subprocess.CompletedProcess([], 0)]):
                with self.assertRaises(subprocess.CalledProcessError):
                    x.change(state, 'unused', 'vless', 'renew', 'customer', 90)
            self.assertEqual(x.load(state / 'xray-users.json'), USERS)
            self.assertEqual(x.load(state / 'xray.json'), {'old': True})

    def test_lifecycle_preserves_uuid_and_separates_protocol_accounts(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            x.atomic(state / 'xray-users.json', USERS)
            x.atomic(state / 'xray-settings.json', SETTINGS)
            x.atomic(state / 'xray.json', {})
            with patch.object(x, 'validate_config'), patch.object(x.subprocess, 'run'):
                x.change(state, 'unused', 'vless', 'renew', 'customer', 90)
                self.assertEqual(x.accounts_at(state)['vless'][0]['uuid'], USERS['vless'][0]['uuid'])
                x.change(state, 'unused', 'vless', 'delete', 'customer')
                self.assertEqual(x.accounts_at(state)['vless'], [])
                self.assertEqual(x.accounts_at(state)['vmess'], USERS['vmess'])
                x.change(state, 'unused', 'vless', 'create', 'customer', 90)
                self.assertNotEqual(x.accounts_at(state)['vless'][0]['uuid'], USERS['vless'][0]['uuid'])

    def test_expiry_and_invalid_requests(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            users = copy.deepcopy(USERS)
            users['vmess'][0]['expiresAt'] = '2000-01-01'
            x.atomic(state / 'xray-users.json', users)
            x.atomic(state / 'xray-settings.json', SETTINGS)
            x.atomic(state / 'xray.json', {})
            with patch.object(x, 'validate_config'), patch.object(x.subprocess, 'run'):
                x.change(state, 'unused', 'vless', 'cleanup')
                self.assertEqual(x.accounts_at(state)['vmess'], [])
                self.assertEqual(x.accounts_at(state)['vless'], USERS['vless'])
                for name, days in [('../root', 30), ('valid', 0), ('valid', 10000)]:
                    with self.assertRaises(ValueError):
                        x.change(state, 'unused', 'vless', 'create', name, days)

    @unittest.skipUnless(os.environ.get('XRAY_TEST_BINARY'), 'set XRAY_TEST_BINARY for real core validation')
    def test_real_core_accepts_generated_configuration(self):
        binary = os.environ['XRAY_TEST_BINARY']
        settings = copy.deepcopy(SETTINGS)
        output = subprocess.check_output([binary, 'x25519'], text=True)
        fields = dict(line.split(':', 1) for line in output.splitlines() if ':' in line)
        settings['reality']['privateKey'] = fields['PrivateKey'].strip()
        with tempfile.TemporaryDirectory() as folder:
            x.validate_config(binary, x.configuration(settings, USERS), folder)

    @unittest.skipUnless(os.environ.get('XRAY_TEST_BINARY'), 'set XRAY_TEST_BINARY for real core initialization')
    def test_real_core_initialization_and_reinstall_preserve_identity(self):
        binary = os.environ['XRAY_TEST_BINARY']
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            x.atomic(state / 'routes.json', {'primaryDomain': 'tls.example.test'})
            argv = ['xray-manager.py', 'init', '--binary', binary, '--domain', 'direct.example.test']
            with patch.dict(os.environ, V6_STATE_DIR=folder), patch.object(x.os, 'geteuid', return_value=0, create=True), \
                    patch.object(x, 'locked', return_value=contextlib.nullcontext()), patch('sys.argv', argv):
                x.main()
                first = x.load(state / 'xray-settings.json')
                x.atomic(state / 'xray-users.json', USERS)
            with patch.dict(os.environ, V6_STATE_DIR=folder), patch.object(x.os, 'geteuid', return_value=0, create=True), \
                    patch.object(x, 'locked', return_value=contextlib.nullcontext()), patch('sys.argv', argv):
                x.main()
            self.assertEqual(x.load(state / 'xray-settings.json'), first)
            self.assertEqual(x.load(state / 'xray-users.json'), USERS)
            self.assertEqual(first['domain'], 'direct.example.test')
            self.assertEqual(first['tlsDomain'], 'tls.example.test')
            self.assertEqual(len(x.load(state / 'xray-routes.json')), 6)


if __name__ == '__main__':
    unittest.main()
