"""Central pairing, revocation, isolation, replay and real HTTPS agent checks."""
import base64
import contextlib
import io
import os
from concurrent.futures import ThreadPoolExecutor
import http.client
import importlib.util
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import types
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from panel_central import Central
from panel_agent import Ledger, origin, send, Unauthorized
import panel_totp

spec = importlib.util.spec_from_file_location('central_web', ROOT / 'panel-server.py')
web = importlib.util.module_from_spec(spec)
spec.loader.exec_module(web)
spec = importlib.util.spec_from_file_location('agent_install', ROOT / 'panel-agent-install.py')
agent_install = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent_install)


class CentralTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.central = Central(self.directory.name, poll_timeout=.15, operation_timeout=.3)

    def tearDown(self):
        self.directory.cleanup()

    def pair(self, label='Germany'):
        code = self.central.pairing_code(label)['code']
        return self.central.pair(code)

    def test_pairing_single_use_expiry_and_hashed_storage(self):
        code = self.central.pairing_code('Germany')['code']
        node = self.central.pair(code)
        with self.assertRaises(ValueError):
            self.central.pair(code)
        self.assertEqual(node['nodeId'], self.central.authenticate(node['token']))
        with self.central.db() as db:
            self.assertNotIn(node['token'], repr(db.execute('SELECT * FROM nodes').fetchall()))
            code = self.central.pairing_code('USA')['code']
            db.execute('UPDATE codes SET expires=0')
        with self.assertRaises(ValueError):
            self.central.pair(code)
        with self.assertRaises(ValueError):
            self.central.pairing_code('<script>bad</script>')

    def test_concurrent_code_redemption_only_once(self):
        code = self.central.pairing_code('USA')['code']
        def redeem():
            try:
                return self.central.pair(code)
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: redeem(), range(2)))
        self.assertEqual(1, sum(result is not None for result in results))

    def test_restart_preserves_registration_not_pending_work(self):
        node = self.pair()
        restarted = Central(self.directory.name, poll_timeout=.01)
        self.assertEqual(node['nodeId'], restarted.authenticate(node['token']))
        self.assertFalse(restarted.nodes()[0]['online'])
        with self.assertRaisesRegex(ValueError, 'offline or busy'):
            restarted.submit(node['nodeId'], {'action':'status'})

    def test_revocation_invalidates_credentials_without_deleting_accounts(self):
        node = self.pair()
        self.central.revoke(node['nodeId'])
        with self.assertRaises(ValueError):
            self.central.authenticate(node['token'])
        self.assertEqual([], self.central.nodes())

    def test_offline_never_queues_or_falls_back(self):
        node = self.pair()
        with self.assertRaisesRegex(ValueError, 'No operation was queued'):
            self.central.submit(node['nodeId'], {'protocol':'ssh','action':'create','name':'alice'})
        self.assertIsNone(self.central.channel(node['nodeId']).job)
        self.assertEqual({'job':None}, self.central.poll(node['nodeId']))

    def test_target_isolation_and_delivery_once(self):
        first, second = self.pair('France'), self.pair('USA')
        channel = self.central.channel(second['nodeId'])
        with ThreadPoolExecutor(max_workers=3) as pool:
            polling = pool.submit(self.central.poll, second['nodeId'])
            with channel.condition:
                self.assertTrue(channel.condition.wait_for(lambda:channel.waiting, 1))
            operation = pool.submit(self.central.submit, second['nodeId'], {'action':'status'})
            job = polling.result()['job']
            self.assertIsNone(self.central.channel(first['nodeId']).job)
            self.assertIsNone(self.central.poll(second['nodeId'])['job'])
            self.central.result(second['nodeId'], job['id'], {'ok':True,'output':'USA only'})
            self.assertEqual('USA only', operation.result()['output'])

    def test_delivery_timeout_no_late_execution(self):
        node = self.pair()
        channel = self.central.channel(node['nodeId'])
        # Simulate a poll that disappeared before delivery.
        channel.waiting = True
        with self.assertRaisesRegex(ValueError, 'not delivered'):
            self.central.submit(node['nodeId'], {'action':'status'})
        channel.waiting = False
        self.assertIsNone(self.central.poll(node['nodeId'])['job'])

    def test_delivered_timeout_is_explicitly_ambiguous_and_not_retried(self):
        node = self.pair()
        channel = self.central.channel(node['nodeId'])
        with ThreadPoolExecutor(max_workers=2) as pool:
            polling = pool.submit(self.central.poll, node['nodeId'])
            with channel.condition:
                self.assertTrue(channel.condition.wait_for(lambda:channel.waiting, 1))
            operation = pool.submit(self.central.submit, node['nodeId'], {'action':'status'})
            job = polling.result()['job']
            with self.assertRaisesRegex(ValueError, 'may have executed'):
                operation.result()
        self.assertTrue(self.central.result(node['nodeId'], job['id'], {'ok':True,'output':'late'})['discarded'])
        self.assertIsNone(self.central.poll(node['nodeId'])['job'])

    def test_result_validation_and_totp_counter_scope(self):
        node = self.pair()
        with self.assertRaises(ValueError):
            self.central.result(node['nodeId'], 'bad', {'ok':'true','output':'bad'})
        self.assertTrue(self.central.consume_totp_counter(123))
        self.assertFalse(self.central.consume_totp_counter(123))
        self.assertFalse(self.central.consume_totp_counter(122))
        self.assertTrue(self.central.consume_totp_counter(124))
        self.assertTrue(self.central.consume_totp_counter(123, 'replacement-secret'))


class AgentTests(unittest.TestCase):
    def test_agent_install_update_keeps_pairing_and_only_restarts_management(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.ExitStack() as stack:
            base=Path(directory)
            for attr,name in [('ROOT','runtime'),('STATE','state'),('UNITS','units')]:
                target=base/name;target.mkdir()
                stack.enter_context(patch.object(agent_install,attr,target))
            routes=base/'routes.json';routes.write_text('{"primaryDomain":"de.example.com"}')
            stack.enter_context(patch.object(agent_install,'ROUTES',routes))
            stack.enter_context(patch.dict('sys.modules',{
                'pwd':types.SimpleNamespace(getpwnam=lambda _:types.SimpleNamespace(pw_uid=995,pw_shell='/usr/sbin/nologin')),
                'grp':types.SimpleNamespace(getgrnam=lambda _:types.SimpleNamespace(gr_gid=995))}))
            stack.enter_context(patch.object(os,'geteuid',return_value=0,create=True))
            stack.enter_context(patch.object(os,'chown',create=True))
            commands=stack.enter_context(patch.object(subprocess,'run'))
            import panel_agent
            pairing=stack.enter_context(patch.object(panel_agent,'send',return_value={'nodeId':'a'*32,'token':'b'*43,'label':'Germany'}))
            output=stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(patch('sys.argv',['panel-agent-install.py','--central','https://panel.example.com:8445']))
            with patch.object(agent_install.getpass,'getpass',return_value='c'*32):
                agent_install.main()
            original=(agent_install.STATE/'config.json').read_bytes()
            pairing.assert_called_once_with('https://panel.example.com:8445','/api/agent/pair',{'code':'c'*32})
            self.assertNotIn('b'*43,output.getvalue())
            self.assertTrue((agent_install.UNITS/'frimps-panel-agent.service').is_file())
            self.assertFalse((agent_install.UNITS/'frimps-panel.service').exists())
            with patch.object(agent_install.getpass,'getpass',side_effect=AssertionError('update must not re-pair')):
                agent_install.main()
            self.assertEqual(original,(agent_install.STATE/'config.json').read_bytes())
            self.assertEqual(1,pairing.call_count)
            for call in commands.call_args_list:
                args=call.args[0]
                if 'restart' in args:
                    self.assertEqual(('systemctl','restart','frimps-panel-helper.service','frimps-panel-agent.service'),args)

    def test_ledger_prevents_replay_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'jobs.sqlite'
            job = {'id':'a'*32,'request':{'protocol':'ssh','action':'create','name':'alice','password':'private-password'}}
            bridge = Mock(return_value={'ok':True,'output':'created'})
            self.assertTrue(Ledger(path).execute(job, bridge)['ok'])
            self.assertFalse(Ledger(path).execute(job, bridge)['ok'])
            self.assertEqual(1, bridge.call_count)
            with sqlite_connect(path) as db:
                self.assertNotIn('private-password', repr(db.execute('SELECT * FROM jobs').fetchall()))

    def test_crash_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / 'jobs.sqlite')
            with ledger.db() as db:
                db.execute('INSERT INTO jobs VALUES(?,?,?,0)', ('a'*32,'hash',time.time()))
            bridge = Mock()
            result = ledger.execute({'id':'a'*32,'request':{'action':'status'}}, bridge)
            self.assertFalse(result['ok'])
            bridge.assert_not_called()

    def test_helper_failure_is_not_repeated(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = Ledger(Path(directory) / 'jobs.sqlite')
            bridge = Mock(side_effect=TimeoutError())
            job = {'id':'b'*32,'request':{'action':'status'}}
            self.assertIn('may have executed', ledger.execute(job, bridge)['output'])
            ledger.execute(job, bridge)
            self.assertEqual(1, bridge.call_count)

    def test_origin_and_service_restrictions(self):
        self.assertEqual('https://panel.example:8445', origin('https://panel.example:8445/'))
        for value in ('http://panel.example','https://user:password@panel.example','https://panel.example/path','https://panel.example?token=x'):
            with self.assertRaises(ValueError):
                origin(value)
        unit = agent_install.unit()
        self.assertIn('User=frimps-panel', unit)
        self.assertIn('StateDirectory=frimps-agent', unit)
        self.assertIn('CapabilityBoundingSet=\n', unit)
        self.assertNotIn('ListenStream', unit)

    def test_totp_rfc6238_vectors_and_wrong_input(self):
        secret = base64.b32encode(b'12345678901234567890').decode()
        for timestamp, expected in ((59,'287082'),(1111111109,'081804'),(1111111111,'050471'),(1234567890,'005924'),(2000000000,'279037'),(20000000000,'353130')):
            self.assertEqual(expected, panel_totp.code(secret, timestamp//30))
            self.assertIsNotNone(panel_totp.verify(secret, expected, timestamp))
        for invalid in ('','123','１２３４５６',None,'abcdef'):
            self.assertIsNone(panel_totp.verify(secret, invalid,59))


def sqlite_connect(path):
    import sqlite3
    from contextlib import closing
    return closing(sqlite3.connect(path))


class HTTPSCentralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which('openssl')
        if not openssl and Path('C:/Program Files/Git/usr/bin/openssl.exe').exists():
            openssl = 'C:/Program Files/Git/usr/bin/openssl.exe'
        if not openssl:
            raise unittest.SkipTest('OpenSSL required for local HTTPS integration')
        cls.directory = tempfile.TemporaryDirectory()
        directory = Path(cls.directory.name)
        cert, key = str(directory/'cert.pem'), str(directory/'key.pem')
        subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
                        '-addext','subjectAltName=DNS:localhost','-keyout',key,'-out',cert], check=True,capture_output=True)
        config = dict(central=True,totpSecret=panel_totp.new_secret(),dataDir=str(directory),
                      username='admin',salt='ab'*16,passwordHash=web.password_hash('abc','ab'*16),origin='')
        cls.local = Mock(return_value={'ok':True,'output':'LOCAL ONLY'})
        cls.server = web.Panel(('127.0.0.1',0), config, cls.local)
        cls.url = f'https://localhost:{cls.server.server_port}'
        config['origin'] = cls.url
        cls.server.central.poll_timeout = 5
        cls.server.central.operation_timeout = 8
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert,key)
        cls.server.socket = context.wrap_socket(cls.server.socket,server_side=True,do_handshake_on_connect=False)
        cls.context = ssl.create_default_context(cafile=cert)
        cls.thread = threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join();cls.directory.cleanup()

    def setUp(self):
        self.local.reset_mock()
        self.server.sessions.clear();self.server.failures.clear();self.server.pair_failures.clear()
        with self.server.central.db() as db:
            db.execute('DELETE FROM counters')

    def admin(self, path, data, headers=None):
        conn = http.client.HTTPSConnection('localhost',self.server.server_port,context=self.context,timeout=6)
        conn.request('POST',path,json.dumps(data),{'Content-Type':'application/json','Origin':self.url,**(headers or {})})
        reply = conn.getresponse()
        result = reply.status,dict(reply.getheaders()),json.loads(reply.read())
        conn.close()
        return result

    def login(self):
        otp = panel_totp.code(self.server.config['totpSecret'],int(time.time()//30))
        status, headers, result = self.admin('/api/login',{'username':'admin','password':'abc','otp':otp})
        self.assertEqual(200,status)
        return {'Cookie':headers['Set-Cookie'].split(';')[0],'X-CSRF-Token':result['csrf']}

    def test_real_tls_pairing_remote_delivery_local_isolation_and_revocation(self):
        auth = self.login()
        status, _, pair = self.admin('/api/pairing-code',{'label':'Germany'},auth)
        self.assertEqual(200,status)
        node = send(self.url,'/api/agent/pair',{'code':pair['code']},context=self.context)
        channel = self.server.central.channel(node['nodeId'])
        with tempfile.TemporaryDirectory() as directory, ThreadPoolExecutor(max_workers=2) as pool:
            bridge = Mock(return_value={'ok':True,'output':'GERMANY ONLY'})
            def agent():
                job = send(self.url,'/api/agent/poll',{},node['token'],context=self.context)['job']
                result = Ledger(Path(directory)/'jobs.sqlite').execute(job,bridge)
                send(self.url,'/api/agent/result',{'id':job['id'],'result':result},node['token'],context=self.context)
            working = pool.submit(agent)
            with channel.condition:
                self.assertTrue(channel.condition.wait_for(lambda:channel.waiting,5))
            status, _, result = self.admin('/api/action',{'server':node['nodeId'],'protocol':'ssh','action':'list'},auth)
            working.result()
            self.assertEqual(200,status)
            self.assertEqual('GERMANY ONLY',result['output'])
            bridge.assert_called_once_with({'protocol':'ssh','action':'list'})
            self.local.assert_not_called()
        self.assertEqual(200,self.admin('/api/revoke-server',{'server':node['nodeId']},auth)[0])
        with self.assertRaises(Unauthorized):
            send(self.url,'/api/agent/poll',{},node['token'],context=self.context)

    def test_totp_required_replay_rejected_and_explicit_target_required(self):
        self.assertEqual(401,self.admin('/api/login',{'username':'admin','password':'abc'})[0])
        auth = self.login()
        otp = panel_totp.code(self.server.config['totpSecret'],int(time.time()//30))
        self.assertEqual(401,self.admin('/api/login',{'username':'admin','password':'abc','otp':otp})[0])
        self.assertEqual(400,self.admin('/api/action',{'action':'status'},auth)[0])
        self.local.assert_not_called()
        self.assertEqual(200,self.admin('/api/action',{'server':'local','action':'status'},auth)[0])
        self.local.assert_called_once_with({'action':'status'})

    def test_agent_endpoints_do_not_allow_browser_session_as_agent_auth(self):
        auth = self.login()
        self.assertEqual(401,self.admin('/api/agent/poll',{},auth)[0])
        self.assertEqual(403,self.admin('/api/pairing-code',{'label':'Bad'},{**auth,'Origin':'https://evil.example'})[0])
        self.local.assert_not_called()

    def test_untrusted_tls_certificate_is_not_accepted(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            send(self.url,'/api/agent/pair',{'code':'a'*32})


if __name__ == '__main__':
    unittest.main()
