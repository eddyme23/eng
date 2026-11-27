"""Real-core loopback tests; no VPS or carrier is contacted.

XRAY_TEST_BINARY, PAYLOADGATE_TEST_BINARY and TLSMUX_TEST_BINARY opt in.
The loopback HTTP destination is explicitly allowed ONLY in the test config.
"""
import contextlib
import base64
import copy
import datetime
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('eng_xray_stream', ROOT / 'xray-manager.py')
x = importlib.util.module_from_spec(spec)
spec.loader.exec_module(x)
BODY = b'ENG verified encrypted account stream\n' * 1024


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def ready(number, process):
    for _ in range(150):
        if process.poll() is not None:
            raise AssertionError('Test process exited before listening: ' + process.test_log.read_text(errors='replace'))
        try:
            with socket.create_connection(('127.0.0.1', number), timeout=.1):
                return
        except OSError:
            time.sleep(.02)
    raise AssertionError(f'Listener {number} did not start')


def read_exact(stream, size):
    data = b''
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError('Unexpected end of test stream')
        data += part
    return data


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


@unittest.skipUnless(all(os.environ.get(k) for k in ['XRAY_TEST_BINARY', 'PAYLOADGATE_TEST_BINARY', 'TLSMUX_TEST_BINARY', 'NGINX_TEST_BINARY']),
                     'set real core and gateway binaries to run loopback integration')
class XrayStreams(unittest.TestCase):
    def test_all_http_transports_authenticate_transfer_and_reconnect(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        binary = os.environ['XRAY_TEST_BINARY']
        with tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as stack:
            directory = Path(folder)
            processes = []
            def start(args, logname):
                log = stack.enter_context((directory / logname).open('wb'))
                p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
                p.test_log = directory / logname
                processes.append(p)
                return p
            def stop_all():
                for p in reversed(processes):
                    if p.poll() is None:
                        p.terminate()
                        p.wait(timeout=5)
            stack.callback(stop_all)
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
            certfile, keyfile = directory / 'cert.pem', directory / 'key.pem'
            certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
            fields = dict(line.split(':', 1) for line in subprocess.check_output([binary, 'x25519'], text=True).splitlines() if ':' in line)
            settings = dict(reality=dict(privateKey=fields['PrivateKey'].strip(), target='www.microsoft.com:443',
                                        serverName='www.microsoft.com', shortId='1234abcd'))
            settings['shadowsocks'] = dict(port=8388, serverKey=base64.b64encode(b'server-test-key!').decode())
            gateway_port, tls_port, h2_port, h1_port = port(), port(), port(), port()
            settings['reality'].update(target=f'127.0.0.1:{tls_port}', serverName='localhost')
            # Exercise the same credential factory used by combined accounts.
            users = {p: [x.new_account(p, 'test', '2099-01-01', 'fixture-combined')] for p in x.PROTOCOLS}
            users['shadowsocks'].append(dict(name='second', expiresAt='2099-01-01', password=base64.b64encode(b'second-test-key!').decode()))
            server = x.configuration(settings, users)
            server['log']['loglevel'] = 'debug'
            server['routing']['rules'] = []  # Test fixture destination is loopback.
            server['outbounds'][0]['settings'] = {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}
            routes, inbound_ports = {}, []
            for inbound in server['inbounds']:
                inbound['port'] = port()
                inbound['listen'] = '127.0.0.1'  # Isolate even the native SS listener.
                inbound_ports.append(inbound['port'])
            for row, inbound in zip(x.TRANSPORTS, server['inbounds']):
                if row[1] != 'grpc':
                    routes[row[2]] = f'127.0.0.1:{inbound["port"]}'
            x.atomic(directory / 'server.json', server)
            x.atomic(directory / 'routes.json', routes)
            core = start([binary, 'run', '-config', str(directory / 'server.json')], 'server.log')
            ready(inbound_ports[0], core)
            gateway = start([os.environ['PAYLOADGATE_TEST_BINARY'], '-listen', f'127.0.0.1:{gateway_port}',
                             '-xray-routes', str(directory / 'routes.json')], 'gateway.log')
            ready(gateway_port, gateway)
            # Exercise the actual generated nginx locations on the HTTP/2 path.
            for name in ['logs', 'temp']:
                (directory / name).mkdir()
            servers = ''.join('server {\n    listen 127.0.0.1:' + str(number) + (' http2' if number == h2_port else '')
                              + ';\n    server_name localhost;\n}\n' for number in [h2_port, h1_port])
            nginx_config = x.overlay_nginx(servers)
            for row, inbound in zip(x.TRANSPORTS, server['inbounds']):
                nginx_config = nginx_config.replace(f'127.0.0.1:{row[3]}', f'127.0.0.1:{inbound["port"]}')
            nginx_config = 'events { worker_connections 256; }\nhttp {\n' + nginx_config + '\n}\n'
            (directory / 'nginx.conf').write_text(nginx_config)
            nginx = start([os.environ['NGINX_TEST_BINARY'], '-p', directory.as_posix() + '/', '-c', 'nginx.conf',
                           '-g', 'daemon off; master_process off;'], 'nginx-stdout.log')
            ready(h2_port, nginx)
            tlsmux = start([os.environ['TLSMUX_TEST_BINARY'], '-listen', f'127.0.0.1:{tls_port}',
                            '-cert', str(certfile), '-key', str(keyfile), '-http1-target', f'127.0.0.1:{gateway_port}',
                            '-h2-target', f'127.0.0.1:{h2_port}'], 'tlsmux.log')
            ready(tls_port, tlsmux)
            httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            stack.callback(httpd.server_close)
            stack.callback(httpd.shutdown)
            extra_cases = (('vless', 'tcp', '', 0), ('shadowsocks', 'ss2022', '', 0), ('shadowsocks', 'ss2022-other', '', 0))
            for protocol, network, path, _ in (*x.TRANSPORTS, *extra_cases):
                for tls in ([False] if protocol == 'shadowsocks' else [True] if network == 'tcp' else x.tls_modes(protocol, network)):
                    with self.subTest(protocol=protocol, network=network, tls=tls):
                        socks = port()
                        user = {'password': users[protocol][0]['password']} if protocol == 'trojan' else {'id': users[protocol][0].get('uuid', '')}
                        stream = {'network': network, 'security': 'tls' if tls else 'none',
                                  {'ws': 'wsSettings', 'httpupgrade': 'httpupgradeSettings', 'xhttp': 'xhttpSettings', 'tcp': 'tcpSettings',
                                   'grpc': 'grpcSettings', 'ss2022': 'tcpSettings', 'ss2022-other': 'tcpSettings'}[network]:
                                  ({'serviceName': path.lstrip('/'), 'multiMode': False} if network == 'grpc'
                                   else dict(path=path, **({'mode': 'auto'} if network == 'xhttp' else {})))}
                        if tls:
                            # Trust only the exact short-lived loopback fixture certificate.
                            stream['tlsSettings'] = dict(serverName='localhost', fingerprint='chrome', pinnedPeerCertSha256=cert.fingerprint(hashes.SHA256()).hex(),
                                                         alpn=['h2', 'http/1.1'] if network in ('xhttp', 'grpc') else ['http/1.1'])
                        destination = dict(address='127.0.0.1', port=tls_port if tls else gateway_port)
                        if network == 'tcp':
                            stream = {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                                'serverName': 'localhost', 'fingerprint': 'chrome', 'shortId': '1234abcd',
                                'publicKey': fields['Password (PublicKey)'].strip(), 'spiderX': '/'}}
                            destination['port'] = next(i['port'] for i in server['inbounds'] if i['tag'] == 'vless-reality')
                            user['flow'] = 'xtls-rprx-vision'
                        if protocol == 'shadowsocks':
                            destination['port'] = next(i['port'] for i in server['inbounds'] if i['tag'] == 'shadowsocks-2022')
                            index = 1 if network.endswith('-other') else 0
                            settings_out = {'servers': [dict(destination, method=x.SS_METHOD,
                                            password=settings['shadowsocks']['serverKey'] + ':' + users['shadowsocks'][index]['password'])]}
                            stream = {'network': 'tcp', 'security': 'none'}
                        elif protocol == 'trojan':
                            settings_out = {'servers': [dict(destination, **user)]}
                        else:
                            settings_out = {'vnext': [dict(destination, users=[dict(user, encryption='none') if protocol == 'vless'
                                                                                   else dict(user, security='auto', alterId=0)])]}
                        client = dict(log={'loglevel': 'debug'}, inbounds=[dict(listen='127.0.0.1', port=socks,
                                      protocol='socks', settings={'auth': 'noauth', 'udp': False})],
                                      outbounds=[dict(protocol=protocol, settings=settings_out, streamSettings=stream)])
                        filename = directory / f'{protocol}-{network}-{tls}.json'
                        x.atomic(filename, client)
                        process = start([binary, 'run', '-config', str(filename)], filename.stem + '.log')
                        ready(socks, process)
                        try:
                            for cycle in range(2):
                                with socket.create_connection(('127.0.0.1', socks), timeout=10) as s:
                                    s.settimeout(15)
                                    s.sendall(b'\x05\x01\x00')
                                    self.assertEqual(read_exact(s, 2), b'\x05\x00')
                                    s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + httpd.server_port.to_bytes(2, 'big'))
                                    response = read_exact(s, 4)
                                    self.assertEqual(response[1], 0)
                                    atyp = response[3]
                                    size = 4 if atyp == 1 else 16 if atyp == 4 else read_exact(s, 1)[0]
                                    read_exact(s, size + 2)
                                    s.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                                    data = b''
                                    while b'\r\n\r\n' not in data or len(data.split(b'\r\n\r\n', 1)[1]) < len(BODY):
                                        chunk = s.recv(65536)
                                        if not chunk:
                                            break
                                        data += chunk
                                    self.assertTrue(data.startswith(b'HTTP/1.0 200'), data[:100])
                                    self.assertEqual(data.split(b'\r\n\r\n', 1)[1], BODY)
                            if network in ('xhttp', 'grpc') and tls:
                                self.assertIn('HTTP/2.0', (directory / 'logs/access.log').read_text())
                        except Exception:
                            import traceback
                            traceback.print_exc()
                            print('Received bytes:', len(data) if 'data' in locals() else 'none', repr(data[:150]) if 'data' in locals() else '')
                            print('Client log:', (directory / (filename.stem + '.log')).read_text(errors='replace'))
                            print('Server log:', (directory / 'server.log').read_text(errors='replace'))
                            print('Gateway log:', (directory / 'gateway.log').read_text(errors='replace'))
                            print('TLS log:', (directory / 'tlsmux.log').read_text(errors='replace'))
                            raise
                        finally:
                            process.terminate()
                            process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
