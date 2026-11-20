"""Opt-in real Node/Go/TLS transport checks; backend echoes OpenVPN-like bytes, not a VPN login."""
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('ENG_RUN_OVPN_WS_INTEGRATION') == '1', 'set ENG_RUN_OVPN_WS_INTEGRATION=1')
class OpenvpnWebsocketTest(unittest.TestCase):
    @staticmethod
    def port():
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            return listener.getsockname()[1]

    @classmethod
    def setUpClass(cls):
        go = os.environ.get('GO_BINARY') or shutil.which('go')
        openssl = os.environ.get('OPENSSL_BINARY') or shutil.which('openssl')
        node = shutil.which('node')
        if not all((go, openssl, node)):
            raise unittest.SkipTest('Go, OpenSSL and Node required')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        folder = Path(cls.temp.name)
        cls.processes = []
        def cleanup():
            for proc in cls.processes:
                proc.terminate()
            for proc in cls.processes:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
        cls.addClassCleanup(cleanup)
        cls.backend = socket.socket()
        cls.backend.bind(('127.0.0.1', 0))
        cls.backend.listen()
        cls.backend.settimeout(.2)
        cls.addClassCleanup(cls.backend.close)
        cls.stop = threading.Event()
        cls.addClassCleanup(cls.stop.set)
        def echo(connection):
            with connection:
                connection.settimeout(3)
                try:
                    while True:
                        data = connection.recv(65536)
                        if not data:
                            return
                        connection.sendall(data)
                except OSError:
                    return
        def accept():
            while not cls.stop.is_set():
                try:
                    connection, _ = cls.backend.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                threading.Thread(target=echo, args=(connection,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
        cls.gateway, cls.payload, cls.tls = cls.port(), cls.port(), cls.port()
        installer = (ROOT / 'openvpn-install.sh').read_text()
        source = re.search(r"openvpn-bshield.js <<'EOF'\n(.*?)\nEOF", installer, re.S).group(1)
        source = source.replace("net.connect(11940,'127.0.0.1')", f"net.connect({cls.backend.getsockname()[1]},'127.0.0.1')")
        source = source.replace(".listen(10081,'127.0.0.1')", f".listen({cls.gateway},'127.0.0.1')")
        gateway = folder / 'gateway.js'
        gateway.write_bytes(source.encode())
        for component in ('payloadgate', 'tlsmux'):
            target = folder / (component + ('.exe' if os.name == 'nt' else ''))
            subprocess.run([go, 'build', '-o', str(target), str(ROOT / component / 'main.go')],
                           check=True, capture_output=True, timeout=120)
        cls.cert, cls.key = folder / 'cert.pem', folder / 'key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(cls.key), '-out', str(cls.cert)], check=True,
                       capture_output=True, timeout=30)
        def start(args, port):
            proc = subprocess.Popen(list(map(str, args)), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    creationflags=0x08000000 if os.name == 'nt' else 0)
            cls.processes.append(proc)
            for _ in range(100):
                if proc.poll() is not None:
                    raise RuntimeError('gateway exited')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        return
                except OSError:
                    time.sleep(.05)
            raise RuntimeError('gateway did not start')
        suffix = '.exe' if os.name == 'nt' else ''
        start([node, gateway], cls.gateway)
        start([folder / ('payloadgate' + suffix), '-listen', f'127.0.0.1:{cls.payload}',
               '-openvpn-target', f'127.0.0.1:{cls.gateway}'], cls.payload)
        start([folder / ('tlsmux' + suffix), '-listen', f'127.0.0.1:{cls.tls}',
               '-cert', cls.cert, '-key', cls.key, '-http1-target', f'127.0.0.1:{cls.payload}'], cls.tls)

    @classmethod
    def connect(cls, port):
        connection = socket.create_connection(('127.0.0.1', port), timeout=3)
        if port == cls.tls:
            context = ssl.create_default_context(cafile=str(cls.cert))
            context.set_alpn_protocols(['http/1.1'])
            connection = context.wrap_socket(connection, server_hostname='localhost')
        connection.settimeout(3)
        return connection

    @staticmethod
    def header(connection):
        result = b''
        while not result.endswith(b'\r\n\r\n'):
            data = connection.recv(1)
            if not data or len(result) > 16384:
                raise AssertionError('invalid HTTP response')
            result += data
        return result

    def test_plain_and_tls_openvpn_upgrade_binary_forwarding_and_reconnects(self):
        payload = b'\x00\x10\x38\x00OpenVPN-transport\x00\xff'
        for port in (self.gateway, self.payload, self.tls):
            for key in (False, True):
                for reconnect in range(3):
                    with self.subTest(port=port, key=key, reconnect=reconnect), self.connect(port) as connection:
                        request = b'GET /openvpn HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n'
                        if key:
                            request += b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n'
                        # Coalesced bytes must survive Node upgrade's buffered head.
                        connection.sendall(request + b'\r\n' + payload)
                        self.assertTrue(self.header(connection).startswith(b'HTTP/1.1 101'))
                        echoed = b''
                        while len(echoed) < len(payload):
                            data = connection.recv(len(payload) - len(echoed))
                            self.assertTrue(data)
                            echoed += data
                        self.assertEqual(echoed, payload)
                        connection.sendall(payload)
                        echoed = b''
                        while len(echoed) < len(payload):
                            data = connection.recv(len(payload) - len(echoed))
                            self.assertTrue(data)
                            echoed += data
                        self.assertEqual(echoed, payload)

    def test_wrong_openvpn_path_is_rejected(self):
        with self.connect(self.gateway) as connection:
            connection.sendall(b'GET /wrong HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n')
            self.assertTrue(self.header(connection).startswith(b'HTTP/1.1 400'))
