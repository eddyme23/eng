"""Opt-in end-to-end tests with real TLS and the three built Go gateways."""
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.environ.get("ENG_RUN_TLS_INTEGRATION") == "1", "set ENG_RUN_TLS_INTEGRATION=1")
class TlsPayloadChainTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        go = os.environ.get("GO_BINARY") or shutil.which("go")
        openssl = os.environ.get("OPENSSL_BINARY") or shutil.which("openssl")
        if not go or not openssl:
            raise unittest.SkipTest("Go and OpenSSL are required")
        cls.procs = []
        def stop_procs():
            for p in cls.procs:
                p.terminate()
            for p in cls.procs:
                try: p.wait(timeout=5)
                except subprocess.TimeoutExpired: p.kill(); p.wait()
        cls.addClassCleanup(stop_procs)
        for component in ("payloadgate", "sshws", "tlsmux"):
            executable = cls.folder / (component + (".exe" if os.name == "nt" else ""))
            subprocess.run([go, "build", "-o", str(executable), str(ROOT/component/"main.go")], check=True, capture_output=True, timeout=120)
        cls.cert = cls.folder/"cert.pem"
        cls.key = cls.folder/"key.pem"
        subprocess.run([openssl,"req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost","-keyout",str(cls.key),"-out",str(cls.cert)],check=True,capture_output=True,timeout=30)
        cls.listener = socket.socket()
        cls.listener.bind(("127.0.0.1", 0)); cls.listener.listen(); cls.listener.settimeout(.2)
        cls.addClassCleanup(cls.listener.close)
        cls.stop = threading.Event(); cls.addClassCleanup(cls.stop.set)
        cls.ssh_port = cls.listener.getsockname()[1]
        def serve(c):
            with c:
                c.settimeout(3)
                try:
                    c.sendall(b"SSH-2.0-test-backend\r\n")
                    data = c.recv(2048)
                    if data: c.sendall(b"ACK:" + data)
                    while c.recv(2048): pass
                except (OSError, TimeoutError): pass
        def accept():
            while not cls.stop.is_set():
                try: c,_=cls.listener.accept()
                except socket.timeout: continue
                except OSError: return
                threading.Thread(target=serve,args=(c,),daemon=True).start()
        threading.Thread(target=accept,daemon=True).start()
        cls.gate_port, cls.ws_port, cls.tls_port = cls.port(), cls.port(), cls.port()
        cls.start("sshws",["-listen",f"127.0.0.1:{cls.ws_port}","-ssh-target",f"127.0.0.1:{cls.ssh_port}"],cls.ws_port)
        cls.start("payloadgate",["-listen",f"127.0.0.1:{cls.gate_port}","-ssh-target",f"127.0.0.1:{cls.ssh_port}","-ws-target",f"127.0.0.1:{cls.ws_port}"],cls.gate_port)
        cls.start("tlsmux",["-listen",f"127.0.0.1:{cls.tls_port}","-cert",str(cls.cert),"-key",str(cls.key),"-ssh-target",f"127.0.0.1:{cls.ssh_port}","-http1-target",f"127.0.0.1:{cls.gate_port}"],cls.tls_port)
    @staticmethod
    def port():
        with socket.socket() as s:
            s.bind(("127.0.0.1",0)); return s.getsockname()[1]
    @classmethod
    def start(cls,name,args,port):
        executable=cls.folder/(name+(".exe" if os.name=="nt" else ""))
        p=subprocess.Popen([str(executable)]+args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=0x08000000 if os.name=="nt" else 0)
        cls.procs.append(p)
        for _ in range(100):
            if p.poll() is not None: raise RuntimeError(name+" exited")
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.1): return
            except OSError: time.sleep(.05)
        raise RuntimeError(name+" did not listen")
    def connect(self):
        context=ssl.create_default_context(cafile=str(self.cert)); context.set_alpn_protocols(["http/1.1"])
        s=context.wrap_socket(socket.create_connection(("127.0.0.1",self.tls_port),timeout=3),server_hostname="localhost")
        s.settimeout(3); return s
    @staticmethod
    def header(s):
        data=b""
        while not data.endswith(b"\r\n\r\n"):
            piece=s.recv(1)
            if not piece: raise EOFError("closed before headers")
            data+=piece
            if len(data)>16384: raise ValueError("oversized header")
        return data
    def test_legacy_without_upgrade_and_reconnects(self):
        for _ in range(5):
            with self.connect() as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                self.assertTrue(self.header(s).startswith(b"HTTP/1.1 101"))
                s.sendall(b"SSH-2.0-client\r\n")
                data=b""
                while b"ACK:SSH-2.0-client\r\n" not in data: data+=s.recv(4096)
                self.assertIn(b"SSH-2.0-test-backend",data)
    def test_legacy_upgrade_and_connect(self):
        for request in (b"GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n",b"CONNECT localhost:22 HTTP/1.1\r\n"):
            with self.connect() as s:
                s.sendall(request+b"Host: localhost\r\n\r\n")
                self.assertRegex(self.header(s).decode(),r"HTTP/1.1 (101|200)")
                s.sendall(b"SSH-2.0-client\r\n")
                self.assertTrue(s.recv(256).startswith(b"SSH-"))
    def test_standard_websocket(self):
        with self.connect() as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            self.assertIn(b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", self.header(s))
            def full(n):
                out=b""
                while len(out)<n:
                    part=s.recv(n-len(out))
                    if not part: raise EOFError()
                    out+=part
                return out
            h=full(2);self.assertEqual(h[0],0x82)
            size=h[1]&127
            if size==126:size=struct.unpack("!H",full(2))[0]
            self.assertTrue(full(size).startswith(b"SSH-"))
    def test_silent_ssl_direct(self):
        with self.connect() as s:
            self.assertTrue(s.recv(256).startswith(b"SSH-"))
