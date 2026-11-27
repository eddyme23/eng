#!/usr/bin/env python3
"""Optional HTTPS-only ENG administrator UI; no third-party dependencies."""
import argparse
import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import ssl
import threading
import time

SOCKET = '/run/frimps-panel/control.sock'
CONFIG = Path('/etc/frimps-panel/web.json')
PAGE = Path(__file__).with_name('panel.html')


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def helper(req):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(125)
        conn.connect(SOCKET)
        conn.sendall(json.dumps(req).encode() + b'\n')
        data = bytearray()
        while b'\n' not in data and len(data) < 1048576:
            chunk = conn.recv(8192)
            if not chunk:
                break
            data.extend(chunk)
        return json.loads(data)


class Panel(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, config, bridge=helper):
        self.config, self.bridge = config, bridge
        self.sessions, self.failures = {}, {}
        self.lock = threading.Lock()
        # Bound slow/untrusted connections before creating worker threads.
        self.workers = threading.BoundedSemaphore(24)
        super().__init__(address, Handler)

    def get_request(self):
        conn, address = super().get_request()
        conn.settimeout(10)
        return conn, address

    def process_request(self, request, address):
        if not self.workers.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.workers.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.workers.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never log submitted credentials or exported bundles.

    def reply(self, code, body, cookie=None, html=False):
        data = body.encode() if html else json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8' if html else 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(data)

    def session(self):
        try:
            cookie = SimpleCookie(self.headers.get('Cookie', ''))
            token = cookie['eng_session'].value
        except (KeyError, ValueError):
            return None
        with self.server.lock:
            session = self.server.sessions.get(token)
            if not session or session['expires'] <= time.monotonic():
                self.server.sessions.pop(token, None)
                return None
            return token, session

    def valid_host(self):
        return self.headers.get('Host') == self.server.config['origin'].split('://', 1)[1]

    def do_GET(self):
        if not self.valid_host():
            return self.reply(400, {'error': 'Invalid host'})
        if self.path in ('/', '/panel.js', '/panel.css'):
            if self.path == '/':
                return self.reply(200, PAGE.read_text(encoding='utf-8'), html=True)
            filename = Path(__file__).with_name(self.path[1:])
            data = filename.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type', 'text/javascript' if self.path.endswith('.js') else 'text/css')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            return self.wfile.write(data)
        session = self.session()
        if not session:
            return self.reply(401, {'error': 'Sign in required'})
        if self.path == '/api/session':
            return self.reply(200, {'csrf': session[1]['csrf']})
        self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        if not self.valid_host() or self.headers.get('Origin') != self.server.config['origin']:
            return self.reply(403, {'error': 'Invalid origin'})
        if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
            return self.reply(400, {'error': 'JSON required'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 65536:
                raise ValueError()
            req = json.loads(self.rfile.read(size))
            if not isinstance(req, dict):
                raise ValueError()
        except (ValueError, OSError):
            return self.reply(400, {'error': 'Invalid request'})
        if self.path == '/api/login':
            return self.login(req)
        session = self.session()
        if not session:
            return self.reply(401, {'error': 'Sign in required'})
        if not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session[1]['csrf']):
            return self.reply(403, {'error': 'Invalid session token'})
        if self.path == '/api/logout':
            with self.server.lock:
                self.server.sessions.pop(session[0], None)
            return self.reply(200, {'ok': True}, 'eng_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
        if self.path != '/api/action':
            return self.reply(404, {'error': 'Not found'})
        try:
            response = self.server.bridge(req)
        except Exception:
            return self.reply(503, {'error': 'Account helper unavailable; check the panel service logs'})
        self.reply(200 if response.get('ok') else 400, response)

    def login(self, req):
        now = time.monotonic()
        ip = self.client_address[0]
        # Global and per-address limits also bound memory and password-hash CPU.
        with self.server.lock:
            self.server.failures = {k: v for k, v in self.server.failures.items() if v[1] > now - 300}
            hits = self.server.failures.get(ip, (0, now))[0]
            total = self.server.failures.get('*', (0, now))[0]
            if hits >= 5 or total >= 30:
                return self.reply(429, {'error': 'Too many attempts; wait five minutes'})
            self.server.failures[ip] = (hits + 1, now)
            self.server.failures['*'] = (total + 1, now)
        password = req.get('password', '')
        if not isinstance(password, str) or len(password) > 256:
            return self.reply(401, {'error': 'Invalid login'})
        actual = password_hash(password, self.server.config['salt'])
        if req.get('username') != self.server.config['username'] or not hmac.compare_digest(actual, self.server.config['passwordHash']):
            return self.reply(401, {'error': 'Invalid login'})
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.server.lock:
            self.server.sessions = {k: v for k, v in self.server.sessions.items() if v['expires'] > now}
            if len(self.server.sessions) >= 32:
                self.server.sessions.pop(next(iter(self.server.sessions)))
            self.server.sessions[token] = {'csrf': csrf, 'expires': now + 1800}
        self.reply(200, {'csrf': csrf}, 'eng_session=' + token + '; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    server = Panel((config['bind'], config['port']), config)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config['cert'], config['key'])
    # TLS handshakes happen inside bounded request workers, not the accept loop.
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == '__main__':
    main()
