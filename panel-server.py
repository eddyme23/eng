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
import sys
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
        self.pair_failures = {}
        self.lock = threading.Lock()
        self.hash_slots = threading.BoundedSemaphore(2)
        self.central = None
        if config.get('central'):
            from panel_central import Central
            if not config.get('totpSecret'):
                raise ValueError('Central management requires administrator two-factor authentication')
            self.central = Central(config['dataDir'])
        # Bound slow/untrusted connections before creating worker threads.
        self.workers = threading.BoundedSemaphore(64 if self.central else 24)
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

    def handle_error(self, request, address):
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError)):
            return  # Expected disconnects and rejected TLS peers are not tracebacks.
        super().handle_error(request, address)


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
        if self.path == '/api/info':
            return self.reply(200, {'central': bool(self.server.central),
                                    'otpRequired': bool(self.server.config.get('totpSecret')),
                                    'origin': self.server.config['origin']})
        session = self.session()
        if not session:
            return self.reply(401, {'error': 'Sign in required'})
        if self.path == '/api/session':
            return self.reply(200, {'csrf': session[1]['csrf']})
        if self.path == '/api/servers':
            local = {'id': 'local', 'label': self.server.config.get('localName', self.server.config.get('domain', 'This VPS')),
                     'online': True, 'ready': True, 'local': True}
            return self.reply(200, {'servers': [local] + (self.server.central.nodes() if self.server.central else [])})
        self.reply(404, {'error': 'Not found'})

    def do_POST(self):
        agent_route = self.path.startswith('/api/agent/') and self.server.central is not None
        if not self.valid_host() or (not agent_route and self.headers.get('Origin') != self.server.config['origin']):
            return self.reply(403, {'error': 'Invalid origin'})
        if self.headers.get('Content-Type') != 'application/json' or self.headers.get('Transfer-Encoding'):
            return self.reply(400, {'error': 'JSON required'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= (2097152 if agent_route and self.path == '/api/agent/result' else 65536):
                raise ValueError()
            req = json.loads(self.rfile.read(size))
            if not isinstance(req, dict):
                raise ValueError()
        except (ValueError, OSError):
            return self.reply(400, {'error': 'Invalid request'})
        if agent_route:
            return self.agent_request(req)
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
        if self.path in ('/api/pairing-code', '/api/revoke-server'):
            if not self.server.central:
                return self.reply(400, {'error': 'Central management is not enabled'})
            try:
                if self.path == '/api/pairing-code':
                    if set(req) != {'label'}:
                        raise ValueError('Specify a server name')
                    result = self.server.central.pairing_code(req['label'])
                else:
                    if set(req) != {'server'}:
                        raise ValueError('Specify the server to remove')
                    result = self.server.central.revoke(req['server'])
                return self.reply(200, result)
            except ValueError as exc:
                return self.reply(400, {'error': str(exc)})
        if self.path != '/api/action':
            return self.reply(404, {'error': 'Not found'})
        try:
            target = req.pop('server', None)
            if self.server.central and target is None:
                raise ValueError('Choose the target VPS explicitly')
            if target in (None, 'local'):
                response = self.server.bridge(req)
            elif self.server.central:
                response = self.server.central.submit(target, req)
            else:
                raise ValueError('Remote management is not enabled')
        except ValueError as exc:
            return self.reply(400, {'error': str(exc)})
        except Exception:
            return self.reply(503, {'error': 'Account helper unavailable; check the panel service logs'})
        self.reply(200 if response.get('ok') else 400, response)

    def agent_request(self, req):
        central = self.server.central
        if self.path == '/api/agent/pair':
            now, ip = time.monotonic(), self.client_address[0]
            with self.server.lock:
                self.server.pair_failures = {k: v for k, v in self.server.pair_failures.items() if v[1] > now - 300}
                hits = self.server.pair_failures.get(ip, (0, now))[0]
                total = self.server.pair_failures.get('*', (0, now))[0]
                if hits >= 5 or total >= 30:
                    return self.reply(429, {'error': 'Too many pairing attempts; wait five minutes'})
                self.server.pair_failures[ip] = (hits + 1, now)
                self.server.pair_failures['*'] = (total + 1, now)
            try:
                if set(req) != {'code'}:
                    raise ValueError('Invalid pairing request')
                return self.reply(200, central.pair(req['code']))
            except ValueError as exc:
                return self.reply(400, {'error': str(exc)})
        try:
            auth = self.headers.get('Authorization', '')
            node = central.authenticate(auth[7:] if auth.startswith('Bearer ') else '')
        except ValueError:
            return self.reply(401, {'error': 'Agent authentication failed'})
        try:
            if self.path == '/api/agent/poll' and not req:
                result = central.poll(node)
            elif self.path == '/api/agent/result' and set(req) == {'id', 'result'}:
                result = central.result(node, req['id'], req['result'])
            else:
                raise ValueError('Invalid agent operation')
            return self.reply(200, result)
        except ValueError as exc:
            return self.reply(400, {'error': str(exc)})

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
        if not self.server.hash_slots.acquire(blocking=False):
            return self.reply(429, {'error': 'Sign-in is busy; try again shortly'})
        try:
            actual = password_hash(password, self.server.config['salt'])
        finally:
            self.server.hash_slots.release()
        if req.get('username') != self.server.config['username'] or not hmac.compare_digest(actual, self.server.config['passwordHash']):
            return self.reply(401, {'error': 'Invalid login'})
        if self.server.config.get('totpSecret'):
            from panel_totp import verify
            counter = verify(self.server.config['totpSecret'], req.get('otp', ''))
            scope = 'totp:' + hashlib.sha256(self.server.config['totpSecret'].encode()).hexdigest()
            if counter is None or (self.server.central and not self.server.central.consume_totp_counter(counter, scope)):
                return self.reply(401, {'error': 'Invalid or already used authenticator code; wait for the next code'})
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
