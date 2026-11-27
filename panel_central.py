"""Central registry and ephemeral, at-most-once delivery to outbound ENG agents."""
import hashlib
from contextlib import contextmanager
import json
import re
import secrets
import sqlite3
import threading
import time
from pathlib import Path


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


class Channel:
    def __init__(self):
        self.condition = threading.Condition()
        self.waiting = False
        self.seen = float('-inf')
        self.job = None
        self.delivered = False
        self.result = None
        self.revoked = False


class Central:
    def __init__(self, directory, poll_timeout=10, operation_timeout=145):
        self.path = Path(directory) / 'central.sqlite'
        self.poll_timeout, self.operation_timeout = poll_timeout, operation_timeout
        self.lock = threading.Lock()
        self.channels = {}
        with self.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS nodes (
                  id TEXT PRIMARY KEY, label TEXT NOT NULL, token_hash TEXT NOT NULL,
                  revoked INTEGER NOT NULL DEFAULT 0, paired_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS codes (
                  hash TEXT PRIMARY KEY, label TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER);
            ''')
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def channel(self, node):
        with self.lock:
            return self.channels.setdefault(node, Channel())

    def pairing_code(self, label):
        if not isinstance(label, str) or not re.fullmatch(r'[\w .()-]{1,48}', label, re.UNICODE):
            raise ValueError('Use a server name of 1-48 letters, numbers, spaces, dots, hyphens or parentheses')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM codes WHERE expires <= ?', (time.time(),))
            if db.execute('SELECT COUNT(*) FROM nodes WHERE revoked=0').fetchone()[0] >= 16:
                raise ValueError('This central panel supports up to 16 paired remote servers')
            if db.execute('SELECT COUNT(*) FROM codes').fetchone()[0] >= 32:
                raise ValueError('Too many unused pairing codes; wait for expiry')
            if db.execute('SELECT 1 FROM nodes WHERE label=? COLLATE NOCASE AND revoked=0', (label,)).fetchone():
                raise ValueError('A paired server already uses that name; choose another')
            db.execute('DELETE FROM codes WHERE label=? COLLATE NOCASE', (label,))
            code = secrets.token_urlsafe(24)
            db.execute('INSERT INTO codes VALUES (?,?,?)', (digest(code), label, time.time() + 900))
        return {'code': code, 'expiresInSeconds': 900, 'label': label}

    def pair(self, code):
        if not isinstance(code, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32}', code):
            raise ValueError('Invalid or expired pairing code')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT label FROM codes WHERE hash=? AND expires>?', (digest(code), time.time())).fetchone()
            if not row:
                raise ValueError('Invalid or expired pairing code')
            if db.execute('SELECT COUNT(*) FROM nodes WHERE revoked=0').fetchone()[0] >= 16:
                raise ValueError('Remote server limit reached')
            if db.execute('SELECT 1 FROM nodes WHERE label=? COLLATE NOCASE AND revoked=0', (row[0],)).fetchone():
                raise ValueError('A paired server already uses that name')
            node, token = secrets.token_hex(16), secrets.token_urlsafe(32)
            db.execute('DELETE FROM codes WHERE hash=?', (digest(code),))
            db.execute('INSERT INTO nodes(id,label,token_hash,paired_at) VALUES(?,?,?,?)',
                       (node, row[0], digest(token), time.time()))
        return {'nodeId': node, 'token': token, 'label': row[0]}

    def authenticate(self, token):
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise ValueError('Agent authentication failed')
        with self.db() as db:
            row = db.execute('SELECT id FROM nodes WHERE token_hash=? AND revoked=0', (digest(token),)).fetchone()
        if not row:
            raise ValueError('Agent authentication failed')
        return row[0]

    def nodes(self):
        with self.db() as db:
            rows = db.execute('SELECT id,label,paired_at FROM nodes WHERE revoked=0 ORDER BY paired_at').fetchall()
        results = []
        for node, label, paired in rows:
            channel = self.channel(node)
            with channel.condition:
                online = time.monotonic() - channel.seen < 25 and not channel.revoked
                results.append({'id': node, 'label': label, 'online': online,
                                'ready': channel.waiting and channel.job is None and not channel.revoked,
                                'pairedAt': paired})
        return results

    def exists(self, node):
        if not isinstance(node, str) or not re.fullmatch(r'[a-f0-9]{32}', node):
            return False
        with self.db() as db:
            return db.execute('SELECT 1 FROM nodes WHERE id=? AND revoked=0', (node,)).fetchone() is not None

    def revoke(self, node):
        if not self.exists(node):
            raise ValueError('Unknown server')
        with self.db() as db:
            db.execute('UPDATE nodes SET revoked=1 WHERE id=?', (node,))
        channel = self.channel(node)
        with channel.condition:
            channel.revoked = True
            channel.condition.notify_all()
        # Already delivered commands cannot be cancelled; VPN services keep running.
        return {'ok': True, 'output': 'Server management access removed. VPN accounts and services are unchanged.'}

    def poll(self, node):
        channel = self.channel(node)
        with channel.condition:
            if channel.revoked:
                raise ValueError('Server access revoked')
            if channel.waiting:
                raise ValueError('An agent poll is already active')
            channel.waiting = True
            channel.seen = time.monotonic()
            channel.condition.notify_all()
            try:
                channel.condition.wait_for(lambda: channel.job is not None or channel.revoked, timeout=self.poll_timeout)
                if channel.revoked:
                    raise ValueError('Server access revoked')
                if channel.job and not channel.delivered:
                    channel.delivered = True
                    channel.condition.notify_all()
                    return {'job': channel.job}
                return {'job': None}
            finally:
                channel.waiting = False
                channel.seen = time.monotonic()

    def submit(self, node, request):
        if not self.exists(node):
            raise ValueError('Unknown or revoked server')
        channel = self.channel(node)
        with channel.condition:
            # No offline queue and no automatic retry of account changes.
            if channel.revoked or not channel.waiting or channel.job:
                raise ValueError('Server is offline or busy. No operation was queued; refresh server status and retry.')
            job_id = secrets.token_hex(16)
            channel.job = {'id': job_id, 'request': request}
            channel.result = None
            channel.delivered = False
            channel.condition.notify_all()
            try:
                done = channel.condition.wait_for(lambda: channel.result is not None or channel.revoked,
                                                  timeout=self.operation_timeout)
                if not done or channel.revoked:
                    if channel.delivered:
                        raise ValueError('Connection lost or operation timed out. It may have executed; inspect the account before retrying. It will not be resent.')
                    raise ValueError('Server disconnected. The operation was not delivered and will not be resent.')
                return channel.result
            finally:
                channel.job = None
                channel.result = None
                channel.delivered = False

    def result(self, node, job_id, result):
        if not isinstance(result, dict) or set(result) != {'ok', 'output'} or type(result['ok']) is not bool or not isinstance(result['output'], str) or len(result['output']) > 262144:
            raise ValueError('Invalid agent result')
        channel = self.channel(node)
        with channel.condition:
            channel.seen = time.monotonic()
            if not channel.job or channel.job['id'] != job_id or not channel.delivered:
                # A response arriving after a timeout is discarded, never re-executed.
                return {'ok': True, 'discarded': True}
            channel.result = result
            channel.condition.notify_all()
        return {'ok': True}

    def consume_totp_counter(self, counter, scope='totp'):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT value FROM counters WHERE name=?', (scope,)).fetchone()
            if row and counter <= row[0]:
                return False
            db.execute('INSERT OR REPLACE INTO counters VALUES(?,?)', (scope, counter))
        return True
