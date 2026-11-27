#!/usr/bin/env python3
"""Outbound-only ENG management agent. Never accepts network connections."""
import argparse
from contextlib import contextmanager
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import time
from urllib.parse import urlsplit

CONFIG = Path('/etc/frimps-panel-agent/config.json')
SOCKET = '/run/frimps-panel/control.sock'


class Unauthorized(Exception):
    pass


def origin(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Use the central HTTPS origin, for example https://panel.vpnguruz.store:8445')
    port = parsed.port or 443
    if not 1 <= port <= 65535:
        raise ValueError('Invalid central port')
    return 'https://' + parsed.netloc


def send(url, path, data, token=None, timeout=30, context=None):
    parsed = urlsplit(origin(url))
    # Standard CA and hostname verification. Redirects are deliberately not followed.
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                       context=context or ssl.create_default_context(), timeout=timeout)
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        conn.request('POST', path, json.dumps(data), headers)
        reply = conn.getresponse()
        body = reply.read(1048577)
        if reply.status == 401:
            raise Unauthorized('Server authorization was revoked or is invalid')
        if reply.status != 200 or len(body) > 1048576:
            raise ValueError(f'Central request failed (HTTP {reply.status}); check server pairing and connectivity')
        return json.loads(body)
    finally:
        conn.close()


def helper(request):
    data = json.dumps(request).encode() + b'\n'
    if len(data) > 65536:
        raise ValueError('Request too large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(125)
        conn.connect(SOCKET)
        conn.sendall(data)
        output = bytearray()
        while b'\n' not in output and len(output) < 1048576:
            chunk = conn.recv(8192)
            if not chunk:
                break
            output.extend(chunk)
        return json.loads(output)


class Ledger:
    def __init__(self, path):
        self.path = Path(path)
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, digest TEXT NOT NULL, started REAL NOT NULL, completed INTEGER NOT NULL DEFAULT 0)')
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def execute(self, job, bridge=helper):
        if not isinstance(job, dict) or set(job) != {'id', 'request'} or not isinstance(job['id'], str) or not re.fullmatch(r'[a-f0-9]{32}', job['id']) or not isinstance(job['request'], dict):
            raise ValueError('Invalid management job')
        # Hash operation type only. Even ZiVPN's name is a password, so neither
        # names nor password fields belong in the durable replay ledger.
        metadata = {key: job['request'].get(key) for key in ('protocol', 'action')}
        fingerprint = hashlib.sha256(json.dumps(metadata, sort_keys=True).encode()).hexdigest()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            prior = db.execute('SELECT digest,completed FROM jobs WHERE id=?', (job['id'],)).fetchone()
            if prior:
                return {'ok': False, 'output': 'This request was already received and will not be executed again. Check the account state before starting another operation.'}
            # Commit before contacting the helper. A crash fails closed on replay.
            db.execute('INSERT INTO jobs(id,digest,started) VALUES(?,?,?)', (job['id'], fingerprint, time.time()))
        try:
            result = bridge(job['request'])
            if not isinstance(result, dict) or type(result.get('ok')) is not bool or not isinstance(result.get('output'), str):
                raise ValueError('Invalid helper response')
            result = {'ok': result['ok'], 'output': result['output'][:262144]}
        except Exception:
            result = {'ok': False, 'output': 'Account helper failed or timed out. The operation may have executed; inspect the account before retrying.'}
        with self.db() as db:
            db.execute('UPDATE jobs SET completed=1 WHERE id=?', (job['id'],))
        return result


def main():
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    url = origin(config['central'])
    directory = Path('/var/lib/frimps-agent')
    # An accidental second agent must not race for this server's requests.
    with (directory / 'agent.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        ledger = Ledger(directory / 'jobs.sqlite')
        print('ENG outbound management agent started', flush=True)
        while True:
            try:
                reply = send(url, '/api/agent/poll', {}, config['token'])
                job = reply.get('job')
                if job is None:
                    continue
                result = ledger.execute(job)
                for attempt in range(3):
                    try:
                        send(url, '/api/agent/result', {'id': job['id'], 'result': result}, config['token'])
                        break
                    except Unauthorized:
                        raise
                    except Exception:
                        if attempt < 2:
                            time.sleep(2)
                # Retry result delivery only, NEVER an account operation.
            except Unauthorized:
                print('Management authorization is no longer valid; agent stopped. VPN services remain running.', flush=True)
                return
            except Exception:
                print('Management connection unavailable; retrying in five seconds.', flush=True)
                time.sleep(5)


if __name__ == '__main__':
    main()
