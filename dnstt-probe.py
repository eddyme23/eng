#!/usr/bin/env python3
"""Probe real encrypted DNSTT streams, locally or through a selected resolver."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def echo_server(listener):
    def echo(sock):
        with sock:
            sock.settimeout(15)
            while True:
                data = sock.recv(65536)
                if not data:
                    return
                sock.sendall(data)
    while True:
        try:
            sock, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=echo, args=(sock,), daemon=True).start()


def probe(client, server=None, domain='eng-probe.example', keys=None, ssh_target=None,
          transport='udp', resolver=None, timeout=20):
    """Local mode starts a candidate server. External mode never starts services."""
    started = time.monotonic()
    processes, listeners = [], []
    with tempfile.TemporaryDirectory(prefix='eng-dnstt-probe-') as directory:
        work = Path(directory)
        logs = []
        def spawn(args, name):
            log = (work / (name + '.log')).open('w+')
            logs.append(log)
            process = subprocess.Popen(list(map(str, args)), stdout=log, stderr=log)
            processes.append(process)
            return process
        try:
            if keys is None:
                if server is None:
                    raise ValueError('External tests require a public-key directory')
                keys = work
                subprocess.run([str(server), '-gen-key', '-privkey-file', str(keys / 'server.key'),
                                '-pubkey-file', str(keys / 'server.pub')], check=True,
                               capture_output=True, timeout=10)
            if server:
                if transport != 'udp' or resolver:
                    raise ValueError('Local candidate smoke test uses direct UDP; select external mode for public DoH/DoT')
                backend = ssh_target
                if not backend:
                    listener = socket.socket()
                    listener.bind(('127.0.0.1', 0))
                    listener.listen()
                    listeners.append(listener)
                    backend = '127.0.0.1:' + str(listener.getsockname()[1])
                    threading.Thread(target=echo_server, args=(listener,), daemon=True).start()
                resolver = '127.0.0.1:' + str(free_port(socket.SOCK_DGRAM))
                spawn([server, '-mtu', '1232', '-udp', resolver, '-privkey-file', keys / 'server.key',
                       domain, backend], 'server')
            if not resolver:
                raise ValueError('Choose a resolver explicitly for an external path test')
            local = '127.0.0.1:' + str(free_port())
            process = spawn([client, '-' + transport, resolver, '-pubkey-file', keys / 'server.pub',
                             domain, local], 'client')
            deadline = started + timeout
            connection = None
            while time.monotonic() < deadline:
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError('DNSTT process exited before the stream was ready')
                try:
                    connection = socket.create_connection(('127.0.0.1', int(local.rsplit(':', 1)[1])), timeout=.2)
                    break
                except OSError:
                    time.sleep(.05)
            if connection is None:
                raise TimeoutError('Local DNSTT client listener did not open')
            ready = time.monotonic() - started
            with connection:
                connection.settimeout(max(.1, deadline - time.monotonic()))
                if ssh_target or not server:
                    reply = b''
                    while b'\n' not in reply and len(reply) < 4096:
                        part = connection.recv(256)
                        if not part:
                            break
                        reply += part
                    if not reply.startswith(b'SSH-'):
                        raise ValueError('Encrypted tunnel returned no SSH identification banner')
                    result = 'encrypted tunnel to raw SSH banner'
                else:
                    payload = b'ENG encrypted DNSTT round-trip\x00' + os.urandom(32768)
                    connection.sendall(payload)
                    reply = b''
                    while len(reply) < len(payload):
                        part = connection.recv(len(payload) - len(reply))
                        if not part:
                            break
                        reply += part
                    if reply != payload:
                        raise ValueError('Encrypted stream round-trip mismatch')
                    result = str(len(payload)) + '-byte encrypted stream round-trip'
            return {'result': result, 'transport': transport, 'resolver': resolver,
                    'listener_ready_seconds': round(ready, 4),
                    'first_verified_stream_seconds': round(time.monotonic() - started, 4),
                    'ssh_login': 'not tested', 'browsing': 'not tested'}
        except Exception as error:
            detail = []
            for log in logs:
                log.flush()
                log.seek(0)
                detail.extend(log.read().splitlines()[-8:])
            raise RuntimeError(str(error) + '\n' + '\n'.join(detail)) from error
        finally:
            for process in reversed(processes):
                stop(process)
            for listener in listeners:
                listener.close()
            for log in logs:
                log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--server', type=Path, help='Start candidate locally; omit to probe an existing server')
    parser.add_argument('--keys', type=Path, help='Contains server.pub; local server also needs server.key')
    parser.add_argument('--domain', default='eng-probe.example')
    parser.add_argument('--ssh-target', help='Local candidate backend; also enables SSH banner verification')
    parser.add_argument('--transport', choices=('udp', 'doh', 'dot'), default='udp')
    parser.add_argument('--resolver', help='UDP HOST:PORT, HTTPS DoH URL, or DoT HOST:PORT')
    parser.add_argument('--timeout', type=int, default=20)
    args = parser.parse_args()
    print(json.dumps(probe(args.client.resolve(), args.server.resolve() if args.server else None,
                           args.domain, args.keys, args.ssh_target, args.transport, args.resolver, args.timeout), indent=2))
