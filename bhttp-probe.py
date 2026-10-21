#!/usr/bin/env python3
"""Bounded BHP1 calibration probes; no SSH login or credentials required."""
import argparse
import hashlib
import os
import re
import socket
import struct
import subprocess
import tempfile
import time


def crypt(data, sid, response=False):
    seed = sid + b'\0' + struct.pack('!Q', 0) + bytes([response])
    result = bytearray()
    for offset in range(0, len(data), 32):
        key = hashlib.sha256(seed + struct.pack('!I', offset // 32)).digest()
        result.extend(a ^ b for a, b in zip(data[offset:offset + 32], key))
    return bytes(result)


def read_exact(sock, count):
    result = bytearray()
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise ValueError('BHTTP response ended early')
        result.extend(chunk)
    return bytes(result)


def probe(port):
    for mode, parameter in [(0, 0), (1, 32768), (2, 1399), (3, 8), (4, 1)]:
        sid = os.urandom(16)
        size = parameter if mode == 1 else 10
        clear = b'BHP1' + bytes([1, mode]) + struct.pack('!I', parameter)
        clear += bytes((i * 31) & 255 for i in range(10, size))
        request = b'\0' + sid + struct.pack('!QI', 0, len(clear)) + crypt(clear, sid)
        with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(request)
            status, length = struct.unpack('!BI', read_exact(sock, 5))
            expected_size = parameter if mode == 2 else 10
            if status != 0 or length != expected_size:
                raise ValueError(f'Unexpected BHP1 mode {mode} response: {status}/{length}')
            response = crypt(read_exact(sock, length), sid, True)
            expected = b'BHP1' + bytes([1, mode]) + struct.pack('!I', parameter)
            expected += bytes((i * 31) & 255 for i in range(10, expected_size))
            if response != expected:
                raise ValueError(f'Invalid BHP1 mode {mode} response')
    print(f'[OK] BHP1 calibration on local TCP {port}', flush=True)


def candidate(binary):
    # The OS selects a private test port; candidate startup cannot seize live ports.
    with tempfile.TemporaryFile(mode='w+b') as output:
        process = subprocess.Popen([binary, '--listen', '127.0.0.1:0', '--target', '127.0.0.1:22'],
                                   stdout=output, stderr=output)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                output.seek(0)
                match = re.search(rb'BHTTP listening on 127\.0\.0\.1:(\d+)', output.read())
                if match:
                    probe(int(match[1]))
                    return
                if process.poll() is not None:
                    raise ValueError('Candidate BHTTP process exited before listening')
                time.sleep(0.05)
            raise TimeoutError('Candidate BHTTP startup timed out')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--candidate')
    group.add_argument('--ports', nargs='+', type=int)
    args = parser.parse_args()
    if args.candidate:
        candidate(args.candidate)
    else:
        for port in args.ports:
            if not 1 <= port <= 65535:
                parser.error('Invalid port')
            probe(port)
