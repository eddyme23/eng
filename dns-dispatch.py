#!/usr/bin/env python3
"""Authoritative UDP tunnel dispatcher. No recursion, caching or packet rewriting."""
import argparse
import asyncio
import json
import socket
import struct


def question(packet):
    if len(packet) < 12:
        raise ValueError('short DNS header')
    _, flags, count, _, _, _ = struct.unpack('!6H', packet[:12])
    if flags & 0xF800 or count != 1:
        raise ValueError('expected one standard query')
    labels, offset = [], 12
    while True:
        if offset >= len(packet):
            raise ValueError('truncated question')
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            raise ValueError('invalid label')
        label = packet[offset:offset + length].decode('ascii').lower()
        if '.' in label or '\x00' in label:
            raise ValueError('invalid name label')
        labels.append(label)
        offset += length
        if offset - 12 > 254:
            raise ValueError('oversize name')
    if offset + 4 > len(packet):
        raise ValueError('truncated type/class')
    return '.'.join(labels), offset + 4


def choose(name, routes):
    for domain, target in sorted(routes.items(), key=lambda item: -len(item[0])):
        if name == domain or name.endswith('.' + domain):
            return target
    return None


class Dispatcher(asyncio.DatagramProtocol):
    def __init__(self, routes, limit=512, timeout=3):
        self.routes, self.limit, self.timeout = routes, limit, timeout
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            name, end = question(data)
            target = choose(name, self.routes)
        except (ValueError, UnicodeError, struct.error):
            return
        if target is None:
            # REFUSED, preserving only the question; never act as an open resolver.
            flags = 0x8005 | (struct.unpack('!H', data[2:4])[0] & 0x0100)
            self.transport.sendto(data[:2] + struct.pack('!5H', flags, 1, 0, 0, 0) + data[12:end], addr)
            return
        if len(self.tasks) >= self.limit:
            return
        task = asyncio.create_task(self.forward(data, addr, target))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def forward(self, data, addr, target):
        # A connected socket per outstanding request isolates identical DNS IDs
        # from different resolvers and accepts responses only from its backend.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.connect(tuple(target))
            loop = asyncio.get_running_loop()
            await loop.sock_sendall(sock, data)
            response = await asyncio.wait_for(loop.sock_recv(sock, 65535), self.timeout)
            if len(response) >= 12 and response[:2] == data[:2] and response[2] & 0x80:
                self.transport.sendto(response, addr)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            sock.close()


async def serve(config):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: Dispatcher(config['routes']), local_addr=tuple(config['listen']))
    try:
        await asyncio.Future()
    finally:
        transport.close()
        for task in protocol.tasks:
            task.cancel()


def load_config(path):
    with open(path, encoding='utf-8') as stream:
        config = json.load(stream)
    socket.inet_aton(config['listen'][0])
    if config['listen'][1] != 53 or len(config['routes']) != 2:
        raise ValueError('expected two tunnel domains and public UDP 53')
    domains = list(config['routes'])
    for domain, target in config['routes'].items():
        if domain != domain.lower() or not domain or len(domain) > 253:
            raise ValueError('invalid domain')
        if any(not label or len(label) > 63 or not all(c.isascii() and (c.isalnum() or c == '-') for c in label)
               or label.startswith('-') or label.endswith('-') for label in domain.split('.')):
            raise ValueError('invalid DNS label')
        if target[0] != '127.0.0.1' or target[1] not in (5301, 5302):
            raise ValueError('backend must be a reserved loopback listener')
    if domains[0] == domains[1] or any(a.endswith('.' + b) for a in domains for b in domains if a != b):
        raise ValueError('tunnel domains must not overlap')
    if {target[1] for target in config['routes'].values()} != {5301, 5302}:
        raise ValueError('each protocol needs its own backend')
    return config


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    settings = load_config(args.config)
    if not args.check:
        asyncio.run(serve(settings))
