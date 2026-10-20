import asyncio
import importlib.util
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dispatch', ROOT / 'dns-dispatch.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def query(name, ident=b'AA'):
    return ident + struct.pack('!5H', 0x0100, 1, 0, 0, 1) + b''.join(
        bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0\0\x10\0\1' + b'\0\0\x29\x04\xd0\0\0\0\0\0\0'


class Backend(asyncio.DatagramProtocol):
    def __init__(self, marker):
        self.marker = marker
        self.received = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.append(data)
        self.transport.sendto(data[:2] + bytes([data[2] | 0x80]) + data[3:] + self.marker, addr)


class DispatcherTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.loop = asyncio.get_running_loop()
        self.transports = []
        routes = {}
        self.backends = []
        for name, marker in [('ns.example.com', b'SLOW'), ('v.example.com', b'VAY')]:
            backend = Backend(marker)
            transport, _ = await self.loop.create_datagram_endpoint(lambda: backend, local_addr=('127.0.0.1', 0))
            self.transports.append(transport)
            self.backends.append(backend)
            routes[name] = transport.get_extra_info('sockname')
        transport, self.dispatcher = await self.loop.create_datagram_endpoint(
            lambda: module.Dispatcher(routes, timeout=0.1), local_addr=('127.0.0.1', 0))
        self.transports.append(transport)
        self.address = transport.get_extra_info('sockname')

    async def asyncTearDown(self):
        for transport in self.transports:
            transport.close()
        for task in list(self.dispatcher.tasks):
            task.cancel()
        await asyncio.sleep(0)

    async def exchange(self, packet):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.connect(self.address)
            await self.loop.sock_sendall(sock, packet)
            return await asyncio.wait_for(self.loop.sock_recv(sock, 65535), 1)
        finally:
            sock.close()

    async def test_routes_case_insensitively_and_preserves_edns_and_payload(self):
        packet = query('AbC.NS.Example.COM')
        reply = await self.exchange(packet)
        self.assertEqual(self.backends[0].received, [packet])
        self.assertEqual(reply, packet[:2] + bytes([packet[2] | 0x80]) + packet[3:] + b'SLOW')
        self.assertFalse(self.backends[1].received)

    async def test_concurrent_identical_ids_remain_isolated(self):
        replies = await asyncio.gather(*(self.exchange(query(name)) for name in
            ['a.ns.example.com', 'b.v.example.com'] * 12))
        self.assertEqual([reply[-4:] for reply in replies], [b'SLOW', b'\x00VAY'] * 12)

    async def test_unknown_domain_refused_without_backend_forwarding(self):
        reply = await self.exchange(query('ns.example.com.attacker.test'))
        self.assertEqual(reply[3] & 15, 5)
        self.assertFalse(any(backend.received for backend in self.backends))

    async def test_overload_and_malformed_packets_do_not_start_tasks(self):
        self.dispatcher.limit = 0
        self.dispatcher.datagram_received(query('v.example.com'), ('127.0.0.1', 9999))
        self.dispatcher.datagram_received(b'invalid', ('127.0.0.1', 9999))
        self.assertFalse(self.dispatcher.tasks)


class ConfigTest(unittest.TestCase):
    def test_rejects_overlapping_domains_and_external_backends(self):
        for routes in [
            {'example.com': ['127.0.0.1', 5301], 'v.example.com': ['127.0.0.1', 5302]},
            {'ns.example.com': ['8.8.8.8', 53], 'v.example.com': ['127.0.0.1', 5302]},
        ]:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'config.json'
                path.write_text(json.dumps({'listen': ['127.0.0.1', 53], 'routes': routes}))
                with self.assertRaises(ValueError):
                    module.load_config(path)


if __name__ == '__main__':
    unittest.main()
