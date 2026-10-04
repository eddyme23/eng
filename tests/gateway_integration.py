"""Local TCP checks for GF payloads and SSH WebSocket frame forwarding.
Usage: python tests/gateway_integration.py --gf gfraw/proxy.js --sshws PATH --payloadgate PATH
Requires node on PATH and prebuilt Go gateway executables. Uses ephemeral ports.
"""
import argparse, base64, hashlib, socket, subprocess, threading, time

BANNER = b'SSH-2.0-test-backend\r\n'
def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0)); return s.getsockname()[1]
def backend(port):
    listener = socket.socket(); listener.bind(('127.0.0.1', port)); listener.listen(8)
    def echo(c):
        with c:
            c.sendall(BANNER)
            while True:
                d = c.recv(65536)
                if not d: return
                c.sendall(d)
    def accept():
        while True:
            try: c, _ = listener.accept()
            except OSError: return
            threading.Thread(target=echo, args=(c,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    return listener

def read_until(c, marker):
    b = b''
    while not b.endswith(marker):
        d = c.recv(1)
        assert d, 'connection closed before expected data'
        b += d
    return b

def read_exact(c, n):
    b = b''
    while len(b) < n:
        d = c.recv(n-len(b)); assert d; b += d
    return b

def legacy(port, method):
    with socket.create_connection(('127.0.0.1', port), 3) as c:
        c.sendall(method+b' / HTTP/1.1\r\nHost: example.com\r\n\r\n')
        response = read_until(c, b'\r\n\r\n')
        assert response.startswith(b'HTTP/1.1 '+(b'200' if method==b'CONNECT' else b'101'))
        # Client waits for the server banner before sending SSH identification.
        assert read_until(c, b'\r\n') == BANNER
        payload = b'SSH-2.0-client\r\n'; c.sendall(payload)
        assert read_exact(c, len(payload)) == payload

def websocket(port):
    key = 'dGhlIHNhbXBsZSBub25jZQ=='
    with socket.create_connection(('127.0.0.1', port), 3) as c:
        c.sendall(('GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: '+key+'\r\nSec-WebSocket-Version: 13\r\n\r\n').encode())
        response = read_until(c, b'\r\n\r\n')
        expected = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        assert b'Sec-WebSocket-Accept: '+expected in response
        def frame():
            head = read_exact(c, 2); assert head[0] == 0x82
            n = head[1] & 127; assert n < 126
            return read_exact(c, n)
        assert frame() == BANNER
        payload = b'SSH-2.0-client\r\n'; mask = b'abcd'
        c.sendall(bytes([0x82, 0x80|len(payload)])+mask+bytes(v^mask[i%4] for i,v in enumerate(payload)))
        assert frame() == payload

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--gf',required=True); parser.add_argument('--sshws',required=True); parser.add_argument('--payloadgate',required=True); args=parser.parse_args()
    ports=[free_port() for _ in range(4)]; ssh,gf,ws,gate=ports; listener=backend(ssh); processes=[]
    try:
        commands=[['node',args.gf,str(gf),'127.0.0.1',str(ssh)], [args.sshws,'-listen','127.0.0.1:'+str(ws),'-ssh-target','127.0.0.1:'+str(ssh)], [args.payloadgate,'-listen','127.0.0.1:'+str(gate),'-ssh-target','127.0.0.1:'+str(ssh),'-ws-target','127.0.0.1:'+str(ws),'-legacy-target','127.0.0.1:'+str(gf)]]
        for cmd in commands: processes.append(subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        for port in [gf,ws,gate]:
            for _ in range(50):
                try:
                    with socket.create_connection(('127.0.0.1',port),.1): pass
                    break
                except OSError: time.sleep(.1)
            else: raise AssertionError('gateway did not start')
        for port in [gf,gate]:
            for method in [b'GET',b'CONNECT']:
                print('legacy', port, method, flush=True); legacy(port,method)
        for port in [ws,gate]:
            print('websocket',port,flush=True); websocket(port)
        print('PASS: GF GET/CONNECT banner and byte forwarding; direct and gateway WebSocket handshake and masked-frame forwarding (6 cases).')
    finally:
        for proc in processes: proc.terminate(); proc.wait()
        listener.close()
if __name__=='__main__': main()
