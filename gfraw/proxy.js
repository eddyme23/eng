// GF legacy clients send an HTTP-looking upgrade followed by raw SSH bytes.
// This listener does not parse RFC 6455 frames; standard WebSockets use sshws.
const net = require('net');
const listenPort = Number(process.argv[2] || 3104);
const sshHost = process.argv[3] || '127.0.0.1';
const sshPort = Number(process.argv[4] || 143);
const headerEnd = b => {
  let n = b.indexOf('\r\n\r\n');
  return n >= 0 ? n + 4 : ((n = b.indexOf('\n\n')) >= 0 ? n + 2 : -1);
};
net.createServer(client => {
  let buffered = Buffer.alloc(0), upstream;
  client.setTimeout(15000);
  const close = () => { if (upstream) upstream.destroy(); client.destroy(); };
  const read = chunk => {
    buffered = Buffer.concat([buffered, chunk]);
    if (buffered.length > 65536) return close();
    const end = headerEnd(buffered);
    if (end < 0) return;
    const connect = buffered.subarray(0, 8).toString('ascii').toUpperCase().startsWith('CONNECT ');
    client.pause();
    client.removeListener('data', read);
    upstream = net.connect(sshPort, sshHost, () => {
      client.setTimeout(0);
      client.write(connect ? 'HTTP/1.1 200 Connection established\r\n\r\n' : 'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
      // Discard chained HTTP payload headers already received in the preface.
      let first = buffered.subarray(end);
      while (/^(GET|POST|CONNECT|HEAD|PUT|OPTIONS|PATCH|DELETE|TRACE) /.test(first.toString('latin1', 0, 16))) {
        const next = headerEnd(first);
        if (next < 0) break;
        first = first.subarray(next);
      }
      if (first.length) upstream.write(first);
      client.pipe(upstream); upstream.pipe(client); client.resume();
    });
    upstream.setTimeout(15000, close);
    upstream.once('connect', () => upstream.setTimeout(0));
    upstream.on('error', close);
    upstream.on('close', () => client.destroy());
  };
  client.on('data', read);
  client.on('timeout', close);
  client.on('error', close);
  client.on('close', () => { if (upstream) upstream.destroy(); });
}).listen(listenPort, '127.0.0.1');
