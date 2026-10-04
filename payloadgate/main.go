package main

import (
	"bufio"
	"bytes"
	"flag"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const maxHeader = 32 * 1024
const maxPreface = 64 * 1024

// Read bytewise from the buffered reader so even a line without a newline
// cannot allocate an unbounded header before the size check.
func readHeader(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 0, 4096)
	for len(header) < maxHeader {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		header = append(header, b)
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) || bytes.HasSuffix(header, []byte("\n\n")) {
			return header, nil
		}
	}
	return nil, io.ErrShortBuffer
}

// GF payloads may include multiple HTTP-looking headers before SSH starts.
// This runs only on the inbound copy: the server banner can flow immediately.
func waitForSSH(reader *bufio.Reader) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	for len(buf) < maxPreface {
		remaining := maxPreface - len(buf)
		if remaining > 2048 {
			remaining = 2048
		}
		chunk := make([]byte, remaining)
		n, err := reader.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if index := bytes.Index(buf, []byte("SSH-")); index >= 0 {
				return buf[index:], nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, io.ErrShortBuffer
}

func hasWebSocketKey(header []byte) bool {
	for _, line := range strings.Split(string(header), "\n")[1:] {
		fields := strings.SplitN(line, ":", 2)
		if len(fields) == 2 && strings.EqualFold(strings.TrimSpace(fields[0]), "Sec-WebSocket-Key") {
			return true
		}
	}
	return false
}

func copyTunnel(client, backend net.Conn, inbound func() error) {
	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		if err := inbound(); err != nil {
			_ = client.Close()
			_ = backend.Close()
			return
		}
		if tcp, ok := backend.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	go func() {
		defer copies.Done()
		_, _ = io.Copy(client, backend)
		_ = client.Close()
	}()
	copies.Wait()
}

func handle(client net.Conn, sshTarget, wsTarget, openvpnTarget string) {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(client)
	header, err := readHeader(reader)
	if err != nil {
		log.Printf("read header: %v", err)
		return
	}
	target := sshTarget
	websocket := hasWebSocketKey(header)
	request := strings.Fields(strings.SplitN(string(header), "\n", 2)[0])
	openvpn := len(request) >= 2 && request[0] == "GET" && request[1] == "/openvpn"
	if openvpn {
		target = openvpnTarget
	} else if websocket {
		target = wsTarget
	}
	backend, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		log.Printf("connect %s: %v", target, err)
		return
	}
	defer backend.Close()
	if websocket || openvpn {
		// sshws validates the upgrade and handles RFC 6455 framing.
		_ = backend.SetWriteDeadline(time.Now().Add(15 * time.Second))
		if _, err := backend.Write(header); err != nil {
			return
		}
		_ = backend.SetWriteDeadline(time.Time{})
		_ = client.SetDeadline(time.Time{})
		copyTunnel(client, backend, func() error { _, err := io.Copy(backend, reader); return err })
		return
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(string(header))), "CONNECT ") {
		response = "HTTP/1.1 200 Connection established\r\nConnection: keep-alive\r\n\r\n"
	}
	if _, err := io.WriteString(client, response); err != nil {
		return
	}
	_ = client.SetWriteDeadline(time.Time{})
	// Connect before waiting for client identification. SSH clients can receive
	// the server banner even when they send no bytes after the HTTP upgrade.
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	copyTunnel(client, backend, func() error {
		firstSSH, err := waitForSSH(reader)
		if err != nil {
			return err
		}
		_ = client.SetReadDeadline(time.Time{})
		_, err = io.Copy(backend, io.MultiReader(bytes.NewReader(firstSSH), reader))
		return err
	})
}

func main() {
	listen := flag.String("listen", "127.0.0.1:3102", "payload gateway listener")
	sshTarget := flag.String("ssh-target", "127.0.0.1:143", "raw SSH target")
	wsTarget := flag.String("ws-target", "127.0.0.1:3103", "SSH WebSocket target")
	openvpnTarget := flag.String("openvpn-target", "127.0.0.1:10081", "OpenVPN HTTP upgrade target")
	flag.Parse()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("payload gateway listening on %s", *listen)
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(client, *sshTarget, *wsTarget, *openvpnTarget)
	}
}
