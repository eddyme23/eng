package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadHeaderPreservesFollowingBytes(t *testing.T) {
	for _, end := range []string{"\r\n\r\n", "\n\n"} {
		header := "GET / HTTP/1.1" + end
		reader := bufio.NewReader(strings.NewReader(header + "SSH-2.0-client\r\n"))
		got, err := readHeader(reader)
		if err != nil || string(got) != header {
			t.Fatalf("header=%q err=%v", got, err)
		}
		rest, _ := io.ReadAll(reader)
		if string(rest) != "SSH-2.0-client\r\n" {
			t.Fatalf("remaining=%q", rest)
		}
	}
}

func TestReadHeaderRejectsOversizeLine(t *testing.T) {
	_, err := readHeader(bufio.NewReader(strings.NewReader(strings.Repeat("A", maxHeader+1))))
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("err=%v", err)
	}
}

func TestWaitForSSHSkipsChainedHeaders(t *testing.T) {
	input := "PATCH / HTTP/1.1\r\nHost: example.com\r\n\r\nSSH-2.0-client\r\nextra"
	reader := bufio.NewReader(strings.NewReader(input))
	first, err := waitForSSH(reader)
	if err != nil {
		t.Fatal(err)
	}
	rest, _ := io.ReadAll(reader)
	if string(append(first, rest...)) != "SSH-2.0-client\r\nextra" {
		t.Fatal("SSH bytes changed")
	}
}

func TestWaitForSSHBoundsPreface(t *testing.T) {
	_, err := waitForSSH(bufio.NewReader(bytes.NewReader(bytes.Repeat([]byte{'A'}, maxPreface+1))))
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("err=%v", err)
	}
}

func TestWebSocketKeyMustBeAHeader(t *testing.T) {
	if hasWebSocketKey([]byte("GET /Sec-WebSocket-Key:fake HTTP/1.1\r\nHost: example.com\r\n\r\n")) {
		t.Fatal("request path treated as a header")
	}
	if !hasWebSocketKey([]byte("GET / HTTP/1.1\r\nsEc-WebSocket-Key: value\r\n\r\n")) {
		t.Fatal("case-insensitive key missed")
	}
}

func TestLegacyDefersBackendAndClosesOnDisconnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() { defer close(done); handle(server, listener.Addr().String(), "unused", "unused") }()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	header, err := readHeader(reader)
	if err != nil || !bytes.HasPrefix(header, []byte("HTTP/1.1 101")) {
		t.Fatalf("response=%q err=%v", header, err)
	}
	tcpListener := listener.(*net.TCPListener)
	tcpListener.SetDeadline(time.Now().Add(50 * time.Millisecond))
	if premature, e := listener.Accept(); e == nil {
		premature.Close()
		t.Fatal("HTTP-only client opened SSH backend")
	}
	tcpListener.SetDeadline(time.Now().Add(time.Second))
	identification := "SSH-2.0-client\r\nextra"
	go func() { _, _ = io.WriteString(client, identification) }()
	backend, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	backend.SetDeadline(time.Now().Add(time.Second))
	data := make([]byte, len(identification))
	if _, err = io.ReadFull(backend, data); err != nil || string(data) != identification {
		t.Fatalf("SSH bytes=%q err=%v", data, err)
	}
	go func() { _, _ = io.WriteString(backend, "SSH-2.0-server\r\n") }()
	line, err := reader.ReadString('\n')
	if err != nil || line != "SSH-2.0-server\r\n" {
		t.Fatalf("banner=%q err=%v", line, err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler retained backend after client disconnected")
	}
	one := make([]byte, 1)
	if _, err = backend.Read(one); err != io.EOF {
		t.Fatalf("backend not closed: %v", err)
	}
}

func TestCopyTunnelClosesBothDirectionsOnInboundEOF(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	backend, backendPeer := net.Pipe()
	defer backendPeer.Close()
	done := make(chan struct{})
	go func() { copyTunnel(client, backend, func() error { return io.EOF }); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay stuck waiting on backend after inbound ended")
	}
}
