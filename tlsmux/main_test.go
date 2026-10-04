package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestClassifyPreservesStream(t *testing.T) {
	for _, tc := range []struct{ data, target string }{{"SSH-2.0-client\r\n", "ssh"}, {"GET / HTTP/1.1\r\n", "http"}, {"GET /openvpn HTTP/1.1\r\n", "http"}} {
		t.Run(tc.target+tc.data[:3], func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			go func() { _, _ = io.WriteString(client, tc.data); _ = client.Close() }()
			target, reader, err := classify(server, "ssh", "http", time.Second)
			if err != nil || target != tc.target {
				t.Fatalf("target=%q err=%v", target, err)
			}
			data, err := io.ReadAll(reader)
			if err != nil || string(data) != tc.data {
				t.Fatalf("stream=%q err=%v", data, err)
			}
		})
	}
}

func TestIdleClientCanReadServerBanner(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	target, reader, err := classify(server, "ssh", "http", 20*time.Millisecond)
	if err != nil || target != "ssh" {
		t.Fatalf("target=%q err=%v", target, err)
	}
	// The timeout must not remain in the buffered reader or connection.
	go func() { _, _ = io.WriteString(client, "SSH-2.0-client\r\n"); _ = client.Close() }()
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "SSH-2.0-client\r\n" {
		t.Fatalf("stream=%q err=%v", data, err)
	}
}

func TestIncompleteHTTPDoesNotFallBackToSSH(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() { _, _ = io.WriteString(client, "GE") }()
	target, _, err := classify(server, "ssh", "http", 30*time.Millisecond)
	if err == nil || target == "ssh" {
		t.Fatalf("target=%q err=%v", target, err)
	}
}
