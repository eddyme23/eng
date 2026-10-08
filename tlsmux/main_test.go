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
			target, reader, err := classify(server, "ssh", "http")
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

func TestClassificationWaitsForClientBytes(t *testing.T) {
	for _, tc := range []struct{ prefix, rest, target string }{{"", "SSH-2.0-client\r\n", "ssh"}, {"GE", "T / HTTP/1.1\r\n", "http"}} {
		t.Run(tc.target, func(t *testing.T) {
			server, client := net.Pipe()
			defer server.Close()
			defer client.Close()
			done := make(chan error, 1)
			go func() {
				target, reader, err := classify(server, "ssh", "http")
				if err != nil {
					done <- err
					return
				}
				if target != tc.target {
					done <- io.ErrUnexpectedEOF
					return
				}
				data, err := io.ReadAll(reader)
				if err == nil && string(data) != tc.prefix+tc.rest {
					err = io.ErrUnexpectedEOF
				}
				done <- err
			}()
			if tc.prefix != "" {
				_, _ = io.WriteString(client, tc.prefix)
			}
			select {
			case err := <-done:
				t.Fatalf("classified before client identification: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			go func() { _, _ = io.WriteString(client, tc.rest); _ = client.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("classification did not finish after client data")
			}
		})
	}
}

func TestSilentClientFallsBackAndDeadlineClears(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	target, reader, err := classifyWithTimeout(server, "ssh", "http", 20*time.Millisecond)
	if err != nil || target != "ssh" {
		t.Fatalf("target=%q err=%v", target, err)
	}
	go func() { time.Sleep(30 * time.Millisecond); _, _ = io.WriteString(client, "SSH-") }()
	data := make([]byte, 4)
	if _, err := io.ReadFull(reader, data); err != nil || string(data) != "SSH-" {
		t.Fatalf("read after idle fallback: %q %v", data, err)
	}
}

func TestPartialHTTPDoesNotFallBack(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() {
		_, _ = io.WriteString(client, "G")
		time.Sleep(60 * time.Millisecond)
		_, _ = io.WriteString(client, "ET / HTTP/1.1\r\n")
		_ = client.Close()
	}()
	target, reader, err := classifyWithTimeout(server, "ssh", "http", 20*time.Millisecond)
	if err != nil || target != "http" {
		t.Fatalf("target=%q err=%v", target, err)
	}
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "GET / HTTP/1.1\r\n" {
		t.Fatalf("stream=%q err=%v", data, err)
	}
}

func TestStalledPartialPrefixTimesOut(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	go func() { _, _ = io.WriteString(client, "G") }()
	target, _, err := classifyWithLimits(server, "ssh", "http", time.Second, 20*time.Millisecond)
	if err == nil || target != "" {
		t.Fatalf("partial prefix routed: %q %v", target, err)
	}
	if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("expected timeout: %v", err)
	}
}
