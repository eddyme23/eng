package main

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
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
