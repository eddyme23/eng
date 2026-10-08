package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

func maskedFrame(opcode byte, payload string) []byte {
	frame := []byte{0x80 | opcode, 0x80 | byte(len(payload)), 1, 2, 3, 4}
	for i, b := range []byte(payload) {
		frame = append(frame, b^byte(i%4+1))
	}
	return frame
}
func TestPingPongAndSSHStream(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	var out bytes.Buffer
	input := append(maskedFrame(9, "keepalive"), maskedFrame(10, "ignored")...)
	input = append(input, maskedFrame(2, "SSH-")...)
	done := make(chan error, 1)
	go func() {
		done <- relayWebSocketToSSH(bufio.NewReader(bytes.NewReader(input)), server, &frameWriter{writer: &out})
	}()
	data := make([]byte, 4)
	if _, err := io.ReadFull(client, data); err != nil || string(data) != "SSH-" {
		t.Fatalf("SSH=%q err=%v", data, err)
	}
	if err := <-done; err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), append([]byte{0x8a, 9}, []byte("keepalive")...)) {
		t.Fatalf("pong=%x", out.Bytes())
	}
}
func TestConcurrentFramesStayIntact(t *testing.T) {
	var out bytes.Buffer
	writer := &frameWriter{writer: &out}
	var wg sync.WaitGroup
	for _, opcode := range []byte{2, 10} {
		wg.Add(1)
		go func(op byte) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := writer.write(op, []byte("abc")); err != nil {
					t.Error(err)
				}
			}
		}(opcode)
	}
	wg.Wait()
	r := bytes.NewReader(out.Bytes())
	counts := map[byte]int{}
	for r.Len() > 0 {
		first, _ := r.ReadByte()
		length, _ := r.ReadByte()
		data := make([]byte, int(length))
		if _, err := io.ReadFull(r, data); err != nil {
			t.Fatal(err)
		}
		if string(data) != "abc" {
			t.Fatalf("corrupted %x", data)
		}
		counts[first]++
	}
	if counts[0x82] != 100 || counts[0x8a] != 100 {
		t.Fatal(counts)
	}
}
func TestInvalidControlFrameRejected(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	frame := maskedFrame(9, "ping")
	frame[0] = 9
	if err := relayWebSocketToSSH(bufio.NewReader(bytes.NewReader(frame)), server, &frameWriter{writer: io.Discard}); err == nil {
		t.Fatal("fragmented ping accepted")
	}
}
