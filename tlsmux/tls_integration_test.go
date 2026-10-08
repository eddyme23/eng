package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestRealTLSSilentFallback(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				raw, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: version, MaxVersion: version})
				if e = server.Handshake(); e != nil {
					done <- e
					return
				}
				target, reader, e := classifyWithTimeout(server, "ssh", "http", 250*time.Millisecond)
				if e != nil {
					done <- e
					return
				}
				if target != "ssh" {
					done <- io.ErrUnexpectedEOF
					return
				}
				server.SetDeadline(time.Now().Add(time.Second))
				_, e = io.WriteString(server, "SSH-2.0-server\r\n")
				if e != nil {
					done <- e
					return
				}
				data := make([]byte, 4)
				_, e = io.ReadFull(reader, data)
				if e == nil && string(data) != "SSH-" {
					e = io.ErrUnexpectedEOF
				}
				done <- e
			}()
			client, e := tls.Dial("tcp", listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			banner := make([]byte, len("SSH-2.0-server\r\n"))
			if _, e = io.ReadFull(client, banner); e != nil {
				t.Fatal(e)
			}
			if _, e = io.WriteString(client, "SSH-"); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
