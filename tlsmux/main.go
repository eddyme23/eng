package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

func proxy(client net.Conn, reader io.Reader, target string, connectTimeout time.Duration, timing bool) {
	started := time.Now()
	backend, err := net.DialTimeout("tcp", target, connectTimeout)
	if err != nil {
		log.Printf("connect %s: %v", target, err)
		_ = client.Close()
		return
	}
	if timing {
		log.Printf("backend ready target=%s connect=%s", target, time.Since(started))
	}
	defer backend.Close()
	defer client.Close()

	var copies sync.WaitGroup
	copies.Add(2)
	go func() { defer copies.Done(); _, _ = io.Copy(backend, reader); _ = backend.(*net.TCPConn).CloseWrite() }()
	go func() { defer copies.Done(); _, _ = io.Copy(client, backend) }()
	copies.Wait()
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9443", "TLS listener")
	certPath := flag.String("cert", "/etc/certificates/main.crt", "certificate file")
	keyPath := flag.String("key", "/etc/certificates/main.key", "private key file")
	sshTarget := flag.String("ssh-target", "127.0.0.1:143", "raw SSH target")
	http1Target := flag.String("http1-target", "127.0.0.1:9081", "HTTP/1.1 target")
	h2Target := flag.String("h2-target", "127.0.0.1:9080", "HTTP/2 target")
	silentTimeout := flag.Duration("silent-timeout", 250*time.Millisecond, "silent TLS client fallback to SSH")
	identifyTimeout := flag.Duration("identify-timeout", 15*time.Second, "maximum time to finish a partial protocol prefix")
	connectTimeout := flag.Duration("connect-timeout", 5*time.Second, "backend connection limit")
	timing := flag.Bool("log-timing", false, "log TLS handshake, routing and backend connection durations")
	flag.Parse()
	if *silentTimeout <= 0 || *identifyTimeout <= 0 || *connectTimeout <= 0 {
		log.Fatal("timeouts must be positive")
	}

	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := tls.Listen("tcp", *listen, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tlsmux listening on %s", *listen)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			started := time.Now()
			tlsConn := c.(*tls.Conn)
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			if err := tlsConn.Handshake(); err != nil {
				log.Printf("TLS handshake: %v", err)
				return
			}
			handshakeElapsed := time.Since(started)
			_ = c.SetDeadline(time.Time{})
			reader := bufio.NewReader(c)
			target := *http1Target
			if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
				target = *h2Target
			} else {
				var err error
				target, reader, err = classifyWithLimits(c, *sshTarget, *http1Target, *silentTimeout, *identifyTimeout)
				if err != nil {
					log.Printf("classify TLS stream: %v", err)
					return
				}
			}
			if *timing {
				log.Printf("TLS route target=%s handshake=%s classify=%s", target, handshakeElapsed, time.Since(started)-handshakeElapsed)
			}
			proxy(c, reader, target, *connectTimeout, *timing)
		}(conn)
	}
}

// A silent TLS client may be waiting for Dropbear to send its SSH banner.
func classify(c net.Conn, sshTarget, httpTarget string) (string, *bufio.Reader, error) {
	return classifyWithTimeout(c, sshTarget, httpTarget, 250*time.Millisecond)
}

func classifyWithTimeout(c net.Conn, sshTarget, httpTarget string, idle time.Duration) (string, *bufio.Reader, error) {
	return classifyWithLimits(c, sshTarget, httpTarget, idle, 15*time.Second)
}

func classifyWithLimits(c net.Conn, sshTarget, httpTarget string, idle, identify time.Duration) (string, *bufio.Reader, error) {
	reader := bufio.NewReader(c)
	if err := c.SetReadDeadline(time.Now().Add(idle)); err != nil {
		return "", reader, err
	}
	_, err := reader.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() && reader.Buffered() == 0 {
			return sshTarget, reader, nil
		}
		return "", reader, err
	}
	// A partial prefix gets a separate limit and must never fall back to SSH.
	if err := c.SetReadDeadline(time.Now().Add(identify)); err != nil {
		return "", reader, err
	}
	defer c.SetReadDeadline(time.Time{})
	prefix, err := reader.Peek(4)
	if err != nil {
		return "", reader, err
	}
	if strings.HasPrefix(string(prefix), "SSH-") {
		return sshTarget, reader, nil
	}
	return httpTarget, reader, nil
}
