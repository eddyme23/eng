// Copied only into a temporary source tree by dnstt_transport_smoke.py.
// Tests genuine DNSTT/Noise streams through local, certificate-verified TLS resolvers.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

func TestEngEncryptedTransports(t *testing.T) {
	server := os.Getenv("ENG_DNSTT_TEST_SERVER")
	if server == "" { t.Fatal("ENG_DNSTT_TEST_SERVER is required") }
	for _, transport := range []string{"doh", "dot"} {
		t.Run(transport, func(t *testing.T) {
			directory := t.TempDir()
			private, public := filepath.Join(directory, "server.key"), filepath.Join(directory, "server.pub")
			if out, err := exec.Command(server, "-gen-key", "-privkey-file", private, "-pubkey-file", public).CombinedOutput(); err != nil { t.Fatalf("keygen %v: %s", err, out) }
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil { t.Fatal(err) }; defer echo.Close()
			go func() { for { c,e := echo.Accept(); if e != nil { return }; go func(){ defer c.Close(); io.Copy(c,c) }() } }()
			reservation, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil { t.Fatal(err) }; udpAddress := reservation.LocalAddr().String(); reservation.Close()
			command := exec.Command(server, "-udp", udpAddress, "-mtu", "1232", "-privkey-file", private, "eng-probe.example", echo.Addr().String())
			if err := command.Start(); err != nil { t.Fatal(err) }
			defer func(){ command.Process.Kill(); command.Wait() }()
			forward := func(query []byte) ([]byte,error) {
				c, err := net.Dial("udp", udpAddress); if err != nil { return nil,err }; defer c.Close()
				c.SetDeadline(time.Now().Add(5*time.Second))
				if _,err=c.Write(query); err != nil { return nil,err }
				reply:=make([]byte,65535); n,err:=c.Read(reply); return reply[:n],err
			}
			https := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
				query,err:=io.ReadAll(io.LimitReader(r.Body,65536)); if err!=nil { http.Error(w,"read",400); return }
				reply,err:=forward(query); if err!=nil { http.Error(w,"forward",502); return }
				w.Header().Set("Content-Type","application/dns-message"); w.Write(reply)
			}))
			https.EnableHTTP2=true; https.StartTLS()
			defer https.Close()
			pool:=x509.NewCertPool(); pool.AddCert(https.Certificate())
			// No InsecureSkipVerify: the private fixture CA is explicitly trusted here.
			tlsConfig:=&tls.Config{RootCAs:pool,MinVersion:tls.VersionTLS12}
			var wire net.PacketConn
			if transport=="doh" {
				wire,err=NewHTTPPacketConn(https.Client().Transport,https.URL+"/dns-query",32)
			} else {
				listener,e:=tls.Listen("tcp","127.0.0.1:0",https.TLS.Clone()); if e!=nil { t.Fatal(e) }; defer listener.Close()
				var connections sync.Map
				defer func(){ connections.Range(func(key,value interface{})bool{key.(net.Conn).Close(); return true}) }()
				go func(){for{c,e:=listener.Accept();if e!=nil{return};connections.Store(c,true);go func(){
					defer c.Close();defer connections.Delete(c);var write sync.Mutex
					for{var size uint16;if binary.Read(c,binary.BigEndian,&size)!=nil{return};q:=make([]byte,int(size));if _,e:=io.ReadFull(c,q);e!=nil{return}
						go func(q []byte){reply,e:=forward(q);if e!=nil{return};write.Lock();defer write.Unlock();binary.Write(c,binary.BigEndian,uint16(len(reply)));c.Write(reply)}(q)
					}
				}()} }()
				wire,err=NewTLSPacketConn(listener.Addr().String(),(&tls.Dialer{Config:tlsConfig}).DialContext)
			}
			if err!=nil{t.Fatal(err)}
			zone,err:=dns.ParseName("eng-probe.example");if err!=nil{t.Fatal(err)}
			remote:=turbotunnel.DummyAddr{}
			packet:=NewDNSPacketConn(wire,remote,zone);defer packet.Close()
			key,err:=readKeyFromFile(public);if err!=nil{t.Fatal(err)}
			local,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil{t.Fatal(e)};address:=local.Addr().(*net.TCPAddr);local.Close()
			go run(key,zone,address,remote,packet)
			var c net.Conn
			deadline:=time.Now().Add(20*time.Second)
			for time.Now().Before(deadline){c,err=net.DialTimeout("tcp",address.String(),100*time.Millisecond);if err==nil{break};time.Sleep(20*time.Millisecond)}
			if err!=nil{t.Fatal(err)};defer c.Close();c.SetDeadline(deadline)
			payload:=bytes.Repeat([]byte("verified DNSTT Noise/TLS stream\x00"),300)
			if _,err=c.Write(payload);err!=nil{t.Fatal(err)}
			reply:=make([]byte,len(payload));if _,err=io.ReadFull(c,reply);err!=nil{t.Fatal(err)}
			if !bytes.Equal(payload,reply){t.Fatal("stream mismatch")}
			t.Logf("%s verified %d bytes through TLS resolver -> UDP authoritative -> raw stream",transport,len(reply))
		})
	}
}
