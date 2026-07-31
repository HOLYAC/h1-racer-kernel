package race

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HOLYAC/h1-racer-kernel/internal/protocol"
)

func TestRunFiresPlainTCPConnections(t *testing.T) {
	const copies = 6
	address, requests, closeServer := startPlainServer(t, copies)
	defer closeServer()
	prefix := []byte("GET /plain HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Race: armed\r\n")
	suffix := []byte("\r\n")
	disabled := false
	plan := protocol.RacePlan{
		SchemaVersion:    protocol.SchemaVersion,
		Target:           address,
		TLS:              protocol.TLSPlan{Enabled: &disabled},
		Copies:           copies,
		PrefixBase64:     base64.StdEncoding.EncodeToString(prefix),
		SuffixBase64:     base64.StdEncoding.EncodeToString(suffix),
		ConnectTimeoutMS: 5000,
		IOTimeoutMS:      2000,
		SettleMS:         5,
	}
	compiled, err := plan.Compile()
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), compiled)
	if !report.Fired || report.ReadyCount != copies || report.AbortError != "" {
		t.Fatalf("unexpected report: fired=%v ready=%d abort=%q", report.Fired, report.ReadyCount, report.AbortError)
	}
	for _, result := range report.Connections {
		if result.Error != "" || result.Phase != "complete" {
			t.Fatalf("connection %d: phase=%s error=%s", result.Index, result.Phase, result.Error)
		}
		if result.HandshakeAfterStartNS != nil || result.TLSVersion != "" {
			t.Fatalf("connection %d reported TLS metadata for plain TCP", result.Index)
		}
	}
	want := string(append(append([]byte{}, prefix...), suffix...))
	for range copies {
		select {
		case request := <-requests:
			if string(request) != want {
				t.Fatalf("request bytes changed: %q", request)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("server did not receive every request")
		}
	}
}

func TestRunFiresAllConnections(t *testing.T) {
	const copies = 6
	address, requests, closeServer := startTLSServer(t, copies)
	defer closeServer()
	prefix := []byte("GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Race: armed\r\n")
	suffix := []byte("\r\n")
	plan := protocol.RacePlan{
		SchemaVersion:    protocol.SchemaVersion,
		Target:           address,
		ServerName:       "localhost",
		TLS:              protocol.TLSPlan{Profile: "default", InsecureSkipVerify: true},
		Copies:           copies,
		PrefixBase64:     base64.StdEncoding.EncodeToString(prefix),
		SuffixBase64:     base64.StdEncoding.EncodeToString(suffix),
		ConnectTimeoutMS: 5000,
		IOTimeoutMS:      2000,
		SettleMS:         5,
	}
	compiled, err := plan.Compile()
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), compiled)
	if !report.Fired || report.ReadyCount != copies || report.AbortError != "" {
		t.Fatalf("unexpected report: fired=%v ready=%d abort=%q", report.Fired, report.ReadyCount, report.AbortError)
	}
	for _, result := range report.Connections {
		if result.Error != "" || result.Phase != "complete" {
			t.Fatalf("connection %d: phase=%s error=%s", result.Index, result.Phase, result.Error)
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(result.ResponseBase64)
		if decodeErr != nil || !bytes.Contains(decoded, []byte("200 OK")) {
			t.Fatalf("connection %d response is invalid", result.Index)
		}
	}
	for index := 0; index < copies; index++ {
		select {
		case request := <-requests:
			if string(request) != string(append(append([]byte{}, prefix...), suffix...)) {
				t.Fatalf("request bytes changed: %q", request)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("server did not receive every request")
		}
	}
}

func TestRunAbortsBeforeFireWhenOneHandshakeFails(t *testing.T) {
	const copies = 5
	address, completedRequests, closeServer := startRejectOneTLSServer(t, copies)
	defer closeServer()
	plan := protocol.RacePlan{
		SchemaVersion:    protocol.SchemaVersion,
		Target:           address,
		ServerName:       "localhost",
		TLS:              protocol.TLSPlan{Profile: "default", InsecureSkipVerify: true},
		Copies:           copies,
		PrefixBase64:     base64.StdEncoding.EncodeToString([]byte("GET /abort HTTP/1.1\r\nHost: localhost\r\nX-Armed: yes\r\n")),
		SuffixBase64:     base64.StdEncoding.EncodeToString([]byte("\r\n")),
		ConnectTimeoutMS: 3000,
		IOTimeoutMS:      1000,
	}
	compiled, err := plan.Compile()
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), compiled)
	if report.Fired {
		t.Fatal("race fired after a pre-FIRE handshake failure")
	}
	if report.AbortError == "" {
		t.Fatal("missing abort error")
	}
	select {
	case request := <-completedRequests:
		t.Fatalf("server received a completed request after abort: %q", request)
	case <-time.After(150 * time.Millisecond):
	}
}

func startPlainServer(t *testing.T, expected int) (string, <-chan []byte, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan []byte, expected)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				request, readErr := readHeaders(conn)
				if readErr != nil {
					return
				}
				requests <- request
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
			}()
		}
	}()
	return listener.Addr().String(), requests, func() {
		_ = listener.Close()
		wg.Wait()
	}
}

func startRejectOneTLSServer(t *testing.T, expected int) (string, <-chan []byte, func()) {
	t.Helper()
	certificate := selfSignedCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	completed := make(chan []byte, expected)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		accepted := 0
		for accepted < expected {
			raw, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			accepted++
			if accepted == 1 {
				_ = raw.Close()
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if handshakeErr := conn.HandshakeContext(ctx); handshakeErr != nil {
					return
				}
				request, readErr := readHeaders(conn)
				if readErr == nil {
					completed <- request
				}
			}()
		}
	}()
	return listener.Addr().String(), completed, func() {
		cancel()
		_ = listener.Close()
		wg.Wait()
	}
}

func startTLSServer(t *testing.T, expected int) (string, <-chan []byte, func()) {
	t.Helper()
	certificate := selfSignedCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan []byte, expected)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				if handshakeErr := conn.HandshakeContext(ctx); handshakeErr != nil {
					return
				}
				request, readErr := readHeaders(conn)
				if readErr != nil {
					return
				}
				requests <- request
				body := "ok"
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}()
		}
	}()
	return listener.Addr().String(), requests, func() {
		cancel()
		_ = listener.Close()
		wg.Wait()
	}
}

func readHeaders(reader io.Reader) ([]byte, error) {
	var data []byte
	buffer := make([]byte, 256)
	for !strings.Contains(string(data), "\r\n\r\n") {
		n, err := reader.Read(buffer)
		if n > 0 {
			data = append(data, buffer[:n]...)
		}
		if err != nil {
			return data, err
		}
		if len(data) > 64<<10 {
			return data, fmt.Errorf("request too large")
		}
	}
	return data, nil
}

func selfSignedCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
