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
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HOLYAC/h1-racer-kernel/internal/protocol"
	"github.com/HOLYAC/h1-racer-kernel/internal/transport"
	utls "github.com/bogdanfinn/utls"
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
		if result.HandshakeAfterStartNS != nil || result.TLSVersion != "" ||
			result.CertificateVerified != nil || result.ClientHelloSHA256 != "" {
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
	structuralHash := ""
	for _, result := range report.Connections {
		if result.Error != "" || result.Phase != "complete" {
			t.Fatalf("connection %d: phase=%s error=%s", result.Index, result.Phase, result.Error)
		}
		if result.TLSIdentitySource != "profile" || result.TLSProfile != "default" {
			t.Fatalf("connection %d identity = %s/%s", result.Index, result.TLSIdentitySource, result.TLSProfile)
		}
		if result.CertificateVerified == nil || *result.CertificateVerified {
			t.Fatalf("connection %d did not report the explicit insecure test policy", result.Index)
		}
		if result.ClientHelloBytes == 0 || len(result.ClientHelloSHA256) != 64 ||
			result.ClientHelloJA3 == "" || len(result.ClientHelloJA3SHA256) != 64 ||
			result.ClientHelloRecordCount == 0 {
			t.Fatalf("connection %d has incomplete ClientHello evidence: %+v", result.Index, result)
		}
		if structuralHash == "" {
			structuralHash = result.ClientHelloJA3SHA256
		} else if result.ClientHelloJA3SHA256 != structuralHash {
			t.Fatalf("connection %d structural TLS identity drifted", result.Index)
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

func TestRunUsesCapturedCustomClientHello(t *testing.T) {
	const copies = 2
	address, requests, closeServer := startTLSServer(t, copies)
	defer closeServer()
	prefix := []byte("GET /custom-hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n")
	suffix := []byte("\r\n")
	plan := protocol.RacePlan{
		SchemaVersion: protocol.SchemaVersion,
		Target:        address,
		ServerName:    "localhost",
		TLS: protocol.TLSPlan{
			ClientHelloHex:     capturedClientHelloHex(t),
			InsecureSkipVerify: true,
		},
		Copies:           copies,
		PrefixBase64:     base64.StdEncoding.EncodeToString(prefix),
		SuffixBase64:     base64.StdEncoding.EncodeToString(suffix),
		ConnectTimeoutMS: 3000,
		IOTimeoutMS:      1000,
	}
	compiled, err := plan.Compile()
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), compiled)
	if !report.Fired || report.AbortError != "" {
		t.Fatalf("custom ClientHello race failed: fired=%v abort=%q", report.Fired, report.AbortError)
	}
	for _, result := range report.Connections {
		if result.TLSIdentitySource != "client_hello_hex" || result.TLSProfile != "" {
			t.Fatalf("connection %d identity = %s/%s", result.Index, result.TLSIdentitySource, result.TLSProfile)
		}
		if result.ClientHelloSHA256 == "" || result.ClientHelloJA3SHA256 == "" {
			t.Fatalf("connection %d lacks custom ClientHello evidence", result.Index)
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
			t.Fatal("server did not receive custom ClientHello request")
		}
	}
}

func TestRunReportsVerifiedCertificateWithCustomCA(t *testing.T) {
	const copies = 2
	certificate, certPEM := selfSignedCertificateMaterial(t)
	address, requests, closeServer := startTLSServerWithCertificate(t, copies, certificate)
	defer closeServer()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	prefix := []byte("GET /verified HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n")
	suffix := []byte("\r\n")
	plan := protocol.RacePlan{
		SchemaVersion:    protocol.SchemaVersion,
		Target:           address,
		ServerName:       "localhost",
		TLS:              protocol.TLSPlan{Profile: "default", CAFile: caFile},
		Copies:           copies,
		PrefixBase64:     base64.StdEncoding.EncodeToString(prefix),
		SuffixBase64:     base64.StdEncoding.EncodeToString(suffix),
		ConnectTimeoutMS: 3000,
		IOTimeoutMS:      1000,
	}
	compiled, err := plan.Compile()
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), compiled)
	if !report.Fired || report.AbortError != "" {
		t.Fatalf("verified race failed: fired=%v abort=%q", report.Fired, report.AbortError)
	}
	for _, result := range report.Connections {
		if result.CertificateVerified == nil || !*result.CertificateVerified {
			t.Fatalf("connection %d did not report verified certificate", result.Index)
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
			t.Fatal("server did not receive verified request")
		}
	}
}

func TestRunAbortsBeforeFireWhenALPNIsAbsent(t *testing.T) {
	const copies = 3
	address, closeServer := startTLSWithoutALPN(t, copies)
	defer closeServer()
	plan := protocol.RacePlan{
		SchemaVersion:    protocol.SchemaVersion,
		Target:           address,
		ServerName:       "localhost",
		TLS:              protocol.TLSPlan{Profile: "default", InsecureSkipVerify: true},
		Copies:           copies,
		PrefixBase64:     base64.StdEncoding.EncodeToString([]byte("GET /alpn HTTP/1.1\r\nHost: localhost\r\n")),
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
		t.Fatal("race fired without negotiated HTTP/1.1 ALPN")
	}
	if !strings.Contains(report.AbortError, "ALPN") {
		t.Fatalf("abort error = %q", report.AbortError)
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

func TestRunSupportsRepresentativeTLSProfiles(t *testing.T) {
	profiles := []string{"default", "chrome_146", "firefox_147", "safari_ios_18_0"}
	const copies = 2
	address, requests, closeServer := startTLSServer(t, len(profiles)*copies)
	defer closeServer()
	prefix := []byte("GET /profiles HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n")
	suffix := []byte("\r\n")
	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			plan := protocol.RacePlan{
				SchemaVersion:    protocol.SchemaVersion,
				Target:           address,
				ServerName:       "localhost",
				TLS:              protocol.TLSPlan{Profile: profile, InsecureSkipVerify: true},
				Copies:           copies,
				PrefixBase64:     base64.StdEncoding.EncodeToString(prefix),
				SuffixBase64:     base64.StdEncoding.EncodeToString(suffix),
				ConnectTimeoutMS: 3000,
				IOTimeoutMS:      1000,
			}
			compiled, err := plan.Compile()
			if err != nil {
				t.Fatal(err)
			}
			report := Run(context.Background(), compiled)
			if !report.Fired || report.AbortError != "" {
				t.Fatalf("profile %s failed: fired=%v abort=%q", profile, report.Fired, report.AbortError)
			}
			for _, result := range report.Connections {
				if result.Error != "" || result.TLSProfile != profile || result.TLSIdentitySource != "profile" {
					t.Fatalf("profile %s result: %+v", profile, result)
				}
			}
			for range copies {
				select {
				case request := <-requests:
					want := append(append([]byte{}, prefix...), suffix...)
					if !bytes.Equal(request, want) {
						t.Fatalf("profile %s changed request bytes", profile)
					}
				case <-time.After(2 * time.Second):
					t.Fatalf("profile %s request missing", profile)
				}
			}
		})
	}
}

func TestRunFiresIPv6LoopbackConnections(t *testing.T) {
	const copies = 3
	address, requests, closeServer, ok := tryStartPlainServer("tcp6", "[::1]:0", copies)
	if !ok {
		t.Skip("IPv6 loopback is unavailable")
	}
	defer closeServer()
	disabled := false
	prefix := []byte("GET /ipv6 HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n")
	suffix := []byte("\r\n")
	plan := protocol.RacePlan{
		SchemaVersion:    protocol.SchemaVersion,
		Target:           address,
		TLS:              protocol.TLSPlan{Enabled: &disabled},
		Copies:           copies,
		PrefixBase64:     base64.StdEncoding.EncodeToString(prefix),
		SuffixBase64:     base64.StdEncoding.EncodeToString(suffix),
		ConnectTimeoutMS: 3000,
		IOTimeoutMS:      1000,
	}
	compiled, err := plan.Compile()
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), compiled)
	if !report.Fired || report.ReadyCount != copies || report.AbortError != "" {
		t.Fatalf("IPv6 race failed: %+v", report)
	}
	for range copies {
		select {
		case request := <-requests:
			if !bytes.Equal(request, append(append([]byte{}, prefix...), suffix...)) {
				t.Fatal("IPv6 request bytes changed")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("IPv6 request missing")
		}
	}
}

func TestRunPhaseInterruptions(t *testing.T) {
	basePlan := func() protocol.CompiledPlan {
		disabled := false
		plan := protocol.RacePlan{
			SchemaVersion:    protocol.SchemaVersion,
			Target:           "127.0.0.1:1",
			TLS:              protocol.TLSPlan{Enabled: &disabled},
			Copies:           3,
			PrefixBase64:     base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: test\r\n")),
			SuffixBase64:     base64.StdEncoding.EncodeToString([]byte("\r\n")),
			ConnectTimeoutMS: 100,
			IOTimeoutMS:      100,
			SettleMS:         0,
			MaxResponseBytes: 1024,
		}
		compiled, err := plan.Compile()
		if err != nil {
			t.Fatal(err)
		}
		return compiled
	}

	t.Run("connect", func(t *testing.T) {
		factory := &scriptedOpener{open: func(int) (*transport.Connection, error) {
			return nil, &transport.PhaseError{Phase: "connect", Err: errors.New("synthetic refusal")}
		}}
		report := runWithOpener(context.Background(), basePlan(), factory)
		assertPreFirePhase(t, report, "connect")
	})

	t.Run("proxy", func(t *testing.T) {
		factory := &scriptedOpener{open: func(int) (*transport.Connection, error) {
			return nil, &transport.PhaseError{Phase: "proxy", Err: errors.New("synthetic proxy refusal")}
		}}
		report := runWithOpener(context.Background(), basePlan(), factory)
		assertPreFirePhase(t, report, "proxy")
	})

	t.Run("handshake", func(t *testing.T) {
		factory := &scriptedOpener{open: func(int) (*transport.Connection, error) {
			return nil, &transport.PhaseError{Phase: "handshake", Err: errors.New("synthetic TLS alert")}
		}}
		report := runWithOpener(context.Background(), basePlan(), factory)
		assertPreFirePhase(t, report, "handshake")
	})

	t.Run("arm", func(t *testing.T) {
		factory := newScriptedFactory(func(index int) *scriptedConn {
			conn := successfulScriptedConn()
			if index == 0 {
				conn.failWriteAt = 1
			}
			return conn
		})
		report := runWithOpener(context.Background(), basePlan(), factory)
		assertPreFirePhase(t, report, "arm")
	})

	t.Run("ready cancellation", func(t *testing.T) {
		plan := basePlan()
		plan.Settle = time.Second
		armed := make(chan struct{}, plan.Copies)
		factory := newScriptedFactory(func(int) *scriptedConn {
			conn := successfulScriptedConn()
			conn.afterFirstWrite = func() { armed <- struct{}{} }
			return conn
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan protocol.RaceReport, 1)
		go func() { done <- runWithOpener(ctx, plan, factory) }()
		for range plan.Copies {
			select {
			case <-armed:
			case <-time.After(2 * time.Second):
				t.Fatal("workers did not arm")
			}
		}
		cancel()
		report := <-done
		if report.Fired || !strings.Contains(report.AbortError, "canceled before FIRE") {
			t.Fatalf("ready cancellation escaped into FIRE: %+v", report)
		}
	})

	t.Run("fire", func(t *testing.T) {
		factory := newScriptedFactory(func(index int) *scriptedConn {
			conn := successfulScriptedConn()
			if index == 0 {
				conn.failWriteAt = 2
			}
			return conn
		})
		report := runWithOpener(context.Background(), basePlan(), factory)
		if !report.Fired || !hasFailedPhase(report, "fire") {
			t.Fatalf("fire failure not preserved: %+v", report)
		}
	})

	t.Run("response", func(t *testing.T) {
		factory := newScriptedFactory(func(index int) *scriptedConn {
			conn := successfulScriptedConn()
			if index == 0 {
				conn.readErr = errors.New("synthetic response reset")
				conn.response = nil
			}
			return conn
		})
		report := runWithOpener(context.Background(), basePlan(), factory)
		if !report.Fired || !hasFailedPhase(report, "response") {
			t.Fatalf("response failure not preserved: %+v", report)
		}
	})
}

func hasFailedPhase(report protocol.RaceReport, phase string) bool {
	for _, result := range report.Connections {
		if result.Phase == phase && result.Error != "" {
			return true
		}
	}
	return false
}

func assertPreFirePhase(t *testing.T, report protocol.RaceReport, phase string) {
	t.Helper()
	if report.Fired || report.AbortError == "" {
		t.Fatalf("phase %s did not abort before FIRE: %+v", phase, report)
	}
	found := false
	for _, result := range report.Connections {
		if result.Phase == phase && result.Error != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("phase %s was not recorded: %+v", phase, report.Connections)
	}
}

type scriptedOpener struct {
	next atomic.Int64
	open func(int) (*transport.Connection, error)
}

func (o *scriptedOpener) Open(context.Context) (*transport.Connection, error) {
	index := int(o.next.Add(1) - 1)
	return o.open(index)
}

func newScriptedFactory(makeConn func(int) *scriptedConn) *scriptedOpener {
	return &scriptedOpener{open: func(index int) (*transport.Connection, error) {
		conn := makeConn(index)
		now := time.Now()
		return &transport.Connection{
			Conn:          conn,
			ConnectedAt:   now,
			LocalAddress:  "127.0.0.1:10000",
			RemoteAddress: "127.0.0.1:10001",
			DialRoute:     "test",
		}, nil
	}}
}

type scriptedConn struct {
	writes          atomic.Int64
	failWriteAt     int64
	afterFirstWrite func()
	response        []byte
	readOffset      int
	readErr         error
	closed          atomic.Bool
}

func successfulScriptedConn() *scriptedConn {
	return &scriptedConn{
		response: []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"),
		readErr:  io.EOF,
	}
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.readOffset < len(c.response) {
		n := copy(p, c.response[c.readOffset:])
		c.readOffset += n
		return n, nil
	}
	return 0, c.readErr
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	call := c.writes.Add(1)
	if call == 1 && c.afterFirstWrite != nil {
		c.afterFirstWrite()
	}
	if c.failWriteAt != 0 && call == c.failWriteAt {
		return 0, errors.New("synthetic write reset")
	}
	return len(p), nil
}

func (c *scriptedConn) Close() error                     { c.closed.Store(true); return nil }
func (c *scriptedConn) LocalAddr() net.Addr              { return scriptedAddr("local") }
func (c *scriptedConn) RemoteAddr() net.Addr             { return scriptedAddr("remote") }
func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

type scriptedAddr string

func (a scriptedAddr) Network() string { return "test" }
func (a scriptedAddr) String() string  { return string(a) }

func capturedClientHelloHex(t *testing.T) string {
	t.Helper()
	client, server := net.Pipe()
	uconn := utls.UClient(
		client,
		&utls.Config{ServerName: "localhost", NextProtos: []string{"http/1.1"}},
		utls.HelloChrome_Auto,
		false,
		true,
		true,
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = uconn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = uconn.Handshake()
		_ = uconn.Close()
	}()
	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatal(err)
	}
	payloadLength := int(header[3])<<8 | int(header[4])
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatal(err)
	}
	record := append(append([]byte(nil), header...), payload...)
	_ = server.Close()
	<-done
	return hex.EncodeToString(record)
}

func startPlainServer(t *testing.T, expected int) (string, <-chan []byte, func()) {
	t.Helper()
	address, requests, closeServer, ok := tryStartPlainServer("tcp4", "127.0.0.1:0", expected)
	if !ok {
		t.Fatal("listen plain server")
	}
	return address, requests, closeServer
}

func tryStartPlainServer(network, address string, expected int) (string, <-chan []byte, func(), bool) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return "", nil, nil, false
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
	}, true
}

func startTLSWithoutALPN(t *testing.T, expected int) (string, func()) {
	t.Helper()
	certificate := selfSignedCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for accepted := 0; accepted < expected; accepted++ {
			raw, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer raw.Close()
				conn := tls.Server(raw, &tls.Config{
					Certificates: []tls.Certificate{certificate},
					MinVersion:   tls.VersionTLS12,
				})
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				_ = conn.HandshakeContext(ctx)
			}()
		}
	}()
	return listener.Addr().String(), func() {
		cancel()
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
	return startTLSServerWithCertificate(t, expected, selfSignedCertificate(t))
}

func startTLSServerWithCertificate(
	t *testing.T,
	expected int,
	certificate tls.Certificate,
) (string, <-chan []byte, func()) {
	t.Helper()
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
	certificate, _ := selfSignedCertificateMaterial(t)
	return certificate
}

func selfSignedCertificateMaterial(t *testing.T) (tls.Certificate, []byte) {
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
	return certificate, certPEM
}
