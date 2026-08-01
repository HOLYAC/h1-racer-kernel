package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/HOLYAC/h1-racer-kernel/internal/protocol"
	utls "github.com/bogdanfinn/utls"
)

type Factory struct {
	plan  protocol.CompiledPlan
	roots *x509.CertPool
}

type Connection struct {
	Conn                   net.Conn
	ConnectedAt            time.Time
	HandshakeAt            *time.Time
	LocalAddress           string
	RemoteAddress          string
	DialRoute              string
	ProxyAddress           string
	TLSVersion             string
	CipherSuite            string
	ALPN                   string
	CertificateVerified    *bool
	TLSIdentitySource      string
	TLSProfile             string
	ClientHelloBytes       int
	ClientHelloSHA256      string
	ClientHelloJA3         string
	ClientHelloJA3SHA256   string
	ClientHelloRecordCount int
}

func NewFactory(plan protocol.CompiledPlan) (*Factory, error) {
	var roots *x509.CertPool
	if plan.UseTLS && plan.TLS.CAFile != "" {
		pemBytes, err := os.ReadFile(plan.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("CA file contains no parseable certificates")
		}
	}
	return &Factory{plan: plan, roots: roots}, nil
}

func (f *Factory) Open(ctx context.Context) (*Connection, error) {
	dialer := &net.Dialer{Timeout: f.plan.ConnectTimeout, KeepAlive: 30 * time.Second}
	raw, dialRoute, proxyAddress, err := dialTarget(ctx, dialer, f.plan.Target, f.plan.ProxyURL)
	connectedAt := time.Now()
	if err != nil {
		return nil, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = raw.Close()
		}
	}()
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	_ = raw.SetDeadline(time.Now().Add(f.plan.ConnectTimeout))

	if !f.plan.UseTLS {
		_ = raw.SetDeadline(time.Time{})
		closeOnError = false
		return &Connection{
			Conn:          raw,
			ConnectedAt:   connectedAt,
			LocalAddress:  raw.LocalAddr().String(),
			RemoteAddress: raw.RemoteAddr().String(),
			DialRoute:     dialRoute,
			ProxyAddress:  proxyAddress,
		}, nil
	}

	config := &utls.Config{
		ServerName:         f.plan.ServerName,
		RootCAs:            f.roots,
		InsecureSkipVerify: f.plan.TLS.InsecureSkipVerify,
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}

	traceRaw := newClientHelloCaptureConn(raw)
	identitySource := "profile"
	profile := f.plan.TLS.Profile
	var uconn *utls.UConn
	if f.plan.TLS.ClientHelloHex != "" {
		identitySource = "client_hello_hex"
		profile = ""
		spec, specErr := clientHelloSpecFromHex(f.plan.TLS.ClientHelloHex)
		if specErr != nil {
			return nil, specErr
		}
		uconn = utls.UClient(traceRaw, config, utls.HelloCustom, false, true, true)
		if err = uconn.ApplyPreset(spec); err != nil {
			return nil, fmt.Errorf("apply client hello: %w", err)
		}
	} else {
		id, idErr := profileID(f.plan.TLS.Profile)
		if idErr != nil {
			return nil, idErr
		}
		uconn = utls.UClient(traceRaw, config, id, false, true, true)
	}
	if err = uconn.HandshakeContext(ctx); err != nil {
		return nil, phaseError("handshake", fmt.Errorf("TLS handshake: %w", err))
	}
	handshakeAt := time.Now()
	_ = uconn.SetDeadline(time.Time{})
	state := uconn.ConnectionState()
	if state.NegotiatedProtocol != "http/1.1" {
		return nil, phaseError("handshake", fmt.Errorf(
			"TLS peer negotiated ALPN %q; required http/1.1",
			state.NegotiatedProtocol,
		))
	}
	captured, overflow := traceRaw.snapshot()
	evidence, evidenceErr := analyzeCapturedClientHello(captured, overflow)
	if evidenceErr != nil {
		return nil, phaseError("handshake", fmt.Errorf("capture outbound ClientHello: %w", evidenceErr))
	}
	verified := !f.plan.TLS.InsecureSkipVerify
	closeOnError = false
	return &Connection{
		Conn:                   uconn,
		ConnectedAt:            connectedAt,
		HandshakeAt:            &handshakeAt,
		LocalAddress:           raw.LocalAddr().String(),
		RemoteAddress:          raw.RemoteAddr().String(),
		DialRoute:              dialRoute,
		ProxyAddress:           proxyAddress,
		TLSVersion:             tls.VersionName(state.Version),
		CipherSuite:            tls.CipherSuiteName(state.CipherSuite),
		ALPN:                   state.NegotiatedProtocol,
		CertificateVerified:    &verified,
		TLSIdentitySource:      identitySource,
		TLSProfile:             profile,
		ClientHelloBytes:       evidence.Bytes,
		ClientHelloSHA256:      evidence.SHA256,
		ClientHelloJA3:         evidence.JA3,
		ClientHelloJA3SHA256:   evidence.JA3SHA256,
		ClientHelloRecordCount: evidence.RecordCount,
	}, nil
}

func WriteAll(conn net.Conn, data []byte, timeout time.Duration) error {
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer conn.SetWriteDeadline(time.Time{})
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func ReadRaw(conn net.Conn, maxBytes int, idleTimeout time.Duration) ([]byte, string, error) {
	buffer := make([]byte, 32<<10)
	response := make([]byte, 0, min(maxBytes, 64<<10))
	for {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return response, "deadline_error", err
		}
		n, err := conn.Read(buffer)
		if n > 0 {
			remaining := maxBytes - len(response)
			if n > remaining {
				response = append(response, buffer[:remaining]...)
				return response, "max_bytes", nil
			}
			response = append(response, buffer[:n]...)
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			return response, "eof", nil
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() && len(response) > 0 {
			return response, "idle_timeout", nil
		}
		return response, "read_error", err
	}
}
