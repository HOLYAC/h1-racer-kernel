package transport

import (
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/bogdanfinn/utls"
)

func TestValidateClientHelloHexAcceptsCapturedUTLSHello(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	config := &utls.Config{ServerName: "example.com", NextProtos: []string{"http/1.1"}}
	uconn := utls.UClient(client, config, utls.HelloChrome_Auto, false, true, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = uconn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = uconn.Handshake()
		_ = uconn.Close()
	}()

	header := make([]byte, 5)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("read TLS record header: %v", err)
	}
	payloadLength := int(header[3])<<8 | int(header[4])
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatalf("read TLS record payload: %v", err)
	}
	record := append(header, payload...)
	if err := ValidateClientHelloHex(hex.EncodeToString(record)); err != nil {
		t.Fatalf("captured ClientHello rejected: %v", err)
	}
	_ = server.Close()
	<-done
}

func TestValidateClientHelloHexRejectsMalformedInput(t *testing.T) {
	for _, value := range []string{"", "0", "zz", "00"} {
		if err := ValidateClientHelloHex(value); err == nil {
			t.Fatalf("malformed ClientHello %q was accepted", value)
		}
	}
}
