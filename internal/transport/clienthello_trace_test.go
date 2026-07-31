package transport

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/bogdanfinn/utls"
)

func TestAnalyzeCapturedClientHelloProducesStableStructuralEvidence(t *testing.T) {
	record := captureUTLSClientHello(t)
	first, err := analyzeCapturedClientHello(record, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.Bytes == 0 || len(first.SHA256) != 64 || first.JA3 == "" || len(first.JA3SHA256) != 64 {
		t.Fatalf("incomplete evidence: %+v", first)
	}
	if first.RecordCount != 1 {
		t.Fatalf("record count = %d", first.RecordCount)
	}

	mutated := append([]byte(nil), record...)
	randomOffset := tlsRecordHeaderBytes + 4 + 2
	if randomOffset >= len(mutated) {
		t.Fatal("captured ClientHello is unexpectedly short")
	}
	mutated[randomOffset] ^= 0xff
	second, err := analyzeCapturedClientHello(mutated, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 == second.SHA256 {
		t.Fatal("raw ClientHello hash ignored random bytes")
	}
	if first.JA3 != second.JA3 || first.JA3SHA256 != second.JA3SHA256 {
		t.Fatal("structural fingerprint changed with ClientHello random")
	}
}

func TestAnalyzeCapturedClientHelloReassemblesTLSRecords(t *testing.T) {
	record := captureUTLSClientHello(t)
	if len(record) < tlsRecordHeaderBytes+8 {
		t.Fatal("captured ClientHello is too short")
	}
	payload := record[tlsRecordHeaderBytes:]
	split := len(payload) / 2
	fragmented := append(
		tlsRecord(record[1], record[2], payload[:split]),
		tlsRecord(record[1], record[2], payload[split:])...,
	)
	original, err := analyzeCapturedClientHello(record, false)
	if err != nil {
		t.Fatal(err)
	}
	reassembled, err := analyzeCapturedClientHello(fragmented, false)
	if err != nil {
		t.Fatal(err)
	}
	if reassembled.RecordCount != 2 {
		t.Fatalf("record count = %d", reassembled.RecordCount)
	}
	if original.SHA256 != reassembled.SHA256 || original.JA3SHA256 != reassembled.JA3SHA256 {
		t.Fatal("TLS record fragmentation changed ClientHello evidence")
	}
}

func TestAnalyzeCapturedClientHelloRejectsIncompleteEvidence(t *testing.T) {
	for _, test := range []struct {
		name     string
		captured []byte
		overflow bool
	}{
		{name: "empty"},
		{name: "truncated record", captured: []byte{22, 3, 1, 0, 8, 1}},
		{name: "wrong record type", captured: []byte{23, 3, 3, 0, 1, 0}},
		{name: "overflow", overflow: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := analyzeCapturedClientHello(test.captured, test.overflow); err == nil {
				t.Fatal("invalid ClientHello evidence was accepted")
			}
		})
	}
}

func captureUTLSClientHello(t *testing.T) []byte {
	t.Helper()
	client, server := net.Pipe()
	config := &utls.Config{
		ServerName: "example.com",
		NextProtos: []string{"http/1.1"},
	}
	uconn := utls.UClient(client, config, utls.HelloChrome_Auto, false, true, true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = uconn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = uconn.Handshake()
		_ = uconn.Close()
	}()

	header := make([]byte, tlsRecordHeaderBytes)
	if _, err := io.ReadFull(server, header); err != nil {
		t.Fatalf("read TLS record header: %v", err)
	}
	payloadLength := int(binary.BigEndian.Uint16(header[3:5]))
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(server, payload); err != nil {
		t.Fatalf("read TLS record payload: %v", err)
	}
	record := append(append([]byte(nil), header...), payload...)
	_ = server.Close()
	<-done
	return record
}

func tlsRecord(major, minor byte, payload []byte) []byte {
	record := make([]byte, tlsRecordHeaderBytes+len(payload))
	record[0] = tlsRecordTypeHandshake
	record[1] = major
	record[2] = minor
	binary.BigEndian.PutUint16(record[3:5], uint16(len(payload)))
	copy(record[tlsRecordHeaderBytes:], payload)
	return record
}

func TestClientHelloCaptureConnRecordsOnlyWrittenBytes(t *testing.T) {
	client, server := net.Pipe()
	capture := newClientHelloCaptureConn(client)
	payload := []byte("capture-me")
	done := make(chan error, 1)
	go func() {
		_, err := capture.Write(payload)
		done <- err
	}()
	read := make([]byte, len(payload))
	if _, err := io.ReadFull(server, read); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, overflow := capture.snapshot()
	if overflow || !bytes.Equal(got, payload) {
		t.Fatalf("capture = %q overflow=%v", got, overflow)
	}
	_ = server.Close()
	_ = client.Close()
}
