package transport

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

const (
	maxHandshakeCaptureBytes = 128 << 10
	tlsRecordHeaderBytes     = 5
	tlsRecordTypeHandshake   = 22
	clientHelloHandshakeType = 1
)

type clientHelloCaptureConn struct {
	net.Conn
	mutex    sync.Mutex
	captured []byte
	overflow bool
}

type clientHelloEvidence struct {
	Bytes       int
	SHA256      string
	JA3         string
	JA3SHA256   string
	RecordCount int
}

func newClientHelloCaptureConn(conn net.Conn) *clientHelloCaptureConn {
	return &clientHelloCaptureConn{Conn: conn}
}

func (c *clientHelloCaptureConn) Write(data []byte) (int, error) {
	written, err := c.Conn.Write(data)
	if written > 0 {
		c.mutex.Lock()
		remaining := maxHandshakeCaptureBytes - len(c.captured)
		if remaining > 0 {
			capture := written
			if capture > remaining {
				capture = remaining
			}
			c.captured = append(c.captured, data[:capture]...)
		}
		if written > remaining {
			c.overflow = true
		}
		c.mutex.Unlock()
	}
	return written, err
}

func (c *clientHelloCaptureConn) snapshot() ([]byte, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([]byte(nil), c.captured...), c.overflow
}

func analyzeCapturedClientHello(captured []byte, overflow bool) (clientHelloEvidence, error) {
	handshake, recordCount, err := extractClientHello(captured)
	if err != nil {
		if overflow {
			return clientHelloEvidence{}, fmt.Errorf(
				"TLS handshake capture exceeded %d bytes before ClientHello completed: %w",
				maxHandshakeCaptureBytes,
				err,
			)
		}
		return clientHelloEvidence{}, err
	}
	ja3, err := ja3Fingerprint(handshake)
	if err != nil {
		return clientHelloEvidence{}, err
	}
	rawDigest := sha256.Sum256(handshake)
	ja3Digest := sha256.Sum256([]byte(ja3))
	return clientHelloEvidence{
		Bytes:       len(handshake),
		SHA256:      fmt.Sprintf("%x", rawDigest[:]),
		JA3:         ja3,
		JA3SHA256:   fmt.Sprintf("%x", ja3Digest[:]),
		RecordCount: recordCount,
	}, nil
}

func extractClientHello(captured []byte) ([]byte, int, error) {
	position := 0
	recordCount := 0
	handshake := make([]byte, 0, min(len(captured), maxClientHelloBytes+4))
	for position < len(captured) {
		if len(captured)-position < tlsRecordHeaderBytes {
			return nil, recordCount, errors.New("truncated TLS record header before ClientHello completed")
		}
		recordType := captured[position]
		payloadLength := int(binary.BigEndian.Uint16(captured[position+3 : position+5]))
		recordEnd := position + tlsRecordHeaderBytes + payloadLength
		if recordEnd > len(captured) {
			return nil, recordCount, errors.New("truncated TLS record payload before ClientHello completed")
		}
		if recordType != tlsRecordTypeHandshake {
			return nil, recordCount, fmt.Errorf(
				"TLS record type %d appeared before ClientHello completed",
				recordType,
			)
		}
		handshake = append(handshake, captured[position+tlsRecordHeaderBytes:recordEnd]...)
		recordCount++
		if len(handshake) >= 4 {
			if handshake[0] != clientHelloHandshakeType {
				return nil, recordCount, fmt.Errorf(
					"first TLS handshake is type %d, not ClientHello",
					handshake[0],
				)
			}
			messageLength := 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
			if messageLength > maxClientHelloBytes+4 {
				return nil, recordCount, fmt.Errorf(
					"ClientHello exceeds %d bytes",
					maxClientHelloBytes,
				)
			}
			if len(handshake) >= messageLength {
				return append([]byte(nil), handshake[:messageLength]...), recordCount, nil
			}
		}
		position = recordEnd
	}
	return nil, recordCount, errors.New("ClientHello did not complete in captured TLS writes")
}

func ja3Fingerprint(handshake []byte) (string, error) {
	if len(handshake) < 4 || handshake[0] != clientHelloHandshakeType {
		return "", errors.New("not a ClientHello handshake")
	}
	declared := 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
	if declared != len(handshake) {
		return "", fmt.Errorf("ClientHello length mismatch: declared %d, captured %d", declared, len(handshake))
	}
	body := handshake[4:]
	position := 0
	read := func(size int) ([]byte, error) {
		if size < 0 || position+size > len(body) {
			return nil, errors.New("truncated ClientHello structure")
		}
		value := body[position : position+size]
		position += size
		return value, nil
	}

	versionBytes, err := read(2)
	if err != nil {
		return "", err
	}
	version := binary.BigEndian.Uint16(versionBytes)
	if _, err = read(32); err != nil {
		return "", err
	}
	sessionLengthBytes, err := read(1)
	if err != nil {
		return "", err
	}
	if _, err = read(int(sessionLengthBytes[0])); err != nil {
		return "", err
	}
	cipherLengthBytes, err := read(2)
	if err != nil {
		return "", err
	}
	cipherLength := int(binary.BigEndian.Uint16(cipherLengthBytes))
	if cipherLength%2 != 0 {
		return "", errors.New("ClientHello cipher-suite vector has odd length")
	}
	cipherBytes, err := read(cipherLength)
	if err != nil {
		return "", err
	}
	ciphers := make([]uint16, 0, cipherLength/2)
	for offset := 0; offset < len(cipherBytes); offset += 2 {
		value := binary.BigEndian.Uint16(cipherBytes[offset : offset+2])
		if !isGREASE(value) {
			ciphers = append(ciphers, value)
		}
	}
	compressionLengthBytes, err := read(1)
	if err != nil {
		return "", err
	}
	if _, err = read(int(compressionLengthBytes[0])); err != nil {
		return "", err
	}

	extensions := make([]uint16, 0)
	groups := make([]uint16, 0)
	pointFormats := make([]uint8, 0)
	if position < len(body) {
		extensionLengthBytes, extensionErr := read(2)
		if extensionErr != nil {
			return "", extensionErr
		}
		extensionLength := int(binary.BigEndian.Uint16(extensionLengthBytes))
		extensionBytes, extensionErr := read(extensionLength)
		if extensionErr != nil {
			return "", extensionErr
		}
		if position != len(body) {
			return "", errors.New("bytes remain after ClientHello extension vector")
		}
		for offset := 0; offset < len(extensionBytes); {
			if len(extensionBytes)-offset < 4 {
				return "", errors.New("truncated ClientHello extension header")
			}
			extensionType := binary.BigEndian.Uint16(extensionBytes[offset : offset+2])
			extensionSize := int(binary.BigEndian.Uint16(extensionBytes[offset+2 : offset+4]))
			offset += 4
			if offset+extensionSize > len(extensionBytes) {
				return "", errors.New("truncated ClientHello extension payload")
			}
			payload := extensionBytes[offset : offset+extensionSize]
			offset += extensionSize
			if !isGREASE(extensionType) {
				extensions = append(extensions, extensionType)
			}
			switch extensionType {
			case 10:
				parsed, parseErr := parseUint16Vector(payload)
				if parseErr != nil {
					return "", fmt.Errorf("supported groups: %w", parseErr)
				}
				for _, group := range parsed {
					if !isGREASE(group) {
						groups = append(groups, group)
					}
				}
			case 11:
				if len(payload) < 1 || int(payload[0]) != len(payload)-1 {
					return "", errors.New("EC point formats vector is malformed")
				}
				pointFormats = append(pointFormats, payload[1:]...)
			}
		}
	} else if position != len(body) {
		return "", errors.New("truncated ClientHello after compression methods")
	}

	return strings.Join([]string{
		strconv.Itoa(int(version)),
		joinUint16(ciphers),
		joinUint16(extensions),
		joinUint16(groups),
		joinUint8(pointFormats),
	}, ","), nil
}

func parseUint16Vector(payload []byte) ([]uint16, error) {
	if len(payload) < 2 {
		return nil, errors.New("vector length is absent")
	}
	length := int(binary.BigEndian.Uint16(payload[:2]))
	if length != len(payload)-2 || length%2 != 0 {
		return nil, errors.New("vector length is invalid")
	}
	values := make([]uint16, 0, length/2)
	for offset := 2; offset < len(payload); offset += 2 {
		values = append(values, binary.BigEndian.Uint16(payload[offset:offset+2]))
	}
	return values, nil
}

func isGREASE(value uint16) bool {
	return byte(value>>8) == byte(value) && value&0x0f0f == 0x0a0a
}

func joinUint16(values []uint16) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(int(value))
	}
	return strings.Join(parts, "-")
}

func joinUint8(values []uint8) string {
	parts := make([]string, len(values))
	for index, value := range values {
		parts[index] = strconv.Itoa(int(value))
	}
	return strings.Join(parts, "-")
}
