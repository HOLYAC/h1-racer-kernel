package transport

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	utls "github.com/bogdanfinn/utls"
)

const maxClientHelloBytes = 64 << 10

func ValidateClientHelloHex(value string) error {
	_, err := clientHelloSpecFromHex(value)
	return err
}

func clientHelloSpecFromHex(value string) (*utls.ClientHelloSpec, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty client hello")
	}
	if len(value)%2 != 0 {
		return nil, errors.New("client hello hex length must be even")
	}
	if len(value)/2 > maxClientHelloBytes {
		return nil, fmt.Errorf("client hello exceeds %d bytes", maxClientHelloBytes)
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode client hello: %w", err)
	}
	fingerprinter := &utls.Fingerprinter{AllowBluntMimicry: true}
	spec, err := fingerprinter.RawClientHello(raw)
	if err != nil {
		return nil, fmt.Errorf("fingerprint client hello: %w", err)
	}
	for i, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.GenericExtension:
			if typed.Id == utls.ExtensionECH {
				spec.Extensions[i] = utls.BoringGREASEECH()
			}
		case *utls.FakePreSharedKeyExtension:
			spec.Extensions[i] = &utls.UtlsPreSharedKeyExtension{}
		}
	}
	return spec, nil
}
