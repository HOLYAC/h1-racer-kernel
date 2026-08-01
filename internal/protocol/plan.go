package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	SchemaVersion           = 1
	MinCopies               = 2
	MaxCopies               = 200
	MaxRequestBytes         = 16 << 20
	MaxSuffixBytes          = 1 << 20
	MaxResponseBytesPerConn = 8 << 20
	MaxTotalResponseBytes   = 128 << 20
)

type TLSPlan struct {
	Enabled            *bool  `json:"enabled,omitempty"`
	Profile            string `json:"profile,omitempty"`
	ClientHelloHex     string `json:"client_hello_hex,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
}

type RacePlan struct {
	SchemaVersion    int     `json:"schema_version"`
	Target           string  `json:"target"`
	ServerName       string  `json:"server_name,omitempty"`
	TLS              TLSPlan `json:"tls"`
	ProxyURL         string  `json:"proxy_url,omitempty"`
	Copies           int     `json:"copies"`
	PrefixBase64     string  `json:"prefix_base64"`
	SuffixBase64     string  `json:"suffix_base64"`
	ConnectTimeoutMS int     `json:"connect_timeout_ms,omitempty"`
	IOTimeoutMS      int     `json:"io_timeout_ms,omitempty"`
	SettleMS         int     `json:"settle_ms,omitempty"`
	MaxResponseBytes int     `json:"max_response_bytes,omitempty"`
}

type CompiledPlan struct {
	Target           string
	ServerName       string
	UseTLS           bool
	TLS              TLSPlan
	ProxyURL         *url.URL
	ProxyDisplay     string
	Copies           int
	Prefix           []byte
	Suffix           []byte
	ConnectTimeout   time.Duration
	IOTimeout        time.Duration
	Settle           time.Duration
	MaxResponseBytes int
}

func (p RacePlan) Compile() (CompiledPlan, error) {
	if p.SchemaVersion != SchemaVersion {
		return CompiledPlan{}, fmt.Errorf("schema_version must be %d", SchemaVersion)
	}

	host, port, err := net.SplitHostPort(p.Target)
	if err != nil || host == "" || port == "" {
		return CompiledPlan{}, fmt.Errorf("target must be host:port: %w", err)
	}
	if p.Copies < MinCopies || p.Copies > MaxCopies {
		return CompiledPlan{}, fmt.Errorf("copies must be between %d and %d", MinCopies, MaxCopies)
	}

	proxyURL, proxyDisplay, err := compileProxyURL(p.ProxyURL)
	if err != nil {
		return CompiledPlan{}, err
	}

	useTLS := true
	if p.TLS.Enabled != nil {
		useTLS = *p.TLS.Enabled
	}
	profile := strings.TrimSpace(p.TLS.Profile)
	clientHelloHex := strings.TrimSpace(p.TLS.ClientHelloHex)
	if !useTLS {
		if profile != "" || clientHelloHex != "" || p.TLS.InsecureSkipVerify || p.TLS.CAFile != "" {
			return CompiledPlan{}, errors.New("TLS options require tls.enabled=true")
		}
	} else {
		if profile != "" && clientHelloHex != "" {
			return CompiledPlan{}, errors.New("tls.profile and tls.client_hello_hex are mutually exclusive")
		}
		if p.TLS.CAFile != "" {
			info, statErr := os.Stat(p.TLS.CAFile)
			if statErr != nil {
				return CompiledPlan{}, fmt.Errorf("tls.ca_file: %w", statErr)
			}
			if info.IsDir() {
				return CompiledPlan{}, errors.New("tls.ca_file must name a file")
			}
		}
		if profile == "" && clientHelloHex == "" {
			profile = "default"
		}
		p.TLS.Profile = profile
	}

	prefix, err := base64.StdEncoding.DecodeString(p.PrefixBase64)
	if err != nil {
		return CompiledPlan{}, fmt.Errorf("prefix_base64: %w", err)
	}
	suffix, err := base64.StdEncoding.DecodeString(p.SuffixBase64)
	if err != nil {
		return CompiledPlan{}, fmt.Errorf("suffix_base64: %w", err)
	}
	if len(prefix) == 0 {
		return CompiledPlan{}, errors.New("prefix must not be empty")
	}
	if len(suffix) == 0 {
		return CompiledPlan{}, errors.New("suffix must not be empty")
	}
	if len(prefix)+len(suffix) > MaxRequestBytes {
		return CompiledPlan{}, fmt.Errorf("request exceeds %d bytes", MaxRequestBytes)
	}
	if len(suffix) > MaxSuffixBytes {
		return CompiledPlan{}, fmt.Errorf("suffix exceeds %d bytes", MaxSuffixBytes)
	}

	connectMS := p.ConnectTimeoutMS
	if connectMS == 0 {
		connectMS = 5000
	}
	ioMS := p.IOTimeoutMS
	if ioMS == 0 {
		ioMS = 5000
	}
	maxResponse := p.MaxResponseBytes
	if maxResponse == 0 {
		maxResponse = 512 << 10
	}
	if connectMS < 1 || connectMS > 120000 {
		return CompiledPlan{}, errors.New("connect_timeout_ms must be between 1 and 120000")
	}
	if ioMS < 1 || ioMS > 120000 {
		return CompiledPlan{}, errors.New("io_timeout_ms must be between 1 and 120000")
	}
	if p.SettleMS < 0 || p.SettleMS > 5000 {
		return CompiledPlan{}, errors.New("settle_ms must be between 0 and 5000")
	}
	if maxResponse < 1 || maxResponse > MaxResponseBytesPerConn {
		return CompiledPlan{}, fmt.Errorf("max_response_bytes must be between 1 and %d", MaxResponseBytesPerConn)
	}
	if int64(p.Copies)*int64(maxResponse) > MaxTotalResponseBytes {
		return CompiledPlan{}, fmt.Errorf("copies * max_response_bytes exceeds total capture budget %d", MaxTotalResponseBytes)
	}

	serverName := p.ServerName
	if useTLS && serverName == "" {
		serverName = host
	}

	return CompiledPlan{
		Target:           p.Target,
		ServerName:       serverName,
		UseTLS:           useTLS,
		TLS:              p.TLS,
		ProxyURL:         proxyURL,
		ProxyDisplay:     proxyDisplay,
		Copies:           p.Copies,
		Prefix:           prefix,
		Suffix:           suffix,
		ConnectTimeout:   time.Duration(connectMS) * time.Millisecond,
		IOTimeout:        time.Duration(ioMS) * time.Millisecond,
		Settle:           time.Duration(p.SettleMS) * time.Millisecond,
		MaxResponseBytes: maxResponse,
	}, nil
}

func compileProxyURL(value string) (*url.URL, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, "", nil
	}
	if len(value) > 4096 {
		return nil, "", errors.New("proxy_url is too long")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, "", fmt.Errorf("proxy_url: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "socks5" && scheme != "socks5h" {
		return nil, "", fmt.Errorf("proxy_url scheme must be http, socks5, or socks5h")
	}
	if parsed.Hostname() == "" || parsed.Port() == "" {
		return nil, "", errors.New("proxy_url must include host and explicit port")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, "", errors.New("proxy_url path is not supported")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, "", errors.New("proxy_url query and fragment are not supported")
	}
	parsed.Scheme = scheme
	parsed.Path = ""
	display := scheme + "://" + parsed.Host
	return parsed, display, nil
}
