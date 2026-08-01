package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const maxProxyResponseHeaderBytes = 32 << 10

func dialTarget(
	ctx context.Context,
	dialer *net.Dialer,
	target string,
	proxyURL *url.URL,
) (net.Conn, string, string, error) {
	if proxyURL == nil {
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, "direct", "", phaseError("connect", err)
		}
		return conn, "direct", "", nil
	}

	switch strings.ToLower(proxyURL.Scheme) {
	case "http":
		conn, err := dialer.DialContext(ctx, "tcp", proxyURL.Host)
		if err != nil {
			return nil, "http-connect", proxyURL.Host, phaseError("proxy", fmt.Errorf("dial HTTP proxy: %w", err))
		}
		if err = establishHTTPConnect(conn, target, proxyURL, dialer.Timeout); err != nil {
			_ = conn.Close()
			return nil, "http-connect", proxyURL.Host, phaseError("proxy", err)
		}
		return conn, "http-connect", proxyURL.Host, nil
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			auth = &xproxy.Auth{User: proxyURL.User.Username(), Password: password}
		}
		proxyDialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, auth, dialer)
		if err != nil {
			return nil, "socks5", proxyURL.Host, phaseError("proxy", fmt.Errorf("create SOCKS5 dialer: %w", err))
		}
		var conn net.Conn
		if contextDialer, ok := proxyDialer.(xproxy.ContextDialer); ok {
			conn, err = contextDialer.DialContext(ctx, "tcp", target)
		} else {
			type outcome struct {
				conn net.Conn
				err  error
			}
			finished := make(chan outcome, 1)
			go func() {
				value, dialErr := proxyDialer.Dial("tcp", target)
				finished <- outcome{conn: value, err: dialErr}
			}()
			select {
			case result := <-finished:
				conn, err = result.conn, result.err
			case <-ctx.Done():
				return nil, "socks5", proxyURL.Host, phaseError("proxy", ctx.Err())
			}
		}
		if err != nil {
			return nil, "socks5", proxyURL.Host, phaseError("proxy", fmt.Errorf("SOCKS5 connect: %w", err))
		}
		return conn, "socks5", proxyURL.Host, nil
	default:
		return nil, "", "", phaseError("proxy", fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme))
	}
}

func establishHTTPConnect(conn net.Conn, target string, proxyURL *url.URL, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("set proxy deadline: %w", err)
	}
	defer conn.SetDeadline(time.Time{})

	var request strings.Builder
	request.WriteString("CONNECT ")
	request.WriteString(target)
	request.WriteString(" HTTP/1.1\r\nHost: ")
	request.WriteString(target)
	request.WriteString("\r\nProxy-Connection: keep-alive\r\n")
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		request.WriteString("Proxy-Authorization: Basic ")
		request.WriteString(token)
		request.WriteString("\r\n")
	}
	request.WriteString("\r\n")
	if err := WriteAll(conn, []byte(request.String()), timeout); err != nil {
		return fmt.Errorf("write CONNECT request: %w", err)
	}

	reader := bufio.NewReaderSize(io.LimitReader(conn, maxProxyResponseHeaderBytes+1), 4096)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read CONNECT status: %w", err)
	}
	headerBytes := len(statusLine)
	statusLine = strings.TrimSuffix(strings.TrimSuffix(statusLine, "\n"), "\r")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || (parts[0] != "HTTP/1.1" && parts[0] != "HTTP/1.0") {
		return fmt.Errorf("malformed CONNECT status line %q", statusLine)
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("malformed CONNECT status code %q", parts[1])
	}
	for {
		line, readErr := reader.ReadString('\n')
		headerBytes += len(line)
		if headerBytes > maxProxyResponseHeaderBytes {
			return errors.New("CONNECT response headers exceed limit")
		}
		if readErr != nil {
			return fmt.Errorf("read CONNECT headers: %w", readErr)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if statusCode < 200 || statusCode > 299 {
		return fmt.Errorf("CONNECT proxy returned status %d", statusCode)
	}
	if reader.Buffered() != 0 {
		return errors.New("CONNECT proxy sent tunnel bytes before request completion")
	}
	return nil
}
