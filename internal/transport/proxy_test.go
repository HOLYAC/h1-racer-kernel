package transport

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDialTargetThroughAuthenticatedHTTPConnectProxy(t *testing.T) {
	target, closeTarget := startEchoTarget(t, "tcp4", "127.0.0.1:0")
	defer closeTarget()
	proxyAddress, observed, closeProxy := startHTTPConnectProxy(t, "user", "pass")
	defer closeProxy()
	proxyURL, err := url.Parse("http://user:pass@" + proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, route, proxyPeer, err := dialTarget(context.Background(), dialer, target, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if route != "http-connect" || proxyPeer != proxyAddress {
		t.Fatalf("route=%q proxy=%q", route, proxyPeer)
	}
	assertEcho(t, conn)
	select {
	case authority := <-observed:
		if authority != target {
			t.Fatalf("CONNECT authority=%q, want %q", authority, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not observe CONNECT")
	}
}

func TestDialTargetThroughAuthenticatedSOCKS5Proxy(t *testing.T) {
	target, closeTarget := startEchoTarget(t, "tcp4", "127.0.0.1:0")
	defer closeTarget()
	proxyAddress, observed, closeProxy := startSOCKS5Proxy(t, "user", "pass")
	defer closeProxy()
	proxyURL, err := url.Parse("socks5://user:pass@" + proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, route, proxyPeer, err := dialTarget(context.Background(), dialer, target, proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if route != "socks5" || proxyPeer != proxyAddress {
		t.Fatalf("route=%q proxy=%q", route, proxyPeer)
	}
	assertEcho(t, conn)
	select {
	case authority := <-observed:
		if authority != target {
			t.Fatalf("SOCKS authority=%q, want %q", authority, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not observe SOCKS CONNECT")
	}
}

func TestDialTargetThroughHTTPConnectToIPv6(t *testing.T) {
	target, closeTarget, ok := tryStartEchoTarget("tcp6", "[::1]:0")
	if !ok {
		t.Skip("IPv6 loopback is unavailable")
	}
	defer closeTarget()
	proxyAddress, observed, closeProxy := startHTTPConnectProxy(t, "", "")
	defer closeProxy()
	proxyURL, _ := url.Parse("http://" + proxyAddress)
	conn, _, _, err := dialTarget(
		context.Background(),
		&net.Dialer{Timeout: 2 * time.Second},
		target,
		proxyURL,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	assertEcho(t, conn)
	if authority := <-observed; authority != target {
		t.Fatalf("CONNECT authority=%q, want %q", authority, target)
	}
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("echo=%q", response)
	}
}

func startEchoTarget(t *testing.T, network, address string) (string, func()) {
	t.Helper()
	target, closeTarget, ok := tryStartEchoTarget(network, address)
	if !ok {
		t.Fatalf("listen %s %s", network, address)
	}
	return target, closeTarget
}

func tryStartEchoTarget(network, address string) (string, func(), bool) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return "", nil, false
	}
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
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		wg.Wait()
	}, true
}

func startHTTPConnectProxy(t *testing.T, user, password string) (string, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan string, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			client, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				reader := bufio.NewReader(client)
				line, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				parts := strings.Split(strings.TrimSpace(line), " ")
				if len(parts) != 3 || parts[0] != "CONNECT" {
					return
				}
				authority := parts[1]
				authorized := user == ""
				for {
					header, headerErr := reader.ReadString('\n')
					if headerErr != nil {
						return
					}
					if strings.EqualFold(strings.TrimSpace(header), "Proxy-Authorization: Basic dXNlcjpwYXNz") {
						authorized = true
					}
					if header == "\r\n" {
						break
					}
				}
				if !authorized {
					_, _ = io.WriteString(client, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				upstream, dialErr := net.DialTimeout("tcp", authority, 2*time.Second)
				if dialErr != nil {
					_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer upstream.Close()
				observed <- authority
				_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
				relay(client, reader, upstream)
			}()
		}
	}()
	return listener.Addr().String(), observed, func() {
		_ = listener.Close()
		wg.Wait()
	}
}

func startSOCKS5Proxy(t *testing.T, user, password string) (string, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	observed := make(chan string, 4)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			client, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer client.Close()
				if err := serveSOCKS5(client, user, password, observed); err != nil {
					return
				}
			}()
		}
	}()
	return listener.Addr().String(), observed, func() {
		_ = listener.Close()
		wg.Wait()
	}
}

func serveSOCKS5(client net.Conn, user, password string, observed chan<- string) error {
	reader := bufio.NewReader(client)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 {
		return fmt.Errorf("bad greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	method := byte(0)
	if user != "" {
		method = 2
	}
	if !containsByte(methods, method) {
		_, _ = client.Write([]byte{5, 0xff})
		return fmt.Errorf("auth method unavailable")
	}
	if _, err := client.Write([]byte{5, method}); err != nil {
		return err
	}
	if method == 2 {
		if err := readSOCKSAuth(reader, client, user, password); err != nil {
			return err
		}
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil || request[0] != 5 || request[1] != 1 {
		return fmt.Errorf("bad CONNECT request")
	}
	host, err := readSOCKSHost(reader, request[3])
	if err != nil {
		return err
	}
	portBytes := make([]byte, 2)
	if _, err = io.ReadFull(reader, portBytes); err != nil {
		return err
	}
	authority := net.JoinHostPort(host, fmt.Sprintf("%d", binary.BigEndian.Uint16(portBytes)))
	upstream, err := net.DialTimeout("tcp", authority, 2*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer upstream.Close()
	observed <- authority
	if _, err = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	relay(client, reader, upstream)
	return nil
}

func readSOCKSAuth(reader *bufio.Reader, client net.Conn, user, password string) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 1 {
		return fmt.Errorf("bad auth request")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return err
	}
	length, err := reader.ReadByte()
	if err != nil {
		return err
	}
	secret := make([]byte, int(length))
	if _, err = io.ReadFull(reader, secret); err != nil {
		return err
	}
	status := byte(0)
	if string(username) != user || string(secret) != password {
		status = 1
	}
	_, _ = client.Write([]byte{1, status})
	if status != 0 {
		return fmt.Errorf("bad credentials")
	}
	return nil
}

func readSOCKSHost(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 1:
		value := make([]byte, 4)
		_, err := io.ReadFull(reader, value)
		return net.IP(value).String(), err
	case 3:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		value := make([]byte, int(length))
		_, err = io.ReadFull(reader, value)
		return string(value), err
	case 4:
		value := make([]byte, 16)
		_, err := io.ReadFull(reader, value)
		return net.IP(value).String(), err
	default:
		return "", fmt.Errorf("unsupported ATYP %d", atyp)
	}
}

func containsByte(values []byte, wanted byte) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func relay(client net.Conn, buffered *bufio.Reader, upstream net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstream, buffered)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstream)
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
}
