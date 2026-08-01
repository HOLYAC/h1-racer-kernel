package race

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/HOLYAC/h1-racer-kernel/internal/protocol"
)

func TestAuthorizedNetworkSoak(t *testing.T) {
	if os.Getenv("H1_RACER_SOAK") != "1" {
		t.Skip("set H1_RACER_SOAK=1 to run the network soak")
	}
	rounds := 50
	if configured := os.Getenv("H1_RACER_SOAK_ROUNDS"); configured != "" {
		parsed, err := strconv.Atoi(configured)
		if err != nil || parsed < 1 || parsed > 1000 {
			t.Fatalf("invalid H1_RACER_SOAK_ROUNDS=%q", configured)
		}
		rounds = parsed
	}

	random := rand.New(rand.NewSource(0x48315241434552))
	var totalConnections int
	for round := 0; round < rounds; round++ {
		copies := 2 + round%15
		mode := round % 4
		address, requests, closeServer := startDegradingPlainServer(t, copies, mode, random.Int63())
		prefix := []byte(fmt.Sprintf("POST /soak/%d HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8\r\nConnection: close\r\nX-Round: %d\r\n\r\nsoak-", round, round))
		suffix := []byte(fmt.Sprintf("%03d", round%1000))
		ioTimeout := 250
		if mode == soakIdleTimeout {
			ioTimeout = 20
		}
		disabled := false
		plan := protocol.RacePlan{
			SchemaVersion:    protocol.SchemaVersion,
			Target:           address,
			TLS:              protocol.TLSPlan{Enabled: &disabled},
			Copies:           copies,
			PrefixBase64:     base64.StdEncoding.EncodeToString(prefix),
			SuffixBase64:     base64.StdEncoding.EncodeToString(suffix),
			ConnectTimeoutMS: 2000,
			IOTimeoutMS:      ioTimeout,
			SettleMS:         round % 4,
			MaxResponseBytes: 64 << 10,
		}
		compiled, err := plan.Compile()
		if err != nil {
			closeServer()
			t.Fatalf("round %d compile: %v", round, err)
		}
		report := Run(context.Background(), compiled)
		if !report.Fired || report.ReadyCount != copies || report.AbortError != "" {
			closeServer()
			t.Fatalf("round %d fired=%v ready=%d/%d abort=%q", round, report.Fired, report.ReadyCount, copies, report.AbortError)
		}

		want := string(append(append([]byte{}, prefix...), suffix...))
		for index := 0; index < copies; index++ {
			select {
			case request := <-requests:
				if string(request) != want {
					closeServer()
					t.Fatalf("round %d request bytes changed: %q", round, request)
				}
			case <-time.After(2 * time.Second):
				closeServer()
				t.Fatalf("round %d missing request %d", round, index)
			}
		}

		for _, result := range report.Connections {
			switch mode {
			case soakTruncatedResponse:
				if result.Phase != "complete" || result.Error != "" || result.ResponseEndedBy != "eof" || result.ResponseBytes >= 59 {
					closeServer()
					t.Fatalf("round %d connection %d truncated raw response result: %+v", round, result.Index, result)
				}
			case soakIdleTimeout:
				if result.Phase != "complete" || result.Error != "" || result.ResponseEndedBy != "idle_timeout" {
					closeServer()
					t.Fatalf("round %d connection %d idle result: %+v", round, result.Index, result)
				}
			default:
				if result.Phase != "complete" || result.Error != "" || result.ResponseEndedBy != "eof" {
					closeServer()
					t.Fatalf("round %d connection %d complete result: %+v", round, result.Index, result)
				}
			}
		}
		closeServer()
		totalConnections += copies
	}
	t.Logf("soak rounds=%d connections=%d", rounds, totalConnections)
}

const (
	soakFragmented = iota
	soakIdleTimeout
	soakTruncatedResponse
	soakJittered
)

func startDegradingPlainServer(t *testing.T, expected, mode int, seed int64) (string, <-chan []byte, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan []byte, expected)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for accepted := 0; accepted < expected; accepted++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			workers.Add(1)
			go func(index int, conn net.Conn) {
				defer workers.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				request, readErr := readRequestWithContentLength(conn)
				if readErr != nil {
					return
				}
				requests <- request
				serveDegradedResponse(conn, mode, seed+int64(index))
			}(accepted, conn)
		}
	}()
	return listener.Addr().String(), requests, func() {
		_ = listener.Close()
		workers.Wait()
	}
}

func readRequestWithContentLength(reader io.Reader) ([]byte, error) {
	head, err := readExactHeaders(reader)
	if err != nil {
		return head, err
	}
	const bodyBytes = 8
	body := make([]byte, bodyBytes)
	if _, err = io.ReadFull(reader, body); err != nil {
		return append(head, body...), err
	}
	return append(head, body...), nil
}

func readExactHeaders(reader io.Reader) ([]byte, error) {
	data := make([]byte, 0, 256)
	ending := []byte{'\r', '\n', '\r', '\n'}
	matched := 0
	one := []byte{0}
	for matched < len(ending) {
		if _, err := io.ReadFull(reader, one); err != nil {
			return data, err
		}
		data = append(data, one[0])
		if one[0] == ending[matched] {
			matched++
		} else if one[0] == ending[0] {
			matched = 1
		} else {
			matched = 0
		}
		if len(data) > 64<<10 {
			return data, fmt.Errorf("headers too large")
		}
	}
	return data, nil
}

func serveDegradedResponse(conn net.Conn, mode int, seed int64) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
	random := rand.New(rand.NewSource(seed))
	switch mode {
	case soakTruncatedResponse:
		_, _ = conn.Write([]byte("HTTP/1.1 200"))
	case soakIdleTimeout:
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\nO"))
		time.Sleep(60 * time.Millisecond)
	case soakFragmented:
		for _, octet := range response {
			_, _ = conn.Write([]byte{octet})
			if random.Intn(5) == 0 {
				time.Sleep(time.Duration(random.Intn(3)) * time.Millisecond)
			}
		}
	default:
		position := 0
		for position < len(response) {
			width := 1 + random.Intn(12)
			end := min(len(response), position+width)
			_, _ = conn.Write(response[position:end])
			position = end
			time.Sleep(time.Duration(random.Intn(3)) * time.Millisecond)
		}
	}
}
