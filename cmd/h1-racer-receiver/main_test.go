package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestReceiverRecordsExactBoundaryEvidence(t *testing.T) {
	const copies = 4
	raw := []byte("GET /receiver HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	prefixBytes := len(raw) - 4
	temporary := t.TempDir()
	requestPath := filepath.Join(temporary, "request.bin")
	readyPath := filepath.Join(temporary, "ready.json")
	reportPath := filepath.Join(temporary, "report.json")
	if err := os.WriteFile(requestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := make(chan int, 1)
	go func() {
		exit <- run([]string{
			"--listen", "127.0.0.1:0",
			"--copies", "4",
			"--request", requestPath,
			"--prefix-bytes", strconv.Itoa(prefixBytes),
			"--ready-file", readyPath,
			"--output", reportPath,
			"--timeout-ms", "3000",
		}, &stdout, &stderr)
	}()

	var ready readyRecord
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		encoded, err := os.ReadFile(readyPath)
		if err == nil && json.Unmarshal(encoded, &ready) == nil && ready.Address != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ready.Address == "" {
		t.Fatalf("receiver did not become ready: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if ready.PrefixBytes != prefixBytes {
		t.Fatalf("prefix bytes=%d want=%d", ready.PrefixBytes, prefixBytes)
	}

	var clients sync.WaitGroup
	for index := 0; index < copies; index++ {
		clients.Add(1)
		go func(index int) {
			defer clients.Done()
			conn, err := net.DialTimeout("tcp", ready.Address, time.Second)
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer conn.Close()
			if _, err = conn.Write(raw[:prefixBytes]); err != nil {
				t.Errorf("write prefix: %v", err)
				return
			}
			time.Sleep(time.Duration(index+1) * time.Millisecond)
			if _, err = conn.Write(raw[prefixBytes:]); err != nil {
				t.Errorf("write suffix: %v", err)
				return
			}
			response, err := io.ReadAll(conn)
			if err != nil || !bytes.Contains(response, []byte("200 OK")) {
				t.Errorf("response=%q err=%v", response, err)
			}
		}(index)
	}
	clients.Wait()

	select {
	case code := <-exit:
		if code != 0 {
			t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("receiver did not exit")
	}

	encoded, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report receiverReport
	if err = json.Unmarshal(encoded, &report); err != nil {
		t.Fatal(err)
	}
	if report.ExactMatches != copies || report.Errors != 0 {
		t.Fatalf("report=%+v", report)
	}
	if report.RequestCompletionSpreadNS == nil || *report.RequestCompletionSpreadNS <= 0 {
		t.Fatalf("missing receiver-side completion spread: %+v", report)
	}
	for _, evidence := range report.Connections {
		if !evidence.ExactMatch || evidence.PrefixCompletedAfterNS == nil || evidence.RequestCompletedAfterNS == nil {
			t.Fatalf("incomplete evidence: %+v", evidence)
		}
		if *evidence.RequestCompletedAfterNS <= *evidence.PrefixCompletedAfterNS {
			t.Fatalf("boundary ordering invalid: %+v", evidence)
		}
	}
}

func TestReceiverRejectsInvalidPrefixLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.bin")
	if err := os.WriteFile(path, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"--copies", "1",
		"--request", path,
		"--prefix-bytes", "4",
		"--ready-file", filepath.Join(t.TempDir(), "ready.json"),
		"--output", filepath.Join(t.TempDir(), "report.json"),
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d", code)
	}
}
