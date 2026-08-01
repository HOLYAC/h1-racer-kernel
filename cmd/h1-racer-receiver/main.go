package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const reportSchemaVersion = 1

var version = "dev"

type readyRecord struct {
	SchemaVersion int    `json:"schema_version"`
	Address       string `json:"address"`
	Copies        int    `json:"copies"`
	RequestBytes  int    `json:"request_bytes"`
	PrefixBytes   int    `json:"prefix_bytes"`
}

type connectionEvidence struct {
	Index                   int    `json:"index"`
	RemoteAddress           string `json:"remote_address,omitempty"`
	PrefixCompletedAfterNS  *int64 `json:"prefix_completed_after_ns,omitempty"`
	RequestCompletedAfterNS *int64 `json:"request_completed_after_ns,omitempty"`
	RequestBytes            int    `json:"request_bytes"`
	RequestSHA256           string `json:"request_sha256,omitempty"`
	ExactMatch              bool   `json:"exact_match"`
	Error                   string `json:"error,omitempty"`
}

type receiverReport struct {
	SchemaVersion             int                  `json:"schema_version"`
	ListenAddress             string               `json:"listen_address"`
	Copies                    int                  `json:"copies"`
	ExpectedRequestBytes      int                  `json:"expected_request_bytes"`
	ExpectedPrefixBytes       int                  `json:"expected_prefix_bytes"`
	ExpectedRequestSHA256     string               `json:"expected_request_sha256"`
	StartedAtUTC              time.Time            `json:"started_at_utc"`
	CompletedAtUTC            time.Time            `json:"completed_at_utc"`
	ExactMatches              int                  `json:"exact_matches"`
	Errors                    int                  `json:"errors"`
	RequestCompletionSpreadNS *int64               `json:"request_completion_spread_ns,omitempty"`
	PrefixToCompletionMinNS   *int64               `json:"prefix_to_completion_min_ns,omitempty"`
	PrefixToCompletionMaxNS   *int64               `json:"prefix_to_completion_max_ns,omitempty"`
	Connections               []connectionEvidence `json:"connections"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("h1-racer-receiver", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listen := flags.String("listen", "127.0.0.1:0", "TCP listen address")
	copies := flags.Int("copies", 0, "expected connection count")
	requestPath := flags.String("request", "", "expected raw request file")
	prefixBytes := flags.Int("prefix-bytes", 0, "expected prefix byte count")
	readyPath := flags.String("ready-file", "", "write listener metadata here after bind")
	outputPath := flags.String("output", "", "receiver evidence JSON path")
	timeoutMS := flags.Int("timeout-ms", 10_000, "per-connection and accept timeout")
	showVersion := flags.Bool("version", false, "print build version")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if *copies < 1 || *copies > 200 {
		fmt.Fprintln(stderr, "copies must be between 1 and 200")
		return 2
	}
	if *requestPath == "" || *readyPath == "" || *outputPath == "" {
		fmt.Fprintln(stderr, "--request, --ready-file, and --output are required")
		return 2
	}
	expected, err := os.ReadFile(*requestPath)
	if err != nil {
		fmt.Fprintf(stderr, "read request: %v\n", err)
		return 2
	}
	if *prefixBytes < 1 || *prefixBytes >= len(expected) {
		fmt.Fprintf(stderr, "prefix-bytes must be between 1 and %d\n", len(expected)-1)
		return 2
	}
	if *timeoutMS < 1 || *timeoutMS > 120_000 {
		fmt.Fprintln(stderr, "timeout-ms must be between 1 and 120000")
		return 2
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(stderr, "listen: %v\n", err)
		return 1
	}
	defer listener.Close()
	startedWall := time.Now().UTC()
	started := time.Now()
	ready := readyRecord{
		SchemaVersion: reportSchemaVersion,
		Address:       listener.Addr().String(),
		Copies:        *copies,
		RequestBytes:  len(expected),
		PrefixBytes:   *prefixBytes,
	}
	if err = writeJSONAtomic(*readyPath, ready); err != nil {
		fmt.Fprintf(stderr, "write ready file: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, listener.Addr().String())

	results := make([]connectionEvidence, *copies)
	var workers sync.WaitGroup
	acceptDeadline := time.Now().Add(time.Duration(*timeoutMS) * time.Millisecond)
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		_ = tcpListener.SetDeadline(acceptDeadline)
	}
	for index := 0; index < *copies; index++ {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			results[index] = connectionEvidence{Index: index, Error: "accept: " + acceptErr.Error()}
			for remaining := index + 1; remaining < *copies; remaining++ {
				results[remaining] = connectionEvidence{Index: remaining, Error: "accept skipped after listener failure"}
			}
			break
		}
		workers.Add(1)
		go func(index int, conn net.Conn) {
			defer workers.Done()
			results[index] = receiveOne(index, conn, expected, *prefixBytes, started, time.Duration(*timeoutMS)*time.Millisecond)
		}(index, conn)
	}
	workers.Wait()

	report := buildReport(listener.Addr().String(), expected, *prefixBytes, startedWall, results)
	if err = writeJSONAtomic(*outputPath, report); err != nil {
		fmt.Fprintf(stderr, "write report: %v\n", err)
		return 1
	}
	if report.Errors != 0 || report.ExactMatches != *copies {
		return 1
	}
	return 0
}

func receiveOne(index int, conn net.Conn, expected []byte, prefixBytes int, started time.Time, timeout time.Duration) connectionEvidence {
	result := connectionEvidence{Index: index, RemoteAddress: conn.RemoteAddr().String()}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	request := make([]byte, len(expected))
	if _, err := io.ReadFull(conn, request[:prefixBytes]); err != nil {
		result.Error = "read prefix: " + err.Error()
		return result
	}
	prefixNS := time.Since(started).Nanoseconds()
	result.PrefixCompletedAfterNS = int64Pointer(prefixNS)
	if _, err := io.ReadFull(conn, request[prefixBytes:]); err != nil {
		result.RequestBytes = prefixBytes
		result.Error = "read suffix: " + err.Error()
		return result
	}
	completedNS := time.Since(started).Nanoseconds()
	result.RequestCompletedAfterNS = int64Pointer(completedNS)
	result.RequestBytes = len(request)
	digest := sha256.Sum256(request)
	result.RequestSHA256 = fmt.Sprintf("%x", digest[:])
	result.ExactMatch = bytes.Equal(request, expected)
	if !result.ExactMatch {
		result.Error = "request bytes differ from expected request"
		return result
	}
	_, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
	if err != nil {
		result.Error = "write response: " + err.Error()
	}
	return result
}

func buildReport(address string, expected []byte, prefixBytes int, startedWall time.Time, results []connectionEvidence) receiverReport {
	digest := sha256.Sum256(expected)
	report := receiverReport{
		SchemaVersion:         reportSchemaVersion,
		ListenAddress:         address,
		Copies:                len(results),
		ExpectedRequestBytes:  len(expected),
		ExpectedPrefixBytes:   prefixBytes,
		ExpectedRequestSHA256: fmt.Sprintf("%x", digest[:]),
		StartedAtUTC:          startedWall,
		CompletedAtUTC:        time.Now().UTC(),
		Connections:           results,
	}
	var completions []int64
	var boundaryDurations []int64
	for _, result := range results {
		if result.Error != "" {
			report.Errors++
		}
		if result.ExactMatch {
			report.ExactMatches++
		}
		if result.RequestCompletedAfterNS != nil {
			completions = append(completions, *result.RequestCompletedAfterNS)
		}
		if result.PrefixCompletedAfterNS != nil && result.RequestCompletedAfterNS != nil {
			boundaryDurations = append(boundaryDurations, *result.RequestCompletedAfterNS-*result.PrefixCompletedAfterNS)
		}
	}
	if len(completions) >= 2 {
		sort.Slice(completions, func(i, j int) bool { return completions[i] < completions[j] })
		spread := completions[len(completions)-1] - completions[0]
		report.RequestCompletionSpreadNS = int64Pointer(spread)
	}
	if len(boundaryDurations) > 0 {
		sort.Slice(boundaryDurations, func(i, j int) bool { return boundaryDurations[i] < boundaryDurations[j] })
		report.PrefixToCompletionMinNS = int64Pointer(boundaryDurations[0])
		report.PrefixToCompletionMaxNS = int64Pointer(boundaryDurations[len(boundaryDurations)-1])
	}
	return report
}

func writeJSONAtomic(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	parent := filepath.Dir(path)
	if err = os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(parent, ".h1-racer-receiver-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err = temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		return os.Rename(temporaryPath, path)
	}
	return nil
}

func int64Pointer(value int64) *int64 {
	return &value
}
