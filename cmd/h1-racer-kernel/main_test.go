package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateClientHelloFlagRejectsMalformedHex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hello.hex")
	if err := os.WriteFile(path, []byte("00"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := run([]string{"--validate-client-hello", path}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "validate client hello") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestQuietRequiresOutput(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := run([]string{"--quiet", "--plan", "missing.json"}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit=%d", exit)
	}
	if !strings.Contains(stderr.String(), "--quiet requires --output") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestCompileRequestFlagReturnsExactSplit(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nabcde")
	path := filepath.Join(t.TempDir(), "request.bin")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := run([]string{"--compile-request", path}, &stdout, &stderr); exit != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	output := stdout.String()
	for _, expected := range []string{
		"schema_version=1",
		"mode=content-length",
		"prefix_base64=",
		"suffix_base64=Y2Rl",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("output %q lacks %q", output, expected)
		}
	}
}

func TestCompileRequestFlagRejectsAmbiguousFraming(t *testing.T) {
	raw := []byte("POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
	path := filepath.Join(t.TempDir(), "request.bin")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if exit := run([]string{"--compile-request", path}, &stdout, &stderr); exit != 2 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "both Content-Length and Transfer-Encoding") {
		t.Fatalf("unexpected stderr: %q", stderr.String())
	}
}

func TestPlanCanBeReadFromStdin(t *testing.T) {
	plan := `{
		"schema_version": 1,
		"target": "invalid-target",
		"tls": {"enabled": false},
		"copies": 2,
		"prefix_base64": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IHRlc3QNCg==",
		"suffix_base64": "DQo="
	}`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exit := runWithInput(
		[]string{"--plan", "-"},
		strings.NewReader(plan),
		&stdout,
		&stderr,
	)
	if exit != 2 || !strings.Contains(stderr.String(), "validate plan") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exit, stdout.String(), stderr.String())
	}
}
