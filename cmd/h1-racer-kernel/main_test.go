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
