package protocol

import (
	"encoding/base64"
	"testing"
)

func validPlan() RacePlan {
	return RacePlan{
		SchemaVersion: SchemaVersion,
		Target:        "localhost:443",
		Copies:        2,
		PrefixBase64:  base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n")),
		SuffixBase64:  base64.StdEncoding.EncodeToString([]byte("\r\n")),
	}
}

func TestCompileDefaults(t *testing.T) {
	compiled, err := validPlan().Compile()
	if err != nil {
		t.Fatal(err)
	}
	if compiled.TLS.Profile != "default" {
		t.Fatalf("profile = %q", compiled.TLS.Profile)
	}
	if compiled.ServerName != "localhost" {
		t.Fatalf("server name = %q", compiled.ServerName)
	}
}

func TestCompileRejectsProfileAndHex(t *testing.T) {
	plan := validPlan()
	plan.TLS.Profile = "default"
	plan.TLS.ClientHelloHex = "00"
	if _, err := plan.Compile(); err == nil {
		t.Fatal("expected conflict error")
	}
}

func TestCompileRejectsEmptySuffix(t *testing.T) {
	plan := validPlan()
	plan.SuffixBase64 = ""
	if _, err := plan.Compile(); err == nil {
		t.Fatal("expected empty suffix error")
	}
}

func TestCompileDisablesTLSForPlainTCP(t *testing.T) {
	plan := validPlan()
	disabled := false
	plan.TLS.Enabled = &disabled
	compiled, err := plan.Compile()
	if err != nil {
		t.Fatal(err)
	}
	if compiled.UseTLS {
		t.Fatal("plain TCP plan unexpectedly enabled TLS")
	}
	if compiled.TLS.Profile != "" {
		t.Fatalf("plain TCP profile = %q", compiled.TLS.Profile)
	}
}

func TestCompileRejectsTLSOptionsWhenDisabled(t *testing.T) {
	plan := validPlan()
	disabled := false
	plan.TLS.Enabled = &disabled
	plan.TLS.Profile = "default"
	if _, err := plan.Compile(); err == nil {
		t.Fatal("expected disabled TLS option error")
	}
}
