package framing

import (
	"bytes"
	"testing"
)

func TestSplitRequestCorpus(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		mode    string
		suffix  []byte
		wantErr string
	}{
		{
			name:   "bodyless",
			raw:    []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
			mode:   "bodyless",
			suffix: []byte("\r\n\r\n"),
		},
		{
			name:   "content length",
			raw:    []byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nabcde"),
			mode:   "content-length",
			suffix: []byte("cde"),
		},
		{
			name:   "chunked trailers",
			raw:    []byte("POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n4\r\ntest\r\n0\r\nX-Proof: yes\r\n\r\n"),
			mode:   "chunked",
			suffix: []byte("0\r\nX-Proof: yes\r\n\r\n"),
		},
		{
			name:    "conflicting framing",
			raw:     []byte("POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
			wantErr: "both Content-Length and Transfer-Encoding",
		},
		{
			name:    "incomplete chunk",
			raw:     []byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabc"),
			wantErr: "incomplete",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			split, err := SplitRequest(test.raw)
			if test.wantErr != "" {
				if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.wantErr)) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if split.Mode != test.mode {
				t.Fatalf("mode = %q, want %q", split.Mode, test.mode)
			}
			if !bytes.Equal(split.Suffix, test.suffix) {
				t.Fatalf("suffix = %q, want %q", split.Suffix, test.suffix)
			}
			joined := append(append([]byte{}, split.Prefix...), split.Suffix...)
			if !bytes.Equal(joined, test.raw) {
				t.Fatalf("split changed bytes\nwant %q\n got %q", test.raw, joined)
			}
		})
	}
}

func FuzzSplitRequest(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
		[]byte("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde"),
		[]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"),
		[]byte("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-A: b\r\n\r\n"),
		[]byte{},
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		split, err := SplitRequest(raw)
		if err != nil {
			return
		}
		if len(split.Suffix) == 0 {
			t.Fatal("accepted split has an empty completion suffix")
		}
		if split.Mode != "bodyless" && split.Mode != "content-length" && split.Mode != "chunked" {
			t.Fatalf("unknown mode %q", split.Mode)
		}
		joined := append(append([]byte{}, split.Prefix...), split.Suffix...)
		if !bytes.Equal(joined, raw) {
			t.Fatalf("accepted split changed request bytes")
		}
		again, secondErr := SplitRequest(raw)
		if secondErr != nil || again.Mode != split.Mode ||
			!bytes.Equal(again.Prefix, split.Prefix) || !bytes.Equal(again.Suffix, split.Suffix) {
			t.Fatalf("split is not deterministic: second error=%v", secondErr)
		}
	})
}
