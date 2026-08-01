package framing

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
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
			name:   "chunked trailers and extensions",
			raw:    []byte("POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n4;proof=yes\r\ntest\r\n0\r\nX-Proof: yes\r\n\r\n"),
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

func TestSplitRequestRejectsKnownParserDifferentials(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "invalid HTTP version",
			raw:  []byte("POST / HTTP/1.x\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
		},
		{
			name: "signed Content-Length",
			raw:  []byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +1\r\n\r\na"),
		},
		{
			name: "whitespace before header colon",
			raw:  []byte("POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 1\r\n\r\na"),
		},
		{
			name: "space in header field-name",
			raw:  []byte("GET / HTTP/1.1\r\nHost: x\r\nBad Name: x\r\n\r\n"),
		},
		{
			name: "unsupported transfer coding before chunked",
			raw:  []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"),
		},
		{
			name: "duplicate chunked coding",
			raw:  []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"),
		},
		{
			name: "signed chunk size",
			raw:  []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n+1\r\na\r\n0\r\n\r\n"),
		},
		{
			name: "whitespace padded chunk size",
			raw:  []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n 1\r\na\r\n0\r\n\r\n"),
		},
		{
			name: "forbidden Content-Length trailer",
			raw:  []byte("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\nContent-Length: 1\r\n\r\n"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := SplitRequest(test.raw); err == nil {
				t.Fatalf("strict framing accepted parser differential: %q", test.raw)
			}
			if err := readWithStandardLibrary(test.raw); err == nil {
				t.Log("standard library accepted this byte sequence; strict mode still rejects it to avoid cross-parser disagreement")
			}
		})
	}
}

func TestSplitRequestAcceptsStandardLibraryCompatibleCorpus(t *testing.T) {
	tests := [][]byte{
		[]byte("GET / HTTP/1.0\r\nHost: example.test\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: example.test\r\nX-Test: value\twith-tab\r\n\r\n"),
		[]byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0005\r\n\r\nabcde"),
		[]byte("POST / HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n1;name=token;quoted=\"x\\\"y\"\r\na\r\n0\r\nX-Proof: yes\r\n\r\n"),
	}
	for _, raw := range tests {
		if err := readWithStandardLibrary(raw); err != nil {
			t.Fatalf("stdlib rejected valid corpus %q: %v", raw, err)
		}
		split, err := SplitRequest(raw)
		if err != nil {
			t.Fatalf("strict framing rejected valid corpus %q: %v", raw, err)
		}
		joined := append(append([]byte{}, split.Prefix...), split.Suffix...)
		if !bytes.Equal(joined, raw) {
			t.Fatalf("split changed valid corpus bytes")
		}
	}
}

func readWithStandardLibrary(raw []byte) error {
	reader := bufio.NewReader(bytes.NewReader(raw))
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	defer request.Body.Close()
	if _, err := io.ReadAll(request.Body); err != nil {
		return err
	}
	if reader.Buffered() != 0 {
		return fmt.Errorf("%d bytes remain after standard-library request parse", reader.Buffered())
	}
	return nil
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
