package framing

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	headerEnd = []byte("\r\n\r\n")
	crlf      = []byte("\r\n")
)

type Split struct {
	Prefix []byte
	Suffix []byte
	Mode   string
}

type header struct {
	name  string
	value string
}

// SplitRequest validates one complete raw HTTP/1 request and isolates the
// protocol-defined bytes whose arrival completes it.
func SplitRequest(raw []byte) (Split, error) {
	headerOffset := bytes.Index(raw, headerEnd)
	if headerOffset < 0 {
		return Split{}, errors.New("HTTP headers must end with CRLF CRLF")
	}
	head := raw[:headerOffset]
	body := raw[headerOffset+len(headerEnd):]
	_, headers, err := parseHead(head)
	if err != nil {
		return Split{}, err
	}
	contentLength, err := parseContentLength(headers)
	if err != nil {
		return Split{}, err
	}
	transferCodings := parseTransferCodings(headers)
	if contentLength != nil && len(transferCodings) != 0 {
		return Split{}, errors.New("request has both Content-Length and Transfer-Encoding")
	}

	if len(transferCodings) != 0 {
		if transferCodings[len(transferCodings)-1] != "chunked" {
			return Split{}, errors.New("final request Transfer-Encoding is not chunked")
		}
		terminalStart, messageEnd, complete, layoutErr := chunkedLayout(body)
		if layoutErr != nil {
			return Split{}, layoutErr
		}
		if !complete {
			return Split{}, errors.New("chunked request is incomplete")
		}
		if messageEnd != len(body) {
			return Split{}, errors.New("bytes exist after the terminal chunk")
		}
		prefixEnd := headerOffset + len(headerEnd) + terminalStart
		return newSplit(raw[:prefixEnd], raw[prefixEnd:], "chunked"), nil
	}

	if contentLength != nil {
		if len(body) != *contentLength {
			return Split{}, fmt.Errorf(
				"Content-Length declares %d, captured body has %d bytes",
				*contentLength,
				len(body),
			)
		}
		if *contentLength > 0 {
			held := min(3, *contentLength)
			return newSplit(raw[:len(raw)-held], raw[len(raw)-held:], "content-length"), nil
		}
	} else if len(body) != 0 {
		return Split{}, errors.New("request body has neither Content-Length nor chunked framing")
	}

	return newSplit(head, headerEnd, "bodyless"), nil
}

func newSplit(prefix, suffix []byte, mode string) Split {
	return Split{
		Prefix: append([]byte(nil), prefix...),
		Suffix: append([]byte(nil), suffix...),
		Mode:   mode,
	}
}

func parseHead(head []byte) (string, []header, error) {
	lines := bytes.Split(head, crlf)
	if len(lines) == 0 || len(lines[0]) == 0 {
		return "", nil, errors.New("request line is absent")
	}
	requestParts := bytes.Split(lines[0], []byte{' '})
	if len(requestParts) != 3 || len(requestParts[0]) == 0 || len(requestParts[1]) == 0 ||
		!bytes.HasPrefix(requestParts[2], []byte("HTTP/1.")) {
		return "", nil, errors.New("request line must be METHOD target HTTP/1.x")
	}

	headers := make([]header, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			return "", nil, errors.New("folded HTTP headers are intentionally unsupported")
		}
		name, value, found := bytes.Cut(line, []byte{':'})
		name = bytes.TrimSpace(name)
		if !found || len(name) == 0 {
			return "", nil, fmt.Errorf("malformed header line: %q", line)
		}
		headers = append(headers, header{
			name:  strings.ToLower(string(name)),
			value: string(bytes.TrimSpace(value)),
		})
	}
	return strings.ToUpper(string(requestParts[0])), headers, nil
}

func parseContentLength(headers []header) (*int, error) {
	var value *string
	for _, item := range headers {
		if item.name != "content-length" {
			continue
		}
		if value != nil && *value != item.value {
			return nil, errors.New("conflicting Content-Length headers")
		}
		copy := item.value
		value = &copy
	}
	if value == nil {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(*value, 10, 64)
	if err != nil {
		return nil, errors.New("Content-Length is not an integer")
	}
	if parsed < 0 {
		return nil, errors.New("Content-Length cannot be negative")
	}
	if parsed > int64(^uint(0)>>1) {
		return nil, errors.New("Content-Length is too large")
	}
	length := int(parsed)
	return &length, nil
}

func parseTransferCodings(headers []header) []string {
	var codings []string
	for _, item := range headers {
		if item.name != "transfer-encoding" {
			continue
		}
		for _, token := range strings.Split(item.value, ",") {
			token = strings.ToLower(strings.TrimSpace(token))
			if token != "" {
				codings = append(codings, token)
			}
		}
	}
	return codings
}

func chunkedLayout(body []byte) (terminalStart, messageEnd int, complete bool, err error) {
	position := 0
	for {
		relativeLineEnd := bytes.Index(body[position:], crlf)
		if relativeLineEnd < 0 {
			return 0, 0, false, nil
		}
		lineEnd := position + relativeLineEnd
		sizeLine := body[position:lineEnd]
		if semicolon := bytes.IndexByte(sizeLine, ';'); semicolon >= 0 {
			sizeLine = sizeLine[:semicolon]
		}
		sizeToken := strings.TrimSpace(string(sizeLine))
		if sizeToken == "" {
			return 0, 0, false, errors.New("chunk size is absent")
		}
		size, parseErr := strconv.ParseUint(sizeToken, 16, 63)
		if parseErr != nil {
			return 0, 0, false, fmt.Errorf("invalid chunk size: %q", sizeToken)
		}
		chunkStart := position
		dataStart := lineEnd + len(crlf)
		if size == 0 {
			trailerPosition := dataStart
			for {
				relativeTrailerEnd := bytes.Index(body[trailerPosition:], crlf)
				if relativeTrailerEnd < 0 {
					return 0, 0, false, nil
				}
				trailerEnd := trailerPosition + relativeTrailerEnd
				if trailerEnd == trailerPosition {
					return chunkStart, trailerEnd + len(crlf), true, nil
				}
				if !bytes.Contains(body[trailerPosition:trailerEnd], []byte{':'}) {
					return 0, 0, false, fmt.Errorf(
						"malformed chunk trailer: %q",
						body[trailerPosition:trailerEnd],
					)
				}
				trailerPosition = trailerEnd + len(crlf)
			}
		}
		if size > uint64(len(body)) || uint64(dataStart)+size+uint64(len(crlf)) > uint64(len(body)) {
			return 0, 0, false, nil
		}
		dataEnd := dataStart + int(size)
		if !bytes.Equal(body[dataEnd:dataEnd+len(crlf)], crlf) {
			return 0, 0, false, errors.New("chunk data is not followed by CRLF")
		}
		position = dataEnd + len(crlf)
	}
}
