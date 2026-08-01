package framing

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
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

// SplitRequest validates one complete raw request and isolates the
// protocol-defined bytes whose arrival completes it. The accepted grammar is
// deliberately narrower than the union of HTTP/1 implementations: if common
// parsers can disagree on the message boundary, the request is rejected.
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
	transferCodings, err := parseTransferCodings(headers)
	if err != nil {
		return Split{}, err
	}
	if contentLength != nil && len(transferCodings) != 0 {
		return Split{}, errors.New("request has both Content-Length and Transfer-Encoding")
	}

	if len(transferCodings) != 0 {
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
		return validateSplit(raw, newSplit(raw[:prefixEnd], raw[prefixEnd:], "chunked"))
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
			return validateSplit(raw, newSplit(raw[:len(raw)-held], raw[len(raw)-held:], "content-length"))
		}
	} else if len(body) != 0 {
		return Split{}, errors.New("request body has neither Content-Length nor chunked framing")
	}

	return validateSplit(raw, newSplit(head, headerEnd, "bodyless"))
}

func newSplit(prefix, suffix []byte, mode string) Split {
	return Split{
		Prefix: append([]byte(nil), prefix...),
		Suffix: append([]byte(nil), suffix...),
		Mode:   mode,
	}
}

func validateSplit(raw []byte, split Split) (Split, error) {
	reader := bufio.NewReader(bytes.NewReader(raw))
	request, err := http.ReadRequest(reader)
	if err != nil {
		return Split{}, fmt.Errorf("standard HTTP/1 parser rejected request: %w", err)
	}
	defer request.Body.Close()
	if _, err := io.Copy(io.Discard, request.Body); err != nil {
		return Split{}, fmt.Errorf("standard HTTP/1 body parser rejected request: %w", err)
	}
	if reader.Buffered() != 0 {
		return Split{}, fmt.Errorf(
			"standard HTTP/1 parser left %d unconsumed bytes",
			reader.Buffered(),
		)
	}
	return split, nil
}

func parseHead(head []byte) (string, []header, error) {
	lines := bytes.Split(head, crlf)
	if len(lines) == 0 || len(lines[0]) == 0 {
		return "", nil, errors.New("request line is absent")
	}
	requestParts := bytes.Split(lines[0], []byte{' '})
	if len(requestParts) != 3 || !validToken(requestParts[0]) ||
		!validRequestTarget(requestParts[1]) ||
		(!bytes.Equal(requestParts[2], []byte("HTTP/1.0")) &&
			!bytes.Equal(requestParts[2], []byte("HTTP/1.1"))) {
		return "", nil, errors.New("request line must be METHOD target HTTP/1.0 or HTTP/1.1")
	}

	headers := make([]header, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			return "", nil, errors.New("folded HTTP headers are intentionally unsupported")
		}
		parsed, err := parseHeaderLine(line)
		if err != nil {
			return "", nil, err
		}
		headers = append(headers, parsed)
	}
	return strings.ToUpper(string(requestParts[0])), headers, nil
}

func parseHeaderLine(line []byte) (header, error) {
	name, value, found := bytes.Cut(line, []byte{':'})
	if !found || !validToken(name) {
		return header{}, fmt.Errorf("malformed header field-name: %q", line)
	}
	if !validFieldValue(value) {
		return header{}, fmt.Errorf("malformed header field-value: %q", line)
	}
	return header{
		name:  strings.ToLower(string(name)),
		value: string(bytes.Trim(value, " \t")),
	}, nil
}

func validToken(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, octet := range value {
		if !isTokenOctet(octet) {
			return false
		}
	}
	return true
}

func isTokenOctet(octet byte) bool {
	if octet >= '0' && octet <= '9' || octet >= 'A' && octet <= 'Z' ||
		octet >= 'a' && octet <= 'z' {
		return true
	}
	switch octet {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validRequestTarget(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, octet := range value {
		if octet <= 0x20 || octet >= 0x7f {
			return false
		}
	}
	return true
}

func validFieldValue(value []byte) bool {
	for _, octet := range value {
		if octet == '\t' || octet >= 0x20 && octet != 0x7f {
			continue
		}
		return false
	}
	return true
}

func parseContentLength(headers []header) (*int, error) {
	values := make([]string, 0, 1)
	for _, item := range headers {
		if item.name == "content-length" {
			values = append(values, item.value)
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, errors.New("multiple Content-Length headers are ambiguous")
	}
	value := values[0]
	if value == "" {
		return nil, errors.New("Content-Length is not a decimal integer")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return nil, errors.New("Content-Length is not a decimal integer")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 63)
	if err != nil {
		return nil, errors.New("Content-Length is not a decimal integer")
	}
	if parsed > uint64(^uint(0)>>1) {
		return nil, errors.New("Content-Length is too large")
	}
	length := int(parsed)
	return &length, nil
}

func parseTransferCodings(headers []header) ([]string, error) {
	values := make([]string, 0, 1)
	for _, item := range headers {
		if item.name == "transfer-encoding" {
			values = append(values, item.value)
		}
	}
	if len(values) == 0 {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, errors.New("multiple Transfer-Encoding headers are ambiguous")
	}
	parts := strings.Split(values[0], ",")
	codings := make([]string, 0, len(parts))
	for _, part := range parts {
		coding := strings.TrimSpace(part)
		if coding == "" || !validToken([]byte(coding)) {
			return nil, errors.New("Transfer-Encoding contains an invalid coding")
		}
		codings = append(codings, strings.ToLower(coding))
	}
	if len(codings) != 1 || codings[0] != "chunked" {
		return nil, errors.New("request Transfer-Encoding must be exactly chunked")
	}
	return codings, nil
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
		sizeToken := sizeLine
		if semicolon := bytes.IndexByte(sizeLine, ';'); semicolon >= 0 {
			sizeToken = sizeLine[:semicolon]
			if !validChunkExtensions(sizeLine[semicolon:]) {
				return 0, 0, false, fmt.Errorf("invalid chunk extensions: %q", sizeLine[semicolon:])
			}
		}
		if !validHexDigits(sizeToken) {
			return 0, 0, false, fmt.Errorf("invalid chunk size: %q", sizeToken)
		}
		size, parseErr := strconv.ParseUint(string(sizeToken), 16, 63)
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
				trailer, trailerErr := parseHeaderLine(body[trailerPosition:trailerEnd])
				if trailerErr != nil {
					return 0, 0, false, fmt.Errorf("malformed chunk trailer: %w", trailerErr)
				}
				if forbiddenTrailer(trailer.name) {
					return 0, 0, false, fmt.Errorf("forbidden chunk trailer field: %s", trailer.name)
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

func validHexDigits(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	for _, octet := range value {
		if octet >= '0' && octet <= '9' || octet >= 'A' && octet <= 'F' ||
			octet >= 'a' && octet <= 'f' {
			continue
		}
		return false
	}
	return true
}

func validChunkExtensions(value []byte) bool {
	for len(value) != 0 {
		if value[0] != ';' {
			return false
		}
		value = value[1:]
		nameLength := tokenPrefixLength(value)
		if nameLength == 0 {
			return false
		}
		value = value[nameLength:]
		if len(value) == 0 || value[0] == ';' {
			continue
		}
		if value[0] != '=' {
			return false
		}
		value = value[1:]
		if len(value) == 0 {
			return false
		}
		if value[0] == '"' {
			length, ok := quotedStringLength(value)
			if !ok {
				return false
			}
			value = value[length:]
		} else {
			length := tokenPrefixLength(value)
			if length == 0 {
				return false
			}
			value = value[length:]
		}
		if len(value) != 0 && value[0] != ';' {
			return false
		}
	}
	return true
}

func tokenPrefixLength(value []byte) int {
	for index, octet := range value {
		if !isTokenOctet(octet) {
			return index
		}
	}
	return len(value)
}

func quotedStringLength(value []byte) (int, bool) {
	if len(value) == 0 || value[0] != '"' {
		return 0, false
	}
	for index := 1; index < len(value); index++ {
		octet := value[index]
		if octet == '"' {
			return index + 1, true
		}
		if octet == '\\' {
			index++
			if index >= len(value) || !validQuotedPairOctet(value[index]) {
				return 0, false
			}
			continue
		}
		if !validQuotedTextOctet(octet) {
			return 0, false
		}
	}
	return 0, false
}

func validQuotedTextOctet(octet byte) bool {
	return octet == '\t' || octet == ' ' || octet == '!' ||
		octet >= '#' && octet <= '[' || octet >= ']' && octet != 0x7f
}

func validQuotedPairOctet(octet byte) bool {
	return octet == '\t' || octet == ' ' || octet >= 0x21 && octet != 0x7f
}

func forbiddenTrailer(name string) bool {
	switch name {
	case "authorization", "connection", "content-length", "host", "keep-alive",
		"proxy-authenticate", "proxy-authorization", "te", "trailer",
		"transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}
