# H1 Racer Kernel


A raw HTTP/1 race transport kernel with browser-style uTLS handshakes.

It opens independent TLS connections, writes an exact request prefix to every connection, aborts before FIRE if any connection fails to arm, then releases the exact suffix across the ready group. Responses are captured as bounded raw bytes with per-connection transport and timing evidence.

## Non-negotiable invariants

- `wire_request == base64(prefix) || base64(suffix)` byte for byte.
- One independent TCP/TLS connection per copy.
- No HTTP serializer, redirects, retries, pooling, or header rewriting.
- No FIRE unless every requested connection reached `PREFIX_ARMED`.
- TLS profile and custom hex ClientHello are mutually exclusive.
- Response capture is bounded per connection and across the entire race, and reports whether it ended by EOF, idle timeout, or byte limit.

## Build and verify

```powershell
./scripts/verify.ps1
```

Portable commands:

```sh
go vet ./...
go test ./... -count=1
go build -trimpath ./cmd/h1-racer-kernel
```

## Run

```sh
h1-racer-kernel --plan examples/local-plan.json --output race-result.json
```

Print the embedded build version:

```sh
h1-racer-kernel --version
```

List accepted profiles:

```sh
h1-racer-kernel --list-profiles
```

## RacePlan v1

The CLI accepts one strict JSON value. Unknown fields are rejected. The machine-readable contract is [`schema/race-plan-v1.schema.json`](schema/race-plan-v1.schema.json).

```json
{
  "schema_version": 1,
  "target": "example.com:443",
  "server_name": "example.com",
  "tls": { "enabled": true, "profile": "default" },
  "copies": 20,
  "prefix_base64": "...",
  "suffix_base64": "...",
  "connect_timeout_ms": 5000,
  "io_timeout_ms": 5000,
  "settle_ms": 10,
  "max_response_bytes": 524288
}
```

`tls.enabled` defaults to `true`; set it to `false` for raw TCP HTTP. `tls.client_hello_hex` may replace `tls.profile` when reproducing an intercepted ClientHello. Certificate verification is enabled by default; `tls.ca_file` adds a PEM trust source. `tls.insecure_skip_verify` exists for controlled local labs.

## Scope

This repository is the transport kernel only. Burp adapters, request framing compilation, and UI live outside the FIRE path.

Use only against systems you own or are explicitly authorized to test.