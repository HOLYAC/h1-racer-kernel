# H1 Racer Kernel

A raw HTTP/1 race transport kernel with browser-style uTLS handshakes.

It opens independent connections, writes an exact request prefix to every connection, aborts before FIRE if any connection fails to arm, then releases the exact suffix across the ready group. Responses are captured as bounded raw bytes with per-connection transport, proxy, TLS identity, and timing evidence.

## Non-negotiable invariants

- `wire_request == base64(prefix) || base64(suffix)` byte for byte.
- One independent TCP/TLS connection per copy.
- No HTTP serializer, redirects, retries, pooling, or header rewriting.
- No FIRE unless every requested connection reached `PREFIX_ARMED`.
- Cancellation during settle aborts before FIRE.
- TLS profile and custom hex ClientHello are mutually exclusive.
- A TLS connection becomes ready only after explicit `http/1.1` ALPN negotiation.
- The target-facing ClientHello is captured at the raw stream boundary before any request prefix is written.
- Response capture is bounded per connection and across the entire race.
- Proxy credentials are used for dialing but omitted from reports.

## Build, test, and fuzz

```powershell
./scripts/verify.ps1
./scripts/fuzz.ps1 -Seconds 15
```

Portable commands:

```sh
go vet ./...
go test ./... -count=1
go test ./internal/framing -run '^$' -fuzz '^FuzzSplitRequest$' -fuzztime 15s
go build -trimpath -buildvcs=false ./cmd/h1-racer-kernel
```

The production request compiler and the fuzz target call the same `internal/framing.SplitRequest` function.

## Compile a captured HTTP/1 request

```sh
h1-racer-kernel --compile-request request.bin
```

The output is a strict properties record containing `mode`, `prefix_base64`, and `suffix_base64`. Burp verifies that the decoded prefix and suffix recompose the original captured bytes before launching a race.

## Run

```sh
h1-racer-kernel --plan examples/local-plan.json --output race-result.json
```

Utilities:

```sh
h1-racer-kernel --version
h1-racer-kernel --list-profiles
h1-racer-kernel --validate-client-hello clienthello.hex
```

## RacePlan v1

The CLI accepts one strict JSON value. Unknown fields are rejected. The machine-readable contract is [`schema/race-plan-v1.schema.json`](schema/race-plan-v1.schema.json).

```json
{
  "schema_version": 1,
  "target": "example.com:443",
  "server_name": "example.com",
  "tls": { "enabled": true, "profile": "default" },
  "proxy_url": "socks5h://user:pass@127.0.0.1:1080",
  "copies": 20,
  "prefix_base64": "...",
  "suffix_base64": "...",
  "connect_timeout_ms": 5000,
  "io_timeout_ms": 5000,
  "settle_ms": 10,
  "max_response_bytes": 524288
}
```

`tls.enabled` defaults to `true`; set it to `false` for raw TCP HTTP. `tls.client_hello_hex` may replace `tls.profile`. Certificate verification is enabled by default; `tls.ca_file` adds a PEM trust source. `tls.insecure_skip_verify` exists for controlled local labs.

`proxy_url` is optional. Supported schemes are authenticated or unauthenticated `http://` CONNECT, `socks5://`, and `socks5h://`, each with an explicit port. The report records a sanitized proxy address and per-connection dial route without credentials.

## TLS identity evidence

Every successful TLS connection records the selected identity source, selected profile when applicable, certificate-verification result, negotiated TLS parameters, and evidence derived from the exact outbound ClientHello handshake bytes:

- `client_hello_sha256`: exact per-connection ClientHello hash, including random material;
- `client_hello_ja3`: ordered structural fingerprint with GREASE values removed;
- `client_hello_ja3_sha256`: stable hash of that structural fingerprint;
- `client_hello_bytes` and `client_hello_record_count`: capture completeness metadata.

If the outbound ClientHello cannot be reconstructed, or ALPN is absent or different, the connection fails before `ARMED` and the batch does not FIRE.

## Failure phase evidence

Connection failures preserve the narrow phase that produced them: `connect`, `proxy`, `handshake`, `arm`, `ready`, `fire`, or `response`. The test suite injects reachable failures at every phase and asserts whether FIRE must remain closed or has already occurred.

## Artifact tooling

`h1-racer-artifact` creates deterministic ZIP/JAR archives and Ed25519 release signatures:

```sh
h1-racer-artifact archive --source stage --output release.zip --prefix h1-racer-0.2.0
h1-racer-artifact sign --subject release.zip --private release-key.pem --output release.zip.sig.json
h1-racer-artifact verify --subject release.zip --public release-public.pem --signature release.zip.sig.json
```

Archives use lexical file ordering, stored entries, fixed permissions, and a fixed 1980-01-01 timestamp. Signature records contain no clock value, so repeated signing of identical bytes with the same Ed25519 key is byte-identical.

## Scope

The kernel owns framing validation, raw transport, synchronization, bounded response capture, proxy dialing, and wire evidence. Burp owns only request selection, UI, persisted operator choices, and process launch.

Use only against systems you own or are explicitly authorized to test.
