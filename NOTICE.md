# Attribution

The custom ClientHello normalization in `internal/transport/clienthello.go` is adapted from Burp Suite Awesome TLS, licensed under GPL-3.0. The kernel uses `github.com/bogdanfinn/tls-client/profiles` and `github.com/bogdanfinn/utls` for browser-style TLS handshakes.

This project deliberately does not import Awesome TLS HTTP clients, request serializers, connection pools, retries, or proxy server code into the race path.