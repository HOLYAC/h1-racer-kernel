# Security and authorized use

H1 Racer Kernel is intended only for systems you own or are explicitly authorized to test.

## Sensitive material

RacePlan may contain private HTTP bytes, a custom ClientHello, a private CA path, and upstream proxy credentials. Integrations should stream sensitive plans over stdin rather than leave plan files behind. Reports deliberately omit proxy credentials and raw ClientHello bytes, but response bodies and request-derived evidence can still be sensitive and must be protected accordingly.

The release private key must remain outside the repository. Only the Ed25519 public verification key is distributable. `h1-racer-artifact keygen` refuses to overwrite an existing key, and the release pipeline refuses dirty source trees.

## Reporting

Do not submit public vulnerability reports containing live credentials, private request bytes, or responses captured from third-party systems. Report implementation vulnerabilities through GitHub private vulnerability reporting when available.
