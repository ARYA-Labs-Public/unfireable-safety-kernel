# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Rust kernel binary providing an authorization and policy-enforcement service.
- HTTP service built on `axum` exposing the kernel's authorize, approve, and
  audit endpoints.
- Ed25519-signed, append-only transparency log with externally verifiable
  Merkle inclusion proofs.
- Rust client SDK with built-in retry, timeout, and circuit-breaker behavior
  for safe integration from upstream services.
- Python defense package shipping a FastAPI middleware and an audit hook for
  request-level enforcement and structured event capture.
- Reference integrations and example deployments for FastAPI, `axum`, and
  `nginx` reverse-proxy front ends.
- OpenAPI 3.1 contract describing every public endpoint, request schema, and
  response shape.
- Reconciler worker that periodically verifies log consistency and surfaces
  drift between the signed log and downstream consumers.

### Changed

- Initial public release; no prior versions to compare against.

### Security

- All authorization decisions are signed and recorded in the transparency log
  before a response is returned to the caller.
- Default deployment configuration assumes TLS termination at the proxy and
  least-privilege credentials for the kernel process.
- Client SDK fails closed on signature-verification errors and on circuit-
  breaker open state.
