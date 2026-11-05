# Positron Go SDK

The dependency-free Go module `github.com/vicotrbb/positron/sdk/go` requires Go 1.24.0 or later. The Rust Public Interface generator owns requests, results, validation, error policy, capability negotiation and delivery helpers. API version and Schema Digest are embedded with the canonical definition and shared fixtures.

Generate with `cargo run --locked -p positron-api --example generate_go_sdk -- sdk/go`, then run `gofmt -w sdk/go`. Run consumer conformance with `cd sdk/tests/go && GOMAXPROCS=2 go test -p 1 ./...`.

Construct `NewClient(endpoint, false)` for verified HTTPS. Plaintext requires explicit opt-in. Pass a bounded `context.Context` and a bearer credential to a typed RPC method. Credentials are never embedded in endpoints or returned in errors. The transport bounds DNS, connections, headers, response bytes and total request duration; redirects and automatic effect retries are disabled. Close the client to release idle connections.

Query requests use decimal strings for Protobuf 64-bit values; administration uses native Go integer fields. Optional scalar fields use pointers to distinguish absence from zero. Canonical oneof messages use JSON raw values and are checked at the generated validation boundary. `Decode`, `Encode` and `DecodeQuery` reject malformed data. `ClientError` preserves stable failure, retry and completion classes. Ambiguous transport outcomes require reconciliation by the caller.

Use `BatchTracker` for Session and Tail delivery. Consume returned batches before submitting `Acknowledgement`; retain the original cursor for cancellation. Helpers reject changed repeats, gaps and terminal contradictions. An incomplete terminal remains incomplete. A cursor never authenticates a request. Each Session/Tail operation negotiates capabilities afresh.

The standard Go module ZIP, module identity, release metadata, canonical API and digest are inspected by Release Trust. Module checksums, SPDX/CycloneDX SBOMs, source/build provenance, native checksum-database proof, signatures, revocation and independent reproducible bytes bind the existing signed Release Manifest. Local tests use private signing authorities and do not establish publication. This implementation does not publish an SDK or announce a completed release set.
