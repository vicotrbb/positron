# Positron Rust SDK

`positron-sdk` contains the generated Positron v1 wire types and typed HTTP clients.
The package and server share the product version and canonical Schema Digest.
The canonical API and its public-interface adapters generate this package.
Generated files must be changed through those owners.

## Use the client

Use `log_query::LogQueryServiceClient` with `LogQueryTransport::Tls`.
Provide the resolved endpoint, verified server name, and protected PEM trust file.
Plaintext requires `LogQueryTransport::PlaintextOptOut`.
Bearer credentials are request metadata. The SDK never stores them in request bodies.

`execute` runs the baseline bounded finite query. `session` admits a page,
resumes an opaque cursor, or polls a live Tail. Session and Tail calls negotiate
the exact added capability each time, so an older server is refused before the
unsupported operation is sent. Compatible additive v1 schema changes do not
require identical digests between an old client and a newer server.

Use `BatchTracker::query()` across historical pages and `BatchTracker::tail()`
across Tail polls. `filter` returns only new batches. It checks the native
sequence/digest chain and normalized canonical wire payload for a repeated batch.
It keeps one receipt, fixed digest state, and no result cache. A failed check
leaves the previous receipt unchanged. The native digest remains server-owned.

A Tail poll delivers at most one pending batch. After the application receives
and accepts that batch, supply `BatchTracker::acknowledgement()` in the next
`LogQueryTailRequest`. A lost response can repeat the last batch with the same
sequence and digest. The SDK never acknowledges delivery implicitly.
Tail terminal counters describe acknowledged logical progress. A pending batch
is separate from that progress until its receipt commits.

`LogQueryTerminal::status()` preserves Complete, Continued, and the typed
Incomplete reason. `continuation()` returns a bounded, Debug-redacted opaque
cursor. Resume never restarts a query or substitutes a newer snapshot.
`cancel` authenticates the cursor and confirms durable release on success.
Repeated cancellation uses the same cursor and current principal authority.
Pre-effect authentication, cursor, and admission refusals remain Rejected.
Queued cleanup, partial paired cleanup, or uncertain publication keeps the
original canonical cause as `AmbiguousCancellation(code)`, with Ambiguous
completion and Never retry. Reconcile that original cursor explicitly.

Query failures expose the canonical retry class and completion state. A transport
failure is Ambiguous and never requests a blind retry. No SDK call retries,
restarts, renews a budget, or weakens a terminal failure automatically.

## Bounds

Finite Execute bounds its complete HTTP exchange to five seconds. Session and
Tail HTTP exchanges allow 30 seconds, with a five-second connection timeout.
Their leases have the canonical hard maximum of 3,600 seconds. Cursors are at most 8,192 bytes. A query
response is at most 262,144 bytes, with at most 128 rows and 128 columns.
Query budgets remain cumulative and server and tenant limits remain authoritative.
Tail polling returns on one delivery or idle observation without holding an
unlimited connection. Native cancellation, authorization, expiry, integrity,
and unavailable-data outcomes stay explicit.

## Generate and test

From the repository root, use the pinned Rust toolchain and locked dependencies:

```console
cargo run --locked -p positron-api --example generate_api_metadata -- api/positron/v1
cargo run --locked -p positron-api --example generate_rust_sdk -- sdk/rust
cargo test --locked -p positron-sdk --tests
cargo test --locked -p positron-sdk --doc
cargo doc --locked -p positron-sdk --no-deps
cargo package --locked -p positron-sdk
```

The package includes the canonical definition, HTTP/OpenAPI metadata, pinned
build configuration, license, examples, and canonical public contract tests.
The reused Nix query fixture in that test suite requires Python 3.
Packaging does not publish the crate.

## Release binding

`package.metadata.positron` declares the API version, Schema Digest, generator
inputs, `SdkRust` Release Manifest surface, and crates.io registry.
Cargo records the source commit in `.cargo_vcs_info.json` when packaging a clean
checkout. The Release Trust owner binds the exact `.crate` checksum and size,
independent reproducible bytes, SPDX/CycloneDX SBOMs, license notices, build
provenance, and publication evidence to the signed Release Manifest inventory.

Use the existing `positron release construct` and `positron release verify`
commands with the complete artifact inventory and explicitly installed trust.
A dirty source package, changed payload, mismatched metadata, missing proof,
revocation, or partial SDK Release Set must be refused. crates.io has no
independently verifiable offline upload receipt. Its native absence profile
binds captured index/publishing metadata under authenticated project provenance.
No package, registry tag, or checksum alone is release authority. Publication
and release remain separate authorized actions.
