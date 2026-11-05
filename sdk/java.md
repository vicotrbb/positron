# Positron JVM SDK

Requires Java 21. Generate from the canonical Rust Public Interface:

```sh
cargo run --locked -p positron-api --example generate_java_sdk -- sdk/java
mvn -f sdk/java/pom.xml package
```

The Maven coordinates are `dev.positron:sdk`, matching the product release version.
The automatic module name is `dev.positron.sdk`. Jackson 2.19.2 is the pinned JSON
adapter; it supplies native record serialization rather than an independent parser.
Public `Types` records cover canonical request and result objects. `Codec` accepts
native records, maps and Jackson trees, validates emitted JSON, and embeds the API
version and Schema Digest. Generated bindings carry no server domain types.

Use `new Client("https://positron.example")` with a tenant bearer. Plain HTTP
requires the explicit second constructor argument `true`, intended for loopback
development. TLS uses the JVM trust store and hostname verification. Credentials,
URLs containing user information, malformed JSON and unsafe text are refused;
errors never include peer text or credentials. Calls never retry automatically.
Finite Execute has a five-second total ceiling; Session and Tail polls permit at
most thirty seconds. A shorter caller deadline always wins, including negotiation.

`Query.decode` validates bounded streams and explicit terminal truth. `BatchTracker`
retains one delivery receipt and fixed digest state, discards verified repeats and
refuses gaps, changed contents or contradictory counters. Acknowledge Tail only
after consuming a returned batch. Cursors are opaque data, never credentials.
Feature negotiation precedes Session and cancellation; unsupported old peers
produce stable UnsupportedFeature without sending the added operation.

Build main, sources, Javadoc JARs and POM with pinned Maven 3.9.11 and Java 21.
The fixed build timestamp produces reproducible payloads. Release packaging stages
source identity in `dev/positron/release.json` before building. The existing
`positron release verify` path authenticates exact Maven identity, API/schema,
checksums, OpenPGP publication signatures, SBOMs, provenance and independent
payload bytes against the signed Release Manifest and installed Project Trust
Root. A local package or private signing fixture does not establish publication.
No SDK is published by generation or tests.

`examples/Example.java` constructs and validates a bounded typed query without
network access when run with no arguments. Supply an HTTPS endpoint argument
and `POSITRON_BEARER` in the process environment to execute it and print the
server's terminal state. Never put bearer credentials in command arguments.

After staging the completed signed release bundle and installed trust, verify
it offline with the existing command (all paths are operator-supplied):

```sh
positron release verify --manifest signed.manifest --inventory inventory.json \
  --trust installed-trust.json --bundle bundle --rebuild independent --target linux-x86_64
```

Main, sources and Javadoc JARs and the exact POM are separate Maven publication
members. `dependencies.json` pins Jackson's three runtime JAR hashes and license
identities; both SPDX and CycloneDX documents must cover those dependencies.
The verifier refuses omitted or changed package identity, native signature,
source/API/schema, SBOM dependency, provenance, inventory, secret scan or
independent payload. Tests use private authorities to exercise those refusals.
