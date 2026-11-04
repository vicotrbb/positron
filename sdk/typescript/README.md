# Positron TypeScript SDK

Generated from the canonical `api/positron/v1` definition and HTTP schema by the Rust Public Interface owner. Node.js 22 or later is required. The package has no runtime dependencies. Protobuf JSON query integers with 64 bits retain decimal strings. Native administration JSON numbers use `number` when safe and `bigint` above that range, preserving the exact numeric wire form. Bytes retain base64 and cursors remain opaque.

```sh
cargo run --locked -p positron-api --example generate_typescript_sdk -- sdk/typescript
cd sdk/typescript
npm ci --ignore-scripts
npm run build
npm pack --ignore-scripts
```

Install the resulting `positron-sdk-*.tgz` in a clean consumer with `npm install --ignore-scripts /absolute/path/to/package.tgz`.

```ts
import { PositronClient } from '@positron/sdk';
const client = new PositronClient({endpoint: 'https://localhost:8443'});
const capability = await client.capabilityNegotiate({api_major: 1});
```

The server controls admission, errors, capabilities, completion and retry truth. Transport loss is ambiguous and is never retried automatically. Credentials are passed in per-call options and never stored by the client. TLS is required unless `allowPlaintext` is explicitly set. Redirects and URL credentials are refused.

Release Trust binds the actual npm archive, API/schema identity, source commit, registry subject, independent reproducible payload, SPDX/CycloneDX, provenance and native npm signature to the existing signed Release Manifest. Local generation and packaging do not publish a package or establish a complete Release Set.

Run the shared wire, delivery, transport and package tests after building:

```sh
POSITRON_TYPESCRIPT_SDK="$PWD/sdk/typescript" node --test sdk/tests/typescript/*.test.mjs
cargo test --locked -p positron-runtime --test native_transport generated_typescript_sdk_conforms
cargo test --locked -p positron-release --test typescript_sdk
```

`logQuerySession` negotiates the current peer before every session or Tail poll. `logQueryCancel` negotiates the corresponding cursor capability. A different v1 Schema Digest is allowed for additive-compatible peers. Unsupported features are refused explicitly.

The package includes a typed finite-query example in `examples/query.ts`. It accepts the endpoint, credential and request from the caller.

For pagination, keep one `BatchTracker`, pass each response to `filter`, and consume only the returned new batches. Read `terminalStatus` to distinguish Complete, Continued and Incomplete. Resume only with the server's continuation cursor. For Tail, use `new BatchTracker('tail')` and supply `acknowledgement()` explicitly in the next Tail request after consuming a batch. Cancel using the original authenticated cursor to release the lease. Aborting an HTTP request leaves the effect ambiguous and does not cancel a server lease.

For release packaging, use a clean source checkout at the intended commit. After generation, locked installation and build, bind the exact source with `npm pkg set gitHead="$(git rev-parse HEAD)"` in the package directory, then `npm pack --ignore-scripts`. Pass the resulting archive and independent rebuild to the existing Release Trust inventory. Its package subject is `pkg:npm/%40positron/sdk@VERSION` on `https://registry.npmjs.org`. This ticket does not publish to npm.
