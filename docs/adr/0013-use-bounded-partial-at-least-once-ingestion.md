# Use bounded partial at-least-once ingestion

Positron groups each ingest request by tenant, signal store, and virtual shard, and each admission group reserves bounded memory, storage, and replication capacity before encoding. Store blocks are the smallest atomic units, successful groups are never rolled back because another group fails, and responses distinguish accepted records from retryable capacity or quorum failures and permanent validation failures. Delivery is at least once, so timeout retries may duplicate data; version 1 does not claim distributed request atomicity, exactly-once ingestion, or global deduplication.

Transient OTLP gRPC capacity and preauthentication rate refusals use `Unavailable`.
Hard receiver limits retain `ResourceExhausted`. This follows the [OTLP failure
contract](https://github.com/open-telemetry/opentelemetry-proto/blob/main/docs/specification.md#failures):
`ResourceExhausted` without `google.rpc.RetryInfo` is not retryable. HTTP capacity
refusals remain `429` with `Retry-After`. Clients retry only explicit transient
precommit refusals with bounded backoff; ambiguous outcomes retain the separate
at-least-once decision and may duplicate accepted records.
