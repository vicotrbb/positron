# Operational State

The Operations Listener serves `GET /health/live`, `GET /health/ready`, and system-
administrator API-key authenticated `GET /status` and `GET /metrics`. Scraping uses the
listener's existing TLS, connection, rate, and deadline limits. The endpoint returns
Prometheus text 0.0.4 by default; an OpenMetrics 1.0 `Accept` header selects OpenMetrics
text. Raw tenant, principal, API-key, trace/span, attribute, path, query, provider, and
deployment identities are never metric labels. Authenticated administration remains the
owner of tenant detail.

Import [the Grafana dashboard](../../monitoring/grafana-dashboard.json), load [the
Prometheus alert rules](../../monitoring/prometheus-alerts.yaml), and adapt [the
ServiceMonitor example](../../monitoring/servicemonitor.yaml) to the actual Operations
Service labels, named port, CA, server identity, and API-key Secret. Use existing key
rotation/revocation; never put a credential in a dashboard, alert, command transcript,
or repository. These are monitoring artifacts and do not provision Kubernetes resources
or change listener configuration.

## Fact ownership and absence

Process phase, viability, readiness, integrity degradation, and security warnings come
from HealthState. Clock and maintenance task/progress facts come from Lifecycle Clock
and Maintenance Coordinator. Capacity, usage, protected reserve, pressure, and admission
refusals come from Resource Governor. Catalog, quarantine, scrub, and operation counts
come from authenticated owner inspection. The scrape reads these owners; it does not
persist metrics or create a Metric Signal Store. Failure to authenticate returns 401;
unavailable inspection returns 503. While Fenced, current restricted authorization keeps
process facts available, `positron_operational_owner_available` is zero, and unavailable
resource/maintenance/catalog facts are omitted. An unavailable scrape is never an all-
zero healthy snapshot. Missing queue age is omitted and
`positron_maintenance_oldest_queued_age_known` is zero; unknown running progress
deadlines remain counted separately from breaches.

Ingestion counters count the actual native Admission Group terminal outcomes: committed,
permanently rejected, retryable, or ambiguous. Request counters use only the finite
listener and terminal response class; scrapes and health probes never create request
traces. Counters reset with the process. Canonical maintenance tasks are counted by
their finite work class and phase, and active plaintext transport warnings use a finite
warning label. Native query completion counters and cumulative duration are distinct
from API request counters; query budget failures identify only the closed limiting
dimension. No future signal store, operator process, or unimplemented service is
represented by synthetic healthy metrics. Monitoring facts describe this process, not
user telemetry.

## Structured logs

One registered process task emits closed event records to stderr through nonblocking
descriptor writes. A full pipe fails immediately rather than delaying task cancellation
or Drain; that finite failure increments the sink counter. The configured
`diagnostics.log_level` filters emitted records. Detached execution uses one JSON object
per line; an attached terminal uses a concise severity and event name. Request records
have a process-generated request number and monotonic elapsed duration. The record
schema has no fields for raw bodies, paths, request headers, tenant/key identity, query
results, or arbitrary errors. Both the recent snapshot and pending output queue retain
at most 32 typed records. Overrun drops the oldest pending record and increments
`positron_operational_events_dropped_total`; sink failures increment
`positron_operational_log_failures_total`. Failure reporting never recursively queues
another log or trace. The snapshot is diagnostic history, not governance audit or a
durable log store.

## External OTLP tracing

Explicit optional `diagnostics.trace_otlp_grpc_address = "127.0.0.1:14317"` selects an
external OTLP gRPC collector; `"disabled"` is the default. This is a restart-required,
file-only setting with a numeric IP and nonzero port; no DNS, URL credentials, implicit
default collector, or hidden environment destination is accepted. The collector receives
only closed Positron operational spans, not tenant telemetry. Only
`service.name=positron` and the `positron.operational` instrumentation scope identify
the resource; event names and durations contain no user data. The plaintext numeric gRPC
connection is intended for a local collector or a protected deployment network; it
carries no authorization credential. Configuration refuses exact and loopback-alias self
addresses. Immediately before every send, the worker rechecks all actual registered TCP
descriptors, including staged/draining generations and ephemeral ports. A same-port
wildcard binding is conservatively refused because numeric input cannot establish
whether it denotes a local interface. A remote collector sharing port 4317 with an
explicitly bound loopback listener is allowed.

Export occurs outside request completion, only while Serving and after one system
diagnostics reservation admits the complete bounded batch/client peak. Each send holds a
1 MiB memory claim, one queued batch, task, I/O permit, CPU work unit and descriptor;
payload and response are capped at 4 KiB, HTTP/2 windows and header sizes are fixed, and
the whole connection/send completes or fails within one second. There is no retry queue
or retained collector error payload. No new send begins after Drain, Fenced, force
cancellation, or worker shutdown. The worker's cancellation/join follows the process
task authority; ordinary collector failures increment a counter and do not claim the
process is dead.

## Health readiness

Check `/health/live` and `/health/ready` separately, then authenticated `/status`.
Readiness is safe admission, not proof that every dependency or stored segment is
healthy. Recovering, Draining, Fenced, and Stopping refuse data admission. Inspect the
existing owner-reported dependency/phase condition. Resolve its cause before restarting;
a restart does not repair ambiguous durable state.

## Clock

A clock-uncertain alert means age-driven destructive work paused. Compare the host clock
and durable Lifecycle Clock evidence through authenticated status and the existing clock
administration workflow. Restore trustworthy time or use explicit audited acceptance
under its contract. Do not fabricate a queue age or a healthy maintenance deadline from
wall-clock subtraction.

## Disk pressure

Inspect finite usage/capacity and protected-reserve metrics and authenticated resource
status. Hard pressure rejects new disk-growing work while preserving safe recovery
capacity. Restore headroom using the existing bounded retention, reclamation, or
capacity workflow. Do not delete live segment/catalog files or borrow Recovery Reserve
for ingestion.

## Integrity

Quarantine isolates a damaged object; ambiguous identity, key custody, ownership, or
durability fences the instance. Read authenticated verification and quarantine evidence.
Never interpret a ready unaffected workload as proof that quarantined data is readable.
Follow verified restore or the explicitly confirmed abandonment workflow; do not
fabricate or return corrupt records.

## Maintenance

Inspect task status/explanation for conflicts, windows, pause, capacity refusal, clock
safety, or failed preconditions. A progress-SLO breach refers only to a Running task
whose committed completed-input count stopped advancing. A missing trusted
clock/progress timestamp is unknown, not healthy. Fix the owning cause and preserve the
coordinator's task identity and immutable inputs. Do not reset checkpoints or force
overlapping maintenance to clear an alert.

## Operational output

Check stderr destination health and collection throughput. The finite recent ring may
show the last records even when a sink failed. Queue-drop counters mean history was
lost, not that the lost work failed. Reduce output pressure through the existing
diagnostics log-level setting or restore the collection sink. Never enable
body/header/secret logging to investigate a dropped event.

## Trace export

Check the explicit destination, actual listener bindings, collector availability, and
governor headroom. Refusals include self/ambiguous destinations or unavailable
admission; failures include bounded connection/send/response refusal. Correct the
configuration and restart when the destination changes. Do not configure Positron's own
receiver as the collector, increase retries, or ingest operational spans into its own
tenant data to conceal failed external export.

## Doctor

Run `positron doctor --online --endpoint ADDRESS --server-name NAME --trust-file FILE --credential-stdin`
with a system administrator credential on standard input. Close standard input after the credential.
For an explicitly selected plaintext listener, replace the TLS options with `--allow-plaintext`.
The client ignores ambient HTTP proxies. An owner may use
`positron doctor --online --control-path PATH --credential-stdin` instead. The owner-only Control
Listener serves `/control/doctor` while Serving or Fenced; `/control/fenced/inspection` remains
available for existing fenced-inspection clients. Neither route changes configuration, maintenance,
clock state, catalog state, keys, or the process phase.

Stop the server before `positron doctor --offline --config FILE`. Offline Doctor acquires the
existing exclusive Storage Ownership Lock without creating it or running a capability probe.
An empty volume or missing lock produces `DOCTOR_BOOTSTRAP_UNAVAILABLE`; a live owner produces
`DOCTOR_STORAGE_LOCKED`. Doctor never initializes a volume, repairs damage, or truncates a tail.
The integrity inspection retains the existing bounded pass and continuation contract. A reported
continuation is a next command for `positron verify --offline`, not an automatic second pass.

Reports use version 1 key/value fields, stable finding codes, severity, evidence scope, and safe
next commands. Exit 0 confirms the reported inspected scope; exit 2 identifies argument or
configuration errors; exit 3 identifies a degraded, incomplete, fenced, unavailable, or failed
inspection. Online network requests have one five-second deadline and an 8 KiB response bound.
Unknown fields and unsupported values cannot enter a report. Missing required observations remain
`missing` or `unavailable`, and a declared `observed` family alone cannot establish completeness.
Storage capability tests require writes, so Doctor reports `not_probed_read_only`. Online headroom,
pressure, maintenance, and Recovery Reserve facts come from their current runtime owners.
Offline reports explicitly identify runtime-only families as unavailable. Backup verification and
purge compatibility remain `not_shipped` until their owning subsystem supplies real observations.

## Support Bundles and Crash Records

Create an encrypted diagnostic export with `positron support bundle create --config FILE
--output FILE.age --recipient AGE_X25519_RECIPIENT --credential-stdin`. Stop the server
for offline collection, or add `--control-path PATH` for authenticated online collection.
The Control collector uses its fixed 1 MiB, 30-second, 300-second recent-record window
and 32-source-file bounds; offline collection may lower the byte, elapsed-time, window,
and source-file limits through the corresponding command options. Native age X25519
recipients are the only accepted encryption recipients. Encrypted archive admission reserves
the bounded framing for the maximum 16 recipients and payload authentication tags.
The signed metadata declares both the plaintext archive budget and final output budget;
source members that exceed the remaining budget produce a declared truncated summary.
Online source-window or source-file overrides that differ from the fixed Control policy
are rejected before authentication or collection. Online exports still enforce a smaller
requested output or client deadline bound.

The closed allowlist excludes telemetry, query output, credentials and hashes, private
keys, recovery material, secret values, raw memory, and core dumps. Deployment identifiers
are pseudonymized with one ephemeral per-bundle mapping. An authenticated administrator
may explicitly request `--retain-identifier data_directory`; the Redaction Report records
both the requested and applied policy, including unavailable retention after runtime retirement.

The archive manifest binds each included member checksum and the Redaction Report.
The report lists included and omitted allowlisted classes, prohibited classes, collection
bounds, omission reasons, encryption, and signature state. If content and metadata exceed
the archive budget, later admitted members are omitted deterministically and the manifest
and report are regenerated before signing. Collection never reports omitted content as complete.
Operational counters come from the existing aggregation owner. Health evidence records
current readiness, liveness, integrity degradation, and security warnings; a Serving phase
alone cannot establish healthy status. Recent operational logs apply the declared monotonic
time window and report both expired records and bounded history eviction.

`--allow-plaintext-bundle` explicitly selects an atomic owner-only plaintext export with
a persistent security warning in the report. Output cannot replace an existing file or
enter managed data/secrets directories. `--offline-key-unavailable` permits a stopped,
exclusively locked instance to export checksum-protected evidence with an explicit unsigned
reason; it never falls back from rejected authentication or decrypts unavailable crash records.

Crash Records accept only fixed phase, component, and finding vocabulary. They contain
bounded build/catalog identity and a bounded backtrace fingerprint, never panic payloads
or backtrace text. The kernel encrypts at most 32 records under existing key custody.
Unauthenticated, oversized, unknown, unsafe, old, and excess records are excluded with
declared omissions. Neither collection path repairs storage or changes process state.
Crash candidates are ordered by canonical record sequence before source-file or byte
truncation. If the directory inventory itself exceeds its bound, collection emits an
empty declared summary instead of selecting an unpredictable subset of directory entries.
