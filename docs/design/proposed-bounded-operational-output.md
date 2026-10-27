# Proposed: isolate the native operational-output writer

Status: **approved by the product owner on 2026-10-26; implementation under validation**.
Related work: issue #118, PR #254. The accepted decision is ADR 0076.

## Approved decision

Permit at most one owned logging helper for the invocation while output is needed, executed from the same
Positron binary, alongside the database or a native invocation that needs a
startup diagnostic. The helper has no database, listener, storage, configuration,
key, or administrative authority. It only writes bounded, already-redacted
operational records to inherited stderr.

This is an exception to `project-positron.md` section 1: “One binary. One process.
One storage kernel.” The binary and storage-kernel promises remain; the literal
one-process promise would require an explicit exception. ADR 0054's structured,
bounded Operational Telemetry and ADR 0067's single Process Phase authority,
cleanup-before-marker boundary, and shutdown semantics remain requirements.
ADR 0076 records the accepted exception and synchronizes the product wording.

## Observed defect and alternatives

`native_host/operational_worker.rs` changes inherited stderr with
`fcntl_setfl(... NONBLOCK)`. File-status flags belong to the shared open file
description, so a native child changes its caller's pipe too. The public
subprocess regression starts with a blocking anonymous pipe and observes
NONBLOCK after an invalid-configuration child exits. A workspace run subsequently
failed inside Rust's test harness while printing an ignored test, with EAGAIN.
Regular-file test capture avoids that backpressure but does not fix the defect.

The following smaller approaches do not meet all requirements:

- Duplicating/cloning stderr preserves the same open file description.
  On the local macOS host, opening `/dev/fd/<writer>` also shares its flags;
  changing the reopened descriptor changed the original in a controlled probe.
- Linux can independently reopen `/proc/self/fd/2`, but that does not solve
  ordinary macOS anonymous pipes. Treating those pipes as unsupported would lose
  required non-interactive JSON diagnostics.
- Temporarily restoring flags still changes the caller while the write runs.
  Poll/kqueue readiness followed by a blocking atomic write races other writers.
- Apple XNU rejects anonymous-pipe POSIX AIO with ESPIPE; active AIO is not a
  reliable cancellable writer. Apple's dispatch I/O changes the supplied stream's
  NONBLOCK flags and later restores them, retaining the shared-descriptor problem.
- A blocking operational thread can stall its owned cleanup. An untracked or
  per-event writer thread leaks ownership; a stuck registered writer can prevent
  normal Drain and does not cover diagnostics before startup.

Primary-source references:
[Apple pipe implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/sys_pipe.c),
[Apple AIO implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_aio.c),
[Apple dispatch I/O implementation](https://github.com/apple-oss-distributions/libdispatch/blob/main/src/io.c).
No tested alternative currently satisfies normal Linux/macOS pipe delivery,
bounded backpressure, unchanged caller flags, and the strict one-process rule.

## Smallest proposed ownership and resource shape

The native invocation owns one output session. It creates the helper lazily
before its first startup diagnostic, or before starting the operational task,
and retains ownership until confirmed reaping. It never creates a process per
record. The helper dispatch occurs before ordinary CLI/configuration startup;
it is an internal execution mode, not a supported operator command, new
configuration field, network endpoint, or release artifact. It must not recurse
or construct a Runtime, Resource Governor, storage owner, or other helper.

The existing pending operational queue remains limited to 32 events. There is
one producer/consumer IPC socket pair and at most one in-flight record, limited
to 512 bytes including framing. Parent endpoints are newly owned descriptors;
only those endpoints may be nonblocking. The child endpoints and inherited
stderr keep their existing status flags. No additional unbounded queue exists.
The helper uses exactly two threads: its main bounded-record writer and one
request reader/parent-death watcher with a fixed 64 KiB requested stack. The
watcher never performs stderr I/O or waits for the writer: it reads framed input
and uses a one-slot fixed-record channel with nonblocking enqueue. The parent
sends only one unacknowledged record, so this adds no unbounded buffering.
The helper holds fixed-size record buffers and returns one acknowledgment
only after the complete stderr write succeeds. Its code must not read configuration,
provider credentials, telemetry bodies, arbitrary files, or database state.
The child inherits the invocation's UID/GID and stderr. This is not filesystem
isolation: the helper has the same OS permissions. Closed code/protocol limits
what it does. Launch clears its environment, nulls unused standard streams, and
uses an exact descriptor allowlist: request input, acknowledgment output, and
stderr only. Both IPC standard streams refer to the child end of the one socket
pair; all parent endpoints and unrelated descriptors remain close-on-exec. There is no new dependency,
helper executable, sidecar image, or signing authority. The parent executes its
current verified executable directly; it never extracts a helper or uses TMPDIR
for executable code.

The existing canonical event renderer remains the only redaction and JSON/text
formatter. Records are encoded before IPC; the child does not invent log
fields. The internal framing has a closed length bound and no external discovery
or authentication authority. It must be fuzzed as an untrusted local input
boundary, despite the normal producer being the parent.

## Delivery, failure, and lifecycle

A normal write is acknowledged; that acknowledgment is the delivery boundary.
The parent never waits more than one second for a record, and checks its shorter
remaining startup/shutdown deadline. A full queue, malformed frame, closed IPC,
child write error, missing acknowledgment, or helper spawn failure is an explicit
output failure. Existing operational failure/drop counters report it. After confirmed cleanup, startup diagnostic delivery returns the existing
unavailable outcome while preserving its intended nonzero exit code. Unconfirmed
cleanup instead takes the non-graceful hard-exit path described below. No recursive attempt writes an error through
the same failed sink.

On normal shutdown, stop admitting records, finish or explicitly fail pending
output under the remaining owner deadline, then send a closed protocol record.
The reader forwards that record and finishes; the main writer acknowledges it,
joins the finished reader, and exits. The parent confirms reaping before the
final Graceful Shutdown Record/marker. The helper has no Process Phase authority.

On an output deadline, close the parent IPC endpoint. A blocked stderr writer
cannot prevent the independent reader from observing EOF. The reader immediately
terminates the helper process with a failure exit code, which ends a blocked
write too. It never waits for the main writer. The same EOF path handles parent
SIGKILL/crash: close-on-exec discipline ensures no descendant accidentally keeps
the parent endpoint alive. No watchdog thread, file, heartbeat timeout, or new
service exists in the database process. This is a fixed helper-local reader,
not an untracked database worker or a process per diagnostic.

After closing IPC, the parent attempts termination and reaping within its
remaining deadline. Once absence is confirmed, optional output failure is counted
and ordinary Drain may continue. If absence/reaping cannot be confirmed, it
must not claim graceful completion or detach a child and continue serving. The
native owner takes the existing non-graceful hard-exit path; its endpoint closes
and the helper reader's parent-death path remains responsible for ending the
helper. No helper respawn occurs within that invocation.

There is **no unconditional guarantee that a process is reaped by a wall-clock
deadline**: an unresponsive kernel or unscheduled process can defeat termination
and reaping. This proposal promises a bounded owner decision and no graceful
marker without confirmed cleanup, plus parent-death termination when the OS
schedules the helper reader. It does not promise confirmed helper reaping before
an emergency parent hard exit. Adoption requires accepting that explicit forced
exit boundary, rather than disguising it as confirmed cleanup. Normal completion
still requires confirmed reaping. The parent cannot both remain indefinitely to
confirm reaping and promise unconditional bounded exit.

Second-signal and orchestrator-kill cases use these same close/death paths.
Direct pre-runtime diagnostics use the same invocation-owned session and bounded
close/reap decision before returning, preserving the intended nonzero native
exit. The helper never owns storage or a Graceful Shutdown Record.

## Required validation before acceptance

Public subprocess tests must cover unchanged caller pipe NONBLOCK flags after
invalid configuration and normal serve/stop, retained JSON/text output, closed
and full stderr, bounded startup failure, helper spawn/early-exit/write failure,
queue overflow, confirmed child cleanup, and parent SIGKILL while the helper is
blocked in a full stderr pipe. The last test must observe helper termination
independently of its blocked writer; test normal close, abrupt EOF, descriptor
inheritance, and delayed/unconfirmed reaping separately. Full-stderr tests must also prove
normal data Drain can complete after confirmed helper termination, with no
false graceful marker when cleanup is unconfirmed. Repeat actual native Linux
amd64/arm64 OCI and macOS executable tests, retained-record recovery, and
shutdown/upgrade behavior. Keep the same exact-artifact trust/SBOM/signature
requirements, required workspace tests/Clippy, production coverage of at least
90% including generated Rust, and applicable fuzz targets.

This proposal is not evidence that those paths work. Implementation, regression
GREEN, independent review, and platform qualification would follow only after
the product decision is accepted.
