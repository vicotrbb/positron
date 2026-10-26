# Isolate bounded operational output in one owned helper

Accepted by the product owner on 2026-10-26. This narrowly amends the literal
one-process promise in the product vision. Positron retains one binary, one
database process, one storage kernel, and one Process Phase authority. A native
invocation may own at most one operational-output helper executing that same
binary. It has no database, configuration, provider, key, listener, or
administrative authority and never respawns within the invocation.

The helper only writes already-redacted canonical operational records. The
existing 32-event producer queue remains bounded. One socket pair carries at
most one unacknowledged record of at most 512 bytes including framing. The
helper has a main writer and one reader with a requested 64 KiB stack, fixed
record buffers, and one nonblocking single-slot handoff. Launch clears the
environment and admits only its IPC standard streams and inherited stderr;
unexpected inherited descriptors cause refusal before reading records. It never
changes the caller's stderr file-status flags, extracts an executable, or adds a
runtime artifact or dependency.

Normal delivery requires an acknowledgment after the complete write. A record
wait is bounded by one second and the remaining owner deadline. Output failure
is explicit through the existing diagnostic outcomes and operational counters.
On normal close the writer acknowledges, joins the completed reader, and exits.
The parent confirms reaping before ADR 0067/0069's final graceful Catalog marker.
On parent death or abandoned IPC the independent reader exits the whole helper
without waiting for a blocked writer, flushing output, or acquiring its locks.

Termination and reaping cannot be unconditionally guaranteed by a wall-clock
deadline when the operating system does not schedule a process. If cleanup is
unconfirmed at the owner deadline, the native owner uses the existing
non-graceful hard-exit boundary. It never reports graceful completion, detaches
a child and continues serving, or extends the deadline. Parent-death EOF remains
responsible for terminating the helper when scheduled. The helper has no
storage ownership or graceful-marker authority.

This decision preserves ADR 0054's structured, bounded telemetry and ADR 0067's
single lifecycle and cleanup-before-marker requirements. The approved design
and rejected alternatives are recorded in
[the operational-output design](../design/proposed-bounded-operational-output.md).
