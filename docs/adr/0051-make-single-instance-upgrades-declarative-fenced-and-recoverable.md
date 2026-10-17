# Make single-instance upgrades declarative, fenced, and recoverable

Operator and database images are independently pinned by immutable digest, and operator version N manages database versions N and N-1 so the controller upgrades first. Database upgrades are declarative and manual by default; only patch upgrades may opt into a signed automatic release channel, while minor or persistent-format changes require an intentional specification update. Preflight verifies signatures, version path, CRD compatibility, Key Provider and recovery readiness, disk headroom, storage semantics, and lifecycle conflicts. Format-neutral failure may roll back the image. A format-changing upgrade stops admission, drains work, seals segments, creates and verifies a Quiescent Upgrade Snapshot, performs a copy-on-write migration, and atomically publishes it. Failure before publication resumes the old version; failure afterward restores the snapshot into fresh storage rather than launching an incompatible binary. Status reports the unavoidable service interruption, progress, rollback availability, and outcome, and release tests prove that rollback loses no acknowledged data.

The native implementation retains one durable Upgrade record and one current
published-release pointer in the Catalog. The pointer outlives operation lookup
history. It distinguishes awaiting verification, verified target, failed target,
and explicit source rollback. A target enters Serving only after its actual
executing artifact matches the independently signed installed release, startup
integrity checks complete, and the existing bounded Query path succeeds. A
signed completion report binds that evidence to the operation, publication, and
exact Catalog predecessor. An instance with no query-readable tenant records
that outcome without creating a tenant or writing sentinel data.

A completed Drain is authenticated by its committed final marker and unchanged
native frontiers. Offline continuation reacquires exclusive volume ownership
and keeps listeners closed while it creates and independently verifies the exact
post-Drain snapshot. The current native path preserves the persistent format.
No concrete whole-volume migration edge is accepted yet, so any format change
is refused before Drain. Catalog key-format evolution does not establish an
Upgrade migration edge. Same-format failure permits an explicit, audited source
artifact rollback while the quiescent proof remains valid. Fresh-target Restore
uses the retained verified snapshot when that rollback boundary cannot apply.
