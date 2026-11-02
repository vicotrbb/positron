# Standalone Helm local qualification

Issue #120 retains single-writer fencing and external Key Provider outage/recovery.
Use the existing `deploy/helm/test_kubernetes.py` integration fixture and its
public native CLI adapter. Keep exact managed CSI/platform qualification open.

1. Add a focused failing adapter test for a same-worker challenger cloned from
   the live pod template: identical live data/secrets PVCs, separate emptyDir
   runtime, Restricted security, no service selector. Exercise the real native
   process in the owned cluster; require live/recovering, not-ready, no data
   admission, unchanged original query and PVC/PV identities. Delete only the
   challenger in `finally`.
2. Add exact OpenBao 2.7.1 fixture configuration and focused refusal/cleanup
   tests at the Kubernetes subprocess boundary. Use verified TLS, private token
   files and a limited renewable transit token. Select a supported short cache
   lease before initialization. Activate the provider via public key migration,
   then observe expired-cache outage, unavailable cold startup, recovery and
   original query results. Preserve unknown operation outcomes for lookup.
3. Run meaningful Python tests and real owned-cluster integration sequentially.
   Report exact image/source/platform and unavailable external matrix cells.
4. Obtain fresh source review, commit and freeze the candidate. Run pinned fmt,
   full Clippy, >=90% workspace coverage, workspace tests and bounded applicable
   ASAN campaigns sequentially. Collect exact-head hosted outcomes. Keep PR draft
   and issue In progress until retained acceptance is demonstrated.
