# Positron timestamp verification profile

Vendored from published Apache-2.0 `sigstore-tsa` 0.15.0,
https://github.com/sigstore/sigstore-rust.

The local patch exposes the existing typed RFC 3161 ASN.1 structures for strict
NuGet profile checks and permits maintained crypto verification of RSA timestamp
signatures. The shared verifier also binds the unsigned CMS signature algorithm
and its parameters to the actual key and digest; a captured valid RSA timestamp
with only its algorithm replaced provides the regression test. Positron validates the native CMS algorithm/attribute/ESS and time
policy before calling the maintained authority-bound timestamp verifier.
No HTTP client or trust fetching feature is enabled by Positron.
