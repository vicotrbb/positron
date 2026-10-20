# Native proof fixtures

`tinyjson.1.0.0.nupkg` is the public TinyJson 1.0.0 package by Alex Parker,
downloaded from https://api.nuget.org/v3-flatcontainer/tinyjson/1.0.0/tinyjson.1.0.0.nupkg.
Its SHA-256 is `d322c003b77e0747fac1ff91d730d5395f2da0dba707181ad2f221f09a74f8e1`.
The upstream license is preserved in `tinyjson-LICENSE`. This captured package
exercises native NuGet repository signature verification. It is not a Positron
SDK, a Positron build, or release acceptance evidence. Its native certificate
roots are authorized independently by test trust, never learned from package
contents during verification.

`positron-1.0.0-1.{aarch64,x86_64}.rpm` and `rpm-protocol-public.asc` are private
protocol fixtures generated with Debian 12's rpmbuild/rpmsign 4.18.0 and GnuPG
2.2.40. The native v4 packages use a gzip/newc payload, SHA256 payload digest,
and an ephemeral RSA-2048 signing primary created at Unix 1749999000. Native
header signatures were made at Unix 1749999900. The included public certificate
has no expiry; its trust comes only from each test's installed root-signed
snapshot. No private key is included. The packages wrap tiny project-owned MIT syscall ELF fixtures, with no linked
third-party code. Each uses a 64-byte ELF header, a 56-byte PT_LOAD program header,
and exit(0) machine code: `b83c00000031ff0f05` for x86_64 and
`000080d2a80b80d2010000d4` for aarch64. They demonstrate RPM encoding/signature verification only,
not Positron execution, ABI correctness, installation, or lifecycle acceptance.

The authoritative RPM structures are documented in the upstream
[RPM v4 format](https://rpm-software-management.github.io/rpm/manual/format_v4.html),
[header format](https://rpm-software-management.github.io/rpm/manual/format_header.html),
and [signature/digest ranges](https://rpm.org/docs/4.20.x/manual/signatures_digests.html).

`positron_1.0.0_{amd64,arm64}.deb` are direct-download protocol fixtures made
with dpkg-deb 1.21.23, gzip level 9, epoch 0, and root-owned archive entries.
They contain the same project-owned syscall ELF fixtures and generated
configuration as the RPM fixtures. The package has no embedded debsig or APT
repository signature. Tests authenticate its final bytes with native GitHub
Actions SLSA evidence under the installed Fulcio, CT, and Rekor roots, plus the
separate project publication assertion binding the final Release Manifest.
These private fixture authorities and package bytes are not published Debian
packages or database lifecycle acceptance evidence.
