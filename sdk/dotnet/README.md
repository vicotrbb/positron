# Positron .NET SDK

The generated `Positron.SDK` NuGet package targets .NET 8. It has no runtime
package dependencies. Its typed requests and results, API version, schema digest,
error policy and capability metadata come from the canonical Public Interface.

```csharp
using Positron;
using var client = new Client("https://localhost:4319");
var capabilities = await client.CapabilityNegotiateAsync(
    new Types.CapabilityRequest { Api_major = 1, Capability = 4 });
Console.WriteLine(Codec.SchemaDigest);
```

Build with the pinned .NET SDK 8.0.427:

```console
python3 pack.py --build --version 1.0.0 --source-commit <clean-source-commit>
```

The packaging command normalizes native NuGet random container metadata before
signing and refuses to rewrite a signed archive. It never edits compiled payloads.
Install the
resulting package through NuGet; no project reference is required. HTTPS verifies
certificates. Plain HTTP requires the explicit constructor opt-in for local tests.
Execute is capped at five seconds; Session/Tail use a separate thirty-second
transport ceiling. The caller's shorter timeout or cancellation always wins.
Every effect has one attempt. Transport loss reports Ambiguous/Never; callers
must reconcile, and the client never retries an ambiguous effect automatically.

Use `BatchTracker("session")` or `BatchTracker("tail")` to validate ordered
receipts, discard verified repeated batches, and obtain the next acknowledgement.
A terminal `incomplete` is observable and never becomes success. Explicit cursor
cancellation preserves the server response and does not imply unconfirmed release.

Package source, XML documentation, portable symbols, MIT license, pinned build
metadata, API definition and digest accompany the DLL. Release Trust binds final
NuGet signature bytes and package identity, SBOMs, provenance and independent
rebuilds to the existing signed Release Manifest. Local builds and private test
signatures establish validation behavior, not NuGet publication.
