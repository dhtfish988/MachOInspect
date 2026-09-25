# MachOInspect

A C++20 library and command-line tool for inspecting Mach-O signing metadata,
declared entitlements, hardening settings and application resource seals.

The inspector explains what a file declares and compares sealed resources with
their recorded digests. It does not authenticate CMS signatures, validate a
certificate chain, recompute executable code pages or determine OS-granted
permissions. Use Apple's `codesign -v` for the system's signature verdict.

## Build

On macOS with the Xcode command-line tools and Homebrew:

```sh
brew install cmake ninja pkgconf nlohmann-json libplist openssl@3 pcre2
cmake --preset release
cmake --build --preset release
ctest --preset release
```

The executable is `build/release/macho-inspect`. Dependencies and the exact versions
used for local verification are recorded in `dependencies.lock.json`. That file is
a validation manifest; CMake accepts the documented compatible versions rather
than silently downloading dependencies. The product has no Python runtime.

## Inspect

For a complete example, [build two owned fixtures and compare their declarations
with codesign](docs/OWNED_BINARY_EXAMPLE.md). The three selected entitlements are
false in the control and true in the review fixture. The recorded run reports
zero versus three high-severity entitlement observations while both ad-hoc
signatures pass `codesign --verify --strict`.

```sh
build/release/macho-inspect /usr/bin/otool
build/release/macho-inspect Example.app
build/release/macho-inspect --json Example.app
build/release/macho-inspect -r --summary build/
build/release/macho-inspect --fail-on high --verbose Example.app
```

Every report distinguishes structural parsing from verification. JSON retains all
architecture slices, CodeDirectories, both entitlement declarations, observations
and errors. Resource inspection detects changed, missing required and newly unlisted files,
changed links, and disagreement between the resource manifest and the digest
recorded by a CodeDirectory. Missing explicitly optional resources remain visible
in JSON without a discrepancy; optional resources that exist are still checked.
Nested-code identity remains unevaluated.

Exit codes are `0` for a completed inspection below the configured threshold,
`1` for a completed inspection reaching `--fail-on`, and `2` for usage, input or
parsing failures, including partial failures. JSON is still emitted when an input
fails. Findings alone do not fail a run unless a threshold is requested.

## Use the library

```cpp
#include <macho_inspect/inspection.hpp>

auto report = macho_inspect::InspectionSession().inspect_path("Example.app");
auto json = macho_inspect::JsonEmitter::render({report});
```

Install to a chosen prefix, then use `find_package(MachOInspect 1 CONFIG REQUIRED)`
and link `MachOInspect::macho_inspect`. An independent consumer is provided in
`examples/library-consumer/`; it was built against the installed library.

## Verification

The current local macOS validation contains **474 checks across five native C++ test
executables**: parser contracts, resource rules, inspection rules, malformed-input
boundaries and real compiler/codesign/CLI integration. Debug, Release and
ASan/UBSan runs are recorded in [Verification](docs/VERIFICATION.md).

The earlier 456-check Release suite, installed-library consumer and owned-signing
walkthrough passed on GitHub for
[`c38a40e`](https://github.com/dhtfish988/MachOInspect/actions/runs/36098199519).
That exact run predates the latest optional-resource and unreadable-scan fixes;
their local results are recorded separately in
[the re-audit evidence](validation/re-audit-2026-09-25/result.json).

The C++ verification tool performs a fresh comparison with Apple's tools:

```sh
build/release/inspect-verify-system
```

The recorded corpus contains 1,157 Mach-O files and 2,301 architecture slices.
All 2,301 signing-metadata comparisons and 883 entitlement comparisons agreed.
These totals describe one macOS installation and are not a fixed test target.

Linux parsing and inspection paths are designed to build with the same C++
dependencies, but **Linux execution is not validated in this delivery**. The macOS
integration test explicitly skips there. A portable build is not established by
the existence of CMake files.

## Scope and provenance

This is a native rewrite of the MIT-licensed machoaudit baseline, commit
`dcd69fcc7475767540a2b496c6415e9adaa83b56`. Its architecture,
implementation, public API, CLI error contract and tests were redesigned. The
baseline's attribution is retained in [LICENSE](LICENSE); dependency notices are
in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The scope includes thin/fat Mach-O, XML/binary plist and Apple entitlement DER,
code-signing metadata, declared hardening and macOS/iOS-style app resource seals.
Framework `Versions` layouts, code-page authentication, certificate trust and
requirements evaluation are outside this version. Resource-rule matching is a
documented approximation, not Apple's complete sealing implementation. Inspect a
stable copy: path containment and change checks are not a transactional snapshot.

- [Architecture](docs/ARCHITECTURE.md)
- [Command line](docs/CLI.md)
- [Report format](docs/FORMAT.md)
- [Migration and intentional differences](docs/MIGRATION.md)
- [Verification and current limits](docs/VERIFICATION.md)
- [Baseline scenario coverage](docs/BASELINE_COVERAGE.md)

Local validation and publication scope: [validation/README.md](validation/README.md).
