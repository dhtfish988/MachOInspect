# Verification record

Evidence filenames and workspace-relative paths below refer to local validation records. See `../validation/README.md` for the published summary; raw local logs are not included.

## Hosted evidence and owned-binary example

GitHub [run 36098199519](https://github.com/dhtfish988/MachOInspect/actions/runs/36098199519)
completed successfully for commit `c38a40e98a4d533c5a7964077c2641bc0b0e232c`.
It ran the earlier 456-check Release suite, an independently linked installed-library
consumer and the owned-signing example. This is evidence for that exact revision;
it predates the optional-resource and unreadable-scan fixes described below.

The new [owned-binary walkthrough](OWNED_BINARY_EXAMPLE.md) was executed locally
on 2026-09-25 using the existing Release tools. All 14 commands returned their
expected statuses. Two native metadata comparisons, two XML/DER pairs and two
`codesign` entitlement comparisons agreed, with zero issues. The control produced
no high-severity entitlement observations and the review fixture produced three.
Both ad-hoc signatures passed `codesign --verify --strict`. The source, plists and
[recorded reports](../validation/owned-signing-2026-09-25/) are public and contain
no private target input. The full 456-check matrices were not rerun for this
example-only change. The later hosted run above also passed the example's 14
expected command statuses, two metadata comparisons, two XML/DER pairs and two
codesign entitlement comparisons with zero issues.

## Subsequent re-audit on 2026-09-25

Rebuilt Debug, Release and ASan/UBSan suites each passed **474 checks across five
native test programs**: 70 core, 50 resource, 92 rule, 204 boundary and 58 macOS
integration assertions. The 18 added checks cover two newly reproduced defects:

- An absent resource explicitly marked optional by codesign was incorrectly
  reported as a high-severity missing resource. A freshly compiled and signed
  owned bundle demonstrates that codesign accepts deletion of its optional
  localization file; both tools reject changed contents and missing required files.
- An unreadable regular file was silently skipped during recursive scans, allowing
  incomplete scans to return success. Persistent read errors now appear beside
  successful results in JSON and return exit 2. Readable short files remain skipped.

Six optional-resource assertions and two recursive-read assertions failed before
their respective fixes. All new checks ran on the local non-root macOS account;
permission checks explicitly report a skip if a privileged account bypasses the
fixture's read restrictions. No sanitizer diagnostics were observed.

The optional merge policy is conservative when legacy and modern records differ;
[the report format](FORMAT.md) documents it without claiming complete Apple
resource-sealer equivalence. [Selected results and transcripts](../validation/re-audit-2026-09-25/)
identify this patch separately from the earlier 456-check and 442-check records.
Historical fuzz and system-corpus comparisons were not rerun for these fixes.

## Earlier review on 2026-09-25

Fresh Debug, Release and ASan/UBSan builds each passed **456 checks across five
native test programs**: 70 core, 40 resource, 92 rule, 204 boundary and 50 macOS
integration assertions. All three runs completed with zero test failures; the
instrumented run produced no sanitizer report. Evidence is stored locally under
`evidence/review-2026-09-25/MachOInspect/` in the surrounding work area.

Fourteen resource and bundle regressions were added. Ten failed against the
pre-fix source, demonstrating that:

- A missing or incorrectly typed declared executable could silently select an
  unrelated Mach-O from the same bundle.
- Conflicting, incorrectly typed or additional unsupported resource digests could
  be discarded while a remaining digest was reported as matching.
- Malformed rule tables could be ignored, and legacy-only rules did not detect
  newly unlisted files.

The fixes preserve exact declared-executable selection, reject contradictory or
malformed digest/rule records, retain unsupported-digest findings and evaluate legacy
rules when modern rules are absent. The remaining regressions ensure valid
declarations, identical duplicate digests and weighted omissions still work.
These tests use synthetic temporary bundles. A fresh Release installation and
independent `find_package` consumer both inspected the newly built product
executable successfully. Earlier fuzz and system-corpus
results below are historical validation and were not repeated for this patch.

## Initial validation on 2026-09-23

Date: 2026-09-23. Host: macOS 26.7 (25G229), arm64. Product builds use Apple clang
21.0.0, CMake 4.3.1 and Ninja 1.13.2. The ASan/UBSan and libFuzzer build uses LLVM
23.1.1 because the installed Apple toolchain has no libFuzzer runtime archive.

The evidence directory in this workspace is `../evidence/machoaudit/`. It contains
build/test logs, corpus comparison JSON, the baseline inventory and final artifact
metadata. Claims in this initial-validation section concern the local runs on
2026-09-23. Later hosted validation is identified separately above.

## Recorded checks

| Gate | Recorded result |
|---|---|
| Isolated Python baseline | 134 tests passed; original checkout unchanged |
| Baseline codesign comparison | 2,301 slices compared, 0 mismatches |
| Baseline entitlement comparison | 947 XML/DER pairs and 481 codesign comparisons, 0 differences |
| New Debug native suite | Five test programs; 442 checks passed |
| New Release native suite | 442 checks passed; `tests-release.txt` |
| New ASan/UBSan native suite | 442 checks passed; `tests-sanitize.txt` |
| New native codesign comparison | 1,157 Mach-O files; 2,301 metadata comparisons; 883 entitlement comparisons; 0 issues in the final Release run |
| Normalized new/old comparison | Same system corpus; 0 differences after selecting the strongest supported declared directory |
| Coverage-guided parser fuzzing | 338,067 executions in 31 seconds; seed 9802, maximum length 65,536; no crash or sanitizer report |
| Independent installed-library consumer | Configured, linked and inspected `/usr/bin/otool` successfully |
| Linux build/runtime | OPEN; no Linux runner was available |

The initial suites contained 70 core, 26 resource, 92 rule, 204 boundary and 50
integration assertions. The scenario inventory in `BASELINE_COVERAGE.md` maps
131 baseline source test functions (134 parameterized cases) to these suites.

Four structural counterexamples were run through both implementations: a fat
slice exceeding its file, a header exceeding its declared slice, a SuperBlob
exceeding its command and a child exceeding its SuperBlob. The baseline accepted
all four; the new Release CLI rejected each with status 2. Exact diagnostics are
in `baseline-boundary-differences.json`.

On the same 1,157-file corpus with `--summary`, three sequential, alternating-order
runs gave median whole-process wall times of 0.245161 seconds (Python baseline)
and 0.246686 seconds (C++ Release). Median peak resident bytes were 203,816,960 and
243,056,640 respectively. This warm-cache local measurement includes startup and
uses `/usr/bin/time -l` for resident memory. It establishes no speed advantage;
the new report retains more detail and its summary currently materializes JSON.
Raw measurements and methodology are in `performance.json`.

## Reproduce

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --verbose
cmake --preset release
cmake --build --preset release
ctest --preset release --verbose
build/release/inspect-verify-system
```

For a clang installation containing libFuzzer, choose its compiler explicitly:

```sh
cmake --fresh --preset sanitize \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++
cmake --build --preset sanitize
ctest --preset sanitize --verbose
build/sanitize/inspect-boundary-tests build/fuzz-corpus
build/sanitize/inspect-fuzz build/fuzz-corpus \
  -max_total_time=30 -max_len=65536 -timeout=5 -rss_limit_mb=1024 -seed=9802
```

The fuzz driver targets the inspection entry point, signature containers, plist
and DER. System-installed third-party dependencies were not rebuilt with
instrumentation, so coverage and sanitizer visibility are strongest in this
project's own code. A short fuzz run is regression evidence, not an exhaustive
proof of parser safety.

## Independent references and scope

The system verifier asks codesign for identifier, team, CodeDirectory size/version,
flags, slot counts, algorithm, every full candidate digest and declared
entitlements. Failed queries or missing comparison fields produce issues, and
zero compared slices does not count as a successful run.

The native default corpus uses `/usr/bin/*`, `/usr/lib/*.dylib`, `/usr/libexec/*`,
`/sbin/*` and `/bin/*`. The old entitlement helper additionally scans
`/System/Library/CoreServices/*` and uses a different per-file/per-slice comparison
policy. Its 947/481 counts therefore should not be substituted for the native
883/883 counts.

Integration fixtures are compiled and signed during the tests. Clean, modified,
added and removed resources are checked against both the inspector and codesign.
Separate resource fixtures cover omission/weight/tie rules, nested code, unknown
digests, parent/leaf symlinks, out-of-bundle paths and capped findings. No test
requires reading a private file.

## What this does not establish

These checks do not authenticate CMS signatures, verify code pages, evaluate
requirements, determine OS grants, prove hostile filesystem-race resistance, cover
every resource-sealer corner case, establish Linux support or guarantee acceptance
for uses outside these tested contracts. Product boundaries are listed in the README and format
documentation.
