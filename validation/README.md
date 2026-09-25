# Local validation record

The subsequent 2026-09-25 re-audit passed **474 checks** in each rebuilt Debug,
Release and ASan/UBSan suite. Eighteen additional checks cover optional resource
absence and incomplete recursive scans; eight failed before their respective
fixes. [The current result](re-audit-2026-09-25/result.json) and
[sanitized transcripts](re-audit-2026-09-25/) are separate from the historical
records below. See [the verification record](../docs/VERIFICATION.md).

The earlier 2026-09-25 review passed **456 checks** in each fresh Debug, Release and
ASan/UBSan build on macOS arm64. Fourteen regressions cover exact bundle-executable
selection and resource-manifest consistency; ten reproduced failures before the
fix. See [the current verification record](../docs/VERIFICATION.md).

MachOInspect 1.0.0 was initially validated locally on macOS arm64 on 2026-09-23.
Debug, Release and ASan/UBSan each passed **442 checks**. The final bounded
fuzz run completed **338,067 executions in 31 seconds** without a crash or
sanitizer report. Finite tests are not an arbitrary-input equivalence proof.

The repository contains the source and reproducible tests. Full raw local logs,
build directories and private workspace material are not published. Evidence
filenames in the detailed validation documents identify the original local
records, not files promised in this repository. Selected transcripts for the current
review are published below; full raw local evidence remains outside the repository.
Linux and Windows execution remain unverified.

`local-source-manifest.json` preserves the accepted local delivery's file hashes.
The initial publication edited only documentation to remove workspace-specific handoff text
and explain evidence availability. Program code, fixtures, build configuration,
tests and licenses initially retained their accepted bytes. Later fixes are
recorded by subsequent Git commits; the original manifest is historical and does
not describe the current checkout. The initial Git commit records
publication; it does not manufacture a prior development history.

The functional baseline is `machoaudit`. Its exact commit and retained attribution
are documented in the project notices. That historical repository may be private;
licenses and source provenance remain available here.

Final system corpus: 1,157 files / 2,301 slices; zero metadata comparison issues.
883 entitlement comparisons agreed. Installed CLI and a separate library consumer
were exercised. No speed advantage was established. See `docs/VERIFICATION.md`.

## Current and earlier review evidence

- [Current re-audit result](re-audit-2026-09-25/result.json) and [test transcripts](re-audit-2026-09-25/) cover the optional-resource and recursive-read fixes.
- [Successful hosted run for c38a40e](https://github.com/dhtfish988/MachOInspect/actions/runs/36098199519) covers that exact revision's earlier 456-check Release suite, installed-library consumer and owned-signing example. It predates the current re-audit fixes.
- [Owned-binary example](../docs/OWNED_BINARY_EXAMPLE.md) and [local paired reports](owned-signing-2026-09-25/) show a fresh compiler/codesign/inspector comparison on 2026-09-25. This example-only change did not rerun the full matrices.
- [Earlier machine-readable review result](current-review.json) and [its sanitized test transcripts](review-2026-09-25/).
- [CMake 3.24 preset compatibility result](current-review-build.json).
- [GitHub macOS verification](https://github.com/dhtfish988/MachOInspect/actions/workflows/verify.yml) builds Release, runs the tests, installs the package and exercises an independent consumer. Read the result for the exact commit; a workflow file alone is not a successful run.

The original 1.0.0 archives remain historical artifacts. Use the current Git commit
for these fixes. This review did not repeat earlier fuzz, system-corpus or IDA runs.
