# Migration from machoaudit 0.2.0

The baseline is `dcd69fcc7475767540a2b496c6415e9adaa83b56`. Keep the Python version
available when migrating an existing consumer. The new tool and library have a
new API and report schema; they do not impersonate the old Python package.

| Previous surface | New surface |
|---|---|
| `machoaudit PATH` | `macho-inspect PATH` |
| Python `audit_bytes` / `audit_file` / `audit_bundle` | C++ `InspectionSession::inspect_bytes` / `inspect_file` / `inspect_path` |
| `FileReport`, `SliceReport`, `Finding` | `InspectionResult`, `ImageResult`, `Observation` |
| root `files` / file `slices` | root `inputs` / input `images` |
| `signed` boolean | `signing.state` plus explicit unperformed verification fields |
| flattened selected CodeDirectory | all `signing.directories` plus `selected_directory_slot` |
| `entitlements` and source label | both declarations, selected typed values, source and errors |
| `findings` with `id` | `observations` with stable `code` |

Common CLI option semantics are retained. New classes and files are organized by
responsibility rather than translated one-to-one from the former module layout.

## Intentional differences

- Any partial input or parsing failure returns 2. The old CLI could return 0 when
  some inputs failed. JSON is emitted even when all inspected inputs fail.
- Declared fat-slice, command, signature-container and child-blob boundaries are
  enforced independently. Inputs accepted only by borrowing bytes outside a
  declared structure are rejected. Version-gated fields must be present.
- Duplicate signing slots, overlapping structural children, mismatched digest
  widths, nonminimal DER lengths/integers, duplicate DER keys, invalid UTF-8 and
  trailing DER values are rejected. Empty encoded entitlement slots are invalid,
  whereas an encoded empty dictionary is valid.
- DER integer size and resource counts have explicit limits. These bound input
  processing; they can reject constructs a generic Python integer would accept.
- Code-slot shortfalls are detected even when the declared slot count is zero.
- Every understood ResourceDir digest across slices is compared. The baseline
  could accept one matching algorithm and collapse conflicting records.
- Resource-rule compilation/matching errors are reported rather than silently
  omitting unsupported expressions. PCRE2 is not claimed to implement every
  Python regular-expression extension. Highest weight wins, with input order
  retained for ties; v1 omissions remain relevant when both rule tables exist.
- Text is plain, observation wording describes declarations, and duplicate input
  paths are normalized. The old terminal styling and exact sentences are not API.
- XML/binary plist dates and UID values have tagged JSON representations rather
  than Python objects; this is documented as a non-lossless edge of the report API.

The real-system baseline comparison checks architectures, selected signing
identity/CDHash, typed entitlement values, and finding code/severity pairs. It is
a functional comparison over a stated corpus, not a claim that all malformed
inputs or every possible app behave identically.
