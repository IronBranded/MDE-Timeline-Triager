# Tests/

Pester test suite (requirement #12) -- 7 files, 120 executed assertions once `-TestCases`
arrays are expanded:
- `Module.Tests.ps1` -- manifest validity, semantic versioning, the exported-function list
  matches the spec's closed 7-cmdlet surface exactly, every cmdlet uses an approved verb,
  every cmdlet's comment-based help is complete (non-placeholder synopsis, description,
  parameters, 2+ examples), `Invoke-MDEDetection`/`New-MDEReport` expose `-WhatIf`.
- `Import-MDETimeline.Tests.ps1` -- schema-set detection for all 7 tables (including a
  dedicated regression test for the DeviceFileEvents/DeviceImageLoadEvents misclassification
  bug caught during Phase 2), encoding detection (UTF-16LE, UTF-8 BOM), the CSV quoting
  engine, data-corruption vs. schema-mismatch handling kept distinct, the missing-header
  heuristic, evidence integrity (source file unmodified), and the row-count pre-scan
  (`Get-MDECsvRowCount` matches the real parsed row count exactly, including on
  `embedded-newline-test.csv` -- a fixture built specifically to prove the pre-scan counts a
  quoted field's embedded newline as part of one row, not as an extra row, which is exactly
  the correctness property a naive `'\n'`-count approach would have gotten wrong).
- `ConvertFrom-MDEEncodedCommand.Tests.ps1` -- all 4 in-scope decode methods individually,
  plus confirming out-of-scope obfuscation is flagged (`PossiblyObfuscated`) rather than
  guessed at, and that `Original` is never mutated.
- `Invoke-MDEDetection.Tests.ps1` -- a known-answer test per rule (all 13) against its
  positive-case fixture row, a negative control confirming zero findings across all 9 benign
  fixtures, the Severity/Confidence independence principle asserted directly against the
  catalog, multi-signal combination and process-lineage reconstruction, baseline-exclusion
  precedence (including that it throws on a malformed config), custom IOC matching,
  `-WhatIf` returning no findings, and the RunSummary object (export timeframe, both
  goalposts, alert-linked rows, suppressed-finding detail).
- `New-MDEReport.Tests.ps1` -- `-WhatIf` writes nothing (even into an existing directory),
  real rendering produces both outputs with the source hash present in both, UTC labeling,
  a genuine HTML-escaping test against a `</script><script>` payload (not a vacuous check
  against fixtures with no adversarial content), redaction on and off, evidence integrity,
  no CDN references anywhere in the rendered file, and the optional-`-OutputPath` behavior:
  explicit `-OutputPath` alone still uses the traditional fixed names (backward compatibility
  guard), explicit `-OutputPath` with `-DatedFileNames` uses dated names at that location,
  and omitting `-OutputPath` entirely resolves to `Get-MDEDownloadsFolder`'s actual result
  with dated names auto-enabled -- including under `-WhatIf`, which must report the resolved
  path and still create nothing.
- `Test-MDEBaseline.Tests.ps1` -- auto-detection of config type, forced `-ConfigType`
  mismatches correctly failing, exact per-entry error pinpointing (not just a pass/fail),
  empty-array-is-valid, and read-only guarantee.
- `Invoke-MDETriage.Tests.ps1` -- added after a real gap was found and fixed (see
  CHANGELOG.md's `[0.2.0]` entry): `Invoke-MDETriage` composes the other three cmdlets
  internally and had never once been called directly by anything in this suite, which is
  exactly how it shipped as a hard-coded stub for five build phases without anything
  catching it. Tests here call `Invoke-MDETriage` itself -- `-WhatIf`, real end-to-end
  execution, parameter pass-through (`-Redact`, `-BaselineConfigPath`), and evidence
  integrity -- never its component stages. Also carries a second, later regression guard of
  the same shape: this cmdlet declares its own separate `-OutputPath` parameter rather than
  inheriting New-MDEReport's, and when New-MDEReport's was made optional, this cmdlet's copy
  was initially missed -- found only by piping simulated input through the real interactive
  launcher end-to-end, not by reading the code. A dedicated test now asserts `-OutputPath` is
  genuinely non-mandatory (inspecting the actual parameter metadata, not just that a default
  value exists) alongside a real omitted-`-OutputPath` execution test.

Run with `Invoke-Pester -Path .\Tests\` from the module root. **This suite has actually run
against real Pester and passes 134/134** -- see README.md's "Getting Pester Running Without
the PowerShell Gallery" section if `Invoke-Pester` isn't already available to you (Pester
4.10.1, unlike 5.x/6.x, needs no `dotnet` SDK and no PowerShell Gallery access).

**`Invoke-ManualLint.ps1`** -- 8 PSScriptAnalyzer-style checks (approved verbs, cmdlet
aliases, `Write-Host`, empty catch blocks, `Invoke-Expression`, global variables, plaintext
password parameters, and a heuristic unused-variable check) implemented against
`[System.Management.Automation.Language.Parser]`, the AST parser built into the PowerShell
engine itself -- since real PSScriptAnalyzer needs a `dotnet` SDK to build from source and,
unlike Pester, has never had a pure-PowerShell version to fall back to (checked its earliest
indexed release through its latest; every one has a compiled C# core). Not a PSScriptAnalyzer
replacement -- 8 categories out of several dozen real rules -- but self-tested against a
deliberately bad scratch file before being trusted, and genuine AST-based analysis rather
than a manual read-through. Includes one deliberate, documented exception matching the real
`[SuppressMessageAttribute]` on `Start-MDETT.ps1`: `PSAvoidUsingWriteHost` is correctly
expected there (an interactive console launcher, not a pipeline-composable module function --
see that file's own `.NOTES`). Run with `pwsh -File .\Tests\Invoke-ManualLint.ps1`: 0 findings
across all 57 module files.

**`Invoke-ManualValidation.ps1`** -- not a Pester file (no `Describe`/`It`, so Pester's
auto-discovery won't pick it up as a test). The actual Pester test runner needs a `dotnet`
SDK to build from source, which was never available while this module was developed and
verified; this script mirrors the Pester suite's assertions with plain `if`/`throw` checks so
the same real-execution validation is possible with nothing beyond PowerShell itself. Run it
directly: `pwsh -File .\Tests\Invoke-ManualValidation.ps1`. Every one of its 71 assertions has
been confirmed passing against this exact module in real PowerShell 7.6.4 -- see
"Verification Status" in `README.md` for exactly what that does and doesn't establish
compared to the genuine Pester suite.

`Fixtures/` holds the synthetic CSVs and config files every test above reads from, including
`DeviceProcessEvents-escaping-test.csv` (added alongside the Pester suite specifically to
give the HTML-escaping test real adversarial content to assert against, rather than trusting
fixtures that happen to contain nothing dangerous).
immediately (verified by an out-of-band Python port of the parsing/schema-matching logic,
run against every fixture below, in the absence of a `pwsh` runtime in the authoring
sandbox — Phase 9's actual Pester suite supersedes that stand-in).

## Fixtures present (as of Phase 2)

Happy path — one per in-scope Advanced Hunting table, plain UTF-8 unless noted:
- `DeviceProcessEvents-happy.csv`, `DeviceNetworkEvents-happy.csv`, `DeviceFileEvents-happy.csv`,
  `DeviceRegistryEvents-happy.csv`, `DeviceLogonEvents-happy.csv`,
  `DeviceImageLoadEvents-happy.csv`, `DeviceEvents-happy.csv`
- `DeviceLogonEvents-happy-utf16le.csv` — same content as the UTF-8 version, re-encoded
  UTF-16 LE with BOM, to exercise real encoding auto-detection (not just the default path).
- `DeviceRegistryEvents-happy-utf8bom.csv` — same content as the UTF-8 version, with a UTF-8
  BOM prepended.
- `DeviceProcessEvents-happy.csv` additionally exercises the CSV quoting engine: one row has
  a comma inside a quoted field, another has an escaped quote (`""`) inside a quoted field.

Malformed — one per distinct failure mode (requirements #1 and #3), not exhaustively repeated
across all 7 tables, since the skip/warn handling logic is table-agnostic:
- `malformed-missing-header.csv` — data rows only, no header row (data-corruption).
- `malformed-truncated-row.csv` — a valid header and two good rows, then a row with fewer
  fields than the header (data-corruption).
- `malformed-extra-column.csv` — a valid DeviceRegistryEvents header plus one column not in
  this module's schema map (schema-mismatch: extra/unexpected column, warn-only).
- `malformed-low-confidence.csv` — a sparse header that doesn't confidently match any known
  table (schema-mismatch: falls to 'Unrecognized', still parses).
- `malformed-decode-corruption.csv` — a valid header and two good rows, with one row
  containing a byte (0xFF) that is invalid UTF-8, verified to decode to U+FFFD on exactly
  that row and no other (data-corruption).

Detection-test fixtures — added Phase 3, one row per built-in rule that should fire it plus
deliberate near-misses that should not, verified end-to-end (parse then detect) via an
out-of-band Python port of both the parsing and rule-matching logic:
- `DeviceProcessEvents-detection-tests.csv` — fires EXEC-001, DEFEVA-001, DEFEVA-002,
  DEFEVA-004 on rows 1-4 respectively; rows 5-8 are near-misses (a bare `-e` flag too short
  to qualify, a suspicious path that only appears in a command-line argument rather than the
  executable's own FolderPath, a clean Program Files execution, and `certutil -hashfile`
  rather than `-decode`) that must NOT fire anything.
- `DeviceRegistryEvents-detection-tests.csv` — fires DEFEVA-003 on rows 1-2
  (`DisableRealtimeMonitoring=True` and `Start=4` under Defender-related keys); rows 3-5 are
  near-misses, including the important case of `DisableRealtimeMonitoring=False` (protection
  being left ON/re-enabled, the *opposite* of tampering) under the same key, which must NOT
  fire despite matching the value name.
- All 9 Phase 2 happy-path fixtures were also re-run against the full Phase 3 rule set as a
  negative control and confirmed to produce zero findings.

Config fixtures — added Phase 4:
- `baseline-sample.json` — a realistic baseline/exclusion config plus two entries deliberately
  designed to exercise the precedence rule against `DeviceProcessEvents-detection-tests.csv`:
  a broad `FileName = powershell.exe` exclusion (no `RuleId`, so it applies to any rule) that
  the High/Critical EXEC-001 and DEFEVA-002 findings on that file must survive with
  `BaselineExclusionOverridden = $true`, and a narrow `RuleId: DEFEVA-001` exclusion on the
  `SketchyApp` path that the Medium-severity DEFEVA-001 finding must NOT survive.
- `custom-ioc-sample.json` — two case-specific IOCs (a C2 IP matched against
  `DeviceNetworkEvents-happy.csv`, a known-bad SHA1 matched against
  `DeviceProcessEvents-happy.csv`), each verified to fire exactly once with the configured
  severity and a synthesized `CUSTOM-2026-041-NNN` RuleId.
- `baseline-invalid.json` — three deliberately malformed entries (missing `Pattern`, invalid
  `MatchType`, unparsable regex `Pattern`), verified to produce exactly three distinct,
  correctly-pinpointed validation errors from `Test-MDEBaseline` and nothing more.

Lineage / combination fixtures — added Phase 5:
- `DeviceProcessEvents-lineage-tests.csv` — two rows forming a 4-generation chain split
  across BOTH rows (`wininit.exe` → `services.exe` → `svchost.exe` from row 1's fields alone,
  then `svchost.exe` → `cmd.exe` from row 2, where row 2's `InitiatingProcessId` +
  `InitiatingProcessCreationTime` exactly match row 1's own subject process). Verified that
  walking `cmd.exe`'s lineage after both rows have streamed through reconstructs the full
  4-element chain, proving cross-row linking (not just the single-row 3-generation context
  every DeviceProcessEvents row already carries on its own).
- `DeviceProcessEvents-combined-signal-test.csv` — one row whose single `ProcessCommandLine`
  contains both an `-enc` payload and an AMSI-internals reference, firing EXEC-001 (Score 70)
  and DEFEVA-002 (Score 90) on the exact same process. Verified the weighted combination
  (90×1.0 + 70×0.5 = 125, capped at 100) correctly elevates both findings to
  `CombinedScore = 100` / `CombinedSeverity = Critical`.
- Regression-checked against the Phase 3 `DeviceProcessEvents-detection-tests.csv` fixture:
  its EXEC-001/DEFEVA-001/DEFEVA-002 findings sit on three different processes (different
  PIDs) and were confirmed to remain uncombined -- each keeps its own individual score as
  `CombinedScore`, exactly as intended for findings with no co-occurring group.

Report-rendering validation — added Phase 6, via out-of-band Python ports (no browser
available in the authoring sandbox, so this is the same substitute-validation approach used
for the parsing/detection logic in earlier phases, applied to the escaping-critical half of
`New-MDEReport`):
- A synthetic finding record carrying a `</script><script>alert(document.cookie)</script>`
  breakout attempt, an `<img src=x onerror=alert(1)>` payload, and a `FileName` value shaped
  exactly like the `__D3_JS__` placeholder token, run through the real HTML-encoding + JSON-
  for-script-embed + single-pass template substitution logic. Verified: no literal executable
  tag survives in the rendered output; the placeholder-lookalike value is not mistaken for a
  real template token by a later substitution pass; `JSON.parse` (simulated) recovers the
  original malicious text byte-for-byte as inert, HTML-escaped data an analyst can safely
  read.
- A complete, realistic sample report (two co-occurring findings, a 3-generation process
  chain) rendered end-to-end through the real template and vendored libraries: confirmed
  well-formed HTML (balanced tags), all four JSON data islands (`report-meta`,
  `findings-data`, `tree-data`, `network-data`) parse correctly, and the inline JavaScript --
  both this module's own logic and the vendored D3/DataTables code, *as embedded* in the
  final file -- passes `node --check` syntax validation. This confirms the template
  substitution never corrupts the surrounding script content, but does not substitute for
  testing in a real browser (which the authoring sandbox cannot do); DOM/D3-API-specific
  behavior should be spot-checked once run in PowerShell with a real browser available.

Phase 7 detection-catalog fixtures — one row per new rule (8 rules across Persistence,
CredentialAccess, LateralMovement, Exfiltration, Discovery) that should fire it, plus
deliberate near-misses (`schtasks /query` not `/create`, `rundll32 printui.dll` not
`comsvcs.dll`+`MiniDump`, `reg.exe query` not `save`, `wmic` without `/node:`, an archive
written to a normal Documents path, a Run key pointing at Program Files) that must NOT fire:
- `DeviceProcessEvents-phase7-tests.csv`, `DeviceRegistryEvents-phase7-tests.csv`.
- Also ran a full regression sweep of all 13 rules (5 original + 8 new) against every prior
  fixture in the project: zero unexpected findings on any of the 9 benign happy-path
  fixtures, and none of the 8 new rules fired on the Phase 3/5 fixtures built to test only
  the original 5 -- confirming the expanded catalog didn't introduce cross-rule false
  positives.

**RunSummary / executive summary incident overview** (`Tests/Invoke-MDEDetection.Tests.ps1`'s
"RunSummary object" context) -- 8 tests against a purpose-built fixture with known, exact
values for every property being asserted on:
- `DeviceProcessEvents-runsummary-tests.csv` -- 4 rows spanning a known 45-minute window: a
  benign row (establishes the export's start), an EXEC-001-triggering row (establishes the
  first-suspicious-activity "left goalpost"), an `AlertTriggered`-ActionType row (the
  alert-linked-events heuristic), and a `MachineIsolationRequested`-ActionType row
  (establishes both the export's end and the first-response "right goalpost" heuristic).

**Row-count pre-scan correctness** (`Import-MDETimeline.Tests.ps1`'s "Row-count pre-scan and
line-count-based progress" context):
- `embedded-newline-test.csv` -- 5 physical lines but exactly 2 logical rows, one of which
  spans 3 physical lines because its `ProcessCommandLine` field contains an embedded newline
  inside quotes. Exists specifically to prove `Get-MDECsvRowCount` counts logical rows, not
  physical lines -- a naive `'\n'`-count would say 4 data rows here; the correct answer,
  matching what `Import-MDETimeline`'s real parse actually produces, is 2.

**Interactive launcher** (`Start-MDETT.ps1`, at the module root, not under `Tests/`): no
Pester coverage of its own, since it's a thin presentation/prompting wrapper around cmdlets
that are already independently tested -- see README.md's Quick Start section. Verified
instead by piping simulated keystrokes through the real script end-to-end (every menu
option, including the full triage flow and its console recap), which is what caught the
`Invoke-MDETriage -OutputPath` regression described above -- reading the launcher's code
would not have caught it, since the bug was in a cmdlet the launcher calls, not in the
launcher itself.
