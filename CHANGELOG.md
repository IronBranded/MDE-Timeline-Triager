# Changelog

All notable changes to MDETimelineTriage are documented in this file. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); this project uses semantic versioning
(`major.minor.patch`) as declared in `MDETimelineTriage.psd1`.

## [0.2.0] - 2026-08-13

Follow-up pass after real `pwsh` (downloaded from PowerShell's GitHub releases, since none
was available in the original authoring sandbox) made genuine execution possible for the
first time, rather than the out-of-band Python validation used throughout the 0.1.0 build.

### Added
- **Documentation consolidation and discrepancy audit.** Requested after a question about
  why 12 separate `README.md` files existed prompted an honest "that's genuinely more than
  needed" answer. The 8 `Private/*/README.md` files (one per subsystem folder) are now one
  `Private/README.md`, organized in actual pipeline order, with the "added in build Phase X"
  chronological narration trimmed where `CHANGELOG.md` already covers it -- the genuine
  technical rationale (why incremental lineage tracking, why hand-rolled CSV writing, why
  forward-only template substitution) is kept. 12 README files down to 5.

  The audit also found real, not cosmetic, discrepancies: every current reference to the
  Pester suite's test count still said 112/112 and the lint result still said "50 files,"
  both stale after the RunSummary work added 8 tests and 4 new source files later in the
  same session without a documentation pass to match -- corrected to the actual current
  120/120 and 54 files, verified fresh rather than assumed. `Data/README.md` never mentioned
  `SchemaMap.json` or `ResponseActionKeywords.json` at all, despite both being real,
  load-bearing files. `Tests/README.md`'s fixture inventory was missing
  `DeviceProcessEvents-runsummary-tests.csv`, used by 8 real tests. A demo-only fixture
  (`example-report-source.csv`, built to generate example reports shown in conversation, not
  referenced by any actual test) was sitting undocumented in `Tests/Fixtures/` and has been
  removed rather than retroactively documented as if it belonged there.
- **Comprehensive incident overview in the executive summary**, added after real feedback
  that the summary needed to answer the questions an analyst actually opens a report to
  answer: what timeframe does this cover, when did the bad activity start and when did MDE
  respond, were there alerts, and was anything excluded. `Invoke-MDEDetection` now tracks
  these across every row processed (not just findings) and emits one
  `MDETimelineTriage.RunSummary`-tagged object as the last item in its output stream --
  export timeframe, first-suspicious-activity ("left") and first-response ("right")
  goalposts, alert-linked rows, and full suppressed-finding detail (not just a count). The
  right goalpost (first automated MDE response/containment action) is explicitly a
  heuristic, not a confirmed match: Microsoft's own `DeviceEvents` documentation states the
  full ActionType list is only available via the in-portal schema reference, not published
  publicly, so this matches a documented, overridable keyword list
  (`Data/ResponseActionKeywords.json`, `-ResponseActionKeywords`) built from Microsoft's
  general documentation vocabulary plus one confirmed fact (containment actions start with
  "Contain") rather than a guessed authoritative list. `New-MDEReport` now separates this
  object from findings automatically by its type tag. 8 new Pester tests cover every new
  RunSummary property against a purpose-built fixture with a known timeframe, both goalposts,
  and an alert-linked row.
- Requirement #2 (Telemetry Mapping), previously planned but never implemented: 
  `Data/TelemetryMapping.json` and `Get-MDETelemetryMapping` correlate each table's
  ActionType values to standard Windows Event IDs and Sysmon Event IDs. Every finding now
  carries `WindowsEventId`/`WindowsEventName`/`SysmonEventId`/`SysmonEventName`, surfaced in
  the HTML report's findings table (new "Native Event ID" column) and the enriched CSV.
- `Tests/Invoke-MDETriage.Tests.ps1`, `Tests/Invoke-ManualValidation.ps1` (71 assertions).
- `Tests/Invoke-ManualLint.ps1`: 8 PSScriptAnalyzer-style checks implemented directly against
  `[System.Management.Automation.Language.Parser]` (the AST parser built into the PowerShell
  engine, no external dependency), since the real PSScriptAnalyzer remains unreachable. Not a
  replacement for it -- 8 rule categories out of several dozen, and the unused-variable check
  is a heuristic, not the real algorithm -- but genuine tool-based analysis rather than
  manual reading. Self-tested against a deliberately bad scratch file (one instance of each
  of the 6 non-parse-error/non-verb checks) before trusting its result, confirming all 6 were
  actually caught. Result against the real module: 0 findings across 54 files.

### Fixed (found only once real execution was possible)
- `Invoke-MDETriage` -- the module's headline "one-line" entry point, used in every Quick
  Start example -- was never actually wired up after the three cmdlets it composes were built
  in later phases. It still threw `NotImplementedException`. No Pester test had ever called
  it directly, only its three stages individually. Now genuinely composes
  `Import-MDETimeline | Invoke-MDEDetection | New-MDEReport`.
- `ConvertFrom-MDEEncodedCommand` threw under `Set-StrictMode -Version Latest` (set globally
  by this module's `.psm1`) on any command line where zero characters matched a `Where-Object`
  filter -- `Where-Object` returns `$null`, not an empty array, when nothing matches, and
  `$null.Count` is restricted under strict mode. This fired specifically on ordinary,
  non-obfuscated command lines (the common case), including inside `EXEC-001`, which calls
  this cmdlet. Fixed with the same `@(...)` array-coercion wrapper used correctly everywhere
  else in this codebase -- confirmed via a full codebase grep that this was the only instance
  of the pattern missing it.
- **`Invoke-MDEDetection`'s own `.NOTES` help text was silently corrupting its entire parsed
  help output.** A cross-reference reading "see .DESCRIPTION for why..." happened to wrap so
  that `.DESCRIPTION` fell at the start of a line; PowerShell's comment-help parser reads any
  line starting with `.KEYWORD` as a new section marker regardless of context, so this was
  read as a second `.DESCRIPTION` section and corrupted the whole parse (`Get-Help` returned
  an empty description and an undercounted example list). Found only by getting real Pester
  running and isolating the cause via a binary search down to a 15-line reproduction. Checked
  the entire codebase (all `Private/` and `Public/` files) for the same pattern -- this was
  the only instance. Fixed by rephrasing to avoid a line-starting keyword reference.
- Two bugs in the Pester test files themselves, found by the same real Pester run:
  `Import-MDETimeline.Tests.ps1` asserted against the wrong CSV field for the escaped-quote
  case (`ProcessCommandLine` instead of `InitiatingProcessCommandLine`, confirmed against the
  actual fixture data); `Invoke-MDEDetection.Tests.ps1` tried to verify a private detection
  function was loaded via `Get-Command` called from outside the module, which cannot see
  non-exported functions by design -- fixed using `& (Get-Module ...) { }` to check from
  inside the module's own scope, confirmed working via a direct scoping test first.

- **The generated report threw a client-side JavaScript error on any report with exactly one
  finding**, found only by actually executing the report's JS in a real DOM (`jsdom`) instead
  of just checking it parses. `ConvertTo-Json` collapses a genuinely single-element array
  into a bare object rather than a one-element array; the findings JSON island silently
  became `{...}` instead of `[{...}]`, and the swimlane view's `findingsData.filter(...)`
  threw `TypeError: findingsData.filter is not a function` the moment its tab was clicked.
  No fixture used anywhere in this build's extensive test history ever had exactly one
  finding. Fixed in `ConvertTo-MDEJsonForScriptEmbed` with a `-ForceArray` switch, applied
  only where the top-level input is genuinely array-shaped. The first version of this fix
  itself shipped with a bug -- it computed the correctly-wrapped string but never returned
  the wrapped version -- caught immediately by re-running the same jsdom test rather than
  trusting the fix on sight. Confirmed clean afterward across 0/1/7-finding reports, clicking
  every tab in each: zero runtime errors.

### Verified (real execution, not simulation)
- **The actual Pester test suite: 120/120 passing**, via Pester 4.10.1 (pure PowerShell, no
  `dotnet` SDK required, downloaded directly from GitHub -- see README.md). This is real
  execution of the literal, unmodified `Tests/*.Tests.ps1` files by the real test runner, not
  a hand-written substitute.
- All 7 public cmdlets actually imported, described (`Get-Help -Full`), and executed against
  every fixture in the project via real PowerShell 7.6.4.
- `Tests/Invoke-ManualValidation.ps1`: 71 distinct checks, 71 passed, 0 failed.
- `Tests/Invoke-ManualLint.ps1`: 8 PSScriptAnalyzer-style checks (AST-based, see Added
  above), 0 findings across 54 files -- self-tested against a deliberately bad file first.
- **Real JavaScript execution via `jsdom`** (see the Fixed entry above for what this caught):
  the generated report's client-side JS actually runs in a real DOM across every tab, for
  0/1/7-finding reports, with zero runtime errors after the fix. Materially stronger than
  syntax-checking alone; still short of visual/CSS confirmation in an actual browser.
- Performance/scale, never previously tested: a genuine 200,000-row / 74MB synthetic export
  processed end-to-end. True-pipeline usage (no intermediate variable capture) kept managed
  memory at ~19MB; throughput is roughly 1,000-1,200 rows/second, meaning a multi-million-row
  export is a 30-60 minute job, not a real-time one. See README.md's "Performance" section.

### Still not achievable in this environment
- PSScriptAnalyzer has no pure-PowerShell version to fall back to the way Pester 4.x was --
  checked its earliest indexed release (1.1.0) through a mid-life release (1.18.2) through
  the current latest (1.25.0), and every one already has a compiled C# core (every individual
  rule is a `.cs` file, not PowerShell, as far back as the project goes). This is an
  architectural difference from Pester, not just a version-number coincidence: Pester's
  compiled component was a later addition to an originally-pure-PowerShell project;
  PSScriptAnalyzer has never been pure PowerShell. `Add-Type`-based compilation without
  `dotnet` was considered and set aside given the Engine/Rules assemblies' interdependencies
  and likely NuGet package references, which `Add-Type` has no equivalent mechanism to
  resolve reliably.
- `jsdom` execution testing (see the new "Verified" entry above) covers real JS runtime
  behavior, but not visual/CSS layout -- actually opening the report in a real browser
  remains the one gap it can't close, and none is available in this sandbox.

## [0.1.0] - Initial build

Complete initial implementation of the module described in the build specification: parse a
single MDE timeline CSV export, run a built-in + custom detection catalog tagged to MITRE
ATT&CK, score findings on independent Severity/Confidence axes, reconstruct process lineage,
combine co-occurring signals, and render a self-contained offline HTML report plus an
enriched CSV.

### Added

**Module structure**
- `.psd1`/`.psm1` with explicit `FunctionsToExport`, Public/Private separation, dual Windows
  PowerShell 5.1 / PowerShell 7+ support throughout.
- The exact 7-cmdlet public surface: `Invoke-MDETriage`, `Import-MDETimeline`,
  `Invoke-MDEDetection`, `New-MDEReport`, `ConvertFrom-MDEEncodedCommand`, `Test-MDEBaseline`,
  `Get-MDEDetectionCatalog`. All seven ship with complete comment-based help.

**Ingest**
- `Import-MDETimeline`: streaming, hand-rolled RFC 4180 CSV parsing ([System.IO.StreamReader]-
  based, batched List[PSCustomObject] emission -- never `Import-Csv`/`ForEach-Object`);
  automatic UTF-8/UTF-8-BOM/UTF-16 encoding detection; schema-set detection across the 7
  supported Advanced Hunting tables (`DeviceProcessEvents`, `DeviceNetworkEvents`,
  `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`,
  `DeviceEvents`), with graceful degradation (not a hard failure) for schema mismatches, and
  distinct per-row skip-and-count handling for data corruption (truncated rows, invalid byte
  sequences for the detected encoding).
- Schema column data sourced from current Microsoft Learn documentation rather than training
  data, including a since-changed detail (MDE boolean fields moved from numeric `1`/`0` to
  textual `True`/`False` on 2026-02-25) that would otherwise have been silently wrong.

**Detection**
- 13 built-in detection rules across all 7 targeted MITRE ATT&CK tactics: Execution,
  DefenseEvasion, Persistence, CredentialAccess, LateralMovement, Exfiltration, Discovery.
  Full list in `README.md` / `Get-MDEDetectionCatalog`.
- `ConvertFrom-MDEEncodedCommand`: Base64/`-EncodedCommand` (UTF-16LE), environment-variable
  expansion (known-default substitution), tick-mark/caret removal, simple character
  reversal; out-of-scope obfuscation flagged as `PossiblyObfuscated` rather than guessed at.
- Explicit Severity taxonomy (Critical/High/Medium/Low/Informational, 0-100 score with
  documented tier thresholds) kept fully independent from a separate Confidence label
  (High/Medium/Low); neither is derived from the other anywhere in the module, and a
  Low-confidence High/Critical-severity finding is never auto-suppressed.
- Process lineage reconstruction (`InitiatingProcessId`/`InitiatingProcessFileName` chains,
  keyed on `Id|CreationTime` to survive PID reuse) and multi-signal combination (co-occurring
  findings on the same process combine via a geometric-decay weighted score, capped at 100).

**Baseline / Custom IOC**
- `-BaselineConfigPath` / `-CustomIOCConfigPath` on `Invoke-MDEDetection`, both validated via
  `Test-MDEBaseline` before use.
- Documented config precedence: baseline exclusions may suppress Medium-and-below findings
  only, never High/Critical, regardless of source (built-in or custom); an overridden
  suppression attempt is recorded on the finding (`BaselineExclusionOverridden`) rather than
  silently dropped.

**Reporting**
- `New-MDEReport`: self-contained HTML report (DataTables v3 findings table, D3 v7 process
  tree/network graph/swimlane -- Mermaid was evaluated and dropped in favor of D3's own
  hierarchy layout once vendoring surfaced its only fully self-contained build is 3.5MB) and
  an enriched CSV for Timeline Explorer, both hand-written for output rather than relying on
  `Export-Csv` (whose default encoding differs between PS 5.1 and 7+).
- HTML-escaping (`[System.Net.WebUtility]::HtmlEncode`) applied to every report-bound value
  before it touches markup, plus a second `</script>`-breakout-specific safeguard for the
  embedded JSON data islands; CSV output separately guarded against formula/CSV injection.
- `-Redact` (stable per-value username/hostname pseudonymization), `-LocalTime` (labeled
  UTC + local timestamps), `-ReportSizeThreshold` (interactive-view capping across all four
  views, with the CSV always complete).
- SHA-256 source-file hash, full path, and UTC processing timestamp recorded in both outputs.

**Testing**
- Pester suite (`Tests/*.Tests.ps1`, ~90 assertions) covering parsing, deobfuscation,
  detection (known-answer tests per rule plus a negative control across every benign
  fixture), baseline/custom-IOC precedence, lineage/combination, `-WhatIf` dry-run behavior
  for both `SupportsShouldProcess` cmdlets, and report escaping/redaction/evidence-integrity.
- ~30 synthetic CSV/JSON fixtures under `Tests/Fixtures/`.

### Fixed (caught during development, before ever shipping)

- Schema-set detection initially misclassified `DeviceFileEvents` exports as
  `DeviceImageLoadEvents` (both share most of their columns); fixed by broadening
  `DeviceImageLoadEvents`'s exclusion-column list and increasing the mismatch penalty weight,
  caught via an out-of-band Python port of the classification logic run against every table
  fixture.
- `DEFEVA-003` (Defender sensor tampering) initially checked only whether a
  `DisableRealtimeMonitoring`-style registry value NAME was set, not its DATA -- meaning
  setting the value to `False` (re-enabling protection) would have incorrectly fired the
  rule. Fixed to require a true-like value before firing.
- The HTML report template's placeholder substitution initially used sequential
  `.Replace()` calls on a mutating string; if an earlier substitution's value (attacker-
  influenced finding data, even once HTML-escaped) happened to contain literal placeholder-
  token-shaped text, a later `.Replace()` could match and corrupt it. Replaced with a single
  forward-only scan across the original template so already-substituted content is never
  re-examined, and verified against a deliberately adversarial finding record containing a
  `</script><script>` breakout attempt and a value shaped like another placeholder token.

### Known limitations

See the "Known Limitations" section of `README.md`.
