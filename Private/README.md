# Private/

Internal (non-exported) functions behind the 7 public cmdlets, organized by subsystem. This
file is the architectural map: what lives where, and why the codebase is organized this way
-- not a chronological build log (see `CHANGELOG.md` for that) or a usage guide (see the root
`README.md` for that). Sections below follow the pipeline: ingest, detect, baseline/IOC,
score, correlate lineage, deobfuscate, report. `Common/` is referenced throughout and covered
first.

## Common/

Shared cross-cutting helpers: SHA-256 source-file hashing (requirement #15), `Write-Progress`
wrappers for long-running parse/detect phases, module-root resolution
(`Get-MDEModuleRoot`, via `$MyInvocation.MyCommand.Module.ModuleBase` -- resolves correctly
regardless of how the module was loaded, by explicit path or by name from `PSModulePath`),
safe row-field access, `ConvertTo-MDEParsedTimestamp` (shared timestamp parsing used by both
finding construction and the executive-summary timeframe/goalpost tracking, so there's one
implementation instead of two that could drift), `Get-MDETelemetryMapping` (requirement #2's
ActionType -> Windows Event ID / Sysmon Event ID lookup -- see `Data/TelemetryMapping.json`),
and `Test-MDEResponseActionKeyword` / `Test-MDEAlertLikeRow` (the two heuristic checks behind
the executive summary's incident overview -- see `Data/ResponseActionKeywords.json` and
`Get-MDEIncidentOverviewHtml.ps1` below for why these are explicitly best-effort estimates,
not authoritative matches against MDE's real ActionType vocabulary, which Microsoft does not
publish in full). `Get-MDEDownloadsFolder` resolves the current user's Downloads folder
cross-platform for `New-MDEReport`'s optional `-OutputPath` -- Windows via the actual Shell
Folders registry value (not a hardcoded `%USERPROFILE%\Downloads` guess, which would be wrong
for a redirected/OneDrive-managed Downloads folder), macOS/Linux via `$HOME/Downloads`
(Linux additionally tries `xdg-user-dir DOWNLOAD` first). Windows PowerShell 5.1 has no
`$IsWindows`/`$IsMacOS`/`$IsLinux` variables at all; since 5.1 only ever runs on Windows,
their absence is itself sufficient confirmation of that platform.

## Parsing/

Encoding detection (UTF-8 / UTF-8 BOM / UTF-16), flattened-column mapping (MDE portal exports
flatten nested JSON like `InitiatingProcess.*` into individual CSV columns), MDE export
schema-set detection (Device Timeline vs. Advanced Hunting vs. Live Response), and the
row-count pre-scan (`Get-MDECsvRowCount`) `Import-MDETimeline` uses by default for accurate
line-count-based progress reporting -- all behind `Import-MDETimeline`.

The pre-scan deliberately reuses `Read-MDELogicalCsvLine`, the same quote-aware reader the
real parse uses, rather than a naive `'\n'`-byte count: a quoted field may legitimately
contain an embedded newline (e.g. a multi-line command captured verbatim in
`ProcessCommandLine`), and counting raw newlines would overcount relative to the actual
number of rows the real parse produces -- the resulting progress percentage would reach 100%
before parsing actually finished. See `Tests/README.md`'s embedded-newline fixture for the
regression test guarding this specifically.

The module sets `Set-StrictMode -Version Latest`. CSV rows have a variable property set by
design -- different export types carry different columns (requirement #1's schema-mismatch
handling). Always check property existence before use:

    if ($row.PSObject.Properties['ColumnName']) { ... }

rather than direct dot-access, when a column might legitimately be absent. (StrictMode
remains valuable for catching genuine typos elsewhere -- finding-object or config-object
property names, which *are* fixed schemas -- it's specifically CSV-row access that needs this
defensive pattern.)

## Detections/

Built-in detection rule implementations as PowerShell functions (requirement #4: "PowerShell
conditional checks" -- rules are code here, not external declarative files; only the
baseline/exclusion and custom-IOC configs are externally editable, see `Baseline/` below).
One file per rule, grouped into subfolders by MITRE ATT&CK Tactic. Rule metadata
(Tactic/TechniqueId/Confidence/BenignExplanation) lives in `Data/DetectionCatalog.json`, read
by both these functions and `Get-MDEDetectionCatalog`.

13 rules across 7 tactics: `Execution/` (EXEC-001, encoded PowerShell), `DefenseEvasion/`
(DEFEVA-001 through 004: suspicious path, AMSI bypass, sensor tampering, certutil decode
abuse), `Persistence/` (PERSIST-001/002: Run key, scheduled task), `CredentialAccess/`
(CREDACCESS-001/002: LSASS dump pattern, SAM/SECURITY/SYSTEM hive save), `LateralMovement/`
(LATMOVE-001/002: PsExec artifact, WMI remote execution), `Exfiltration/` (EXFIL-001: archive
staging), `Discovery/` (DISC-001: domain trust reconnaissance).

Each rule function takes one parsed row and returns either `$null` (no hit) or a small object
with just `RuleId` and a dynamic, per-row `Explanation` string -- all static metadata is
looked up from `Data/DetectionCatalog.json` by `New-MDEFinding` (`Scoring/`), so a rule file
never duplicates metadata that already lives in the catalog. `Invoke-MDEDetection` resolves
each catalog entry's `FunctionName` to a loaded command at runtime and calls it dynamically,
so adding a rule is: write the function, add a catalog entry, done -- no change to
`Invoke-MDEDetection` itself.

## Baseline/

- `Test-MDEFieldMatch.ps1` -- shared Field/MatchType(Exact|Contains|Regex)/Pattern matcher
  used by both the baseline/exclusion engine and the custom IOC engine, since both configs
  use the same shape. Regex matches carry a 500ms timeout to guard against a pathological
  pattern in an externally-editable config file.
- `Test-MDEBaselineExclusion.ps1` -- given a finding and the loaded baseline config, returns
  the first matching exclusion entry (or `$null`), so `Invoke-MDEDetection` can report which
  specific entry was responsible for a suppression or an override.

Both the baseline/exclusion engine (requirement #9) and the custom IOC/keyword matching
engine (requirement #10) are wired into `Invoke-MDEDetection` itself (`Public/`) rather than
as additional files here, since the per-row orchestration (run built-in rules, run custom
IOCs, then apply exclusions with the precedence rule) is `Invoke-MDEDetection`'s own job.

**Config precedence, as implemented:** a baseline exclusion may suppress a Medium/Low/
Informational finding (built-in or custom) that matches it; it can never suppress a High or
Critical finding, which survives with `BaselineExclusionOverridden = $true` on the returned
finding object instead of being silently dropped. This reads the spec's "baseline exclusions
may suppress findings only at Medium severity or below" as a ceiling on the exclusion
mechanism itself, not only on the custom-IOC-vs-baseline conflict used as the requirement's
example -- documented here and in `Invoke-MDEDetection`'s comment-based help so the reasoning
is traceable, not just the behavior.

Backs both `Invoke-MDEDetection` (applies the configs) and `Test-MDEBaseline` (validates
their schema without processing a CSV).

## Scoring/

The Severity rubric and the independent Confidence/FP-likelihood lookup, behind
`Invoke-MDEDetection`. Severity and Confidence are two separate axes and neither is ever
derived from the other (requirement #5) -- this is also why a Low-confidence, Critical-
severity finding is never auto-suppressed.

- `Get-MDESeverityFromScore.ps1` -- the score-to-tier rubric (Critical 85-100, High 65-84,
  Medium 40-64, Low 15-39, Informational 0-14). Does double duty: individual built-in rules
  assign their own curated Severity directly in the catalog, but this mapping is also the
  score-to-tier half of multi-signal combination, converting a group's CombinedScore back to
  a CombinedSeverity.
- `Get-MDEScoreFromSeverity.ps1` -- the inverse mapping (tier midpoint -> score), needed
  because custom IOC entries specify a Severity directly rather than a score, but every
  finding still needs a numeric Score to participate in combination.
- `New-MDEFinding.ps1` -- the single constructor every finding passes through, guaranteeing
  the exact Finding Object Schema property set regardless of which rule fired or whether it
  came from the built-in catalog or a custom IOC. `ProcessLineage`/`CombinedScore`/
  `CombinedSeverity`/`CoOccurringFindings` are all set to sensible single-finding defaults at
  construction and only overwritten by `Invoke-MDEDetection` once lineage reconstruction and
  combination grouping are complete.

## Lineage/

Five small functions rather than one monolithic one: `New-MDEProcessLineageIndex.ps1`
(creates the empty index), `Add-MDEProcessLineageNode.ps1` (adds/backfills one process
identity node), `Update-MDEProcessLineageIndex.ps1` (extracts the edge(s) observable on one
row; called once per row during `Invoke-MDEDetection`'s streaming pass),
`Get-MDERowSubjectProcessKey.ps1` (determines which process a row/finding is "about" -- also
the grouping key for multi-signal combination), `Get-MDEProcessLineageChain.ps1` (walks the
index upward from a key, root-first, cycle-safe and hop-capped).

**Why incremental, not batch:** a process's ancestors can be described in rows anywhere in
the file -- not necessarily ones already seen -- so full reconstruction genuinely requires
the whole row stream. Rather than buffer every row (which would undo the module's memory-
bounded design), `Invoke-MDEDetection` feeds each row into this index as it streams past
(compact -- proportional to distinct processes observed, not events) and separately buffers
only the sparse set of *findings* until the index is complete, attaching `ProcessLineage` in
its `end{}` block.

Identity uses a composite `Id|CreationTime` key throughout, not PID alone, since Windows PID
reuse would otherwise merge two unrelated processes that happen to share a PID at different
points in a multi-day export into one incorrect lineage node.

Feeds both the `ProcessLineage` field on finding objects (requirement #7) and the
process-tree view in the HTML report.

## Deobfuscation/

Decode helpers behind `ConvertFrom-MDEEncodedCommand`. In scope: Base64 / PowerShell
`-EncodedCommand`, environment-variable expansion, tick-mark/caret removal, simple character
reversal. Out of scope (nested/multi-layer encoding, XOR, custom ciphers): flagged as
"possibly obfuscated -- manual review recommended," never guessed at.

Decoded output is exactly as untrusted as the raw value -- callers must still HTML-escape it
before display (see `Reporting/` below).

The four decode methods live directly inside `Public/ConvertFrom-MDEEncodedCommand.ps1` as
sequential, individually-commented steps, rather than as separate helper files in this
folder -- none of the four is ever invoked in isolation from the full decode pipeline, and
keeping them together made the method-by-method flow easier to review as one unit than four
thin wrapper files would have. This folder remains reserved for a future deobfuscation helper
that a detection rule needs to call independently of the full pipeline.

## Reporting/

- `ConvertTo-MDEHtmlEncodedString.ps1` -- the HTML-escaping function every report-bound
  string passes through (requirement #8, critical). Wraps
  `[System.Net.WebUtility]::HtmlEncode` rather than a hand-rolled replace chain.
- `ConvertTo-MDEJsonForScriptEmbed.ps1` -- neutralizes the `</script>`-breakout risk when
  JSON is embedded as a `<script type="application/json">` tag's content, on top of the
  HTML-escaping above. Its `-ForceArray` switch exists because `ConvertTo-Json` silently
  collapses a genuinely single-element array into a bare object rather than a one-element
  array -- a real bug this module shipped with until a report containing exactly one finding
  was actually rendered and executed in a real DOM; see `CHANGELOG.md`.
- `Protect-MDESensitiveValue.ps1` -- `-Redact`'s stable per-value username/hostname
  pseudonymization (requirement #17).
- `ConvertTo-MDEReportFindingRecord.ps1` -- the single place every finding becomes a flat,
  escaped, redaction-applied record; every other reporting function consumes its output, not
  a raw finding.
- `Get-MDEReportProcessTree.ps1` / `Get-MDEReportNetworkGraph.ps1` -- merge report records
  into the D3-ready tree/graph structures server-side, in PowerShell, deliberately -- this
  keeps the harder "merge many findings' data into one structure" logic somewhere it can be
  reasoned about and tested, leaving the client-side D3 code a comparatively simple "take an
  already-correct structure and draw it" job.
- `ConvertTo-MDECsvField.ps1` / `Protect-MDECsvFormulaInjection.ps1` /
  `Export-MDEEnrichedCsv.ps1` -- the enriched CSV writer (requirement #10), hand-rolled
  rather than built on `Export-Csv` because `Export-Csv`'s default `-Encoding UTF8` differs
  between Windows PowerShell 5.1 (produces a BOM) and PowerShell 7+ (does not) -- writing
  bytes directly via `[System.Text.UTF8Encoding]::new($false)` guarantees identical output on
  both runtimes.
- `Get-MDEIncidentOverviewHtml.ps1` -- renders the executive summary's incident overview:
  alert-linked events timeline (shown first when present), export timeframe, first-
  suspicious-activity and first-response "goalposts," exclusions applied. Consumes the
  `MDETimelineTriage.RunSummary`-tagged object `New-MDEReport` separates from findings by its
  `PSTypeName` -- see `CHANGELOG.md` for why the right goalpost is explicitly labeled a
  heuristic rather than a confirmed match.
- `New-MDEReportHtml.ps1` -- reads `Data/ReportTemplate.html` and substitutes in the vendored
  libraries, the escaped/redacted records, and the tree/network/summary data. Uses a single
  forward-only scan across the *original* template rather than sequential `.Replace()` calls
  on a mutating string -- sequential replacement has a real failure mode here: if an earlier
  substitution's value (attacker-influenced finding data, even once HTML-escaped) happened to
  contain literal placeholder-token-shaped text, a later `.Replace()` would match and corrupt
  it. Forward-only scanning makes that structurally impossible. Verified against a
  deliberately adversarial finding (a `</script><script>` breakout attempt) -- see
  `Tests/README.md`.

`New-MDEReport` (`Public/`) is the thin orchestrator: buffers piped findings, separates the
`RunSummary` object from them by its `PSTypeName`, computes the source hash and processing
timestamp, calls `New-MDEReportHtml`, writes it via the same explicit UTF-8-no-BOM approach
as the CSV, then calls `Export-MDEEnrichedCsv`.
