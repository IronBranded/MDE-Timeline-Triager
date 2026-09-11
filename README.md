# MDETimelineTriage

A PowerShell module that triages Microsoft Defender for Endpoint (MDE) Windows timeline CSV
exports: it parses the export, runs a built-in detection catalog tagged to MITRE ATT&CK,
scores findings on two independent axes (Severity and Confidence), reconstructs process
lineage, combines co-occurring signals into an elevated verdict, and renders a self-contained,
fully offline-capable interactive HTML report plus an enriched CSV ready for Eric Zimmerman's
Timeline Explorer.

Single-device scope: an MDE timeline export is per-device, so v1 processes one CSV per
invocation. Windows-only.

---

## Requirements

- **PowerShell**: Windows PowerShell 5.1, or PowerShell 7+ (Desktop or Core edition). Every
  cmdlet and internal helper is written to behave identically on both; where the two runtimes
  genuinely diverge (notably `Export-Csv`'s default encoding), the module avoids the
  divergent cmdlet entirely rather than special-casing it.
- **Dependencies**: none. No external PowerShell modules are required at runtime. The HTML
  report's JavaScript/CSS (D3 v7, DataTables v3) is vendored into the module and inlined into
  every generated report -- nothing is downloaded, at install time or report-render time.
- **Platform**: Windows (the module reads Windows-specific telemetry; nothing about the
  PowerShell code itself is Windows-only, but there is no reason to run it elsewhere).

## Setup

**1. Get the code.** Clone it, or download the ZIP from GitHub's "Code" button and extract
it:

```powershell
git clone https://github.com/IronBranded/MDE-Timeline-Triager.git
```

**2. Unblock the files (Windows).** Anything extracted from a ZIP downloaded off the
internet carries Windows' "Mark of the Web," which blocks PowerShell from running it by
default -- you'll otherwise hit a "cannot be loaded because running scripts is disabled" or
"is not digitally signed" error the first time you try to import the module or run
`Start-MDETT.ps1`. Unblock the whole folder at once rather than one file at a time:

```powershell
Get-ChildItem -Path .\MDE-Timeline-Triager -Recurse | Unblock-File
```

**3. Allow script execution (Windows), if needed.** Check your current policy:

```powershell
Get-ExecutionPolicy -Scope CurrentUser
```

If that returns `Restricted` (a common default), allow locally-run scripts for your own
account only, without changing anything machine-wide or for other users:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

`RemoteSigned` still requires scripts that carry the Mark of the Web to be either signed or
explicitly unblocked (step 2) -- it doesn't disable script safety checks outright, it just
stops blocking scripts you wrote or downloaded and unblocked yourself. If your organization
enforces a stricter policy via Group Policy (e.g. `AllSigned`) and this command is itself
blocked, you'll need your IT/SOC team to either sign the module or grant an exception --
this module ships unsigned, and no step here can work around an org-enforced policy for you.

**4. Import the module and verify it loaded:**

```powershell
Import-Module .\MDE-Timeline-Triager\MDETimelineTriage.psd1
Get-Command -Module MDETimelineTriage
Get-MDEDetectionCatalog | Measure-Object   # should report 13 rules
```

Or copy the `MDETimelineTriage` folder to a location on your `$env:PSModulePath` instead, so
`Import-Module MDETimelineTriage` works by name from anywhere without a path.

**5. Initiate it** -- either the interactive launcher or a direct cmdlet call both work from
here; see "Quick Start" immediately below for what each looks like:

```powershell
cd .\MDE-Timeline-Triager\MDETimelineTriage
.\Start-MDETT.ps1
```

## Quick Start

**Interactive (no cmdlet syntax to remember):**

```powershell
.\Start-MDETT.ps1
```

Drops into a numbered menu -- Full Triage, decode a command line, validate a config file,
view the detection catalog, or run a diagnostic check. Full Triage prompts for the CSV path
and any optional configs, then runs the pipeline with `-OutputPath` omitted, so the report
and CSV land straight in your Downloads folder (Windows and macOS -- see "Output Location and
Naming" below) named `MDETT-<date>-Report.html` / `MDETT-<date>-Findings.csv`, and a quick
severity-count recap prints to the console when it's done. This is a thin wrapper around the
same cmdlets below -- nothing here is logic that isn't independently Pester-tested.

**Scripted / one-liner:**

```powershell
Invoke-MDETriage -Path .\host01-timeline.csv -OutputPath .\out
```

This parses the export, runs the full built-in detection catalog, reconstructs process
lineage, and writes `out\MDETimelineTriage-Report.html` (open it in any browser -- no
internet connection needed) and `out\MDETimelineTriage-Findings.csv`. Omit `-OutputPath`
entirely for the same Downloads-folder-plus-dated-names behavior the interactive launcher
uses.

With baseline noise suppression, case-specific IOCs, redaction, and local time enabled:

```powershell
Invoke-MDETriage -Path .\host01-timeline.csv -OutputPath .\out `
    -BaselineConfigPath .\config\baseline.json `
    -CustomIOCConfigPath .\config\case-2026-041-iocs.json `
    -Redact -LocalTime
```

Or use the pipeline directly for more control between stages:

```powershell
Import-MDETimeline -Path .\host01-timeline.csv -Verbose |
    Invoke-MDEDetection -BaselineConfigPath .\config\baseline.json |
    New-MDEReport -SourcePath .\host01-timeline.csv -OutputPath .\out -Redact
```

---

## Cmdlet Reference

All seven cmdlets below have complete comment-based help; `Get-Help <CmdletName> -Full` is
genuinely useful for each without needing to open source code. This section mirrors that
help at a glance.

### Invoke-MDETriage

The primary entry point. Runs the full pipeline (parse -> detect -> score -> correlate
lineage -> render HTML + CSV) in one call.

```powershell
Invoke-MDETriage -Path <String> [-OutputPath <String>] [-DatedFileNames]
    [-BaselineConfigPath <String>] [-CustomIOCConfigPath <String>]
    [-Redact] [-LocalTime] [-ReportSizeThreshold <Int32>]
    [-WhatIf] [-Confirm]
```

| Parameter | Mandatory | Default | Notes |
|---|---|---|---|
| `Path` | Yes | -- | The source MDE timeline CSV. |
| `OutputPath` | No | Downloads folder | Directory for the HTML report and CSV; created if missing. Omit for automatic Downloads-folder resolution plus `-DatedFileNames` -- see "Output Location and Naming" below. |
| `DatedFileNames` | No | auto-on if `OutputPath` omitted | Names outputs `MDETT-<yyyy-MM-dd>-Report.html`/`-Findings.csv` instead of the fixed traditional names. |
| `BaselineConfigPath` | No | none | JSON baseline/exclusion config. |
| `CustomIOCConfigPath` | No | none | JSON custom IOC config. |
| `Redact` | No | off | Pseudonymize usernames/hostnames in the HTML report. |
| `LocalTime` | No | off | Add a labeled local-time value alongside UTC. |
| `ReportSizeThreshold` | No | 5000 | Findings above this cap the interactive views to a top-N-by-score subset (the CSV is always complete). |

```powershell
Invoke-MDETriage -Path .\host01-timeline.csv -OutputPath .\out
```

### Import-MDETimeline

Parses a single MDE timeline CSV export into normalized, typed pipeline objects. Ingest only
-- no detection, no report.

```powershell
Import-MDETimeline -Path <String> [-SkipRowCountPreScan]
```

```powershell
Import-MDETimeline -Path .\host01-timeline.csv -Verbose | Invoke-MDEDetection
```

Auto-detects encoding (UTF-8, UTF-8 with BOM, UTF-16) and which of the 7 supported Advanced
Hunting tables the export matches (`DeviceProcessEvents`, `DeviceNetworkEvents`,
`DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`,
`DeviceEvents`); an export that doesn't confidently match one -- including Defender portal
"Device Timeline" exports, whose columns are user-customizable and not governed by any fixed
schema Microsoft publishes -- is classified `Unrecognized` and still parsed using whatever
columns are present. Malformed rows (truncated, invalid byte sequences for the detected
encoding) are skipped and counted, never a terminating error.

By default, this cmdlet reads through the file once first (cheaply -- no field-splitting, no
object construction) to get an exact row count, so `Write-Progress` reports genuine "row N of
M" percentages during the real parse instead of a bytes-read estimate. Measured cost on a
real 200,000-row/71MB file: **+~22% to total parse time** (30.46s with the pre-scan vs.
24.97s without, in the environment this was measured in -- real numbers, not a guess). Pass
`-SkipRowCountPreScan` to skip it and fall back to the byte-based estimate if you'd rather
trade progress accuracy for a faster start.

### Invoke-MDEDetection

Runs the built-in detection catalog, any supplied custom IOC entries, baseline exclusion
filtering, process-lineage correlation, and multi-signal combination against parsed rows.
Every returned finding also carries `WindowsEventId`/`SysmonEventId` (requirement #2 --
correlated from `Data/TelemetryMapping.json`, `$null` when no verified correlation is known
for that row's ActionType).

```powershell
Invoke-MDEDetection -InputObject <PSObject[]>
    [-BaselineConfigPath <String>] [-CustomIOCConfigPath <String>]
    [-ResponseActionKeywords <String[]>]
    [-WhatIf] [-Confirm]
```

```powershell
Import-MDETimeline -Path .\host01-timeline.csv |
    Invoke-MDEDetection -BaselineConfigPath .\config\baseline.json -CustomIOCConfigPath .\config\case-2026-041-iocs.json
```

Implements `SupportsShouldProcess`: `-WhatIf` reports the loaded rule/custom-IOC counts
without evaluating any row or returning any finding. Note: buffers findings (not rows)
internally to complete process-lineage reconstruction before returning anything -- see
"Architecture" below.

### New-MDEReport

Renders the HTML report and enriched CSV from finding objects. Kept separate from detection
so a report can be re-rendered (e.g. toggling `-Redact`) without re-running detection.

```powershell
New-MDEReport -InputObject <PSObject[]> -SourcePath <String>
    [-OutputPath <String>] [-DatedFileNames]
    [-Redact] [-LocalTime] [-ReportSizeThreshold <Int32>]
    [-WhatIf] [-Confirm]
```

```powershell
$findings | New-MDEReport -SourcePath .\host01-timeline.csv -OutputPath .\out -Redact -LocalTime -WhatIf
```

Implements `SupportsShouldProcess`: `-WhatIf` reports which files would be written (flagging
if that would overwrite an existing report) without writing them.

**Output Location and Naming.** `-OutputPath` is optional. Supplied explicitly, behavior is
unchanged from earlier versions: fixed `MDETimelineTriage-Report.html`/
`MDETimelineTriage-Findings.csv` names at that exact location. Omitted entirely, this cmdlet
resolves to the current user's Downloads folder and automatically switches on
`-DatedFileNames`, writing `MDETT-<yyyy-MM-dd>-Report.html`/`MDETT-<yyyy-MM-dd>-Findings.csv`
(today's date, not the export's own data timeframe) instead. Downloads-folder resolution is
cross-platform: Windows reads the actual Shell Folders registry value rather than assuming
`%USERPROFILE%\Downloads`, so a redirected/OneDrive-managed Downloads folder still resolves
correctly; macOS and Linux use `$HOME/Downloads` (Linux additionally tries `xdg-user-dir
DOWNLOAD` first, if available). `-DatedFileNames` can also be combined with an explicit
`-OutputPath` for dated names at a custom location. See `Get-MDEDownloadsFolder` in
`Private/README.md` for the full resolution logic.

### ConvertFrom-MDEEncodedCommand

Standalone command-line deobfuscation utility, usable outside a full triage run.

```powershell
ConvertFrom-MDEEncodedCommand -CommandLine <String>
```

```powershell
ConvertFrom-MDEEncodedCommand -CommandLine 'powershell.exe -enc SQBFAFgA...'
```

In scope for automatic decoding: Base64/`-EncodedCommand` (UTF-16LE, per PowerShell's own
convention), environment-variable expansion (a small set of well-known Windows variables,
substituted with their standard default value -- a static CSV export carries no live
environment to verify against), tick-mark/caret removal, simple character reversal. Anything
beyond that -- nested/multi-layer encoding, XOR, custom ciphers -- is reported as
`PossiblyObfuscated`, never guessed at.

### Test-MDEBaseline

Validates a baseline/exclusion or custom IOC config file's schema without processing any CSV.

```powershell
Test-MDEBaseline -Path <String> [-ConfigType {Auto | Baseline | CustomIOC}]
```

```powershell
Test-MDEBaseline -Path .\config\case-2026-041-iocs.json -ConfigType CustomIOC -Verbose
```

Checks every entry (not just the first failure), auto-detecting config type by whether
entries carry a `Severity` field.

### Get-MDEDetectionCatalog

Lists all built-in detection rules with their MITRE ATT&CK tags and confidence/FP profile.

```powershell
Get-MDEDetectionCatalog [-Tactic <String>] [-Confidence <String>]
```

```powershell
Get-MDEDetectionCatalog -Tactic DefenseEvasion | Format-Table RuleId, Name, TechniqueId, Confidence
```

---

## Severity and Confidence: two independent axes

Every finding carries both a **Severity** tier and a **Confidence** label, and they are never
conflated or auto-derived from one another:

- **Severity** (`Critical` / `High` / `Medium` / `Low` / `Informational`) describes how bad
  the finding is *if true*. Backed by a 0-100 `Score`; thresholds are Critical 85-100, High
  65-84, Medium 40-64, Low 15-39, Informational 0-14.
- **Confidence** (`High` / `Medium` / `Low`) describes how likely the rule is to have fired
  correctly -- its false-positive profile.

`DEFEVA-001` (Suspicious Execution Path) is the clearest example in this catalog: **Medium
severity, Low confidence**. Execution from AppData/ProgramData/Temp is a real, sometimes-bad
pattern, but it's also extremely common in legitimate installers and auto-updaters -- so it's
noisy (Low confidence) without being any less worth flagging when it *is* bad (Medium
severity, not downgraded to compensate for the noise).

Conversely, `CREDACCESS-001` (LSASS memory dump pattern) is **Critical severity AND High
confidence** -- some indicators are both rare and severe at once, and a Low-confidence
finding at High/Critical severity is *never* auto-suppressed anywhere in this module
(including by a baseline exclusion config -- see below), because those are often the most
important cases for an analyst to manually review, precisely because they're rare and
high-impact.

**Multi-signal combination**: when two or more findings land on the *same process*
(`ProcessLineage`'s subject, not just the same row), their scores combine -- highest at full
weight, each next-highest at half the previous weight, capped at 100 -- into a
`CombinedScore`/`CombinedSeverity` shown alongside each finding's own individual values, with
`CoOccurringFindings` naming what else fired on that process.

## Detection Catalog

13 built-in rules across 7 MITRE ATT&CK tactics as of this release. `Get-MDEDetectionCatalog`
is the live reference (name, technique ID, severity, confidence, and a benign-explanation
note for every rule); a snapshot:

| Tactic | Rules |
|---|---|
| Execution | `EXEC-001` Encoded PowerShell Command |
| Defense Evasion | `DEFEVA-001` Suspicious Execution Path, `DEFEVA-002` AMSI Bypass Indicator, `DEFEVA-003` Defender Sensor Tampering, `DEFEVA-004` Certutil Decode Abuse |
| Persistence | `PERSIST-001` Registry Run Key Suspicious Target, `PERSIST-002` Scheduled Task Creation |
| Credential Access | `CREDACCESS-001` LSASS Memory Dump Pattern, `CREDACCESS-002` Registry Hive Save |
| Lateral Movement | `LATMOVE-001` PsExec Service Artifact, `LATMOVE-002` WMI Remote Execution |
| Exfiltration | `EXFIL-001` Archive Staging Suspicious Path |
| Discovery | `DISC-001` Domain Trust Reconnaissance |

## Baseline / Custom IOC configuration

Both are JSON arrays of objects sharing a base shape:

```json
{ "Field": "InitiatingProcessFileName", "MatchType": "Exact", "Pattern": "CcmExec.exe" }
```

- `Field` -- a property name on the parsed row to test.
- `MatchType` -- `Exact`, `Contains`, or `Regex` (regex matches carry a 500ms timeout).
- `Pattern` -- the value/pattern.
- `RuleId` (baseline only, optional) -- scope the exclusion to one rule; omit to apply
  broadly.

A **custom IOC** entry additionally requires `Severity` and accepts optional `CaseId`,
`Confidence`, `SourceTables`, `Explanation`, `Name`, `BenignExplanation`. A matched entry
produces a finding with a synthesized `CUSTOM-<CaseId>-NNN` RuleId.

```json
[
  {
    "CaseId": "2026-041", "Name": "Known C2 IP", "Field": "RemoteIP",
    "MatchType": "Exact", "Pattern": "203.0.113.44",
    "SourceTables": ["DeviceNetworkEvents"], "Severity": "Critical"
  }
]
```

**Config precedence (documented explicitly, per requirement #10):** a baseline exclusion may
suppress a finding at Medium severity or below. It can never suppress a High or Critical
finding, regardless of whether that finding came from the built-in catalog or a custom IOC
match -- that finding survives with `BaselineExclusionOverridden = $true` on the returned
object instead of being silently dropped. This module reads the spec's "baseline exclusions
may suppress findings only at Medium severity or below" as a ceiling on the exclusion
mechanism itself, not only on the specific custom-IOC-vs-baseline conflict used as the
requirement's example; see `Invoke-MDEDetection`'s comment-based help and
`Private/README.md`'s Baseline/ section for the full reasoning.

## Report Views

The executive summary opens with an **incident overview**: the export's timeframe (earliest
to latest event across every row processed, not just findings), two investigation
"goalposts" -- first suspicious/malicious activity, and, heuristically, first automated MDE
response/containment action -- an alert-linked events timeline when the export contains any
(shown first, ahead of the timeframe/goalposts, when present), and what baseline exclusions
suppressed, if any. The right goalpost is explicitly labeled as an estimate: Microsoft
doesn't publish an authoritative list of ActionType values for isolation/quarantine/remediation
actions, so this matches against a documented, overridable keyword heuristic (see
`Invoke-MDEDetection -ResponseActionKeywords` and `Data/ResponseActionKeywords.json`) rather
than a confirmed set of exact values -- pass your own tenant's exact ActionType strings via
that parameter when precision matters.

The HTML report has four interactive views, all vendored/inlined (D3 v7, DataTables v3 --
no jQuery, no CDN reference anywhere), plus an executive summary:

1. **Findings Table** (DataTables) -- sortable, filterable, color-coded by severity.
2. **Process Tree** (D3 hierarchy layout) -- every finding's process lineage merged into one
   tree; nodes colored by the worst severity observed at that process, hover for detail.
3. **Network Graph** (D3 force-directed) -- host <-> remote device/IP correlation from
   network- and logon-relevant findings, for lateral-movement context.
4. **Swimlane** (D3 time-axis scatter) -- findings plotted by time, grouped by source table.

If the finding count exceeds `-ReportSizeThreshold` (default 5000), all four views switch to
a top-N-by-`CombinedScore` subset with a banner explaining the rest are in the CSV; the CSV
always contains the complete, uncapped set.

*(Report screenshot placeholder -- insert a screenshot of the Executive Summary and Findings
Table tabs here once generated against a real export.)*

## Evidence Handling

- The source CSV is opened for reading only and never modified, at any stage.
- `New-MDEReport` re-computes the source file's SHA-256 hash at render time (rather than
  trusting a value threaded through from ingest) -- this doubles as a check that the evidence
  hasn't changed since it was first parsed. The hash, full source path, and UTC processing
  timestamp are recorded in the HTML report header and repeated on every row of the enriched
  CSV, so a single extracted/copied CSV row still carries its own provenance.
- No telemetry, phone-home, or auto-upload behavior anywhere in the module.
- `-Redact` masks usernames and hostnames with stable per-value placeholders (`USER-1`,
  `HOST-1`, ...) rather than blanking them outright, so relational patterns (the same
  account/device recurring across findings) stay visible in a report safe to share outside
  the immediate IR team.
- Every value that reaches the HTML report -- including values already auto-decoded by
  `ConvertFrom-MDEEncodedCommand` -- is HTML-encoded before it touches markup, and the JSON
  embedded in the report is additionally guarded against a `</script>`-breakout injection.
  Nothing from a parsed row or finding is ever string-concatenated into HTML.

## Performance

Measured, not assumed: a synthetic 200,000-row / 74MB `DeviceProcessEvents` export (60
deliberately malicious rows mixed into otherwise-benign traffic) run through the real module
in real PowerShell 7.6.4:

| Usage pattern | Result |
|---|---|
| `Import-MDETimeline \| Invoke-MDEDetection \| New-MDEReport` as a true pipeline (no intermediate variable capture) | ~170s end-to-end, managed memory stayed at ~19MB |
| Same work, but capturing `$rows`/`$findings` into variables between stages | Same wall-clock ballpark, but memory rose to ~1.8GB, since holding the full result set in a variable is exactly what that does in any language |
| `Import-MDETimeline`'s row-count pre-scan (default, for accurate line-count progress) vs. `-SkipRowCountPreScan` | +~22% to parse time on the same 200K-row file (30.46s with pre-scan vs. 24.97s without) for an exact row count instead of a byte-based estimate |

Throughput is roughly 1,000-1,200 rows/second overall, meaning a multi-million-row export
takes on the order of 30-60 minutes, not seconds. `Invoke-MDEDetection` (13 rules evaluated
per row) is the slower stage of the three. This module is built for thorough offline/batch
triage, not real-time processing -- an accurate characterization to plan around, not a
defect. If you need to re-verify this yourself, generate a synthetic CSV with the same
column shape as `Tests/Fixtures/DeviceProcessEvents-happy.csv` at whatever row count you care
about and run the pipeline above with `[System.Diagnostics.Stopwatch]`.

**Memory scales with distinct-process count, not just row count -- worth knowing given
MDE's own 7-day device-timeline export limit.** The `~19MB` figure above held for that
specific file's data shape: a small, realistic pool of process names reused across rows.
Prompted by the real-world 7-day export limit (confirmed directly from Microsoft's own
documentation, not assumed) and the genuine possibility of a busy/heavily-instrumented host
producing an export with a very large number of *distinct* processes over a full 7-day
window, a synthetic 1,000,000-row file where every single row was a distinct process
(deliberately worst-case for the lineage index, which is keyed per distinct process) was
run against the pipeline -- and it OOM-killed the machine it ran on. Traced directly (not
guessed) to the process-lineage index storing each node as a `[PSCustomObject]`, which
carries substantial per-instance overhead in PowerShell; at real scale that compounds into
gigabytes. Fixed by switching lineage nodes to plain hashtables -- full story, including why
the first hypothesis (an unbounded per-parent children list) was wrong, in `CHANGELOG.md`.

Re-verified after the fix at the same worst-case shape (every row a distinct process),
scaled back to sizes this environment could complete safely after the first attempt
destabilized the whole sandbox:

| Scale (every row a distinct process) | Result |
|---|---|
| 200,000 rows / 71MB | 133.7s, managed memory ~14MB |
| 500,000 rows / 176MB | 329.1s, managed memory ~14MB, peak resident memory ~1.2GB (safely bounded, with normal GC reclaim between checks -- not the unbounded growth seen before the fix) |

The full 1,000,000-row worst-case scenario was **not** re-attempted after the fix: the
first attempt at that scale had already destabilized the sandbox enough to force a full
reboot, and a second attempt carried real, demonstrated risk for a third crash rather than
new information the 200K/500K trend didn't already strongly suggest. Treat "handles a
genuinely heavy, close-to-1,000,000-distinct-process 7-day export" as *well-supported by a
clear trend*, not *directly verified at that exact scale* -- an honest distinction worth
preserving rather than rounding up.

**The report's 5,000-finding summarization threshold (requirement #8) was also confirmed
for real for the first time** during this same investigation: a 200,000-row file with 6,000
deliberately malicious rows correctly set `sizeThresholdApplied: true`, embedded exactly
5,000 of the 6,000 findings in the HTML (confirmed both by parsing the embedded JSON and by
querying DataTables' own API for its loaded record count, not just counting visible/
paginated DOM rows), while the CSV still held the complete, uncapped 6,000.

## Verification Status

What "verified" means varies across this module, and it's worth being precise rather than
letting the word do too much work. Full narrative detail on any of these -- what broke, how
it was found, exactly how it was fixed -- lives in `CHANGELOG.md`; this section is the
current-state summary, not the story.

- **The actual Pester suite has run and passed: 134/134**, via real Pester 4.10.1 (pure
  PowerShell, no `dotnet` SDK needed -- see "Getting Pester Running" below), not a
  hand-written substitute. Three real bugs surfaced the first time this suite ever ran
  against real Pester, all fixed; see `CHANGELOG.md`'s `[0.2.0]` entry.
- **Every cmdlet has been executed directly in real PowerShell 7.6.4** -- including
  `Invoke-MDETriage` itself, not just the three stages it composes -- against every fixture
  in the project: all 13 detection rules, baseline/custom-IOC precedence, process lineage
  and multi-signal combination, the telemetry-mapping correlation, redaction, evidence
  hashing, adversarial-payload HTML escaping, and a 200,000-row performance run.
  `Tests/Invoke-ManualValidation.ps1` (71/71 passing) is the record of this and ships in the
  module -- not a Pester substitute, but useful for anyone who can't get Pester running
  either.
- **The generated HTML report has actually been executed** (via `jsdom`, not a real
  browser -- none available in the environment this was built in), not just syntax-checked:
  every tab clicked programmatically across 0/1/7-finding report scenarios, zero runtime
  errors. This is materially stronger than checking the JS parses, and it caught a real,
  previously-shipped bug (a report with exactly one finding threw a client-side
  `TypeError` -- see `CHANGELOG.md`'s `[0.2.0]` entry) -- but it still isn't pixel-level
  visual confirmation; a CSS/layout issue wouldn't show up in either jsdom or a syntax check.
- **`Tests/Invoke-ManualLint.ps1`** (8 of PSScriptAnalyzer's real rule categories,
  AST-based, self-tested against a deliberately bad file before being trusted -- not a
  PSScriptAnalyzer replacement): **0 findings across all 57 module files.**
- **Real PSScriptAnalyzer has never run, and this is architecturally out of reach in the
  environment this module was built in, not just inconvenient.** Unlike Pester (whose 4.x
  line is pure PowerShell with no compiled component), PSScriptAnalyzer has had a compiled
  C# core since its earliest indexed release -- there's no equivalent pure-PowerShell
  version to fall back to. `.github/workflows/ci.yml` runs it for real on GitHub's hosted
  runners (which have PowerShell Gallery access this environment didn't), across Windows
  PowerShell 5.1, PowerShell 7+ on Windows, and PowerShell 7+ on Linux -- its first genuine
  test is your first push.
- **Known-by-design gaps, not defects**: requirement #2's telemetry mapping is scoped to
  verified, well-established correlations for the ActionTypes this module's rules and
  fixtures reference (see `Data/TelemetryMapping.json`'s own header note), not an exhaustive
  enumeration of every ActionType MDE can emit. ETW blinding and LOLDriver abuse remain
  uncovered by any rule. `Invoke-MDEDetection -ResponseActionKeywords`'s "first MDE
  response" estimate is a documented heuristic, not a confirmed match against MDE's real
  ActionType vocabulary -- see "Report Views" above.
- **Everything above was tested against synthetic data.** No fixture in this project has
  ever been a genuine (even sanitized) Defender-portal export.

If you have a moment to look at a generated report in a real browser, that remains the one
meaningful gap `jsdom` execution testing can't close on its own.

## Known Limitations

- **False-positive-prone detections by design**: `DEFEVA-001` (suspicious path),
  `PERSIST-002` (scheduled task creation), `EXFIL-001` (archive staging), and `DISC-001`
  (domain trust recon) are all Low-confidence in the catalog on purpose -- they're common,
  genuinely useful signals that are also common in legitimate IT activity. Use
  `-BaselineConfigPath` to suppress known-good sources in your environment; see the
  precedence rule above for why this never suppresses your most severe findings.
- **Coverage gaps**: 13 rules is a representative catalog across all 7 tactics this module
  targets, not an exhaustive one. Notably absent: ETW blinding (distinct from the AMSI
  bypass `DEFEVA-002` covers), LOLDriver abuse, and a source-side (as opposed to
  `LATMOVE-001`'s target-side) view of lateral movement, which single-device scope makes
  hard to observe from one export alone.
- **Deobfuscation scope**: `ConvertFrom-MDEEncodedCommand` handles Base64/`-EncodedCommand`,
  environment-variable expansion (standard defaults only, not the live host's actual values),
  tick/caret removal, and simple reversal. Nested/multi-layer encoding, XOR, and custom
  ciphers are flagged as `PossiblyObfuscated`, never guessed at.
- **Process lineage and single-device scope**: reconstruction is complete only for processes
  whose creation/parent info appears somewhere in the export; a process that existed before
  the export's time window (e.g. `explorer.exe` since login) appears as a leaf ancestor with
  no further parent, not an error.

See "Verification Status" above for what has and hasn't been independently confirmed.

## Architecture

`Private/README.md` is the architectural map of every subfolder below -- what it contains
and why. Brief map:

- `Private/Parsing/` -- encoding detection, the hand-rolled CSV engine, schema-set detection.
- `Private/Detections/<Tactic>/` -- the 13 rule functions, one file each.
- `Private/Scoring/` -- the Finding object constructor, severity/score mapping.
- `Private/Lineage/` -- the incrementally-built process lineage index.
- `Private/Baseline/` -- the shared Field/MatchType/Pattern matcher for both config types.
- `Private/Reporting/` -- HTML escaping, the report template substitution engine, CSV export.
- `Private/Common/` -- small cross-cutting helpers (module-root resolution, file hashing).
- `Data/` -- `SchemaMap.json`, `DetectionCatalog.json`, `ReportTemplate.html`, `Vendor/`.

One architectural note worth knowing: `Invoke-MDEDetection` streams rows through built-in
rule evaluation and baseline/custom-IOC filtering exactly as they arrive, but buffers the
(typically sparse) set of *findings* -- not the full row stream -- until process-lineage
reconstruction is complete, since a process's ancestors can be described in rows anywhere in
the file. This is a deliberate, documented departure from the otherwise single-pass,
bounded-memory design used everywhere else in the pipeline; see `Private/README.md`'s
Lineage/ section and `Invoke-MDEDetection`'s comment-based help for the full reasoning.

## Testing

```powershell
Invoke-Pester -Path .\Tests\
```

If `Invoke-Pester` isn't available (Pester's default/latest major version needs a `dotnet`
SDK to build from source in environments without access to the PowerShell Gallery -- see
"Getting Pester Running" and "Verification Status" below), run the equivalent hand-written
validation instead:

```powershell
pwsh -File .\Tests\Invoke-ManualValidation.ps1
```

See `Tests/README.md` for what each covers.

## Getting Pester Running Without the PowerShell Gallery

Pester 6.x (and 5.x) require a `dotnet` SDK to build their compiled component from source.
**Pester 4.10.1 does not** -- it's pure PowerShell, no build step, and every test in this
module's `Tests/*.Tests.ps1` suite runs correctly under it (confirmed: 134/134 passing). If
`Invoke-Pester` isn't already on your machine and you can't reach the PowerShell Gallery:

```powershell
# Download Pester 4.10.1 source directly from GitHub (no Gallery needed)
Invoke-WebRequest -Uri 'https://codeload.github.com/pester/Pester/tar.gz/refs/tags/4.10.1' -OutFile pester4.tar.gz
tar -xzf pester4.tar.gz
Import-Module '.\Pester-4.10.1\Pester.psd1' -Force
Invoke-Pester -Script '.\Tests\*.Tests.ps1'
```

Two things worth knowing if you go this route: Pester 4.x needs `BeforeAll`/`AfterAll` nested
*inside* a `Describe` or `Context` block -- unlike Pester 5.x/6.x, it doesn't support a
file-level `BeforeAll` running before all `Describe` blocks in that file, and this module's
test files are already written the compatible way for exactly this reason. And `-TestCases`,
`Should -Be`/`-Throw`/`-BeGreaterOrEqual`/etc., and `-Because` all work identically to what
you'd expect from 5.x, so nothing else needs adapting.

## Versioning

Semantic versioning (`major.minor.patch`) in `MDETimelineTriage.psd1`. See `CHANGELOG.md`.
