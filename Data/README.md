# Data/

`SchemaMap.json` -- the 7 supported tables' full column lists plus, for each, a set of
"signature" columns (present, weighted positively) and "exclusion" columns (present,
weighted negatively at 3x) used to disambiguate tables whose column sets overlap. Read by
`Import-MDETimeline`'s schema-set detection; a row's SourceTable and match confidence are
determined by scoring against every table's signature/exclusion sets and taking the best
match, falling back to `Unrecognized` (not a hard failure) when nothing scores confidently.

`DetectionCatalog.json` — one object per built-in detection rule: `RuleId`, `Name`,
`FunctionName`, `Tactic`, `TechniqueId` (array), `SourceTables`, `Severity`, `Score`,
`Confidence`, `BenignExplanation`, `Reference`. Read by `Invoke-MDEDetection` (resolves each
`FunctionName` to a loaded command and calls it dynamically), `New-MDEFinding` (looks up
static metadata by `RuleId` to merge with a rule's dynamic per-row `Explanation`), and
`Get-MDEDetectionCatalog` — so rule metadata has a single source of truth instead of living
as scattered comments across rule files.

Populated with 13 rules across 7 tactics as of Phase 7 (full breadth): Execution,
DefenseEvasion, Persistence, CredentialAccess, LateralMovement, Exfiltration, Discovery.

`Vendor/` — see its own README.

`ReportTemplate.html` — the static HTML/CSS/JS skeleton `New-MDEReportHtml` reads and
substitutes `__TOKEN__` placeholders into (tabs for executive summary / findings table /
process tree / network graph / swimlane, plus the JSON data-island `<script>` tags the
client-side D3/DataTables code reads from). Added in build Phase 6.

`TelemetryMapping.json` — requirement #2: correlates each supported table's ActionType
values to the standard Windows Event ID and Sysmon Event ID they correspond to (e.g.
`DeviceProcessEvents`/`ProcessCreated` -> Windows 4688 / Sysmon 1). Read by
`Get-MDETelemetryMapping` (`Private/README.md`'s Common/ section), loaded once by
`Invoke-MDEDetection` and passed to `New-MDEFinding`, so every finding carries
`WindowsEventId`/`SysmonEventId` alongside its MITRE tags. Deliberately scoped to verified,
well-established correlations for the ActionTypes this module's rules and fixtures actually
reference, not an exhaustive enumeration of every ActionType MDE can emit -- see the file's
own header note.

`ResponseActionKeywords.json` -- the substring-match keyword list
`Test-MDEResponseActionKeyword` uses to heuristically estimate the executive summary's
"first automated MDE response/containment action" goalpost. Explicitly documented (in the
file's own header note, and again here) as a best-effort estimate, not an authoritative
list: Microsoft's own `DeviceEvents` table reference states the full ActionType vocabulary
is only available via the in-portal schema reference, not published publicly. Overridable
per-call via `Invoke-MDEDetection -ResponseActionKeywords`.
