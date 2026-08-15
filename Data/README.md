# Data/

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
`Get-MDETelemetryMapping` (`Private/Common/`), loaded once by `Invoke-MDEDetection` and
passed to `New-MDEFinding`, so every finding carries `WindowsEventId`/`SysmonEventId`
alongside its MITRE tags. Deliberately scoped to verified, well-established correlations for
the ActionTypes this module's rules and fixtures actually reference, not an exhaustive
enumeration of every ActionType MDE can emit -- see the file's own header note.
