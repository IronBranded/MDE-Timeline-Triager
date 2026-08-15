# Private/Common/

Shared cross-cutting helpers: SHA-256 source-file hashing (requirement #15), `Write-Progress`
wrappers for long-running parse/detect phases, module-root resolution, safe row-field access,
`Get-MDETelemetryMapping` (requirement #2's ActionType -> Windows Event ID / Sysmon Event
ID lookup, added once real `pwsh` became available and this gap was found -- see
`Data/TelemetryMapping.json`), `ConvertTo-MDEParsedTimestamp` (shared timestamp parsing,
extracted from logic `New-MDEFinding` used to duplicate inline so the RunSummary tracking
added to `Invoke-MDEDetection` didn't grow a second, slightly-different copy), and
`Test-MDEResponseActionKeyword` / `Test-MDEAlertLikeRow` (the two heuristic checks behind the
executive summary's incident overview -- see `Data/ResponseActionKeywords.json` and
`Private/Reporting/Get-MDEIncidentOverviewHtml.ps1` for why these are explicitly best-effort
estimates, not authoritative matches against MDE's real ActionType vocabulary).

Populated starting build Phase 2.
