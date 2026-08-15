# Private/Detections/

Built-in detection rule implementations as PowerShell functions (per requirement #4's
"PowerShell conditional checks" — rules are code here, not external declarative files;
only the baseline/exclusion and custom-IOC configs are externally editable, see
`Private/Baseline/`). One file per rule, grouped into subfolders by MITRE ATT&CK Tactic
(e.g. `Execution/`, `DefenseEvasion/`, `CredentialAccess/`, `LateralMovement/`,
`Persistence/`, `Exfiltration/`, `Discovery/`).

Rule metadata (Tactic/TechniqueId/Confidence/BenignExplanation) lives in
`Data/DetectionCatalog.json`, read by both these functions and `Get-MDEDetectionCatalog`.

Populated with 13 rules across 7 tactics as of Phase 7 (full breadth):
- `Execution/` — EXEC-001 (encoded PowerShell)
- `DefenseEvasion/` — DEFEVA-001 through DEFEVA-004 (suspicious path, AMSI bypass, sensor
  tampering, certutil decode abuse)
- `Persistence/` — PERSIST-001 (autostart Run key to a suspicious path), PERSIST-002
  (scheduled task creation)
- `CredentialAccess/` — CREDACCESS-001 (LSASS memory dump pattern), CREDACCESS-002 (SAM/
  SECURITY/SYSTEM hive save)
- `LateralMovement/` — LATMOVE-001 (PsExec service artifact), LATMOVE-002 (WMI remote
  execution)
- `Exfiltration/` — EXFIL-001 (archive staging to a suspicious path)
- `Discovery/` — DISC-001 (AD domain trust reconnaissance)

Each rule function takes one parsed row and returns either `$null` (no hit) or a small object
with just `RuleId` and a dynamic, per-row `Explanation` string -- all static metadata
(Tactic/TechniqueId/Severity/Confidence/BenignExplanation) is looked up from
`Data/DetectionCatalog.json` by `New-MDEFinding` (`Private/Scoring/`), so a rule file never
duplicates metadata that already lives in the catalog. `Invoke-MDEDetection` resolves each
catalog entry's `FunctionName` to a loaded command at runtime and calls it dynamically, so
adding a rule is: write the function, add a catalog entry, done -- no change to
`Invoke-MDEDetection` itself. Every rule was regression-checked against every other fixture
in the project (see `Tests/README.md`) to confirm it doesn't fire unexpectedly on benign
telemetry or on fixtures built for other rules.
