# Private/Reporting/

Populated in build Phase 6:
- `ConvertTo-MDEHtmlEncodedString.ps1` -- the HTML-escaping function every report-bound
  string passes through (requirement #8, critical). Wraps `[System.Net.WebUtility]::
  HtmlEncode` rather than a hand-rolled replace chain.
- `ConvertTo-MDEJsonForScriptEmbed.ps1` -- neutralizes the separate `</script>`-breakout risk
  when JSON is embedded as a `<script type="application/json">` tag's content, on top of
  (not instead of) the HTML-escaping above.
- `Protect-MDESensitiveValue.ps1` -- `-Redact`'s stable per-value username/hostname
  pseudonymization (requirement #17).
- `ConvertTo-MDEReportFindingRecord.ps1` -- the single place every finding becomes a flat,
  escaped, redaction-applied record; every other reporting function consumes its output, not
  a raw finding.
- `Get-MDEReportProcessTree.ps1` / `Get-MDEReportNetworkGraph.ps1` -- merge report records
  into the D3-ready tree/graph structures (server-side, in PowerShell, deliberately -- this
  keeps the harder "merge many findings' data into one structure" logic somewhere it can be
  reasoned about and tested, leaving the client-side D3 code a comparatively simple "take an
  already-correct structure and draw it" job).
- `ConvertTo-MDECsvField.ps1` / `Protect-MDECsvFormulaInjection.ps1` / `Export-MDEEnrichedCsv.ps1`
  -- the enriched CSV writer (requirement #10), hand-rolled rather than built on `Export-Csv`
  because `Export-Csv`'s default `-Encoding UTF8` differs between Windows PowerShell 5.1
  (produces a BOM) and PowerShell 7+ (does not) -- writing bytes directly via
  `[System.Text.UTF8Encoding]::new($false)` guarantees identical output on both runtimes.
- `New-MDEReportHtml.ps1` -- reads `Data/ReportTemplate.html` and substitutes in the vendored
  libraries, the escaped/redacted records, and the tree/network/summary data. Uses a single
  forward-only scan across the *original* template rather than sequential `.Replace()` calls
  on a mutating string -- sequential replacement has a real failure mode here: if an earlier
  substitution's value (attacker-influenced finding data, even once HTML-escaped) happened to
  contain literal placeholder-token-shaped text, a later `.Replace()` would match and corrupt
  it. Forward-only scanning makes that structurally impossible. Verified against a
  deliberately adversarial finding (a `</script><script>` breakout attempt, an `onerror=`
  payload, and a filename shaped exactly like another placeholder token) via an out-of-band
  Python port -- see `Tests/README.md`.

- `Get-MDEIncidentOverviewHtml.ps1` -- added alongside the RunSummary work in
  `Invoke-MDEDetection`: renders the executive summary's incident overview (alert-linked
  events timeline, shown first when present; export timeframe; first-suspicious-activity and
  first-response "goalposts"; exclusions applied). Consumes the
  `MDETimelineTriage.RunSummary`-tagged object New-MDEReport separates from findings by its
  PSTypeName -- see this folder's parent CHANGELOG entry for why the right goalpost is
  explicitly labeled a heuristic rather than a confirmed match.

`New-MDEReport` (`Public/`) is the thin orchestrator: buffers piped findings, computes the
source hash and processing timestamp, calls `New-MDEReportHtml`, writes it via the same
explicit UTF-8-no-BOM approach as the CSV, then calls `Export-MDEEnrichedCsv`.
