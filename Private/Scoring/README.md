# Private/Scoring/

The Severity rubric (point values per indicator, defined thresholds per tier — Critical /
High / Medium / Low / Informational) and the independent Confidence/FP-likelihood lookup,
behind `Invoke-MDEDetection`. Severity and Confidence are two separate axes and neither is
ever derived from the other (see requirement #5) — this is also why a Low-confidence,
Critical-severity finding is never auto-suppressed here.

Populated in build Phase 3, extended in Phase 5:
- `Get-MDESeverityFromScore.ps1` -- the score-to-tier rubric (Critical 85-100, High 65-84,
  Medium 40-64, Low 15-39, Informational 0-14). Now doing double duty: individual built-in
  rules still assign their own curated Severity directly in the catalog, but this mapping is
  also the score-to-tier half of Phase 5's multi-signal combination, converting a group's
  CombinedScore back to a CombinedSeverity.
- `Get-MDEScoreFromSeverity.ps1` -- added Phase 5, the inverse mapping (tier midpoint ->
  score), needed because custom IOC entries specify a Severity directly rather than a score,
  but every finding still needs a numeric Score to participate in combination.
- `New-MDEFinding.ps1` -- the single constructor every finding passes through, guaranteeing
  the exact Finding Object Schema property set regardless of which rule fired or whether it
  came from the built-in catalog or a custom IOC. `ProcessLineage`/`CombinedScore`/
  `CombinedSeverity`/`CoOccurringFindings` are all set to sensible single-finding defaults at
  construction and only overwritten by `Invoke-MDEDetection` once lineage reconstruction and
  combination grouping are complete (Phase 5).
