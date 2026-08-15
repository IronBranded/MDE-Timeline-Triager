# Private/Baseline/

Populated in build Phase 4:
- `Test-MDEFieldMatch.ps1` -- shared Field/MatchType(Exact|Contains|Regex)/Pattern matcher
  used by both the baseline/exclusion engine and the custom IOC engine, since both configs
  use the same shape. Regex matches carry a 500ms timeout to guard against a pathological
  pattern in an externally-editable config file.
- `Test-MDEBaselineExclusion.ps1` -- given a finding and the loaded baseline config, returns
  the first matching exclusion entry (or `$null`), so `Invoke-MDEDetection` can report which
  specific entry was responsible for a suppression or an override.

Both the baseline/exclusion engine (requirement #9 -- known corporate noise: IT management
tools, Intune/SCCM, legitimate tenant scripts, Windows Update, MDE/AV noise) and the custom
IOC/keyword matching engine (requirement #10) are wired into `Invoke-MDEDetection` itself
(`Public/`) rather than as additional files here, since the per-row orchestration (run
built-in rules, run custom IOCs, then apply exclusions with the precedence rule) is
`Invoke-MDEDetection`'s own job and didn't warrant a further layer of indirection.

**Config precedence, as implemented:** a baseline exclusion may suppress a Medium/Low/
Informational finding (built-in or custom) that matches it; it can never suppress a High or
Critical finding, which survives with `BaselineExclusionOverridden = $true` on the returned
finding object instead of being silently dropped. This module reads the spec's "baseline
exclusions may suppress findings only at Medium severity or below" as a ceiling on the
exclusion mechanism itself, not only on the custom-IOC-vs-baseline conflict used as the
requirement's example -- documented here and in `Invoke-MDEDetection`'s comment-based help
so the reasoning is traceable, not just the behavior.

Backs both `Invoke-MDEDetection` (applies the configs) and `Test-MDEBaseline` (validates
their schema without processing a CSV).
