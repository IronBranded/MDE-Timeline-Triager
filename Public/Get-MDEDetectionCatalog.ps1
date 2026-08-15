function Get-MDEDetectionCatalog {
    <#
    .SYNOPSIS
        Lists all built-in detection rules with their MITRE ATT&CK tags and confidence/FP profile.

    .DESCRIPTION
        Get-MDEDetectionCatalog reads Data/DetectionCatalog.json -- the module's detection
        catalog metadata (name, MITRE ATT&CK Tactic and Technique ID(s), Severity, Score,
        Confidence/false-positive-likelihood profile, and BenignExplanation) -- and returns
        one object per built-in detection rule. It does not process any CSV or run detection;
        it exists for documentation and to help an analyst decide what belongs in a
        baseline/exclusion config before a live run (see Test-MDEBaseline).

        The returned objects include the internal FunctionName each rule maps to and its
        SourceTables/Reference fields; this is deliberately more than the minimum "name, tags,
        confidence" the requirement calls out, since the extra fields cost nothing to expose
        and are useful for advanced/debugging use without needing to open source code.

        Optional filters narrow the listing by Tactic or Confidence without needing to pipe
        into Where-Object for the common cases.

    .PARAMETER Tactic
        Optional. Filters the returned catalog to rules tagged with this MITRE ATT&CK Tactic
        (e.g. 'Execution', 'DefenseEvasion'). Exact match, case-sensitive to the catalog's
        stored casing. If omitted, all tactics are returned.

    .PARAMETER Confidence
        Optional. Filters the returned catalog to rules carrying this Confidence label (e.g.
        'High', 'Medium', 'Low'). Exact match. If omitted, all confidence levels are returned.

    .EXAMPLE
        Get-MDEDetectionCatalog

        Lists every built-in detection rule with its full metadata (5 rules as of this build:
        EXEC-001, DEFEVA-001 through DEFEVA-004).

    .EXAMPLE
        Get-MDEDetectionCatalog -Tactic DefenseEvasion | Format-Table RuleId, Name, TechniqueId, Confidence

        Lists only Defense Evasion rules (sensor tampering, AMSI bypass, LOLBAS abuse, etc.)
        as a quick reference table.

    .INPUTS
        None.

    .OUTPUTS
        PSCustomObject
        One object per built-in detection rule, exposing at minimum: RuleId, Name, Tactic,
        TechniqueId, Severity, Score, Confidence, and BenignExplanation.

    .NOTES
        Build status: real as of Phase 3, listing the 5 rules implemented so far. Full
        catalog breadth (additional tactics: CredentialAccess, LateralMovement, Persistence,
        Exfiltration, Discovery) lands in build Phase 7.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter()]
        [string]
        $Tactic,

        [Parameter()]
        [string]
        $Confidence
    )

    $catalogPath = Join-Path -Path (Get-MDEModuleRoot) -ChildPath 'Data/DetectionCatalog.json'
    $results = @(Get-Content -Path $catalogPath -Raw | ConvertFrom-Json)

    if ($PSBoundParameters.ContainsKey('Tactic')) {
        $results = @($results | Where-Object { $_.Tactic -eq $Tactic })
    }
    if ($PSBoundParameters.ContainsKey('Confidence')) {
        $results = @($results | Where-Object { $_.Confidence -eq $Confidence })
    }

    return $results
}
