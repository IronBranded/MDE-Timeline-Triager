function ConvertTo-MDEAttackNavigatorLayer {
    <#
    .SYNOPSIS
        Builds a MITRE ATT&CK Navigator v4.5 layer JSON string from a finding set.
    .DESCRIPTION
        Produces a standalone artifact for briefings separate from the full HTML report
        (per the original scope's Export-MDEAttackNavigatorLayer deliverable) -- a technique
        coverage/heat-map layer, importable directly into the official ATT&CK Navigator
        (github.com/mitre-attack/attack-navigator) via its "Open Existing Layer" -> "Upload
        from local" option. Built against the real, current v4.5 layer format specification
        (github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md),
        fetched and read directly rather than written from memory, given how easy it would be
        to get a schema like this subtly wrong in a way that only shows up when a real
        analyst tries to import it.

        One technique entry per *distinct* TechniqueId across all findings (a finding's
        TechniqueId may itself be an array if a rule tags more than one technique; each is
        counted independently) -- not one entry per finding, since the same technique
        commonly fires on multiple findings. Score is the highest CombinedScore observed
        for that technique across all findings that tagged it, so the layer's color gradient
        reflects "how severe did this technique get in this incident," not just "did it
        fire." The comment lists which RuleIds contributed and how many findings, so an
        analyst gets some context without leaving Navigator.

        Tactic names are mapped from this module's internal PascalCase catalog values
        (e.g. "CredentialAccess") to Navigator's lowercase-hyphenated tactic IDs (e.g.
        "credential-access") via an explicit lookup table scoped to the 7 tactics this
        module's catalog actually uses, not a generic PascalCase-to-kebab-case transform --
        explicit and verifiable beats a regex that could silently mismap an edge case.
        A technique whose tactic isn't in the table (should not happen given the closed
        catalog, but defensively) is still included with no 'tactic' field set, which
        Navigator's own spec defines as graceful degradation, not a hard failure: '[the
        technique] will appear under every tactic the technique belongs to.'
    .PARAMETER Findings
        The finding objects to build the layer from (e.g. piped from Invoke-MDEDetection,
        with the RunSummary object already filtered out by the caller). Mandatory; an empty
        array produces a structurally valid layer with zero techniques, not an error.
    .PARAMETER LayerName
        The layer's display name in Navigator. Optional, default 'MDETimelineTriage Findings'.
    .OUTPUTS
        System.String -- the layer as a JSON string (not yet HTML-escaped; this is a
        standalone JSON file, not something embedded in the HTML report's markup).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$Findings,

        [Parameter()]
        [string]$LayerName = 'MDETimelineTriage Findings'
    )

    $tacticMap = @{
        'Execution'        = 'execution'
        'DefenseEvasion'   = 'defense-evasion'
        'Persistence'      = 'persistence'
        'CredentialAccess' = 'credential-access'
        'LateralMovement'  = 'lateral-movement'
        'Exfiltration'     = 'exfiltration'
        'Discovery'        = 'discovery'
    }

    # Key: techniqueId -> { Score, RuleIds (HashSet), FindingCount, Tactic }
    $byTechnique = [System.Collections.Generic.Dictionary[string, PSObject]]::new()

    foreach ($finding in $Findings) {
        $techniqueIds = @($finding.TechniqueId) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        foreach ($techniqueId in $techniqueIds) {
            $score = if ($null -ne $finding.CombinedScore) { [double]$finding.CombinedScore } else { 0.0 }
            if (-not $byTechnique.ContainsKey($techniqueId)) {
                $byTechnique[$techniqueId] = [PSCustomObject]@{
                    Score         = $score
                    RuleIds       = [System.Collections.Generic.HashSet[string]]::new()
                    FindingCount  = 0
                    Tactic        = $finding.Tactic
                }
            }
            $entry = $byTechnique[$techniqueId]
            if ($score -gt $entry.Score) { $entry.Score = $score }
            [void]$entry.RuleIds.Add($finding.RuleId)
            $entry.FindingCount++
        }
    }

    $techniques = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($techniqueId in ($byTechnique.Keys | Sort-Object)) {
        $entry = $byTechnique[$techniqueId]
        $ruleList = ($entry.RuleIds | Sort-Object) -join ', '
        $plural = if ($entry.FindingCount -eq 1) { 'finding' } else { 'findings' }
        $techniqueObj = @{
            techniqueID = $techniqueId
            score       = $entry.Score
            comment     = "$($entry.FindingCount) $plural -- rule(s): $ruleList"
            enabled     = $true
        }
        if ($tacticMap.ContainsKey($entry.Tactic)) {
            $techniqueObj['tactic'] = $tacticMap[$entry.Tactic]
        }
        $techniques.Add($techniqueObj)
    }

    $layer = [ordered]@{
        name        = $LayerName
        versions    = [ordered]@{
            navigator = '4.9.0'
            layer     = '4.5'
        }
        domain      = 'enterprise-attack'
        description = 'Generated by MDETimelineTriage -- technique coverage for this triage run. Import via ATT&CK Navigator''s Open Existing Layer -> Upload from local.'
        techniques  = $techniques
        gradient    = [ordered]@{
            colors   = @('#ffffff', '#ffe766', '#ff6666')
            minValue = 0
            maxValue = 100
        }
        sorting     = 3
    }

    return ($layer | ConvertTo-Json -Depth 10)
}
