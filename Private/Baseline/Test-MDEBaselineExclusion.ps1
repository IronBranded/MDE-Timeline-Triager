function Test-MDEBaselineExclusion {
    <#
    .SYNOPSIS
        Determines whether a finding matches a baseline/exclusion config entry.
    .DESCRIPTION
        Checks each baseline exclusion entry against the finding: if an entry specifies a
        RuleId, the finding's RuleId must match that entry before its Field/MatchType/Pattern
        is even tested (Test-MDEFieldMatch); an entry with no RuleId applies across every
        rule. Returns the first matching exclusion entry -- not a plain boolean -- so the
        caller can report which specific exclusion was responsible for a suppression (or
        override) decision, keeping the "why" traceable rather than a silent yes/no.
    .PARAMETER Finding
        A finding object (from New-MDEFinding). Mandatory.
    .PARAMETER BaselineConfig
        The loaded baseline/exclusion config (array of entries). Mandatory; may be empty.
    .OUTPUTS
        PSCustomObject (the matching baseline entry) or $null if none match.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Finding,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$BaselineConfig
    )

    foreach ($entry in $BaselineConfig) {
        if ($entry.PSObject.Properties['RuleId'] -and $entry.RuleId -and $entry.RuleId -ne $Finding.RuleId) {
            continue
        }
        if (Test-MDEFieldMatch -Row $Finding.SourceRow -Field $entry.Field -MatchType $entry.MatchType -Pattern $entry.Pattern) {
            return $entry
        }
    }
    return $null
}
