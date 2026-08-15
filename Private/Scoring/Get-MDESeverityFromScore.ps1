function Get-MDESeverityFromScore {
    <#
    .SYNOPSIS
        Maps a 0-100 composite score to a Severity tier using this module's scoring rubric.
    .DESCRIPTION
        Score-to-tier thresholds (requirement #5's "point values per indicator and defined
        thresholds per tier"): Critical 85-100, High 65-84, Medium 40-64, Low 15-39,
        Informational 0-14.

        Individual built-in rules assign their own curated Severity directly in
        Data/DetectionCatalog.json -- a human-chosen tier is more accurate for a single,
        well-understood indicator than one mechanically derived from a score. This function
        is instead the score-to-tier half of requirement #5's *combination* logic: "how
        multiple weak/co-occurring signals on the same row or process chain combine into an
        elevated verdict." That combination/aggregation itself -- summing or otherwise
        combining several findings' Score values once they're known to belong to the same
        process chain -- lands in build Phase 5, once process-lineage grouping exists to
        determine which findings belong together. This function is ready for that logic to
        call once it lands.
    .PARAMETER Score
        Integer, 0-100. Mandatory.
    .OUTPUTS
        System.String
        One of: Critical, High, Medium, Low, Informational.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 100)]
        [int]$Score
    )

    if ($Score -ge 85) { return 'Critical' }
    if ($Score -ge 65) { return 'High' }
    if ($Score -ge 40) { return 'Medium' }
    if ($Score -ge 15) { return 'Low' }
    return 'Informational'
}
