function Test-MDEResponseActionKeyword {
    <#
    .SYNOPSIS
        Heuristically checks whether an ActionType value looks like an automated MDE response/containment action.
    .DESCRIPTION
        Substring match (case-insensitive) against a keyword list -- see
        Data/ResponseActionKeywords.json for why this is explicitly a best-effort heuristic
        and not an authoritative match against MDE's real ActionType vocabulary, which
        Microsoft does not publish in full. Used to estimate the "right goalpost" (first
        automated response/quarantine) in the executive summary's incident-timeframe
        overview -- always labeled in the report as an estimate, never presented as
        confirmed fact.
    .PARAMETER ActionType
        The row's ActionType value. Optional; empty input returns $false.
    .PARAMETER Keywords
        The keyword list to match against. Mandatory.
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ActionType,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Keywords
    )

    if ([string]::IsNullOrWhiteSpace($ActionType)) { return $false }

    foreach ($kw in $Keywords) {
        if ($ActionType -like "*$kw*") { return $true }
    }
    return $false
}
