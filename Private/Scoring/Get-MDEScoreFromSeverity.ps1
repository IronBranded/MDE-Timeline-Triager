function Get-MDEScoreFromSeverity {
    <#
    .SYNOPSIS
        Maps a Severity tier to a representative 0-100 score (the midpoint of that tier's range).
    .DESCRIPTION
        The inverse of Get-MDESeverityFromScore. Needed when a Score is required but only a
        Severity is available -- specifically for custom IOC findings (build Phase 4), where
        an analyst specifies Severity directly in a custom IOC config entry rather than
        supplying a numeric score. Uses the midpoint of each tier's range from
        Get-MDESeverityFromScore's rubric: Critical -> 92, High -> 75, Medium -> 50, Low ->
        25, Informational -> 7.
    .PARAMETER Severity
        One of Critical, High, Medium, Low, Informational. Mandatory.
    .OUTPUTS
        System.Int32
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity
    )

    switch ($Severity) {
        'Critical' { return 92 }
        'High' { return 75 }
        'Medium' { return 50 }
        'Low' { return 25 }
        'Informational' { return 7 }
    }
}
