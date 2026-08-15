function Test-MDEAlertLikeRow {
    <#
    .SYNOPSIS
        Heuristically checks whether a parsed row appears to be alert-linked.
    .DESCRIPTION
        This module's 7 supported tables (see the module README's Scope section) are
        device-timeline tables, not MDE's separate AlertInfo/AlertEvidence/DeviceAlertEvents
        tables, which are out of scope for this build. This heuristic surfaces what CAN be
        detected from data actually present in a supported export: a non-empty AlertId-named
        column (some exports carry one even on device-timeline tables), or an ActionType
        value containing "Alert". Like Test-MDEResponseActionKeyword, this is explicitly a
        best-effort estimate over data that happens to be present, not a substitute for
        genuinely ingesting AlertInfo/AlertEvidence, which remains out of scope.
    .PARAMETER Row
        The parsed row to check. Mandatory.
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Row
    )

    foreach ($propName in @('AlertId', 'AlertIds')) {
        if ($Row.PSObject.Properties[$propName] -and -not [string]::IsNullOrWhiteSpace([string]$Row.$propName)) {
            return $true
        }
    }

    if ($Row.PSObject.Properties['ActionType'] -and [string]$Row.ActionType -like '*Alert*') {
        return $true
    }

    return $false
}
