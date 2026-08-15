function Get-MDETelemetryMapping {
    <#
    .SYNOPSIS
        Looks up the standard Windows Event ID / Sysmon Event ID equivalent for a (SourceTable, ActionType) pair.
    .DESCRIPTION
        Requirement #2: correlation between MDE ActionType values, standard Windows Event
        IDs, and Sysmon events, so an analyst working across MDE telemetry and another log
        source (the Windows Security log, a Sysmon-instrumented host, a SIEM ingesting both)
        can see immediately which native event a given MDE row corresponds to.

        Takes the already-loaded mapping data (from Data/TelemetryMapping.json) rather than
        reading the file itself, so callers that need a lookup per-finding (New-MDEFinding,
        called once per finding by Invoke-MDEDetection) load the file once and reuse it,
        rather than re-reading it from disk on every call -- the same pattern this module
        uses for Data/DetectionCatalog.json in Invoke-MDEDetection's begin{} block.

        A (SourceTable, ActionType) pair not present in the mapping returns an object with
        all-null fields rather than throwing, since the mapping is deliberately scoped to
        well-established, verified correlations (see Data/TelemetryMapping.json's own header
        note) rather than attempting to enumerate every ActionType MDE can emit.
    .PARAMETER MappingData
        The already-loaded (ConvertFrom-Json'd) contents of Data/TelemetryMapping.json.
        Mandatory.
    .PARAMETER SourceTable
        The row's SourceTable (as set by Import-MDETimeline). Mandatory.
    .PARAMETER ActionType
        The row's ActionType value. Mandatory; may be empty.
    .OUTPUTS
        PSCustomObject -- {WindowsEventId, WindowsEventName, SysmonEventId, SysmonEventName},
        all $null if no mapping is known for this pair.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$MappingData,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$SourceTable,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ActionType
    )

    $empty = [PSCustomObject]@{
        WindowsEventId   = $null
        WindowsEventName = $null
        SysmonEventId    = $null
        SysmonEventName  = $null
    }

    if ([string]::IsNullOrEmpty($SourceTable) -or [string]::IsNullOrEmpty($ActionType)) { return $empty }
    if (-not $MappingData.Mappings.PSObject.Properties[$SourceTable]) { return $empty }

    $tableMap = $MappingData.Mappings.$SourceTable
    if (-not $tableMap.PSObject.Properties[$ActionType]) { return $empty }

    return $tableMap.$ActionType
}
