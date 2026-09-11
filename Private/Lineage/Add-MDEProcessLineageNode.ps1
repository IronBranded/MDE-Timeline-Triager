function Add-MDEProcessLineageNode {
    <#
    .SYNOPSIS
        Adds or backfills a process identity node in a lineage index's Nodes hashtable.
    .DESCRIPTION
        If -Key is not yet present in -Nodes, adds it. If it IS present but its FileName is
        still empty and a non-empty -FileName is now available, backfills it -- a process is
        often first observed only as an InitiatingProcessParent (a role several tables don't
        record a FileName for) before being seen with full identity elsewhere in the export;
        this lets a later, richer observation fill in an earlier, sparser one, without ever
        overwriting a FileName already trusted from a prior observation.

        Stores each node as a plain hashtable, not a [PSCustomObject]. This matters at real
        scale: PSCustomObject carries substantial per-instance overhead (the full PSObject/
        extended-type-system wrapper), and this index can genuinely reach hundreds of
        thousands to millions of entries for a busy host's full export -- confirmed directly
        by an OOM kill during a 1-million-distinct-process synthetic test before this fix;
        see CHANGELOG.md. A plain hashtable carries none of that dynamic-member machinery
        this use case never needed in the first place. Access with bracket notation
        ($node['FileName']), not dot notation -- unlike PSCustomObject, a plain hashtable
        does not support property-style dot access.
    .PARAMETER Nodes
        The Nodes hashtable to mutate in place. Mandatory.
    .PARAMETER Key
        The Id|CreationTime composite key. Mandatory; a null/empty key is silently ignored so
        callers don't need to pre-check before calling.
    .PARAMETER Id
        The process ID. Mandatory.
    .PARAMETER CreationTime
        The process creation timestamp, as the row's own string representation (not parsed
        here -- this index only needs it as a stable, comparable identity component, not a
        real datetime). Mandatory; may be empty if a row didn't record one.
    .PARAMETER FileName
        The process's file name, if known. Optional.
    .PARAMETER FolderPath
        The process's folder path, if known. Optional.
    .OUTPUTS
        None. Mutates -Nodes in place.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Nodes,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$CreationTime,

        [Parameter()]
        [AllowNull()]
        [string]$FileName,

        [Parameter()]
        [AllowNull()]
        [string]$FolderPath
    )

    if ([string]::IsNullOrEmpty($Key)) { return }

    if (-not $Nodes.ContainsKey($Key)) {
        $Nodes[$Key] = @{
            ProcessId    = $Id
            CreationTime = $CreationTime
            FileName     = $FileName
            FolderPath   = $FolderPath
        }
        return
    }

    if ([string]::IsNullOrEmpty($Nodes[$Key]['FileName']) -and -not [string]::IsNullOrEmpty($FileName)) {
        $Nodes[$Key]['FileName'] = $FileName
        $Nodes[$Key]['FolderPath'] = $FolderPath
    }
}
