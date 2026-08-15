function New-MDEProcessLineageIndex {
    <#
    .SYNOPSIS
        Creates an empty process lineage index for Update-MDEProcessLineageIndex to populate.
    .DESCRIPTION
        The index is two hashtables: Nodes (process identity key -> {ProcessId,
        CreationTime, FileName, FolderPath}) and Edges (child key -> parent key). Built
        incrementally, one row at a time, by Update-MDEProcessLineageIndex during
        Invoke-MDEDetection's streaming pass, so the module never needs to hold a full row
        buffer in memory just to reconstruct lineage -- only this compact index, which scales
        with the number of distinct processes observed rather than the number of rows/events.
    .OUTPUTS
        PSCustomObject exposing Nodes (hashtable) and Edges (hashtable), both empty.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    return [PSCustomObject]@{
        Nodes = @{}
        Edges = @{}
    }
}
