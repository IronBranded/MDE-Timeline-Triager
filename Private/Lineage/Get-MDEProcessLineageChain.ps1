function Get-MDEProcessLineageChain {
    <#
    .SYNOPSIS
        Walks a process lineage index upward from a given process key and returns the chain root-first.
    .DESCRIPTION
        Starting from -StartKey, follows the index's Edges lookup (child -> parent) upward
        until no further parent is known or -MaxHops is reached, then returns the resulting
        chain ordered from the oldest reconstructed ancestor down to -StartKey itself --
        requirement #7's "visually grouping related events," in data form (rendering the
        grouping is New-MDEReport's job, build Phase 6). The hop limit exists because a
        malformed export could in principle contain a cyclic edge (a process erroneously
        listed as its own ancestor); a Add()-into-a-HashSet cycle check stops walking the
        instant a key is revisited, and MaxHops is a second, independent bound regardless of
        the data's shape.
    .PARAMETER Index
        The lineage index from New-MDEProcessLineageIndex / Update-MDEProcessLineageIndex.
        Mandatory.
    .PARAMETER StartKey
        The Id|CreationTime key to start from -- typically a finding's own subject process
        key (Get-MDERowSubjectProcessKey). Mandatory.
    .PARAMETER MaxHops
        Maximum number of parent hops to walk before stopping. Optional, default 10 (real
        Windows process trees rarely exceed 6-8 generations).
    .OUTPUTS
        [hashtable[]] -- ordered root-first, ending with the process at -StartKey. Empty
        array if -StartKey is not a known node in the index (e.g. the row had no usable
        process-identity columns at all). Each element is a plain hashtable
        ({ProcessId, CreationTime, FileName, FolderPath}), not a [PSCustomObject] -- see
        Add-MDEProcessLineageNode's .DESCRIPTION for why; access with bracket notation.
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Index,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$StartKey,

        [Parameter()]
        [ValidateRange(1, 100)]
        [int]$MaxHops = 10
    )

    if ([string]::IsNullOrEmpty($StartKey) -or -not $Index.Nodes.ContainsKey($StartKey)) {
        return , @()
    }

    $chain = [System.Collections.Generic.List[hashtable]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $currentKey = $StartKey
    $hops = 0

    while ($currentKey -and $Index.Nodes.ContainsKey($currentKey) -and $hops -le $MaxHops) {
        if (-not $visited.Add($currentKey)) {
            break
        }
        $chain.Insert(0, $Index.Nodes[$currentKey])
        $currentKey = if ($Index.Edges.ContainsKey($currentKey)) { $Index.Edges[$currentKey] } else { $null }
        $hops++
    }

    return , $chain.ToArray()
}
