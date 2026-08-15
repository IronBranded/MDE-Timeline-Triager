function Update-MDEProcessLineageIndex {
    <#
    .SYNOPSIS
        Updates a process lineage index with the parent-child edge(s) observable on one row.
    .DESCRIPTION
        Called once per row during Invoke-MDEDetection's streaming pass (requirement #7:
        "linking InitiatingProcessId and InitiatingProcessFileName to child execution
        telemetry"). Extracts up to two edges per row:
          - InitiatingProcessParent -> InitiatingProcess: present on every table that records
            an initiating process, since every table carries InitiatingProcessParentId/
            FileName alongside InitiatingProcessId/FileName.
          - InitiatingProcess -> the newly created process: only DeviceProcessEvents rows
            describe an actual new process being born; other tables' InitiatingProcess is
            performing an action (network connection, file write, etc.), not spawning a
            child process.
        Process identity uses a composite Id|CreationTime key rather than PID alone, because
        Windows reuses PIDs over time -- two unrelated processes that happen to share a PID
        at different points in a multi-day export must not be merged into one lineage node.
    .PARAMETER Index
        The lineage index (from New-MDEProcessLineageIndex) to update in place. Mandatory.
    .PARAMETER Row
        The single parsed timeline row to extract lineage info from. Mandatory.
    .OUTPUTS
        None. Mutates -Index's Nodes/Edges hashtables in place.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Index,

        [Parameter(Mandatory = $true)]
        [PSObject]$Row
    )

    if ($Row.PSObject.Properties['InitiatingProcessId'] -and $Row.InitiatingProcessId) {
        $initiatingCreationTime = if ($Row.PSObject.Properties['InitiatingProcessCreationTime']) { $Row.InitiatingProcessCreationTime } else { '' }
        $childKey = "$($Row.InitiatingProcessId)|$initiatingCreationTime"

        Add-MDEProcessLineageNode -Nodes $Index.Nodes -Key $childKey -Id $Row.InitiatingProcessId -CreationTime $initiatingCreationTime `
            -FileName $(if ($Row.PSObject.Properties['InitiatingProcessFileName']) { $Row.InitiatingProcessFileName } else { $null }) `
            -FolderPath $(if ($Row.PSObject.Properties['InitiatingProcessFolderPath']) { $Row.InitiatingProcessFolderPath } else { $null })

        if ($Row.PSObject.Properties['InitiatingProcessParentId'] -and $Row.InitiatingProcessParentId) {
            $parentCreationTime = if ($Row.PSObject.Properties['InitiatingProcessParentCreationTime']) { $Row.InitiatingProcessParentCreationTime } else { '' }
            $parentKey = "$($Row.InitiatingProcessParentId)|$parentCreationTime"

            Add-MDEProcessLineageNode -Nodes $Index.Nodes -Key $parentKey -Id $Row.InitiatingProcessParentId -CreationTime $parentCreationTime `
                -FileName $(if ($Row.PSObject.Properties['InitiatingProcessParentFileName']) { $Row.InitiatingProcessParentFileName } else { $null }) `
                -FolderPath $null

            if (-not $Index.Edges.ContainsKey($childKey)) {
                $Index.Edges[$childKey] = $parentKey
            }
        }
    }

    if ($Row.SourceTable -eq 'DeviceProcessEvents' -and $Row.PSObject.Properties['ProcessId'] -and $Row.ProcessId) {
        $newCreationTime = if ($Row.PSObject.Properties['ProcessCreationTime']) { $Row.ProcessCreationTime } else { '' }
        $newKey = "$($Row.ProcessId)|$newCreationTime"

        Add-MDEProcessLineageNode -Nodes $Index.Nodes -Key $newKey -Id $Row.ProcessId -CreationTime $newCreationTime `
            -FileName $(if ($Row.PSObject.Properties['FileName']) { $Row.FileName } else { $null }) `
            -FolderPath $(if ($Row.PSObject.Properties['FolderPath']) { $Row.FolderPath } else { $null })

        if ($Row.PSObject.Properties['InitiatingProcessId'] -and $Row.InitiatingProcessId) {
            $initiatingCreationTime = if ($Row.PSObject.Properties['InitiatingProcessCreationTime']) { $Row.InitiatingProcessCreationTime } else { '' }
            $parentKey = "$($Row.InitiatingProcessId)|$initiatingCreationTime"
            if (-not $Index.Edges.ContainsKey($newKey)) {
                $Index.Edges[$newKey] = $parentKey
            }
        }
    }
}
