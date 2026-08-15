function Get-MDERowSubjectProcessKey {
    <#
    .SYNOPSIS
        Returns the process-identity key (Id|CreationTime) that a parsed row is "about".
    .DESCRIPTION
        For a DeviceProcessEvents row, the row's subject is the newly created process
        (ProcessId + ProcessCreationTime). For a row from any other table, there is no new
        process -- the row's subject is the process that performed the recorded action, i.e.
        InitiatingProcessId + InitiatingProcessCreationTime. This is also the key used to
        group findings for requirement #5's multi-signal combination: findings sharing a
        subject key are, by definition, multiple things observed about the very same process.
    .PARAMETER Row
        The parsed timeline row. Mandatory.
    .OUTPUTS
        System.String, or $null if the row carries no usable process-identity columns (e.g.
        a DeviceLogonEvents row with no initiating process recorded).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Row
    )

    if ($Row.SourceTable -eq 'DeviceProcessEvents' -and $Row.PSObject.Properties['ProcessId'] -and $Row.ProcessId) {
        $creationTime = if ($Row.PSObject.Properties['ProcessCreationTime']) { $Row.ProcessCreationTime } else { '' }
        return "$($Row.ProcessId)|$creationTime"
    }
    if ($Row.PSObject.Properties['InitiatingProcessId'] -and $Row.InitiatingProcessId) {
        $creationTime = if ($Row.PSObject.Properties['InitiatingProcessCreationTime']) { $Row.InitiatingProcessCreationTime } else { '' }
        return "$($Row.InitiatingProcessId)|$creationTime"
    }
    return $null
}
