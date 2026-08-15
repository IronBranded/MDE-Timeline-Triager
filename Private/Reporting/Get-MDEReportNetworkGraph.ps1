function Get-MDEReportNetworkGraph {
    <#
    .SYNOPSIS
        Builds a nodes/edges structure for the D3 network graph view from network- and logon-relevant report records.
    .DESCRIPTION
        Surfaces lateral-movement-relevant correlation: an edge is drawn between the host
        device and whatever remote endpoint a DeviceNetworkEvents or DeviceLogonEvents
        finding references (RemoteDeviceName preferred when present, else RemoteIP). Nodes
        are deduplicated by display value; a node's Severity is the highest CombinedSeverity
        of any finding that touched it, used for node color on the client side.
    .PARAMETER Records
        The report records to build the graph from. Mandatory.
    .OUTPUTS
        PSCustomObject -- {Nodes: [{Id, Type, Severity}], Edges: [{Source, Target, RuleId}]}.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$Records
    )

    $severityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Informational = 0 }
    $nodes = @{}
    $edges = [System.Collections.Generic.List[PSCustomObject]]::new()

    function local:EnsureNode {
        param([string]$Id, [string]$Type, [string]$Severity)
        if ([string]::IsNullOrEmpty($Id)) { return }
        if (-not $nodes.ContainsKey($Id)) {
            $nodes[$Id] = [PSCustomObject]@{ Id = $Id; Type = $Type; SeverityRank = -1; Severity = $null }
        }
        $rank = $severityRank[$Severity]
        if ($rank -gt $nodes[$Id].SeverityRank) {
            $nodes[$Id].SeverityRank = $rank
            $nodes[$Id].Severity = $Severity
        }
    }

    foreach ($record in $Records) {
        if ($record.SourceTable -notin @('DeviceNetworkEvents', 'DeviceLogonEvents')) { continue }

        $hostId = if ($record.DeviceName) { $record.DeviceName } else { '(unknown host)' }
        EnsureNode -Id $hostId -Type 'Host' -Severity $record.CombinedSeverity

        $remoteId = if ($record.RemoteDeviceName) { $record.RemoteDeviceName }
        elseif ($record.RemoteIP) { $record.RemoteIP }
        else { $null }

        if ($remoteId) {
            EnsureNode -Id $remoteId -Type 'Remote' -Severity $record.CombinedSeverity
            $edges.Add([PSCustomObject]@{
                    Source = $hostId
                    Target = $remoteId
                    RuleId = $record.RuleId
                })
        }
    }

    return [PSCustomObject]@{
        Nodes = @($nodes.Values)
        Edges = @($edges)
    }
}
