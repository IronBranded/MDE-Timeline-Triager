function Get-MDEReportProcessTree {
    <#
    .SYNOPSIS
        Merges the ProcessLineageChain of every report record into one tree for the D3 process-tree view.
    .DESCRIPTION
        Each report record (ConvertTo-MDEReportFindingRecord) carries its own linear
        root-to-subject chain. Multiple findings sharing an ancestor -- the common case, since
        one host's chain of activity typically shares a parent process somewhere -- need
        those shared ancestors merged into a single tree rather than rendered as several
        disconnected, duplicate chains. Merging is keyed on each chain node's Id|CreationTime
        Key (not display name/PID alone), the same PID-reuse-safe identity used throughout
        Private/Lineage/. Real Windows process activity is usually a forest (several
        independent root processes, e.g. one per logon session or service), so this returns
        a single synthetic root whose children are every distinct top-level ancestor
        observed, ready for d3.hierarchy() on the client side.
    .PARAMETER Records
        The report records (typically the report's *display* set, not necessarily every
        finding if -ReportSizeThreshold capped it) to merge. Mandatory.
    .OUTPUTS
        PSCustomObject -- {Name, ProcessId, Severity, RuleIds, Children[]}, recursively.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$Records
    )

    $severityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Informational = 0 }
    $nodesByKey = @{}
    $rootKeys = [System.Collections.Generic.List[string]]::new()

    foreach ($record in $Records) {
        $chain = $record.ProcessLineageChain
        if (-not $chain -or $chain.Count -eq 0) { continue }

        for ($i = 0; $i -lt $chain.Count; $i++) {
            $node = $chain[$i]
            if (-not $nodesByKey.ContainsKey($node.Key)) {
                $nodesByKey[$node.Key] = [PSCustomObject]@{
                    Key            = $node.Key
                    Name           = $node.FileName
                    ProcessId      = $node.ProcessId
                    SeverityRank   = -1
                    Severity       = $null
                    FindingRuleIds = [System.Collections.Generic.List[string]]::new()
                    ChildKeys      = [System.Collections.Generic.List[string]]::new()
                }
                if ($i -eq 0) { $rootKeys.Add($node.Key) }
            }
            if ($i -gt 0) {
                $parentKey = $chain[$i - 1].Key
                if (-not $nodesByKey[$parentKey].ChildKeys.Contains($node.Key)) {
                    $nodesByKey[$parentKey].ChildKeys.Add($node.Key)
                }
            }
            if ($i -eq ($chain.Count - 1)) {
                $rank = $severityRank[[string]$record.CombinedSeverity]
                if ($rank -gt $nodesByKey[$node.Key].SeverityRank) {
                    $nodesByKey[$node.Key].SeverityRank = $rank
                    $nodesByKey[$node.Key].Severity = $record.CombinedSeverity
                }
                if (-not $nodesByKey[$node.Key].FindingRuleIds.Contains($record.RuleId)) {
                    $nodesByKey[$node.Key].FindingRuleIds.Add($record.RuleId)
                }
            }
        }
    }

    function local:ConvertToHierarchyNode {
        param([string]$Key)
        $n = $nodesByKey[$Key]
        return [PSCustomObject]@{
            Name      = $n.Name
            ProcessId = $n.ProcessId
            Severity  = $(if ($n.Severity) { $n.Severity } else { 'Informational' })
            RuleIds   = @($n.FindingRuleIds)
            Children  = @($n.ChildKeys | ForEach-Object { ConvertToHierarchyNode -Key $_ })
        }
    }

    $rootChildren = @($rootKeys | Select-Object -Unique | ForEach-Object { ConvertToHierarchyNode -Key $_ })

    return [PSCustomObject]@{
        Name      = 'Observed Process Roots'
        ProcessId = ''
        Severity  = 'Informational'
        RuleIds   = @()
        Children  = $rootChildren
    }
}
