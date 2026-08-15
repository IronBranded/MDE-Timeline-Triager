function Export-MDEEnrichedCsv {
    <#
    .SYNOPSIS
        Writes the full finding set to an enriched CSV optimized for Eric Zimmerman's Timeline Explorer.
    .DESCRIPTION
        Unlike the HTML report's interactive views (which may be capped by
        -ReportSizeThreshold for browser performance -- see New-MDEReportHtml), this always
        writes every finding: the full flagged set, per requirement #8's report-size
        guidance ("push the full flagged set to the enriched CSV output"). Column order is
        deliberately Timeline-Explorer-friendly: Timestamp first (an ISO-8601 UTC string,
        directly sortable), followed by the severity/confidence/tactic fields analysts triage
        on, then supporting detail columns, then chain-of-custody columns (requirement #15's
        source hash/path/processing timestamp) repeated on every row -- redundant, but it
        means a single extracted/copied row still carries its own provenance.

        Field values are NOT HTML-escaped here (this is a CSV a human or Timeline Explorer
        reads directly -- an HTML-escaped '&amp;' would be actively wrong/confusing) but ARE
        guarded against CSV/formula injection via Protect-MDECsvFormulaInjection, and are
        quoted per RFC 4180 via ConvertTo-MDECsvField -- both hand-rolled rather than using
        Export-Csv, whose default -Encoding differs subtly between Windows PowerShell 5.1
        (UTF-8 WITH BOM under -Encoding UTF8) and PowerShell 7+ (UTF-8 WITHOUT BOM under the
        same parameter value). Writing bytes directly via
        [System.Text.UTF8Encoding]::new($false) guarantees identical output on both runtimes,
        consistent with this module's Phase 2 stance on hand-rolled CSV I/O for exactly this
        kind of cross-runtime divergence.
    .PARAMETER Findings
        The full finding set (Finding objects, not pre-escaped report records -- this
        function does its own CSV-appropriate value handling). Mandatory.
    .PARAMETER Path
        Output CSV file path. Mandatory.
    .PARAMETER SourceFileHash
        The source CSV's SHA-256 hash (requirement #15), written on every row. Mandatory.
    .PARAMETER SourceFilePath
        The source CSV's full path, written on every row. Mandatory.
    .PARAMETER ProcessingTimestampUtc
        The UTC processing timestamp (ISO-8601 string), written on every row. Mandatory.
    .OUTPUTS
        None. Writes -Path.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$SourceFileHash,

        [Parameter(Mandatory = $true)]
        [string]$SourceFilePath,

        [Parameter(Mandatory = $true)]
        [string]$ProcessingTimestampUtc
    )

    $columns = @(
        'Timestamp', 'Severity', 'Confidence', 'CombinedSeverity', 'RuleId', 'RuleName',
        'Tactic', 'TechniqueId', 'Explanation', 'BenignExplanation', 'DeviceName',
        'FileName', 'FolderPath', 'ProcessCommandLine', 'InitiatingProcessFileName',
        'InitiatingProcessCommandLine', 'AccountName', 'AccountDomain', 'RemoteIP',
        'RemotePort', 'RemoteUrl', 'LocalIP', 'LocalPort', 'Protocol', 'RegistryKey',
        'RegistryValueName', 'RegistryValueData', 'SHA1', 'SHA256', 'MD5', 'LogonType',
        'FailureReason', 'SourceTable', 'DetectionSource', 'WindowsEventId', 'SysmonEventId',
        'Score', 'CombinedScore',
        'CoOccurringFindings', 'BaselineExclusionOverridden', 'SourceRowNumber', 'ReportId',
        'SourceFileHash', 'SourceFilePath', 'ProcessingTimestampUtc'
    )

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append(($columns -join ',')).Append("`r`n")

    foreach ($finding in $Findings) {
        $row = $finding.SourceRow

        $values = @(
            $(if ($finding.Timestamp) { $finding.Timestamp.ToString('o') } else { '' }),
            [string]$finding.Severity,
            [string]$finding.Confidence,
            [string]$finding.CombinedSeverity,
            [string]$finding.RuleId,
            [string]$finding.RuleName,
            [string]$finding.Tactic,
            (($finding.TechniqueId) -join '; '),
            [string]$finding.Explanation,
            [string]$finding.BenignExplanation,
            (Get-MDERowFieldOrEmpty -Row $row -Name 'DeviceName'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'FileName'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'FolderPath'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'ProcessCommandLine'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'InitiatingProcessFileName'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'InitiatingProcessCommandLine'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'AccountName'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'AccountDomain'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'RemoteIP'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'RemotePort'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'RemoteUrl'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'LocalIP'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'LocalPort'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'Protocol'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'RegistryKey'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'RegistryValueName'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'RegistryValueData'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'SHA1'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'SHA256'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'MD5'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'LogonType'),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'FailureReason'),
            [string]$finding.SourceTable,
            [string]$finding.DetectionSource,
            [string]$finding.WindowsEventId,
            [string]$finding.SysmonEventId,
            [string]$finding.Score,
            [string]$finding.CombinedScore,
            (($finding.CoOccurringFindings) -join '; '),
            [string]$finding.BaselineExclusionOverridden,
            $(if ($row -and $row.PSObject.Properties['SourceRowNumber']) { [string]$row.SourceRowNumber } else { '' }),
            (Get-MDERowFieldOrEmpty -Row $row -Name 'ReportId'),
            $SourceFileHash,
            $SourceFilePath,
            $ProcessingTimestampUtc
        )

        $formatted = $values | ForEach-Object {
            ConvertTo-MDECsvField -Value (Protect-MDECsvFormulaInjection -Value $_)
        }
        [void]$sb.Append(($formatted -join ',')).Append("`r`n")
    }

    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), $utf8NoBom)
}
