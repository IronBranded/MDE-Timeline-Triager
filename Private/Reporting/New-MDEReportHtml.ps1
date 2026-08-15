function New-MDEReportHtml {
    <#
    .SYNOPSIS
        Assembles the complete self-contained HTML report from finding objects and manifest info.
    .DESCRIPTION
        Reads Data/ReportTemplate.html (a static skeleton with __TOKEN__ placeholders) and
        the vendored D3/DataTables assets, computes the executive summary and the process
        tree / network graph aggregations (Get-MDEReportProcessTree /
        Get-MDEReportNetworkGraph), converts each finding to a report-safe record
        (ConvertTo-MDEReportFindingRecord -- HTML-escaped and, if requested, redacted), and
        substitutes everything into the template.

        SUBSTITUTION SAFETY: uses a single forward-only scan across the ORIGINAL template
        string, not a sequence of .Replace() calls on a progressively-mutated string.
        Sequential replacement has a subtle failure mode here specifically: if an earlier
        substitution's value (e.g. escaped finding data, which is attacker-influenced
        telemetry) happened to contain literal placeholder-token-shaped text, a LATER
        .Replace() call would match and corrupt it -- turning a robustness bug into something
        adjacent to a template-injection primitive. Scanning only ever advances forward
        through the original template and never re-examines content already written to the
        output, so this is structurally impossible regardless of what a finding's data
        contains.

        SIZE THRESHOLD (requirement #8): if the total finding count exceeds
        -ReportSizeThreshold, ALL FOUR interactive views (table, tree, network, swimlane) --
        not just the table -- render from the same capped top-N-by-CombinedScore subset,
        with a banner explaining the rest are in the enriched CSV (Export-MDEEnrichedCsv,
        which always writes the full set regardless of this cap). Executive summary counts
        are computed from the full set either way, since exact totals cost nothing to
        compute and matter even when the interactive views are capped.
    .PARAMETER Findings
        The full finding set (Finding objects, from Invoke-MDEDetection). Mandatory.
    .PARAMETER SourcePath
        Path to the original source CSV, for the report header. Mandatory.
    .PARAMETER SourceHash
        SHA-256 hash of the source CSV (requirement #15). Mandatory.
    .PARAMETER ProcessingTimestampUtc
        UTC processing timestamp string, for the report header. Mandatory.
    .PARAMETER ModuleVersion
        This module's version, for the report header/footer. Mandatory.
    .PARAMETER Redact
        Switch. Applies username/hostname pseudonymization throughout. Optional.
    .PARAMETER LocalTime
        Switch. Adds a separately-labeled local-time value alongside UTC. Optional.
    .PARAMETER ReportSizeThreshold
        Row count above which the interactive views summarize to the top-N by score.
        Optional, default 5000.
    .PARAMETER RunSummary
        The 'MDETimelineTriage.RunSummary'-tagged object from the end of
        Invoke-MDEDetection's output stream, used to build the executive summary's incident
        overview (export timeframe, first-activity/first-response goalposts, alert-linked
        events, exclusions applied). Optional -- $null renders a minimal fallback notice
        instead of the full overview, so a report built by hand from bare finding objects
        (bypassing Invoke-MDEDetection) doesn't throw.
    .OUTPUTS
        System.String -- the complete, self-contained HTML document.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [PSObject[]]$Findings,

        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$SourceHash,

        [Parameter(Mandatory = $true)]
        [string]$ProcessingTimestampUtc,

        [Parameter(Mandatory = $true)]
        [string]$ModuleVersion,

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [switch]$LocalTime,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ReportSizeThreshold = 5000,

        [Parameter()]
        [AllowNull()]
        [PSObject]$RunSummary
    )

    $moduleRoot = Get-MDEModuleRoot
    $template = Get-Content -Path (Join-Path -Path $moduleRoot -ChildPath 'Data/ReportTemplate.html') -Raw
    $d3Js = Get-Content -Path (Join-Path -Path $moduleRoot -ChildPath 'Data/Vendor/d3.min.js') -Raw
    $dataTablesJs = Get-Content -Path (Join-Path -Path $moduleRoot -ChildPath 'Data/Vendor/dataTables.min.js') -Raw
    $dataTablesCss = Get-Content -Path (Join-Path -Path $moduleRoot -ChildPath 'Data/Vendor/dataTables.min.css') -Raw

    $totalCount = $Findings.Count
    $sizeThresholdApplied = $totalCount -gt $ReportSizeThreshold

    $displayFindings = if ($sizeThresholdApplied) {
        @($Findings | Sort-Object -Property CombinedScore -Descending | Select-Object -First $ReportSizeThreshold)
    }
    else {
        @($Findings)
    }

    $redactionMap = @{}
    $records = @($displayFindings | ForEach-Object {
            ConvertTo-MDEReportFindingRecord -Finding $_ -Redact:$Redact -RedactionMap $redactionMap -LocalTime:$LocalTime
        })

    $treeData = Get-MDEReportProcessTree -Records $records
    $networkData = Get-MDEReportNetworkGraph -Records $records

    $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Informational')
    $severityCounts = [ordered]@{}
    foreach ($sev in $severityOrder) {
        $severityCounts[$sev] = @($Findings | Where-Object { $_.CombinedSeverity -eq $sev }).Count
    }

    $summaryCardsHtml = "<div class='summary-card'><div class='count'>$totalCount</div><div class='label'>Total Findings</div></div>`n"
    $summaryCardsHtml += (($severityOrder | ForEach-Object {
                $cls = "sev-$($_.ToLowerInvariant())"
                "<div class='summary-card'><div class='count $cls'>$($severityCounts[$_])</div><div class='label'>$_</div></div>"
            }) -join "`n")

    $redactionBanner = if ($Redact) {
        "<div class='notice-banner notice-info'>This report has redaction enabled: usernames and hostnames are shown as consistent placeholders (USER-1, HOST-1, ...) rather than their real values.</div>"
    }
    else { '' }

    $sizeThresholdBanner = if ($sizeThresholdApplied) {
        "<div class='notice-banner notice-warn'>This run produced $totalCount findings, exceeding the configured display threshold of $ReportSizeThreshold. The interactive views below show the top $ReportSizeThreshold findings by combined score; the complete set of $totalCount findings is in the enriched CSV output.</div>"
    }
    else { '' }

    $localTimeNote = if ($LocalTime) {
        " Local-time values use this rendering machine's local timezone, shown as a separately labeled value/column next to the UTC one."
    }
    else { '' }

    $incidentOverviewHtml = Get-MDEIncidentOverviewHtml -RunSummary $RunSummary -LocalTime:$LocalTime

    $reportMeta = [PSCustomObject]@{
        hasLocalTime           = [bool]$LocalTime
        redacted                = [bool]$Redact
        sizeThresholdApplied    = $sizeThresholdApplied
        totalFindingCount       = $totalCount
        displayedFindingCount   = $records.Count
    }

    $findingCountSummary = if ($sizeThresholdApplied) {
        "$totalCount total ($($records.Count) shown in interactive views; full set in CSV)"
    }
    else {
        "$totalCount"
    }

    $replacements = [ordered]@{
        '__REPORT_TITLE__'          = ConvertTo-MDEHtmlEncodedString -Value "MDE Timeline Triage - $(Split-Path -Path $SourcePath -Leaf)"
        '__DATATABLES_CSS__'        = $dataTablesCss
        '__SOURCE_PATH__'           = ConvertTo-MDEHtmlEncodedString -Value $SourcePath
        '__SOURCE_HASH__'           = ConvertTo-MDEHtmlEncodedString -Value $SourceHash
        '__PROCESSING_TIMESTAMP__'  = ConvertTo-MDEHtmlEncodedString -Value $ProcessingTimestampUtc
        '__MODULE_VERSION__'        = ConvertTo-MDEHtmlEncodedString -Value $ModuleVersion
        '__FINDING_COUNT_SUMMARY__' = ConvertTo-MDEHtmlEncodedString -Value $findingCountSummary
        '__REDACTION_BANNER__'      = $redactionBanner
        '__SIZE_THRESHOLD_BANNER__' = $sizeThresholdBanner
        '__INCIDENT_OVERVIEW__'     = $incidentOverviewHtml
        '__SUMMARY_CARDS__'         = $summaryCardsHtml
        '__LOCAL_TIME_NOTE__'       = ConvertTo-MDEHtmlEncodedString -Value $localTimeNote
        '__REPORT_META_JSON__'      = ConvertTo-MDEJsonForScriptEmbed -InputObject $reportMeta
        '__FINDINGS_JSON__'         = ConvertTo-MDEJsonForScriptEmbed -InputObject $records -ForceArray
        '__TREE_JSON__'             = ConvertTo-MDEJsonForScriptEmbed -InputObject $treeData
        '__NETWORK_JSON__'          = ConvertTo-MDEJsonForScriptEmbed -InputObject $networkData
        '__D3_JS__'                 = $d3Js
        '__DATATABLES_JS__'         = $dataTablesJs
    }

    $sb = [System.Text.StringBuilder]::new($template.Length + 500000)
    $pos = 0
    while ($true) {
        $nextIndex = -1
        $nextToken = $null
        foreach ($token in $replacements.Keys) {
            $idx = $template.IndexOf($token, $pos, [System.StringComparison]::Ordinal)
            if ($idx -ge 0 -and ($nextIndex -eq -1 -or $idx -lt $nextIndex)) {
                $nextIndex = $idx
                $nextToken = $token
            }
        }
        if ($nextIndex -eq -1) {
            [void]$sb.Append($template.Substring($pos))
            break
        }
        [void]$sb.Append($template.Substring($pos, $nextIndex - $pos))
        [void]$sb.Append($replacements[$nextToken])
        $pos = $nextIndex + $nextToken.Length
    }

    return $sb.ToString()
}
