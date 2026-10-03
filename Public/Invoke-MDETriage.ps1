function Invoke-MDETriage {
    <#
    .SYNOPSIS
        Runs the full MDE timeline triage pipeline -- parse, detect, score, correlate, and report -- in one call.

    .DESCRIPTION
        Invoke-MDETriage is the primary entry point for typical use: a thin orchestrator that
        composes Import-MDETimeline, Invoke-MDEDetection, and New-MDEReport with sensible
        defaults, so a single call takes a source CSV straight through to a rendered HTML
        report and enriched CSV. The three stages remain independently usable and testable
        (see Import-MDETimeline, Invoke-MDEDetection, New-MDEReport) -- Invoke-MDETriage
        exists for the common case where an analyst just wants the end-to-end result.

        Because this cmdlet's execution ultimately writes the HTML report and enriched CSV to
        disk (via New-MDEReport internally), it implements SupportsShouldProcess itself, in
        addition to the two cmdlets it wraps: under -WhatIf, no files are written; -Confirm
        prompts before overwriting an existing report. This was not explicitly required by
        the cmdlet surface spec (which names only Invoke-MDEDetection and New-MDEReport) but
        is added here for consistency -- the one-call convenience wrapper should offer the
        same dry-run safety as the stages it composes, at no UX cost to normal use.

        Under -WhatIf, the ENTIRE pipeline is skipped -- Import-MDETimeline never runs, so
        the source file is never even parsed -- rather than partially running the pipeline to
        produce a more detailed What-if message. This keeps -WhatIf's cost proportionate to
        what it reports (a one-line summary of what would be written) and matches
        New-MDEReport's own -WhatIf behavior, which this cmdlet's help text has always
        described as what it mirrors.

    .PARAMETER Path
        Path to the single MDE timeline CSV export to process. Mandatory.

    .PARAMETER OutputPath
        Directory to write the HTML report and enriched CSV into. Optional. Created if it
        does not already exist. When omitted, resolves to the current user's Downloads
        folder (cross-platform) and automatically switches on -DatedFileNames -- see
        New-MDEReport's help for the full behavior, since this parameter is passed straight
        through.
    .PARAMETER DatedFileNames
        Switch. Names the two output files `MDETT-<yyyy-MM-dd>-Report.html` /
        `MDETT-<yyyy-MM-dd>-Findings.csv` instead of the fixed traditional names.
        Automatically turned on when -OutputPath is omitted. See New-MDEReport's help.
    .PARAMETER ExportAttackNavigatorLayer
        Switch. Also writes a standalone MITRE ATT&CK Navigator v4.5 layer JSON file
        alongside the HTML/CSV, passed straight through to New-MDEReport -- see its help for
        the full behavior. Optional, default $false.

    .PARAMETER BaselineConfigPath
        Path to a JSON baseline/exclusion config file. Optional; passed through to
        Invoke-MDEDetection. If omitted, no baseline suppression is applied.

    .PARAMETER CustomIOCConfigPath
        Path to a JSON/YAML custom IOC/keyword config file. Optional; passed through to
        Invoke-MDEDetection. If omitted, only the built-in detection catalog runs.

    .PARAMETER Redact
        Switch. Passed through to New-MDEReport to mask usernames/hostnames in the HTML
        report. Default: off.

    .PARAMETER LocalTime
        Switch. Passed through to New-MDEReport to additionally render local time alongside
        UTC. Default: off (UTC only).

    .PARAMETER ReportSizeThreshold
        Integer. Passed through to New-MDEReport. Default: 5000.

    .EXAMPLE
        Invoke-MDETriage -Path .\host01-timeline.csv -OutputPath .\out

        End-to-end run with default settings: parse, detect against the full built-in
        catalog, and render an unredacted, UTC-only report.

    .EXAMPLE
        Invoke-MDETriage -Path .\host01-timeline.csv -OutputPath .\out -BaselineConfigPath .\config\baseline.json -CustomIOCConfigPath .\config\case-2026-041-iocs.json -Redact -LocalTime

        End-to-end run with baseline noise suppression, case-specific custom IOCs, redacted
        output, and both UTC and local time displayed.

    .INPUTS
        None. This cmdlet does not accept pipeline input; it reads directly from -Path.

    .OUTPUTS
        None. Writes an HTML file and a CSV file to -OutputPath; does not return objects to
        the pipeline. Use Import-MDETimeline / Invoke-MDEDetection / New-MDEReport directly
        if you need the intermediate objects.

    .NOTES
        SupportsShouldProcess: mirrors New-MDEReport's -WhatIf/-Confirm behavior for the
        files this cmdlet ultimately writes; under -WhatIf the whole pipeline is skipped,
        including parsing -Path.

        Read-only guarantee: -Path is never modified.

        Build status: real as of this release. Composes Import-MDETimeline,
        Invoke-MDEDetection, and New-MDEReport directly -- see those cmdlets for the
        behavior each stage contributes.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Leaf)) {
                    throw "Path '$_' does not exist or is not a file."
                }
                $true
            })]
        [string]
        $Path,

        [Parameter()]
        [string]
        $OutputPath,

        [Parameter()]
        [switch]
        $DatedFileNames,

        [Parameter()]
        [string]
        $BaselineConfigPath,

        [Parameter()]
        [string]
        $CustomIOCConfigPath,

        [Parameter()]
        [switch]
        $Redact,

        [Parameter()]
        [switch]
        $LocalTime,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]
        $ReportSizeThreshold = 5000,

        [Parameter()]
        [switch]
        $ExportAttackNavigatorLayer
    )

    $baselineNote = if ($BaselineConfigPath) { $BaselineConfigPath } else { '<none>' }
    $customIocNote = if ($CustomIOCConfigPath) { $CustomIOCConfigPath } else { '<none>' }
    $configNote = " (baseline: $baselineNote; custom IOC: $customIocNote; redact: $($Redact.IsPresent); local time: $($LocalTime.IsPresent); size threshold: $ReportSizeThreshold)"
    $destinationNote = if ([string]::IsNullOrWhiteSpace($OutputPath)) { 'your Downloads folder (MDETT-dated file names, -OutputPath not supplied)' } else { $OutputPath }

    if ($PSCmdlet.ShouldProcess($Path, "Run full MDE triage pipeline and write report to '$destinationNote'$configNote")) {
        $detectionParams = @{}
        if ($BaselineConfigPath) { $detectionParams['BaselineConfigPath'] = $BaselineConfigPath }
        if ($CustomIOCConfigPath) { $detectionParams['CustomIOCConfigPath'] = $CustomIOCConfigPath }

        $reportParams = @{
            SourcePath          = $Path
            ReportSizeThreshold = $ReportSizeThreshold
        }
        if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $reportParams['OutputPath'] = $OutputPath }
        if ($DatedFileNames) { $reportParams['DatedFileNames'] = $true }
        if ($Redact) { $reportParams['Redact'] = $true }
        if ($LocalTime) { $reportParams['LocalTime'] = $true }
        if ($ExportAttackNavigatorLayer) { $reportParams['ExportAttackNavigatorLayer'] = $true }

        Import-MDETimeline -Path $Path | Invoke-MDEDetection @detectionParams | New-MDEReport @reportParams
    }
}
