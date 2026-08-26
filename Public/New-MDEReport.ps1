function New-MDEReport {
    <#
    .SYNOPSIS
        Renders the interactive offline HTML report and enriched CSV from scored MDE findings.

    .DESCRIPTION
        New-MDEReport is the reporting stage of the MDETimelineTriage pipeline. It accepts
        finding objects -- typically piped directly from Invoke-MDEDetection -- and writes
        two outputs to -OutputPath: a self-contained, fully offline-capable interactive HTML
        report and an enriched CSV formatted for direct ingestion into Eric Zimmerman's
        Timeline Explorer.

        THE HTML REPORT has four interactive views -- a DataTables findings table, a D3
        process-tree, a D3 force-directed network graph (lateral-movement-relevant
        correlation: host <-> remote device/IP), and a D3 time-axis swimlane -- plus an
        executive summary computed from the complete finding set. DataTables v3 and D3 v7 are
        vendored and inlined directly into the file (Data/Vendor/); nothing is loaded from a
        CDN, so the report renders correctly with zero internet access. (Mermaid was
        originally planned for the process tree per this module's design notes, but its only
        genuinely self-contained browser build is 3.5MB -- over 10x every other vendored
        asset combined -- for a diagram type D3's own hierarchy/tree layout, already vendored
        for the other two views, handles just as well; the tree is rendered with D3 instead.)

        OUTPUT SANITIZATION (requirement #8, critical): every value that reaches the report --
        command lines, file paths, process names, including values already auto-decoded by
        ConvertFrom-MDEEncodedCommand -- passes through ConvertTo-MDEReportFindingRecord
        first, which HTML-encodes every string field via .NET's own encoder before it ever
        touches markup. The JSON data embedded in the report additionally passes through
        ConvertTo-MDEJsonForScriptEmbed, which neutralizes the separate risk of a value
        containing a literal '</script' sequence breaking out of its containing script tag.
        Nothing from a parsed row or finding is ever string-concatenated into HTML or an
        inline script.

        REPORT SIZE (requirement #8): if the finding count exceeds -ReportSizeThreshold, all
        four interactive views -- not just the table -- render from the same capped top-N
        (by CombinedScore) subset, with a banner explaining the rest are in the CSV; the CSV
        always contains the complete, uncapped finding set regardless of this threshold.

        TIMEZONE (requirement #8): timestamps are UTC by default, always explicitly labeled
        as such. -LocalTime adds a separately-labeled local-time value/column next to the UTC
        one -- both are always shown labeled with their zone, never an ambiguous bare
        timestamp.

        EVIDENCE INTEGRITY (requirement #15): -SourcePath is re-hashed (SHA-256) at render
        time rather than trusting a value threaded through from ingest, which doubles as a
        check that the evidence file has not changed since it was first parsed; the hash,
        full source path, and UTC processing timestamp are recorded in both the HTML header
        and repeated on every row of the enriched CSV.

        This cmdlet implements SupportsShouldProcess because it writes files: -WhatIf reports
        which files would be written (and flags if that would overwrite an existing file)
        without writing them; -Confirm prompts before writing.

    .PARAMETER InputObject
        Finding object(s), typically piped from Invoke-MDEDetection. Mandatory, accepted
        from the pipeline by value. Invoke-MDEDetection's output also includes one object
        tagged 'MDETimelineTriage.RunSummary' as the last item in the stream -- this cmdlet
        recognizes and separates it automatically (by that PSTypeName, not by shape or
        position) to build the executive summary's incident overview; it is never treated as
        a finding or written as a row in the enriched CSV.

    .PARAMETER SourcePath
        Path to the original source MDE timeline CSV that produced these findings. Mandatory.
        Used to compute the SHA-256 hash recorded in the report header.

    .PARAMETER OutputPath
        Directory to write the HTML report and enriched CSV into. Optional. Created if it
        does not already exist. When omitted entirely, resolves to the current user's
        Downloads folder (cross-platform -- see Get-MDEDownloadsFolder) and automatically
        switches on -DatedFileNames, so a bare `New-MDEReport` with no path/naming details
        supplied still lands somewhere sensible and findable. Explicitly supplying
        -OutputPath keeps the traditional fixed file names unless -DatedFileNames is also
        given.
    .PARAMETER DatedFileNames
        Switch. Names the two output files `MDETT-<yyyy-MM-dd>-Report.html` and
        `MDETT-<yyyy-MM-dd>-Findings.csv` (today's date) instead of the fixed
        `MDETimelineTriage-Report.html`/`MDETimelineTriage-Findings.csv`. Automatically
        turned on when -OutputPath is omitted; can also be combined with an explicit
        -OutputPath for dated names at a custom location. Note this names files by the date
        the report was *generated*, not by the export's own data timeframe (see the
        executive summary's incident overview for that). Optional, default $false unless
        -OutputPath is omitted.

    .PARAMETER Redact
        Switch. Masks usernames and hostnames in the HTML report with stable per-value
        placeholders (USER-1, HOST-1, ...) rather than blanking them outright, so relational
        patterns (the same account/device recurring across findings) remain visible in a
        report that's safe to share outside the immediate IR team. Default: off.

    .PARAMETER LocalTime
        Switch. Additionally renders local time alongside the default UTC timestamps, with
        both zones clearly labeled. Default: off (UTC only).

    .PARAMETER ReportSizeThreshold
        Integer. Number of findings above which the HTML report's interactive views render a
        top-N-by-score subset instead of every finding across all four views. Default: 5000.

    .EXAMPLE
        Import-MDETimeline -Path .\host01-timeline.csv | Invoke-MDEDetection | New-MDEReport -SourcePath .\host01-timeline.csv -OutputPath .\out

        Runs the full pipeline manually and renders the report with default settings (UTC
        only, unredacted, 5000-finding summarization threshold).

    .EXAMPLE
        $findings | New-MDEReport -SourcePath .\host01-timeline.csv -OutputPath .\out -Redact -LocalTime -WhatIf

        Reports which files would be written, with redaction and local-time display enabled,
        without writing anything -- useful for confirming output paths before overwriting an
        existing report.

    .INPUTS
        PSCustomObject
        Finding objects, e.g. from Invoke-MDEDetection.

    .OUTPUTS
        None. Writes an HTML file and a CSV file to -OutputPath; does not return objects to
        the pipeline.

    .NOTES
        SupportsShouldProcess: -WhatIf reports the HTML/CSV paths that would be written
        (noting if that would overwrite an existing file) without writing them; -Confirm
        prompts before writing.

        Read-only guarantee: -SourcePath is opened for reading only (to compute its hash),
        never modified.

        PII: no telemetry, phone-home, or auto-upload behavior anywhere in this cmdlet or the
        module. Use -Redact when the report will leave the immediate IR team.

        Build status: real as of Phase 6.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject[]]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Leaf)) {
                    throw "SourcePath '$_' does not exist or is not a file."
                }
                $true
            })]
        [string]
        $SourcePath,

        [Parameter()]
        [string]
        $OutputPath,

        [Parameter()]
        [switch]
        $DatedFileNames,

        [Parameter()]
        [switch]
        $Redact,

        [Parameter()]
        [switch]
        $LocalTime,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]
        $ReportSizeThreshold = 5000
    )

    begin {
        $findingsBuffer = [System.Collections.Generic.List[PSObject]]::new()
        $runSummary = $null
    }

    process {
        foreach ($item in $InputObject) {
            if ($item.PSObject.TypeNames -contains 'MDETimelineTriage.RunSummary') {
                $runSummary = $item
            }
            else {
                $findingsBuffer.Add($item)
            }
        }
    }

    end {
        $resolvedOutputPath = $OutputPath
        $useDatedNames = $DatedFileNames.IsPresent

        if ([string]::IsNullOrWhiteSpace($resolvedOutputPath)) {
            $resolvedOutputPath = Get-MDEDownloadsFolder
            $useDatedNames = $true
            Write-Verbose "New-MDEReport: -OutputPath not supplied -- resolved to Downloads folder '$resolvedOutputPath', using MDETT-dated file names."
        }

        if ($useDatedNames) {
            $dateStamp = (Get-Date).ToString('yyyy-MM-dd')
            $htmlPath = Join-Path -Path $resolvedOutputPath -ChildPath "MDETT-$dateStamp-Report.html"
            $csvPath = Join-Path -Path $resolvedOutputPath -ChildPath "MDETT-$dateStamp-Findings.csv"
        }
        else {
            $htmlPath = Join-Path -Path $resolvedOutputPath -ChildPath 'MDETimelineTriage-Report.html'
            $csvPath = Join-Path -Path $resolvedOutputPath -ChildPath 'MDETimelineTriage-Findings.csv'
        }

        $htmlExists = Test-Path -Path $htmlPath -PathType Leaf
        $csvExists = Test-Path -Path $csvPath -PathType Leaf
        $overwriteNote = if ($htmlExists -or $csvExists) { ' (will OVERWRITE existing file(s) at this path)' } else { '' }

        $target = "$($findingsBuffer.Count) finding object(s) from source '$SourcePath'"
        $timeNote = if ($LocalTime) { 'UTC + local time' } else { 'UTC only' }
        $redactNote = if ($Redact) { 'redacted' } else { 'unredacted' }
        $action = "Write $redactNote HTML report ($timeNote, summarization threshold $ReportSizeThreshold findings) to '$htmlPath' and enriched CSV to '$csvPath'$overwriteNote"

        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            return
        }

        if (-not (Test-Path -Path $resolvedOutputPath -PathType Container)) {
            Write-Verbose "New-MDEReport: creating output directory '$resolvedOutputPath'."
            [void](New-Item -Path $resolvedOutputPath -ItemType Directory -Force)
        }

        Write-Verbose "New-MDEReport: computing SHA-256 for '$SourcePath'..."
        $sourceHash = Get-MDEFileHash -Path $SourcePath
        $processingTimestampUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
        $moduleVersion = if ($MyInvocation.MyCommand.Module) { $MyInvocation.MyCommand.Module.Version.ToString() } else { '0.0.0' }

        $findingsArray = $findingsBuffer.ToArray()

        Write-Verbose "New-MDEReport: rendering HTML report ($($findingsArray.Count) finding(s))..."
        $html = New-MDEReportHtml -Findings $findingsArray -SourcePath $SourcePath -SourceHash $sourceHash `
            -ProcessingTimestampUtc $processingTimestampUtc -ModuleVersion $moduleVersion `
            -Redact:$Redact -LocalTime:$LocalTime -ReportSizeThreshold $ReportSizeThreshold -RunSummary $runSummary

        $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText($htmlPath, $html, $utf8NoBom)
        Write-Verbose "New-MDEReport: wrote HTML report to '$htmlPath' ($('{0:N0}' -f (Get-Item -LiteralPath $htmlPath).Length) bytes)."

        Write-Verbose 'New-MDEReport: writing enriched CSV...'
        Export-MDEEnrichedCsv -Findings $findingsArray -Path $csvPath -SourceFileHash $sourceHash `
            -SourceFilePath $SourcePath -ProcessingTimestampUtc $processingTimestampUtc
        Write-Verbose "New-MDEReport: wrote enriched CSV to '$csvPath' ($('{0:N0}' -f (Get-Item -LiteralPath $csvPath).Length) bytes)."

        Write-Verbose 'New-MDEReport: complete.'
    }
}
