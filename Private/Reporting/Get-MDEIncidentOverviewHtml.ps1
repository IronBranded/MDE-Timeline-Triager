function Get-MDEIncidentOverviewHtml {
    <#
    .SYNOPSIS
        Builds the HTML for the executive summary's incident overview section.
    .DESCRIPTION
        Renders, in this order: an alert-linked-events timeline (only when at least one
        alert-like row was found -- shown first, ahead of everything else, per the reporting
        requirement that an alert/incident timeline take priority when one exists), the
        export's timeframe (earliest to latest timestamp across every row processed, not
        just flagged findings), the two investigation "goalposts" (first suspicious/malicious
        activity and, heuristically, first automated MDE response/containment action), and,
        only when at least one finding was suppressed, what baseline exclusions removed.

        All display values pass through ConvertTo-MDEHtmlEncodedString; ActionType/DeviceName
        values in particular originate from the same untrusted CSV telemetry as every other
        field this report renders (requirement #8) and are never safe to embed unescaped.
    .PARAMETER RunSummary
        The 'MDETimelineTriage.RunSummary'-tagged object from the end of Invoke-MDEDetection's
        output stream. Optional -- $null (e.g. a report built by hand from finding objects
        without going through Invoke-MDEDetection's normal streaming) renders a minimal
        fallback notice rather than throwing.
    .PARAMETER LocalTime
        Whether to also render a local-time value alongside each UTC timestamp shown, e.g.
        the -LocalTime switch on New-MDEReport. Optional, default $false.
    .OUTPUTS
        System.String -- HTML fragment for the '__INCIDENT_OVERVIEW__' template token.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()]
        [AllowNull()]
        [PSObject]$RunSummary,

        [Parameter()]
        [switch]$LocalTime
    )

    function Format-MDEOverviewTimestamp {
        param([Nullable[DateTime]]$Value)
        if ($null -eq $Value) { return $null }
        $utcText = $Value.ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
        if ($LocalTime) {
            $localText = $Value.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
            return "$utcText (Local: $localText)"
        }
        return $utcText
    }

    if ($null -eq $RunSummary) {
        return '<div class="incident-overview"><p class="timeframe-row">Incident overview unavailable -- this report was not built from a full Invoke-MDEDetection run.</p></div>'
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<div class="incident-overview">')

    if (@($RunSummary.AlertLikeRows).Count -gt 0) {
        [void]$sb.Append('<h2>Alert-Linked Events Timeline</h2>')
        [void]$sb.Append('<p class="goalpost-note">Heuristic: rows carrying an AlertId-shaped field or an ActionType containing "Alert". This module ingests device-timeline tables, not MDE''s separate AlertInfo/AlertEvidence tables (out of scope for this build) -- this reflects only what happens to be present in the ingested export, not a complete alert history.</p>')
        [void]$sb.Append('<ul class="alert-timeline">')
        foreach ($row in $RunSummary.AlertLikeRows) {
            $ts = ConvertTo-MDEHtmlEncodedString -Value (Format-MDEOverviewTimestamp -Value $row.Timestamp)
            $at = ConvertTo-MDEHtmlEncodedString -Value $row.ActionType
            $dn = ConvertTo-MDEHtmlEncodedString -Value $row.DeviceName
            [void]$sb.Append("<li><strong>$ts</strong> -- $at<span class='goalpost-sub'>$dn</span></li>")
        }
        [void]$sb.Append('</ul>')
        [void]$sb.Append('<div class="incident-subhead">Timeframe &amp; Goalposts</div>')
    }
    else {
        [void]$sb.Append('<h2>Incident Overview</h2>')
    }

    $startText = ConvertTo-MDEHtmlEncodedString -Value (Format-MDEOverviewTimestamp -Value $RunSummary.ExportTimeframeStart)
    $endText = ConvertTo-MDEHtmlEncodedString -Value (Format-MDEOverviewTimestamp -Value $RunSummary.ExportTimeframeEnd)
    if ($startText -and $endText) {
        [void]$sb.Append("<p class='timeframe-row'>This export covers <strong>$($RunSummary.TotalRowsProcessed)</strong> event(s) from <strong>$startText</strong> to <strong>$endText</strong>.</p>")
    }
    else {
        [void]$sb.Append("<p class='timeframe-row'>This export's timeframe could not be determined (no parseable Timestamp values across $($RunSummary.TotalRowsProcessed) event(s) processed).</p>")
    }

    [void]$sb.Append('<div class="goalpost-row">')

    if ($null -ne $RunSummary.FirstSuspiciousActivityTimestamp) {
        $leftText = ConvertTo-MDEHtmlEncodedString -Value (Format-MDEOverviewTimestamp -Value $RunSummary.FirstSuspiciousActivityTimestamp)
        [void]$sb.Append("<div class='goalpost goalpost-left'><div class='goalpost-label'>Left goalpost -- first suspicious activity</div><div class='goalpost-value'>$leftText</div></div>")
    }
    else {
        [void]$sb.Append("<div class='goalpost goalpost-empty'><div class='goalpost-label'>Left goalpost -- first suspicious activity</div><div class='goalpost-value'>None detected</div></div>")
    }

    if ($null -ne $RunSummary.FirstResponseActionTimestamp) {
        $rightText = ConvertTo-MDEHtmlEncodedString -Value (Format-MDEOverviewTimestamp -Value $RunSummary.FirstResponseActionTimestamp)
        $rightAction = ConvertTo-MDEHtmlEncodedString -Value $RunSummary.FirstResponseActionType
        $rightDevice = ConvertTo-MDEHtmlEncodedString -Value $RunSummary.FirstResponseDeviceName
        [void]$sb.Append("<div class='goalpost goalpost-right'><div class='goalpost-label'>Right goalpost -- first MDE response (estimated)</div><div class='goalpost-value'>$rightText</div><div class='goalpost-sub'>$rightAction on $rightDevice</div><div class='goalpost-note'>Heuristic match, not a confirmed MDE isolation/quarantine event -- see README.</div></div>")
    }
    else {
        [void]$sb.Append("<div class='goalpost goalpost-empty'><div class='goalpost-label'>Right goalpost -- first MDE response (estimated)</div><div class='goalpost-value'>None detected</div><div class='goalpost-note'>No ActionType in this export matched the heuristic response/containment keywords -- see README for how to supply your tenant's exact ActionType values.</div></div>")
    }

    [void]$sb.Append('</div>')

    if ($RunSummary.SuppressedFindingsCount -gt 0) {
        [void]$sb.Append("<p class='exclusion-note'><strong>$($RunSummary.SuppressedFindingsCount)</strong> finding(s) were suppressed by baseline exclusion (Medium severity or below only -- High/Critical findings always survive):</p>")
        [void]$sb.Append('<ul class="exclusion-list">')
        foreach ($item in $RunSummary.SuppressedFindingsDetail) {
            $rn = ConvertTo-MDEHtmlEncodedString -Value $item.RuleName
            $sv = ConvertTo-MDEHtmlEncodedString -Value $item.Severity
            $ts = ConvertTo-MDEHtmlEncodedString -Value (Format-MDEOverviewTimestamp -Value $item.Timestamp)
            [void]$sb.Append("<li>$rn ($sv) at $ts</li>")
        }
        [void]$sb.Append('</ul>')
    }

    [void]$sb.Append('</div>')
    return $sb.ToString()
}
