function Write-MDEProgress {
    <#
    .SYNOPSIS
        Emits a consistently formatted Write-Progress call for long-running streaming phases.
    .DESCRIPTION
        Used by Import-MDETimeline and Invoke-MDEDetection to report progress during a
        streaming pass over a potentially massive file. Percent complete is computed from
        actual row count when -TotalRows is supplied (Import-MDETimeline pre-scans this via
        Get-MDECsvRowCount specifically so this is possible) -- this is the accurate, direct
        metric callers should prefer, since it corresponds exactly to "row N of M," not an
        approximation. Falls back to bytes-read-versus-file-size when -TotalRows isn't
        supplied, for callers that don't have (or can't cheaply obtain) a row count.
    .PARAMETER Activity
        The high-level activity name (e.g. 'Parsing host01-timeline.csv'). Mandatory.
    .PARAMETER RowsProcessed
        Rows processed so far. Mandatory.
    .PARAMETER TotalRows
        Total row count, typically from a pre-scan (Get-MDECsvRowCount). Optional; when
        supplied, this is used for PercentComplete instead of the bytes-read fallback.
    .PARAMETER BytesRead
        Bytes read so far from the source stream. Mandatory only when -TotalRows is not
        supplied (used for the fallback percentage).
    .PARAMETER TotalBytes
        Total size of the source file in bytes. Mandatory only when -TotalRows is not
        supplied (used for the fallback percentage).
    .PARAMETER StartTime
        The [datetime] the operation began, used to compute rows/sec. Mandatory.
    .PARAMETER Id
        Progress bar Id, for nesting multiple simultaneous progress bars. Optional, default 0.
    .OUTPUTS
        None. Calls Write-Progress directly.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Activity,

        [Parameter(Mandatory = $true)]
        [int64]$RowsProcessed,

        [Parameter()]
        [int64]$TotalRows = -1,

        [Parameter()]
        [int64]$BytesRead = -1,

        [Parameter()]
        [int64]$TotalBytes = -1,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter()]
        [int]$Id = 0
    )

    $percent = -1
    $etaSuffix = ''

    if ($TotalRows -gt 0) {
        $percent = [Math]::Min(100, [Math]::Round(($RowsProcessed / $TotalRows) * 100))
        $elapsedForEta = ((Get-Date) - $StartTime).TotalSeconds
        if ($elapsedForEta -gt 1 -and $RowsProcessed -gt 0 -and $RowsProcessed -lt $TotalRows) {
            $rowsPerSecondForEta = $RowsProcessed / $elapsedForEta
            if ($rowsPerSecondForEta -gt 0) {
                $etaSeconds = [Math]::Round(($TotalRows - $RowsProcessed) / $rowsPerSecondForEta)
                $etaSuffix = " (ETA: $([TimeSpan]::FromSeconds($etaSeconds).ToString('mm\:ss')))"
            }
        }
    }
    elseif ($TotalBytes -gt 0) {
        $percent = [Math]::Min(100, [Math]::Round(($BytesRead / $TotalBytes) * 100))
    }

    $elapsedSeconds = ((Get-Date) - $StartTime).TotalSeconds
    $rowsPerSecond = if ($elapsedSeconds -gt 0) { [Math]::Round($RowsProcessed / $elapsedSeconds) } else { 0 }
    $status = if ($TotalRows -gt 0) {
        "{0:N0} of {1:N0} rows ({2:N0} rows/sec){3}" -f $RowsProcessed, $TotalRows, $rowsPerSecond, $etaSuffix
    }
    else {
        "{0:N0} rows processed ({1:N0} rows/sec)" -f $RowsProcessed, $rowsPerSecond
    }

    $progressParams = @{
        Activity = $Activity
        Status   = $status
        Id       = $Id
    }
    if ($percent -ge 0) {
        $progressParams['PercentComplete'] = $percent
    }

    Write-Progress @progressParams
}
