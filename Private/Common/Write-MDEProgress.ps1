function Write-MDEProgress {
    <#
    .SYNOPSIS
        Emits a consistently formatted Write-Progress call for long-running streaming phases.
    .DESCRIPTION
        Used by Import-MDETimeline (and, from build Phase 3 onward, Invoke-MDEDetection) to
        report progress during a streaming pass over a potentially massive file without
        needing a separate pre-count pass to determine total row count: percent-complete is
        derived from bytes read so far versus total file size, which is available immediately
        from the file handle. Callers are expected to throttle how often this is invoked
        (e.g. every N rows) themselves, since Write-Progress itself has non-trivial overhead
        if called for every single row on a multi-million-row file.
    .PARAMETER Activity
        The high-level activity name (e.g. 'Parsing host01-timeline.csv'). Mandatory.
    .PARAMETER RowsProcessed
        Rows processed so far. Mandatory.
    .PARAMETER BytesRead
        Bytes read so far from the source stream. Mandatory.
    .PARAMETER TotalBytes
        Total size of the source file in bytes, used to compute percent complete. Mandatory.
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

        [Parameter(Mandatory = $true)]
        [int64]$BytesRead,

        [Parameter(Mandatory = $true)]
        [int64]$TotalBytes,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime,

        [Parameter()]
        [int]$Id = 0
    )

    $percent = if ($TotalBytes -gt 0) {
        [Math]::Min(100, [Math]::Round(($BytesRead / $TotalBytes) * 100))
    }
    else {
        -1
    }

    $elapsedSeconds = ((Get-Date) - $StartTime).TotalSeconds
    $rowsPerSecond = if ($elapsedSeconds -gt 0) { [Math]::Round($RowsProcessed / $elapsedSeconds) } else { 0 }
    $status = "{0:N0} rows processed ({1:N0} rows/sec)" -f $RowsProcessed, $rowsPerSecond

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
