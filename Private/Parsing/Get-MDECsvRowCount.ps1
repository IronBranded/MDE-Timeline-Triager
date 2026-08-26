function Get-MDECsvRowCount {
    <#
    .SYNOPSIS
        Pre-scans a CSV file to count total data rows (excluding the header), for an accurate
        line-count-based progress percentage during the real parse.
    .DESCRIPTION
        Uses the same quote-aware Read-MDELogicalCsvLine reader Import-MDETimeline's real
        parse uses, rather than a naive newline count -- a field wrapped in quotes may
        legitimately contain embedded newlines (e.g. a multi-line command captured verbatim
        in ProcessCommandLine), so counting raw '\n' bytes would overcount relative to the
        actual number of rows the real parse will produce, and the resulting progress
        percentage would reach 100% before the real parse actually finished. This pass does
        nothing but read and discard each logical line -- no field-splitting, no object
        construction, no schema matching -- so it is meaningfully cheaper than the real parse
        despite doing a full read of the file, but it is not free: see Import-MDETimeline's
        own comment-based help for the measured overhead this adds.

        Opens its own independent file handle and StreamReader (same encoding-detection
        approach as the real parse) rather than sharing one with the caller, so this can run
        to completion and be fully disposed before the real parse's own handle opens.
    .PARAMETER Path
        Path to the CSV file. Mandatory.
    .OUTPUTS
        System.Int64 -- the number of data rows (header excluded). 0 for an empty file (no
        header) or a file containing only a header row.
    #>
    [CmdletBinding()]
    [OutputType([int64])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $fileStream = $null
    $streamReader = $null
    $rowCount = 0L

    try {
        $fileStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $defaultEncoding = [System.Text.UTF8Encoding]::new($false)
        $streamReader = [System.IO.StreamReader]::new($fileStream, $defaultEncoding, $true)

        $headerLine = Read-MDELogicalCsvLine -Reader $streamReader
        if ($null -eq $headerLine) {
            return 0L
        }

        while ($null -ne (Read-MDELogicalCsvLine -Reader $streamReader)) {
            $rowCount++
        }
    }
    finally {
        if ($streamReader) { $streamReader.Dispose() }
        if ($fileStream) { $fileStream.Dispose() }
    }

    return $rowCount
}
