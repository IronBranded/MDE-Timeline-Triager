function Import-MDETimeline {
    <#
    .SYNOPSIS
        Parses a single MDE timeline CSV export into normalized, typed pipeline objects.

    .DESCRIPTION
        Import-MDETimeline is the ingest stage of the MDETimelineTriage pipeline. It reads a
        single Microsoft Defender for Endpoint (MDE) timeline export -- an Advanced Hunting
        CSV export of one of DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents,
        DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, or DeviceEvents, a
        Defender portal "Device Timeline" export, or Live Response output -- and streams one
        typed PSCustomObject per row to the pipeline.

        ENCODING: file encoding (UTF-8, UTF-8 with BOM, or UTF-16) is detected and handled by
        .NET's own StreamReader byte-order-mark auto-detection, which correctly identifies
        and skips the BOM for all three in-scope encodings; a separate lightweight peek
        (Get-MDEFileEncoding) reports what was found via -Verbose for diagnostic purposes
        only, decoupled from the actual reading logic.

        SCHEMA-SET DETECTION: the header row is matched against the 7 known Advanced Hunting
        table schemas (Resolve-MDESchemaType). Because MDE portal exports flatten nested JSON
        (such as InitiatingProcess.* fields) into individual CSV columns already, no JSON
        reconstruction is needed -- the flattened column names are used as-is. A header that
        does not confidently match a known table (which is expected for Device Timeline
        exports, since Microsoft does not publish a fixed schema for that user-customizable
        UI export, and for Live Response output) is classified 'Unrecognized'; parsing still
        proceeds using whatever columns are present. This is the *schema-mismatch* failure
        mode (requirement #1): missing or extra columns relative to a matched table's known
        schema are warned on once per file, never treated as fatal, and never cause any row
        to be skipped by themselves.

        DATA CORRUPTION: independently of schema-set detection, each row is validated
        structurally as it is read -- a row whose field count does not match the header
        (a truncated row, or one with an unbalanced quote that never closes) is skipped, and
        a row containing a Unicode replacement character (U+FFFD, which .NET's decoder
        substitutes for byte sequences invalid in the detected encoding) is skipped as likely
        encoding corruption. This is the *data-corruption* failure mode (requirement #3),
        distinct from schema-mismatch: it is a per-row problem with the row's own bytes, not
        a file-level difference in which columns are present. Skipped rows are counted and
        reported via -Verbose (per row, with reason) and a summary Write-Warning.

        PERFORMANCE: the file is streamed via [System.IO.StreamReader], never fully
        materialized; multi-line quoted fields (a field containing an embedded newline, such
        as a captured multi-line script) are correctly reassembled rather than incorrectly
        split into extra rows (Read-MDELogicalCsvLine). Parsed rows are batched into a
        [System.Collections.Generic.List[PSCustomObject]] and flushed to the pipeline in
        batches of 1000 -- bounding memory use on multi-million-row exports while avoiding
        the per-object overhead of emitting one row at a time. Write-Progress is reported
        periodically based on bytes read versus total file size.

        This cmdlet performs ingest only -- it does not run detection logic (see
        Invoke-MDEDetection) and does not render a report (see New-MDEReport). The source CSV
        is always treated as read-only evidence: it is opened for reading only and is never
        modified.

    .PARAMETER Path
        Path to the single MDE timeline CSV export to parse. Mandatory. Must point to an
        existing, readable file; v1 processes exactly one CSV per invocation (no
        multi-file/batch ingestion -- see project scope).
    .PARAMETER SkipRowCountPreScan
        By default, this cmdlet reads through the file once (cheaply -- no field-splitting,
        no object construction) to get an exact row count before the real parse begins, so
        Write-Progress can report accurate "row N of M" percentages instead of an estimate.
        This adds real time on very large files -- see this cmdlet's .NOTES for measured
        overhead. Pass this switch to skip the pre-scan and fall back to a
        bytes-read-versus-file-size percentage estimate instead, if you'd rather trade
        progress accuracy for a faster start. Optional, default $false (pre-scan runs).

    .EXAMPLE
        Import-MDETimeline -Path 'C:\Cases\2026-041\host01-timeline.csv'

        Parses the given export and returns typed pipeline objects, one per CSV row, each
        carrying SourceTable (the detected/'Unrecognized' schema type) and SourceRowNumber
        (1-indexed, counting the header as row 1) in addition to that row's own columns.

    .EXAMPLE
        Import-MDETimeline -Path .\host01-timeline.csv -Verbose | Invoke-MDEDetection | New-MDEReport -SourcePath .\host01-timeline.csv -OutputPath .\out

        The full composable pipeline -- ingest, then detect, then render -- equivalent to
        calling Invoke-MDETriage directly, but with each stage inspectable in between.
        -Verbose surfaces per-row skip reasons and progress detail during ingest.

    .INPUTS
        None. This cmdlet does not accept pipeline input; it reads directly from -Path.

    .OUTPUTS
        PSCustomObject
        One object per successfully parsed CSV row (malformed rows are skipped, not
        returned), always exposing SourceTable and SourceRowNumber plus every column present
        in that export's header, as string values (no type coercion is performed at ingest;
        Invoke-MDEDetection's rules are responsible for interpreting field contents).

    .NOTES
        Read-only guarantee: the source file at -Path is never opened for write and is never
        modified in place.

        A row is skipped (data-corruption path) when its field count does not match the
        header or it contains invalid byte sequences for the detected encoding; it is never
        skipped merely because the file's schema doesn't perfectly match a known table
        (schema-mismatch path), which only produces warnings.

        Missing-header detection is a best-effort heuristic (checking whether the first row's
        values look like a timestamp or GUID rather than column names) since distinguishing
        "no header, data starts immediately" from "header present" is not fully reliable from
        content alone; treat that specific warning as a prompt to verify the source file, not
        a guarantee.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
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
        [switch]
        $SkipRowCountPreScan
    )

    $sourceFile = Get-Item -LiteralPath $Path
    Write-Verbose "Import-MDETimeline: starting ingest of '$($sourceFile.FullName)' ($('{0:N0}' -f $sourceFile.Length) bytes)."

    $hash = Get-MDEFileHash -Path $sourceFile.FullName
    Write-Verbose "Import-MDETimeline: source SHA-256 = $hash"

    $encodingName = Get-MDEFileEncoding -Path $sourceFile.FullName
    Write-Verbose "Import-MDETimeline: detected encoding (diagnostic) = $encodingName"

    $totalRowCount = -1
    if (-not $SkipRowCountPreScan) {
        Write-Progress -Activity "Scanning $($sourceFile.Name)" -Status 'Counting rows for progress reporting...' -PercentComplete -1
        $preScanStart = Get-Date
        $totalRowCount = Get-MDECsvRowCount -Path $sourceFile.FullName
        $preScanSeconds = ((Get-Date) - $preScanStart).TotalSeconds
        Write-Progress -Activity "Scanning $($sourceFile.Name)" -Completed
        Write-Verbose "Import-MDETimeline: row count pre-scan found $('{0:N0}' -f $totalRowCount) data row(s) in $('{0:N1}' -f $preScanSeconds)s."
    }

    $fileStream = $null
    $streamReader = $null
    $rowsEmitted = 0
    $rowsSkipped = 0
    $rowNumber = 1
    $startTime = Get-Date
    $lastProgressRowCount = 0
    $progressInterval = 5000
    $batchSize = 1000
    $batch = [System.Collections.Generic.List[PSCustomObject]]::new($batchSize)

    try {
        $fileStream = [System.IO.File]::Open($sourceFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $defaultEncoding = [System.Text.UTF8Encoding]::new($false)
        $streamReader = [System.IO.StreamReader]::new($fileStream, $defaultEncoding, $true)

        $headerLine = Read-MDELogicalCsvLine -Reader $streamReader
        if ($null -eq $headerLine) {
            throw "Import-MDETimeline: '$($sourceFile.FullName)' is empty (no header row)."
        }

        $headerColumns = ConvertTo-MDECsvFields -Line $headerLine
        Write-Verbose "Import-MDETimeline: header has $($headerColumns.Count) column(s)."

        if ($headerColumns.Count -gt 0 -and
            ($headerColumns[0] -match '^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2})?' -or
             $headerColumns[0] -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')) {
            Write-Warning "Import-MDETimeline: the first row of '$($sourceFile.Name)' looks like a data row (starts with what appears to be a timestamp or identifier), not a column-name header row. This file may be missing its header row (e.g. due to truncation) -- if so, every row below will be parsed against incorrect column names. Verify the source file. (Best-effort heuristic; not a guarantee.)"
        }

        $schemaResult = Resolve-MDESchemaType -HeaderColumns $headerColumns
        Write-Verbose "Import-MDETimeline: schema-set detection -> $($schemaResult.TableType) (confidence $($schemaResult.Confidence))"

        if ($schemaResult.TableType -eq 'Unrecognized') {
            Write-Warning "Import-MDETimeline: '$($sourceFile.Name)' did not confidently match any known MDE export schema (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents, DeviceEvents). This is expected for Defender portal 'Device Timeline' exports (columns are user-customizable there and not governed by a published schema) and for Live Response output. Parsing continues using the $($headerColumns.Count) column(s) present; built-in detections that depend on a specific known table will simply not evaluate against this data."
        }
        else {
            if ($schemaResult.MissingKnownColumns.Count -gt 0) {
                Write-Warning "Import-MDETimeline: '$($sourceFile.Name)' matched $($schemaResult.TableType) but is missing $($schemaResult.MissingKnownColumns.Count) column(s) normally present for that table. Detections depending on those columns simply will not fire for this export; this is not treated as a fatal error. Run with -Verbose for the full list."
                Write-Verbose "Import-MDETimeline: missing known columns for $($schemaResult.TableType): $($schemaResult.MissingKnownColumns -join ', ')"
            }
            if ($schemaResult.ExtraColumns.Count -gt 0) {
                Write-Warning "Import-MDETimeline: '$($sourceFile.Name)' matched $($schemaResult.TableType) but has $($schemaResult.ExtraColumns.Count) column(s) not in this module's known schema for that table -- possibly a Microsoft schema change since this module's schema map was last updated. These columns are preserved on every returned object but are not evaluated by any built-in detection yet. Run with -Verbose for the full list."
                Write-Verbose "Import-MDETimeline: unrecognized extra columns: $($schemaResult.ExtraColumns -join ', ')"
            }
        }

        $headerCount = $headerColumns.Count

        while ($true) {
            $rawLine = Read-MDELogicalCsvLine -Reader $streamReader
            if ($null -eq $rawLine) {
                break
            }
            $rowNumber++

            if ($rawLine.Length -eq 0) {
                continue
            }

            if ($rawLine.IndexOf([char]0xFFFD) -ge 0) {
                Write-Verbose "Import-MDETimeline: row $rowNumber contains invalid byte sequences for the detected encoding -- skipped (data-corruption)."
                $rowsSkipped++
                continue
            }

            try {
                $fields = ConvertTo-MDECsvFields -Line $rawLine

                if ($fields.Count -ne $headerCount) {
                    Write-Verbose "Import-MDETimeline: row $rowNumber has $($fields.Count) field(s), expected $headerCount -- skipped (truncated/malformed row, data-corruption)."
                    $rowsSkipped++
                    continue
                }

                $rowObject = [ordered]@{
                    SourceTable     = $schemaResult.TableType
                    SourceRowNumber = $rowNumber
                }
                for ($i = 0; $i -lt $headerCount; $i++) {
                    $rowObject[$headerColumns[$i]] = $fields[$i]
                }

                $batch.Add([PSCustomObject]$rowObject)
                $rowsEmitted++
            }
            catch {
                Write-Verbose "Import-MDETimeline: row $rowNumber raised an unexpected parse error ($($_.Exception.Message)) -- skipped (data-corruption)."
                $rowsSkipped++
                continue
            }

            if ($batch.Count -ge $batchSize) {
                $batch
                $batch = [System.Collections.Generic.List[PSCustomObject]]::new($batchSize)
            }

            if (($rowsEmitted - $lastProgressRowCount) -ge $progressInterval) {
                $lastProgressRowCount = $rowsEmitted
                Write-MDEProgress -Activity "Parsing $($sourceFile.Name)" -RowsProcessed $rowsEmitted -TotalRows $totalRowCount -BytesRead $fileStream.Position -TotalBytes $sourceFile.Length -StartTime $startTime
            }
        }

        if ($batch.Count -gt 0) {
            $batch
        }

        Write-Progress -Activity "Parsing $($sourceFile.Name)" -Completed
        Write-Verbose "Import-MDETimeline: finished. $rowsEmitted row(s) emitted, $rowsSkipped row(s) skipped, out of $($rowNumber - 1) data row(s) total."

        if ($rowsSkipped -gt 0) {
            Write-Warning "Import-MDETimeline: skipped $rowsSkipped malformed/truncated row(s) out of $($rowNumber - 1) data row(s) in '$($sourceFile.Name)'. Re-run with -Verbose to see the specific row numbers and reasons."
        }
    }
    finally {
        if ($streamReader) {
            $streamReader.Dispose()
        }
        elseif ($fileStream) {
            $fileStream.Dispose()
        }
    }
}
