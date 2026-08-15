function Resolve-MDESchemaType {
    <#
    .SYNOPSIS
        Determines which known MDE export schema a CSV header row matches, if any.
    .DESCRIPTION
        Compares the given header column names against the SignatureColumns (and, where
        defined, ExclusionColumns) of each known table in Data/SchemaMap.json -- the 7
        in-scope Advanced Hunting tables: DeviceProcessEvents, DeviceNetworkEvents,
        DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents,
        DeviceEvents -- and returns the best-scoring match as a fraction in [0, 1].

        A header that does not score above -ConfidenceThreshold against any known table is
        classified 'Unrecognized' rather than forced into a poor match. This deliberately
        covers Defender portal "Device Timeline" exports (whose column set is user-
        customizable in the portal UI and not governed by any schema Microsoft publishes), 
        Live Response output, and any other CSV shape. Import-MDETimeline still parses and
        normalizes an Unrecognized export using whatever columns are present -- this is
        requirement #1's "detect the column set present at runtime and degrade gracefully"
        in its purest form, since there is no known baseline to compare against at all.

        For a confidently matched table, this function also reports which of that table's
        KnownColumns are absent from the header (MissingKnownColumns) and which header
        columns are not in that table's KnownColumns (ExtraColumns) -- both are warned on by
        Import-MDETimeline but are NOT treated as fatal, per requirement #1's explicit
        "skip/warn" (not hard-fail) framing for schema-mismatch handling.
    .PARAMETER HeaderColumns
        The array of column names from the CSV's header row. Mandatory.
    .PARAMETER SchemaMapPath
        Path to the schema map JSON file. Optional; defaults to Data/SchemaMap.json resolved
        via Get-MDEModuleRoot.
    .PARAMETER ConfidenceThreshold
        Minimum signature-match score (0.0-1.0) required to accept a match rather than
        falling back to 'Unrecognized'. Optional; default 0.5.
    .OUTPUTS
        PSCustomObject
        Exposes: TableType (string, or 'Unrecognized'), Confidence (double, 0-1),
        MissingKnownColumns (string[]), ExtraColumns (string[]).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$HeaderColumns,

        [Parameter()]
        [string]$SchemaMapPath,

        [Parameter()]
        [ValidateRange(0.0, 1.0)]
        [double]$ConfidenceThreshold = 0.5
    )

    if ([string]::IsNullOrEmpty($SchemaMapPath)) {
        $SchemaMapPath = Join-Path -Path (Get-MDEModuleRoot) -ChildPath 'Data/SchemaMap.json'
    }

    if (-not (Test-Path -Path $SchemaMapPath -PathType Leaf)) {
        throw "Resolve-MDESchemaType: schema map not found at '$SchemaMapPath'. The module installation may be incomplete."
    }

    $schemaMap = Get-Content -Path $SchemaMapPath -Raw | ConvertFrom-Json
    $headerSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$HeaderColumns, [System.StringComparer]::OrdinalIgnoreCase)

    $bestTable = $null
    $bestScore = 0.0

    foreach ($tableProperty in $schemaMap.Tables.PSObject.Properties) {
        $tableName = $tableProperty.Name
        $tableDef = $tableProperty.Value

        $signatureColumns = @($tableDef.SignatureColumns)
        if ($signatureColumns.Count -eq 0) {
            continue
        }

        $hits = 0
        foreach ($col in $signatureColumns) {
            if ($headerSet.Contains($col)) { $hits++ }
        }
        $score = $hits / $signatureColumns.Count

        if ($tableDef.PSObject.Properties.Match('ExclusionColumns').Count -gt 0) {
            $exclusionColumns = @($tableDef.ExclusionColumns)
            if ($exclusionColumns.Count -gt 0) {
                $exclusionHits = 0
                foreach ($col in $exclusionColumns) {
                    if ($headerSet.Contains($col)) { $exclusionHits++ }
                }
                # Multiplier of 3.0 (not a gentler 0.5) is deliberate: DeviceImageLoadEvents'
                # own columns are a strict subset of DeviceFileEvents/DeviceProcessEvents/
                # DeviceEvents' columns (nothing is unique to it), so a weak penalty lets a
                # generic positive signature match beat the real, more-specific table when
                # only a handful of that table's extra columns are present in a compact
                # export. Verified against all 7 table fixtures plus malformed variants
                # during development (see Tests/Fixtures/).
                $score -= ($exclusionHits / $exclusionColumns.Count) * 3.0
            }
        }

        if ($score -gt $bestScore) {
            $bestScore = $score
            $bestTable = $tableName
        }
    }

    if ($null -eq $bestTable -or $bestScore -lt $ConfidenceThreshold) {
        return [PSCustomObject]@{
            TableType           = 'Unrecognized'
            Confidence          = [Math]::Round($bestScore, 2)
            MissingKnownColumns = [string[]]@()
            ExtraColumns        = [string[]]@()
        }
    }

    $knownColumns = @($schemaMap.Tables.$bestTable.KnownColumns)
    $knownSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$knownColumns, [System.StringComparer]::OrdinalIgnoreCase)

    $missing = @($knownColumns | Where-Object { -not $headerSet.Contains($_) })
    $extra = @($HeaderColumns | Where-Object { -not $knownSet.Contains($_) })

    return [PSCustomObject]@{
        TableType           = $bestTable
        Confidence           = [Math]::Round($bestScore, 2)
        MissingKnownColumns = [string[]]$missing
        ExtraColumns        = [string[]]$extra
    }
}
