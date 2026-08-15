function ConvertTo-MDECsvField {
    <#
    .SYNOPSIS
        Formats one value as an RFC 4180 CSV field, quoting when necessary.
    .DESCRIPTION
        The write-side mirror of ConvertTo-MDECsvFields (Phase 2's read-side parser): wraps a
        value in double quotes (escaping any embedded quote as "") whenever it contains a
        comma, double quote, or newline, per RFC 4180. Hand-rolled for the same reason the
        Phase 2 reader is hand-rolled: guaranteed-identical behavior on Windows PowerShell 5.1
        and PowerShell 7+, rather than depending on Export-Csv's own quoting/encoding
        behavior, which differs subtly across the two runtimes (see Export-MDEEnrichedCsv).
    .PARAMETER Value
        The value to format. Mandatory; $null/empty becomes an empty field.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) { return '' }

    $needsQuoting = $Value.IndexOfAny([char[]]@(',', '"', "`n", "`r")) -ge 0
    if (-not $needsQuoting) { return $Value }

    return '"' + $Value.Replace('"', '""') + '"'
}
