function ConvertTo-MDEParsedTimestamp {
    <#
    .SYNOPSIS
        Parses an MDE CSV Timestamp string into a UTC [datetime], or $null if it doesn't parse.
    .DESCRIPTION
        Extracted from the parsing logic New-MDEFinding already used for its own Timestamp
        property, so a second, slightly-different implementation doesn't drift into the
        run-summary tracking added alongside requirement-driven executive-summary work
        (export timeframe, first-activity/first-response goalposts). Uses invariant-culture
        parsing with AdjustToUniversal|AssumeUniversal, since MDE timestamps are UTC but not
        always suffixed with a 'Z' or offset in every export variant.
    .PARAMETER Value
        The raw timestamp string (e.g. a row's Timestamp field). Optional; $null/empty input
        returns $null rather than throwing.
    .OUTPUTS
        System.DateTime, or $null if -Value is empty or does not parse as a valid timestamp.
    #>
    [CmdletBinding()]
    [OutputType([DateTime])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

    try {
        return [datetime]::Parse(
            $Value,
            [System.Globalization.CultureInfo]::InvariantCulture,
            ([System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
        )
    }
    catch {
        return $null
    }
}
