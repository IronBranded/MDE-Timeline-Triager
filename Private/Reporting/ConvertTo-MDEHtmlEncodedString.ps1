function ConvertTo-MDEHtmlEncodedString {
    <#
    .SYNOPSIS
        HTML-encodes a string for safe embedding in HTML markup (element content or attribute values).
    .DESCRIPTION
        Every CSV-derived value rendered into the report -- command lines, file paths,
        process names, decoded command-line output, etc. -- originates from potentially
        attacker-controlled telemetry (requirement #8). This is the single function every
        such value passes through before it touches report markup; nothing from a parsed row
        or finding is ever string-concatenated into HTML without going through this first,
        including values already auto-decoded by ConvertFrom-MDEEncodedCommand, which are
        exactly as untrusted as the raw value.

        Uses [System.Net.WebUtility]::HtmlEncode -- .NET's own well-tested HTML entity
        encoder -- rather than a hand-rolled replace chain, which risks missing an edge case
        or getting escaping order wrong (e.g. '&' must be escaped before other entities that
        themselves start with '&', or you double-escape).
    .PARAMETER Value
        The string to encode. Mandatory (accepted from the pipeline); $null/empty is passed
        through as an empty string rather than throwing, since many finding fields are
        legitimately empty for a given table/row.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    process {
        if ([string]::IsNullOrEmpty($Value)) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($Value)
    }
}
