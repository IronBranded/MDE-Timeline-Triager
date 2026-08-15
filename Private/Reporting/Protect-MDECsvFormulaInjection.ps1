function Protect-MDECsvFormulaInjection {
    <#
    .SYNOPSIS
        Neutralizes leading characters that spreadsheet applications may interpret as a formula.
    .DESCRIPTION
        A cell beginning with '=', '+', '-', '@', a tab, or a carriage return can be
        interpreted by Excel and similar applications as the start of a formula -- a
        well-known CSV/formula-injection risk when cell content originates from untrusted
        data. Every value in the enriched CSV is ultimately sourced from attacker-influenced
        MDE telemetry, the same category of risk requirement #8 addresses for the HTML
        report; this is that same defensive posture applied to the CSV output, even though
        the requirement text calls out HTML specifically. Prefixing such a value with a
        single quote is the standard, low-cost mitigation: spreadsheet applications display
        the value as literal text instead of evaluating it.
    .PARAMETER Value
        The value to check. Mandatory; $null/empty passes through unchanged.
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

    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    if ($Value[0] -in @('=', '+', '-', '@', "`t", "`r")) {
        return "'" + $Value
    }
    return $Value
}
