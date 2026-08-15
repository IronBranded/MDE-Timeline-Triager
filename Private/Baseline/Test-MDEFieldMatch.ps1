function Test-MDEFieldMatch {
    <#
    .SYNOPSIS
        Tests whether a row's field value matches a baseline/custom-IOC config entry's pattern.
    .DESCRIPTION
        Shared matching logic for both the baseline/exclusion engine and the custom IOC
        engine, since both configs use the same Field/MatchType/Pattern shape (requirements
        #9 and #10). Regex matches are compiled with an explicit timeout (500ms) so a
        pathological pattern in an externally-editable config file cannot hang detection on a
        large timeline -- the same ReDoS concern this module is careful about anywhere a
        regex pattern originates outside the module's own code.
    .PARAMETER Row
        The parsed timeline row (or a finding's SourceRow) to test. Mandatory.
    .PARAMETER Field
        The property name on Row to test. Mandatory.
    .PARAMETER MatchType
        One of Exact, Contains, Regex. Mandatory.
    .PARAMETER Pattern
        The value/pattern to match against. Mandatory (may be an empty string, though that
        will never usefully match anything).
    .OUTPUTS
        System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Row,

        [Parameter(Mandatory = $true)]
        [string]$Field,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Exact', 'Contains', 'Regex')]
        [string]$MatchType,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Pattern
    )

    if (-not $Row.PSObject.Properties[$Field]) { return $false }
    $value = [string]$Row.$Field
    if ([string]::IsNullOrEmpty($value)) { return $false }

    switch ($MatchType) {
        'Exact' {
            return $value -eq $Pattern
        }
        'Contains' {
            return $value.IndexOf($Pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0
        }
        'Regex' {
            try {
                return [regex]::IsMatch($value, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromMilliseconds(500))
            }
            catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
                Write-Warning "Test-MDEFieldMatch: regex pattern '$Pattern' timed out matching field '$Field' -- treating as no match. Review this pattern for catastrophic backtracking."
                return $false
            }
        }
    }
}
