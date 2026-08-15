function Protect-MDESensitiveValue {
    <#
    .SYNOPSIS
        Returns a consistent pseudonym for a username/hostname value, for -Redact mode.
    .DESCRIPTION
        Rather than blanking sensitive values outright, replaces each distinct value with a
        stable placeholder (USER-1, USER-2, HOST-1, ...) via -Map, a dictionary shared across
        one whole report render. The same real value always maps to the same placeholder, so
        an analyst reading a redacted report can still see relational patterns -- the same
        account across multiple findings, the same device across multiple rows -- that a
        blanket blank-out would destroy, while the actual username/hostname text (requirement
        #17) never appears in the output.
    .PARAMETER Value
        The value to pseudonymize. Mandatory; $null/empty passes through unchanged.
    .PARAMETER Prefix
        The placeholder prefix, e.g. 'USER' or 'HOST'. Mandatory.
    .PARAMETER Map
        A hashtable (namespaced key -> placeholder) shared across every call for one report
        render -- the caller creates one empty hashtable per New-MDEReport invocation and
        passes the same instance to every call, so the same input value always yields the
        same placeholder and the per-prefix counter increments consistently. Mandatory.
    .OUTPUTS
        System.String
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $true)]
        [string]$Prefix,

        [Parameter(Mandatory = $true)]
        [hashtable]$Map
    )

    if ([string]::IsNullOrEmpty($Value)) { return $Value }

    $mapKey = "$Prefix|$Value"
    if (-not $Map.ContainsKey($mapKey)) {
        $existingCount = @($Map.Keys | Where-Object { $_.StartsWith("$Prefix|") }).Count
        $Map[$mapKey] = "$Prefix-$($existingCount + 1)"
    }
    return $Map[$mapKey]
}
