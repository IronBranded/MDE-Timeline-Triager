function Get-MDERowFieldOrEmpty {
    <#
    .SYNOPSIS
        Safely reads a named property from a parsed row, returning an empty string if absent.
    .DESCRIPTION
        Rows from different MDE export tables carry different columns by design (requirement
        #1). This is the standard defensive accessor used wherever report/export code needs a
        specific column that may not exist on a given row's table -- avoiding both a
        PropertyNotFoundException under this module's Set-StrictMode and a scattered
        $row.PSObject.Properties[...] existence check re-written at every call site.
    .PARAMETER Row
        The parsed row (or $null -- a finding's SourceRow is not expected to ever be $null in
        practice, but this accessor tolerates it rather than assuming). Mandatory.
    .PARAMETER Name
        The property name to read. Mandatory.
    .OUTPUTS
        System.String -- the property's string value, or '' if -Row is $null or lacks that
        property.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [PSObject]$Row,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Row -or -not $Row.PSObject.Properties[$Name]) { return '' }
    return [string]$Row.$Name
}
