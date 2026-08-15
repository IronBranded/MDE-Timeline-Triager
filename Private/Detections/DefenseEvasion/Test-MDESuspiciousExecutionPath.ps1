function Test-MDESuspiciousExecutionPath {
    <#
    .SYNOPSIS
        Rule DEFEVA-001: detects a process executing from a user-writable, non-standard path.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FolderPath falls under AppData\Roaming,
        ProgramData, any \Temp\ directory, or C:\Users\Public -- paths writable by a standard
        (non-admin) user and commonly used to stage and run payloads outside the locations
        application-allowlisting policies typically watch. MITRE ATT&CK T1036.005
        (Masquerading: Match Legitimate Name or Location).

        Deliberately broad, and deliberately Low confidence in the catalog: many legitimate
        installers and auto-updaters use exactly these paths. This rule is the canonical
        example in this module of Severity and Confidence being independent axes -- a hit
        here can be a genuinely bad (Medium-severity) finding despite being common and noisy
        (Low confidence); it is never auto-suppressed for that reason (requirement #5).
    .PARAMETER Row
        A single parsed timeline row (from Import-MDETimeline). Mandatory.
    .OUTPUTS
        PSCustomObject with RuleId and Explanation if the rule fires, otherwise $null.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Row
    )

    if ($Row.SourceTable -ne 'DeviceProcessEvents') { return $null }
    if (-not $Row.PSObject.Properties['FolderPath']) { return $null }

    $folderPath = [string]$Row.FolderPath
    if ([string]::IsNullOrEmpty($folderPath)) { return $null }

    if ($folderPath -notmatch '(?i)\\AppData\\Roaming(\\|$)|\\ProgramData(\\|$)|\\Temp\\|\\Users\\Public\\') {
        return $null
    }

    $fileName = if ($Row.PSObject.Properties['FileName']) { [string]$Row.FileName } else { '(unknown)' }

    return [PSCustomObject]@{
        RuleId      = 'DEFEVA-001'
        Explanation = "'$fileName' executed from '$folderPath', a user-writable path commonly used to evade path-based application allowlisting rather than a standard installation directory."
    }
}
