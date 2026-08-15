function Test-MDEWmiRemoteExecution {
    <#
    .SYNOPSIS
        Rule LATMOVE-002: detects wmic.exe targeting a remote system for command execution.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FileName is wmic.exe and ProcessCommandLine
        contains the /node: flag, specifying a remote target. WMI-based remote execution is
        a documented lateral-movement technique that avoids dropping an executable on the
        target device. MITRE ATT&CK T1047 (Windows Management Instrumentation).

        wmic /node is also used by legitimate remote-management scripts, though less commonly
        than more mainstream tooling; Medium confidence in the catalog reflects this.
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
    if (-not $Row.PSObject.Properties['FileName'] -or -not $Row.PSObject.Properties['ProcessCommandLine']) { return $null }

    $fileName = [string]$Row.FileName
    $commandLine = [string]$Row.ProcessCommandLine
    if ([string]::IsNullOrEmpty($commandLine)) { return $null }
    if ($fileName -notmatch '(?i)^wmic\.exe$') { return $null }
    if ($commandLine -notmatch '(?i)/node:') { return $null }

    return [PSCustomObject]@{
        RuleId      = 'LATMOVE-002'
        Explanation = "wmic.exe was invoked with /node:, targeting a remote system: $commandLine. This is a documented lateral-movement technique that avoids dropping an executable on the target."
    }
}
