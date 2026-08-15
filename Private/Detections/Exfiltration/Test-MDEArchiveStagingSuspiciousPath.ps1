function Test-MDEArchiveStagingSuspiciousPath {
    <#
    .SYNOPSIS
        Rule EXFIL-001: detects an archive utility writing to a user-writable staging path.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FileName is a common archive utility
        (7z.exe, 7za.exe, winrar.exe, rar.exe) and ProcessCommandLine references AppData\
        Roaming, ProgramData, \Temp\, or a public folder -- the same suspicious-path pattern
        used elsewhere in this catalog, applied here to where an archive is being written
        rather than where a process is executing from. Archiving data to a location like this
        is a common step immediately prior to exfiltration. MITRE ATT&CK T1560.001 (Archive
        Collected Data: Archive via Utility).

        Deliberately Low confidence: archive tools plus AppData/Temp paths are also extremely
        common for entirely benign reasons (extracting a downloaded zip, temporary working
        directories for legitimate business processes).
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
    if ($fileName -notmatch '(?i)^(7z|7za|winrar|rar)\.exe$') { return $null }
    if ($commandLine -notmatch '(?i)\\AppData\\Roaming(\\|$)|\\ProgramData(\\|$)|\\Temp\\|\\Users\\Public\\') { return $null }

    return [PSCustomObject]@{
        RuleId      = 'EXFIL-001'
        Explanation = "'$fileName' was run with a command line referencing a user-writable staging path: $commandLine. Archiving data to a location like this is a common step immediately prior to exfiltration."
    }
}
