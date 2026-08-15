function Test-MDELsassMemoryDumpPattern {
    <#
    .SYNOPSIS
        Rule CREDACCESS-001: detects a command-line pattern consistent with dumping LSASS process memory.
    .DESCRIPTION
        Fires on two well-documented techniques for extracting credentials from LSASS memory,
        matched via ProcessCommandLine on a DeviceProcessEvents row:
          - rundll32.exe invoking comsvcs.dll's MiniDump export (a signed-Windows-DLL LOLBIN
            technique requiring no attacker-supplied binary at all).
          - procdump.exe / procdump64.exe (Sysinternals) with lsass as its target.
        Anchoring on the DLL/flag/target combination rather than just "rundll32.exe" or
        "procdump.exe" alone keeps this specific to LSASS targeting rather than firing on
        those tools' many legitimate, unrelated uses. MITRE ATT&CK T1003.001 (OS Credential
        Dumping: LSASS Memory).
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

    $isComsvcsMiniDump = ($fileName -match '(?i)^rundll32\.exe$') -and ($commandLine -match '(?i)comsvcs\.dll') -and ($commandLine -match '(?i)MiniDump')
    $isProcdumpLsass = ($fileName -match '(?i)^procdump(64)?\.exe$') -and ($commandLine -match '(?i)lsass')

    if (-not ($isComsvcsMiniDump -or $isProcdumpLsass)) { return $null }

    $method = if ($isComsvcsMiniDump) { 'rundll32.exe + comsvcs.dll MiniDump' } else { 'ProcDump targeting lsass.exe' }

    return [PSCustomObject]@{
        RuleId      = 'CREDACCESS-001'
        Explanation = "Command line matches a known technique for dumping LSASS process memory ($method): $commandLine. This is a documented method for extracting credentials from memory, outside any routine troubleshooting purpose."
    }
}
