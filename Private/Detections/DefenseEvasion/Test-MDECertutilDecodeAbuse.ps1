function Test-MDECertutilDecodeAbuse {
    <#
    .SYNOPSIS
        Rule DEFEVA-004: detects certutil.exe invoked with -decode (a documented LOLBAS technique).
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FileName is certutil.exe and ProcessCommandLine
        contains the -decode flag. certutil.exe is a signed, built-in Windows certificate-
        management utility; -decode is a long-documented LOLBAS technique for deobfuscating a
        Base64-encoded payload previously dropped to disk, entirely outside certutil's
        intended purpose. MITRE ATT&CK T1140 (Deobfuscate/Decode Files or Information).

        Scope note: certutil has other LOLBAS abuse patterns not covered by this rule --
        notably -urlcache/-verifyctl for using certutil as a download utility, which maps to
        a different technique (T1105, Command and Control tactic) rather than T1140. That
        pattern is left for a future rule (build Phase 7) to keep this one focused.
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
    if ($fileName -notmatch '(?i)^certutil\.exe$') { return $null }
    if ($commandLine -notmatch '(?i)-decode\b') { return $null }

    return [PSCustomObject]@{
        RuleId      = 'DEFEVA-004'
        Explanation = "certutil.exe was invoked with -decode. certutil is a LOLBAS binary; -decode is a documented technique to deobfuscate a Base64-encoded payload dropped to disk, entirely outside certutil's intended certificate-management purpose."
    }
}
