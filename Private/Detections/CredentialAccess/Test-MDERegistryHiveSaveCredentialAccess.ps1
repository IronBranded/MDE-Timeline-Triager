function Test-MDERegistryHiveSaveCredentialAccess {
    <#
    .SYNOPSIS
        Rule CREDACCESS-002: detects reg.exe saving a copy of the SAM, SECURITY, or SYSTEM hive.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FileName is reg.exe and ProcessCommandLine
        contains "save" targeting one of the SAM, SECURITY, or SYSTEM registry hives. Offline
        copies of these hives (SAM holds local password hashes; SYSTEM holds the boot key
        needed to decrypt them; SECURITY can hold cached domain credentials/LSA secrets) are
        a documented, classic credential-access technique -- extraction typically happens
        later, offline, against the saved files. MITRE ATT&CK T1003.002 (OS Credential
        Dumping: Security Account Manager).
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
    if ($fileName -notmatch '(?i)^reg\.exe$') { return $null }
    if ($commandLine -notmatch '(?i)\bsave\b') { return $null }
    if ($commandLine -notmatch '(?i)\\(SAM|SECURITY|SYSTEM)\b') { return $null }

    return [PSCustomObject]@{
        RuleId      = 'CREDACCESS-002'
        Explanation = "reg.exe was used to save a copy of a sensitive registry hive: $commandLine. Offline copies of SAM/SECURITY/SYSTEM can be used to extract cached credentials or the key needed to decrypt them."
    }
}
