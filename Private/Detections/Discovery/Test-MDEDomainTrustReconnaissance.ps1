function Test-MDEDomainTrustReconnaissance {
    <#
    .SYNOPSIS
        Rule DISC-001: detects nltest.exe enumerating Active Directory domain trusts.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FileName is nltest.exe and ProcessCommandLine
        contains /domain_trusts. Enumerating AD trust relationships is a common
        reconnaissance step used to identify paths for further lateral movement, particularly
        in multi-domain/forest environments. MITRE ATT&CK T1482 (Domain Trust Discovery).

        Deliberately Low confidence: IT/helpdesk staff and various legitimate AD management
        or monitoring scripts run this command routinely.
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
    if ($fileName -notmatch '(?i)^nltest\.exe$') { return $null }
    if ($commandLine -notmatch '(?i)/domain_trusts') { return $null }

    return [PSCustomObject]@{
        RuleId      = 'DISC-001'
        Explanation = "nltest.exe was invoked with /domain_trusts: $commandLine. This enumerates Active Directory trust relationships, a common reconnaissance step for identifying further lateral-movement paths."
    }
}
