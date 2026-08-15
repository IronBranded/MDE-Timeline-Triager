function Test-MDEPsExecServiceArtifact {
    <#
    .SYNOPSIS
        Rule LATMOVE-001: detects the PsExec service artifact left on a TARGET device.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FileName is PSEXESVC.exe -- the service
        executable Sysinternals PsExec installs on a target host to run commands remotely.
        Because this module's scope is single-device triage (project scope: an MDE timeline
        export is per-device), this rule is written for what is observable from the TARGET
        side of a PsExec session, not the source side (which would show as an outbound
        connection to an admin share from a different device's own export). MITRE ATT&CK
        T1021.002 (Remote Services: SMB/Windows Admin Shares).

        PsExec is also a legitimate, widely-used sysadmin tool; Medium confidence in the
        catalog reflects that its presence alone does not establish malicious intent.
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
    if (-not $Row.PSObject.Properties['FileName']) { return $null }

    $fileName = [string]$Row.FileName
    if ([string]::IsNullOrEmpty($fileName)) { return $null }
    if ($fileName -notmatch '(?i)^psexesvc\.exe$') { return $null }

    $initiator = if ($Row.PSObject.Properties['InitiatingProcessFileName']) { [string]$Row.InitiatingProcessFileName } else { '(unknown)' }

    return [PSCustomObject]@{
        RuleId      = 'LATMOVE-001'
        Explanation = "PSEXESVC.exe was created on this device (initiated by '$initiator') -- the service artifact Sysinternals PsExec installs on a TARGET when used for remote command execution. This device was the target of a PsExec-style connection, not necessarily the source."
    }
}
