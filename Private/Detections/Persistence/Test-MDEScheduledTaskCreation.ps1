function Test-MDEScheduledTaskCreation {
    <#
    .SYNOPSIS
        Rule PERSIST-002: detects creation of a new scheduled task via schtasks.exe or PowerShell.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's FileName is schtasks.exe with a /create flag,
        or a PowerShell host whose command line references Register-ScheduledTask -- both
        create a task that survives reboot without needing a registry autostart entry. MITRE
        ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task).

        Deliberately Low confidence in the catalog: scheduled-task creation is routine and
        extremely common in managed enterprise environments (SCCM, backup software, update
        mechanisms). This rule is intentionally broad; pair with a baseline/exclusion config
        for known task-creating tooling in your environment.
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

    $isSchtasksCreate = ($fileName -match '(?i)^schtasks\.exe$') -and ($commandLine -match '(?i)/create\b')
    $isPowerShellRegisterTask = ($fileName -match '(?i)^(powershell|pwsh)\.exe$') -and ($commandLine -match '(?i)Register-ScheduledTask')

    if (-not ($isSchtasksCreate -or $isPowerShellRegisterTask)) { return $null }

    return [PSCustomObject]@{
        RuleId      = 'PERSIST-002'
        Explanation = "'$fileName' created a new scheduled task: $commandLine. Scheduled tasks are a common persistence mechanism that survives reboot."
    }
}
