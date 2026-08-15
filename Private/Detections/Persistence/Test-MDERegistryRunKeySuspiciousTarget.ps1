function Test-MDERegistryRunKeySuspiciousTarget {
    <#
    .SYNOPSIS
        Rule PERSIST-001: detects an autostart Run/RunOnce registry value pointing at a user-writable path.
    .DESCRIPTION
        Fires when a DeviceRegistryEvents row's RegistryKey falls under
        ...\CurrentVersion\Run (the substring match also covers RunOnce, RunServices, and
        RunServicesOnce -- all historical autostart locations sharing that path segment) AND
        the value being set (RegistryValueData) references AppData\Roaming, ProgramData,
        \Temp\, or a public folder -- the same suspicious-path signal as DEFEVA-001, applied
        here to the *persistence target* rather than a process's own execution location.
        Combining "this survives reboot" with "this points somewhere a standard user could
        have written to" is a stronger, more specific signal than either alone. MITRE ATT&CK
        T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder).
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

    if ($Row.SourceTable -ne 'DeviceRegistryEvents') { return $null }
    if (-not $Row.PSObject.Properties['RegistryKey'] -or -not $Row.PSObject.Properties['RegistryValueData']) { return $null }

    $registryKey = [string]$Row.RegistryKey
    $valueData = [string]$Row.RegistryValueData
    if ([string]::IsNullOrEmpty($registryKey) -or [string]::IsNullOrEmpty($valueData)) { return $null }

    if ($registryKey -notmatch '(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run') { return $null }
    if ($valueData -notmatch '(?i)\\AppData\\Roaming(\\|$)|\\ProgramData(\\|$)|\\Temp\\|\\Users\\Public\\') { return $null }

    $valueName = if ($Row.PSObject.Properties['RegistryValueName']) { [string]$Row.RegistryValueName } else { '(unknown)' }

    return [PSCustomObject]@{
        RuleId      = 'PERSIST-001'
        Explanation = "Autostart registry value '$valueName' under '$registryKey' points to '$valueData', a user-writable path commonly used to stage payloads rather than a standard installation directory."
    }
}
