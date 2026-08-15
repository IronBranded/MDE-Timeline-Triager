function Test-MDESensorTamperingRegistry {
    <#
    .SYNOPSIS
        Rule DEFEVA-003: detects a registry write consistent with disabling Defender protection.
    .DESCRIPTION
        Fires when a DeviceRegistryEvents row targets a Windows Defender-related registry key
        (matching "Windows Defender", "Windows Advanced Threat Protection", or "WinDefend" in
        RegistryKey) AND either:
          - sets one of DisableAntiSpyware / DisableRealtimeMonitoring /
            DisableBehaviorMonitoring / DisableIOAVProtection / DisableAntiVirus to a
            true-like value (1 or True -- note MDE's boolean-field text representation
            changed from numeric 1/0 to textual True/False on 2026-02-25, so both are
            checked); or
          - sets the WinDefend service's Start value to 4 (Windows service "Disabled").
        Deliberately checks the VALUE, not just the value name: DisableRealtimeMonitoring
        being set to False/0 means protection is being left ON (or re-enabled), which is the
        opposite of tampering and must not fire this rule. MITRE ATT&CK T1562.001 (Impair
        Defenses: Disable or Modify Tools).
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
    if (-not $Row.PSObject.Properties['RegistryKey'] -or -not $Row.PSObject.Properties['RegistryValueName']) { return $null }

    $registryKey = [string]$Row.RegistryKey
    $valueName = [string]$Row.RegistryValueName
    if ([string]::IsNullOrEmpty($registryKey) -or [string]::IsNullOrEmpty($valueName)) { return $null }

    if ($registryKey -notmatch '(?i)Windows Defender|Windows Advanced Threat Protection|WinDefend') {
        return $null
    }

    $valueData = if ($Row.PSObject.Properties['RegistryValueData']) { [string]$Row.RegistryValueData } else { '' }

    $isDisableFlagTamper = ($valueName -match '(?i)^(DisableAntiSpyware|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableAntiVirus)$') -and
                           ($valueData -match '(?i)^(1|true)$')
    $isServiceStartTamper = ($valueName -match '(?i)^Start$') -and ($valueData -match '^4$')

    if (-not ($isDisableFlagTamper -or $isServiceStartTamper)) { return $null }

    return [PSCustomObject]@{
        RuleId      = 'DEFEVA-003'
        Explanation = "Registry value '$valueName' under '$registryKey' was set to '$valueData' -- this key/value/data combination is associated with disabling or weakening Microsoft Defender's real-time protection."
    }
}
