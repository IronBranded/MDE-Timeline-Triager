function Test-MDEAmsiBypassIndicator {
    <#
    .SYNOPSIS
        Rule DEFEVA-002: detects a command line referencing AMSI internals associated with bypass techniques.
    .DESCRIPTION
        Fires when a DeviceProcessEvents row's ProcessCommandLine references
        System.Management.Automation.AmsiUtils, AmsiScanBuffer, or amsiInitFailed -- .NET
        reflection targets and field names that appear across the large majority of publicly
        documented AMSI-bypass proofs-of-concept, which patch or blind the Antimalware Scan
        Interface in-process before running further (often otherwise-detectable) code.
        MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools).
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
    if (-not $Row.PSObject.Properties['ProcessCommandLine']) { return $null }

    $commandLine = [string]$Row.ProcessCommandLine
    if ([string]::IsNullOrEmpty($commandLine)) { return $null }

    if ($commandLine -notmatch '(?i)amsiutils|amsiscanbuffer|amsiinitfailed|System\.Management\.Automation\.AmsiUtils') {
        return $null
    }
    $matchedTerm = $Matches[0]

    $fileName = if ($Row.PSObject.Properties['FileName']) { [string]$Row.FileName } else { '(unknown)' }

    return [PSCustomObject]@{
        RuleId      = 'DEFEVA-002'
        Explanation = "'$fileName' command line references AMSI internals ('$matchedTerm'), a pattern seen in AMSI-bypass techniques that blind PowerShell's antimalware scanning before running further code."
    }
}
