function Test-MDEEncodedPowerShellCommand {
    <#
    .SYNOPSIS
        Rule EXEC-001: detects a PowerShell host launched with a Base64/-EncodedCommand payload.
    .DESCRIPTION
        Fires when the row is a DeviceProcessEvents process-creation event whose FileName is
        a PowerShell host (powershell.exe, powershell_ise.exe, or pwsh.exe) and whose
        ProcessCommandLine successfully decodes via ConvertFrom-MDEEncodedCommand's Base64/
        -EncodedCommand method. Delegates all decoding to ConvertFrom-MDEEncodedCommand
        (requirement #6) rather than duplicating regex logic here, so the decode behavior a
        rule reports and the decode behavior an analyst gets from the standalone cmdlet are
        guaranteed identical.
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
    if ($fileName -notmatch '(?i)^(powershell|powershell_ise|pwsh)\.exe$') { return $null }

    $decodeResult = ConvertFrom-MDEEncodedCommand -CommandLine $commandLine
    if ($decodeResult.MethodsApplied -notcontains 'Base64/-EncodedCommand (UTF-16LE)') {
        return $null
    }

    $preview = if ($decodeResult.Decoded.Length -gt 200) {
        $decodeResult.Decoded.Substring(0, 200) + '...'
    }
    else {
        $decodeResult.Decoded
    }

    return [PSCustomObject]@{
        RuleId      = 'EXEC-001'
        Explanation = "'$fileName' was launched with a Base64-encoded (-EncodedCommand) payload. Decoded, it reads: $preview"
    }
}
