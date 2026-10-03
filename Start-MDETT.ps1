<#
.SYNOPSIS
    Interactive, menu-driven entry point for MDETimelineTriage -- run this directly for the
    streamlined path; the underlying cmdlets (Import-MDETimeline, Invoke-MDEDetection,
    New-MDEReport, Invoke-MDETriage, ConvertFrom-MDEEncodedCommand, Test-MDEBaseline,
    Get-MDEDetectionCatalog) remain fully usable on their own for scripted/pipeline use.
.DESCRIPTION
    Modeled on the launcher pattern from IronBranded/Microsoft-Audit-Tracker-V2
    (github.com/IronBranded/Microsoft-Audit-Tracker-V2): one script, a numbered menu, no
    cmdlet syntax to remember. This does not replace the module -- every menu option is a
    thin wrapper around a real public cmdlet, so nothing here is logic that isn't already
    independently tested via the Pester suite. The launcher's own job is only ever
    presentation and prompting.

    Self-locates the module via $PSScriptRoot, so it works regardless of the current working
    directory, run either from inside the repository or after being copied elsewhere
    alongside the module folder.
.EXAMPLE
    .\Start-MDETT.ps1

    Launches the interactive menu.
.EXAMPLE
    pwsh ./Start-MDETT.ps1

    Same, from macOS/Linux.
.NOTES
    Requirement #13 (PSScriptAnalyzer, no unexplained suppressions): PSAvoidUsingWriteHost is
    suppressed script-wide below, deliberately, not as a blanket habit. This file is a
    top-level interactive console script, not a pipeline-composable module function --
    Write-Host is the *correct* tool here (immediate, formatted console output for a human
    reading the terminal directly), and using Write-Output instead would incorrectly mix
    menu/prompt text into a pipeline output stream this script was never meant to produce.
    Every actual module function (Public/, Private/) still uses Write-Verbose/-Warning/
    -Progress exclusively, and Tests/Invoke-ManualLint.ps1 (this repo's stand-in for
    PSScriptAnalyzer where the real tool can't run) carries a matching, equally-explicit
    exception for this one file.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Interactive console launcher, not a pipeline-composable module function -- see .NOTES above.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$moduleManifestPath = Join-Path -Path $PSScriptRoot -ChildPath 'MDETimelineTriage.psd1'
if (-not (Test-Path -Path $moduleManifestPath -PathType Leaf)) {
    Write-Host "MDETimelineTriage.psd1 not found next to this script ($PSScriptRoot)." -ForegroundColor Red
    Write-Host 'Start-MDETT.ps1 must stay in the same folder as the module manifest.' -ForegroundColor Red
    exit 1
}

try {
    Import-Module $moduleManifestPath -Force -ErrorAction Stop
}
catch {
    Write-Host "Failed to import MDETimelineTriage: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

function Write-MDETTBanner {
    $moduleVersion = (Get-Module MDETimelineTriage).Version.ToString()
    Write-Host ''
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host '   MDETT -- MDE Windows Timeline Triage'  -ForegroundColor Cyan
    Write-Host "   v$moduleVersion" -ForegroundColor DarkCyan
    Write-Host '========================================================' -ForegroundColor Cyan
    Write-Host ''
}

function Wait-MDETTKeypress {
    Write-Host ''
    Write-Host 'Press Enter to return to the menu...' -ForegroundColor DarkGray -NoNewline
    [void](Read-Host)
}

function Read-MDETTPath {
    param([string]$Prompt, [switch]$AllowBlank)
    while ($true) {
        $value = Read-Host -Prompt $Prompt
        if ([string]::IsNullOrWhiteSpace($value)) {
            if ($AllowBlank) { return $null }
            Write-Host '  A value is required.' -ForegroundColor Yellow
            continue
        }
        $value = $value.Trim('"', "'", ' ')
        if (-not (Test-Path -Path $value -PathType Leaf)) {
            Write-Host "  '$value' does not exist or is not a file. Try again, or Ctrl+C to cancel." -ForegroundColor Yellow
            continue
        }
        return $value
    }
}

function Read-MDETTYesNo {
    param([string]$Prompt, [bool]$DefaultYes = $false)
    $suffix = if ($DefaultYes) { '[Y/n]' } else { '[y/N]' }
    $response = Read-Host -Prompt "$Prompt $suffix"
    if ([string]::IsNullOrWhiteSpace($response)) { return $DefaultYes }
    return $response.Trim().ToUpperInvariant().StartsWith('Y')
}

function Show-MDETTRecap {
    param([string]$HtmlPath, [string]$CsvPath, [string]$NavigatorPath, [int]$FindingCount, [System.Collections.Generic.Dictionary[string, int]]$SeverityCounts)

    Write-Host ''
    Write-Host '--- Triage complete ---' -ForegroundColor Green
    Write-Host "  Findings: $FindingCount"
    if ($SeverityCounts -and $FindingCount -gt 0) {
        foreach ($sev in @('Critical', 'High', 'Medium', 'Low', 'Informational')) {
            $count = if ($SeverityCounts.ContainsKey($sev)) { $SeverityCounts[$sev] } else { 0 }
            if ($count -gt 0) {
                $color = switch ($sev) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; default { 'Gray' } }
                Write-Host "    $sev`: $count" -ForegroundColor $color
            }
        }
    }
    Write-Host "  Report:    $HtmlPath"
    Write-Host "  CSV:       $CsvPath"
    if ($NavigatorPath -and (Test-Path -Path $NavigatorPath -PathType Leaf)) {
        Write-Host "  ATT&CK:    $NavigatorPath"
    }
}

function Open-MDETTReport {
    param([string]$Path)
    if (-not (Test-Path -Path $Path -PathType Leaf)) { return }
    try {
        Start-Process -FilePath $Path -ErrorAction Stop
        Write-Host '  Opened in your default browser.' -ForegroundColor DarkGray
    }
    catch {
        # Start-Process opening a file by path needs a GUI file-association mechanism
        # underneath (the OS shell on Windows/macOS, xdg-open on Linux) -- not guaranteed
        # on a headless/server Linux box, even though this launcher is itself interactive.
        # Degrade to a one-line notice rather than let this fail the whole triage run.
        Write-Host "  Could not auto-open the report ($($_.Exception.Message)) -- open it manually: $Path" -ForegroundColor Yellow
    }
}

function Invoke-MDETTFullTriage {
    Write-Host ''
    Write-Host '=== Full Triage ===' -ForegroundColor Cyan
    $csvPath = Read-MDETTPath -Prompt 'Path to the MDE timeline CSV export'

    $useBaseline = Read-MDETTYesNo -Prompt 'Apply a baseline/exclusion config?'
    $baselinePath = if ($useBaseline) { Read-MDETTPath -Prompt 'Path to the baseline/exclusion JSON' } else { $null }

    $useCustomIoc = Read-MDETTYesNo -Prompt 'Apply a custom IOC config?'
    $customIocPath = if ($useCustomIoc) { Read-MDETTPath -Prompt 'Path to the custom IOC JSON' } else { $null }

    $redact = Read-MDETTYesNo -Prompt 'Redact usernames/hostnames in the report?'

    $params = @{ Path = $csvPath; Verbose = $true; ExportAttackNavigatorLayer = $true }
    if ($baselinePath) { $params['BaselineConfigPath'] = $baselinePath }
    if ($customIocPath) { $params['CustomIOCConfigPath'] = $customIocPath }
    if ($redact) { $params['Redact'] = $true }
    # OutputPath intentionally omitted -- Invoke-MDETriage/New-MDEReport resolve to the
    # Downloads folder with MDETT-dated file names automatically when it isn't supplied.

    try {
        Invoke-MDETriage @params
    }
    catch {
        Write-Host "Triage failed: $($_.Exception.Message)" -ForegroundColor Red
        Wait-MDETTKeypress
        return
    }

    $downloadsFolder = & (Get-Module MDETimelineTriage) { Get-MDEDownloadsFolder }
    $dateStamp = (Get-Date).ToString('yyyy-MM-dd')
    $htmlPath = Join-Path -Path $downloadsFolder -ChildPath "MDETT-$dateStamp-Report.html"
    $csvOutPath = Join-Path -Path $downloadsFolder -ChildPath "MDETT-$dateStamp-Findings.csv"
    $navigatorOutPath = Join-Path -Path $downloadsFolder -ChildPath "MDETT-$dateStamp-AttackNavigatorLayer.json"

    $severityCounts = [System.Collections.Generic.Dictionary[string, int]]::new()
    $findingCount = 0
    if (Test-Path -Path $csvOutPath -PathType Leaf) {
        $csvRows = @(Import-Csv -Path $csvOutPath)
        $findingCount = $csvRows.Count
        foreach ($row in $csvRows) {
            if ($severityCounts.ContainsKey($row.Severity)) { $severityCounts[$row.Severity]++ }
            else { $severityCounts[$row.Severity] = 1 }
        }
    }

    Show-MDETTRecap -HtmlPath $htmlPath -CsvPath $csvOutPath -NavigatorPath $navigatorOutPath -FindingCount $findingCount -SeverityCounts $severityCounts
    Open-MDETTReport -Path $htmlPath
    Wait-MDETTKeypress
}

function Invoke-MDETTDecode {
    Write-Host ''
    Write-Host '=== Decode a Command Line ===' -ForegroundColor Cyan
    $commandLine = Read-Host -Prompt 'Command line to decode'
    if ([string]::IsNullOrWhiteSpace($commandLine)) { Write-Host '  Nothing entered.' -ForegroundColor Yellow; Wait-MDETTKeypress; return }
    $result = ConvertFrom-MDEEncodedCommand -CommandLine $commandLine
    Write-Host ''
    Write-Host "  Scope:           $($result.Scope)"
    Write-Host "  Methods applied: $($result.MethodsApplied -join ', ')"
    Write-Host "  Decoded:         $($result.Decoded)"
    Wait-MDETTKeypress
}

function Invoke-MDETTValidateConfig {
    Write-Host ''
    Write-Host '=== Validate a Config File ===' -ForegroundColor Cyan
    $configPath = Read-MDETTPath -Prompt 'Path to the baseline/exclusion or custom-IOC JSON'
    $result = Test-MDEBaseline -Path $configPath
    Write-Host ''
    Write-Host "  Config type: $($result.ConfigType)"
    Write-Host "  Valid:       $($result.IsValid)" -ForegroundColor $(if ($result.IsValid) { 'Green' } else { 'Red' })
    if ($result.Errors.Count -gt 0) {
        Write-Host "  Errors ($($result.Errors.Count)):" -ForegroundColor Yellow
        foreach ($e in $result.Errors) { Write-Host "    - $e" }
    }
    Wait-MDETTKeypress
}

function Invoke-MDETTShowCatalog {
    Write-Host ''
    Write-Host '=== Detection Catalog ===' -ForegroundColor Cyan
    Write-Host ''
    Get-MDEDetectionCatalog | Sort-Object Tactic, RuleId | ForEach-Object {
        $color = switch ($_.Severity) { 'Critical' { 'Red' }; 'High' { 'DarkYellow' }; 'Medium' { 'Yellow' }; default { 'Gray' } }
        Write-Host ("  {0,-14} {1,-38} {2,-9} {3}" -f $_.RuleId, $_.Name, $_.Severity, $_.TechniqueId) -ForegroundColor $color
    }
    Wait-MDETTKeypress
}

function Invoke-MDETTDiagnostic {
    Write-Host ''
    Write-Host '=== Diagnostic Check ===' -ForegroundColor Cyan
    Write-Host ''
    $psVersion = $PSVersionTable.PSVersion
    Write-Host "  PowerShell version: $psVersion $(if ($psVersion.Major -ge 7) {'(pwsh)'} elseif ($psVersion.Major -eq 5) {'(Windows PowerShell)'} else {'(unsupported -- 5.1 or 7+ required)'})"
    $mod = Get-Module MDETimelineTriage
    Write-Host "  Module loaded:       $($null -ne $mod) ($($mod.Version), $($mod.ExportedCommands.Count) commands exported)"
    $downloadsFolder = & (Get-Module MDETimelineTriage) { Get-MDEDownloadsFolder }
    Write-Host "  Downloads folder:    $downloadsFolder $(if (Test-Path -Path $downloadsFolder -PathType Container) {'(exists)'} else {'(will be created on first report)'})"
    Wait-MDETTKeypress
}

$exitRequested = $false
while (-not $exitRequested) {
    Write-MDETTBanner
    Write-Host '  [1] Full Triage         -- parse, detect, and generate the report (the common case)'
    Write-Host '  [2] Decode a Command Line'
    Write-Host '  [3] Validate a Config File'
    Write-Host '  [4] View Detection Catalog'
    Write-Host '  [D] Diagnostic Check'
    Write-Host '  [Q] Quit'
    Write-Host ''
    $choice = Read-Host -Prompt 'Select an option'

    switch ($choice.Trim().ToUpperInvariant()) {
        '1' { Invoke-MDETTFullTriage }
        '2' { Invoke-MDETTDecode }
        '3' { Invoke-MDETTValidateConfig }
        '4' { Invoke-MDETTShowCatalog }
        'D' { Invoke-MDETTDiagnostic }
        'Q' { $exitRequested = $true }
        default { Write-Host "  Unrecognized option '$choice'." -ForegroundColor Yellow; Start-Sleep -Milliseconds 800 }
    }
}

Write-Host ''
Write-Host 'Exiting MDETT.' -ForegroundColor DarkGray
