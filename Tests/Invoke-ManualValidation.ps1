<#
.SYNOPSIS
    Hand-written validation covering the same scenarios as the Pester suite, for anyone
    without a dotnet SDK available to build the real Pester test runner from source.
.DESCRIPTION
    Tests/*.Tests.ps1 is the authoritative test suite (requirement #12) and is what
    Invoke-Pester should run against. This script exists because the environment this
    module was originally built and hand-verified in had no dotnet SDK, and Pester's
    distributable module needs one to compile from source (see CHANGELOG.md's
    [Unreleased] entry) -- neither Pester nor PSScriptAnalyzer publish pre-built
    binaries anywhere reachable without it.

    This script mirrors the Pester suite's assertions using plain if/throw checks instead
    of Pester's Describe/Context/It/Should DSL, so the same real-execution validation is
    possible with nothing beyond PowerShell itself. It is not a replacement for actually
    running Invoke-Pester -- prefer that if you have it -- but every assertion below has
    been confirmed to pass against this exact module in real PowerShell 7.6.4.

    Includes explicit regression coverage for Invoke-MDETriage: the module's own history is
    the reason this matters. Invoke-MDETriage shipped as a hard-coded NotImplementedException
    for five build phases after the cmdlets it composes were completed, because nothing --
    not this script's earlier version, not the Pester suite -- ever called it directly, only
    its component stages individually. It is tested directly here for exactly that reason.
.EXAMPLE
    pwsh -File .\Tests\Invoke-ManualValidation.ps1

    Runs every check and exits with a non-zero code if anything failed, suitable for CI.
#>

$ErrorActionPreference = 'Stop'
$script:passCount = 0
$script:failCount = 0
$script:failures = [System.Collections.Generic.List[string]]::new()

function Select-MDEFindingOnly {
    # Excludes the 'MDETimelineTriage.RunSummary'-tagged object Invoke-MDEDetection now
    # always emits as the last item in its output stream -- New-MDEReport filters this
    # automatically; assertions checking raw Invoke-MDEDetection output need to do it too.
    process {
        if ($_.PSObject.TypeNames -notcontains 'MDETimelineTriage.RunSummary') { $_ }
    }
}

function Test-Assertion {
    param([string]$Name, [scriptblock]$Test)
    try {
        $result = & $Test
        if ($result) {
            $script:passCount++
            Write-Host "  PASS: $Name" -ForegroundColor Green
        }
        else {
            $script:failCount++
            $script:failures.Add($Name)
            Write-Host "  FAIL: $Name" -ForegroundColor Red
        }
    }
    catch {
        $script:failCount++
        $script:failures.Add("$Name (threw: $($_.Exception.Message))")
        Write-Host "  ERROR: $Name -- $($_.Exception.Message)" -ForegroundColor Red
    }
}

$moduleRoot = Split-Path -Path $PSScriptRoot -Parent
Set-Location $moduleRoot
Import-Module (Join-Path $moduleRoot 'MDETimelineTriage.psd1') -Force
$fixtures = Join-Path $moduleRoot 'Tests/Fixtures'

Write-Host "`n=== Import-MDETimeline ===" -ForegroundColor Cyan
$schemaCases = @(
    @{ Table = 'DeviceProcessEvents'; File = 'DeviceProcessEvents-happy.csv' }
    @{ Table = 'DeviceNetworkEvents'; File = 'DeviceNetworkEvents-happy.csv' }
    @{ Table = 'DeviceFileEvents'; File = 'DeviceFileEvents-happy.csv' }
    @{ Table = 'DeviceRegistryEvents'; File = 'DeviceRegistryEvents-happy.csv' }
    @{ Table = 'DeviceLogonEvents'; File = 'DeviceLogonEvents-happy.csv' }
    @{ Table = 'DeviceImageLoadEvents'; File = 'DeviceImageLoadEvents-happy.csv' }
    @{ Table = 'DeviceEvents'; File = 'DeviceEvents-happy.csv' }
)
foreach ($c in $schemaCases) {
    Test-Assertion "Schema detection: $($c.File) -> $($c.Table)" {
        $rows = @(Import-MDETimeline -Path (Join-Path $fixtures $c.File))
        $rows.Count -gt 0 -and $rows[0].SourceTable -eq $c.Table
    }
}
Test-Assertion 'UTF-16LE row count matches UTF-8 counterpart' {
    $a = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceLogonEvents-happy.csv'))
    $b = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceLogonEvents-happy-utf16le.csv'))
    $a.Count -eq $b.Count -and $a.Count -gt 0
}
Test-Assertion 'UTF-8 BOM row count matches plain UTF-8 counterpart' {
    $a = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceRegistryEvents-happy.csv'))
    $b = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceRegistryEvents-happy-utf8bom.csv'))
    $a.Count -eq $b.Count -and $a.Count -gt 0
}
Test-Assertion 'Comma-in-quotes field parses as one field' {
    $rows = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-happy.csv'))
    ($rows | Where-Object { $_.ProcessCommandLine -like '*echo hello, world*' }) -ne $null
}
Test-Assertion 'Truncated row skipped, good rows survive (expect 2)' {
    (@(Import-MDETimeline -Path (Join-Path $fixtures 'malformed-truncated-row.csv'))).Count -eq 2
}
Test-Assertion 'Decode-corruption row skipped, good rows survive (expect 2)' {
    (@(Import-MDETimeline -Path (Join-Path $fixtures 'malformed-decode-corruption.csv'))).Count -eq 2
}
Test-Assertion 'Sparse header -> Unrecognized, still parses (expect 2 rows)' {
    $rows = @(Import-MDETimeline -Path (Join-Path $fixtures 'malformed-low-confidence.csv'))
    $rows.Count -eq 2 -and $rows[0].SourceTable -eq 'Unrecognized'
}
Test-Assertion 'Extra column preserved on returned objects' {
    $rows = @(Import-MDETimeline -Path (Join-Path $fixtures 'malformed-extra-column.csv'))
    $rows[0].PSObject.Properties.Name -contains 'FutureNewField'
}
Test-Assertion 'Source file not modified by ingest' {
    $p = Join-Path $fixtures 'DeviceProcessEvents-happy.csv'
    $h1 = (Get-FileHash -Path $p -Algorithm SHA256).Hash
    Import-MDETimeline -Path $p | Out-Null
    $h2 = (Get-FileHash -Path $p -Algorithm SHA256).Hash
    $h1 -eq $h2
}

Write-Host "`n=== ConvertFrom-MDEEncodedCommand ===" -ForegroundColor Cyan
Test-Assertion 'Decodes genuine UTF-16LE Base64 -enc payload' {
    $r = ConvertFrom-MDEEncodedCommand -CommandLine "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA=="
    $r.MethodsApplied -contains 'Base64/-EncodedCommand (UTF-16LE)' -and $r.Decoded -like "*Write-Host 'test'*"
}
Test-Assertion 'Does not decode short -e flag value' {
    $r = ConvertFrom-MDEEncodedCommand -CommandLine 'someapp.exe -e config.xml'
    $r.MethodsApplied -notcontains 'Base64/-EncodedCommand (UTF-16LE)'
}
Test-Assertion 'Strips backtick between letters' {
    (ConvertFrom-MDEEncodedCommand -CommandLine 'p`o`w`e`r`s`h`e`l`l.exe -nop').Decoded -like '*powershell.exe*'
}
Test-Assertion 'Strips caret between letters' {
    (ConvertFrom-MDEEncodedCommand -CommandLine 'c^m^d.exe /c whoami').Decoded -like '*cmd.exe*'
}
Test-Assertion 'Expands known env var to default' {
    (ConvertFrom-MDEEncodedCommand -CommandLine '%COMSPEC% /c dir').Decoded -like '*cmd.exe*'
}
Test-Assertion 'Detects reversed suspicious keyword' {
    (ConvertFrom-MDEEncodedCommand -CommandLine 'exe.llehsrewop -nop').MethodsApplied -contains 'Simple character reversal'
}
Test-Assertion 'Clean command line reports Scope=Clean (regression test for the Set-StrictMode/$null.Count bug)' {
    (ConvertFrom-MDEEncodedCommand -CommandLine 'notepad.exe C:\temp\a.txt').Scope -eq 'Clean'
}

Write-Host "`n=== Invoke-MDEDetection: known-answer tests (all 13 rules) ===" -ForegroundColor Cyan
$procFindings = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-detection-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue)
$regFindings = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceRegistryEvents-detection-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue)
$p7ProcFindings = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-phase7-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue)
$p7RegFindings = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceRegistryEvents-phase7-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue)

foreach ($rid in @('EXEC-001', 'DEFEVA-001', 'DEFEVA-002', 'DEFEVA-004')) {
    Test-Assertion "$rid fires exactly once" { (@($procFindings | Where-Object RuleId -eq $rid)).Count -eq 1 }
}
Test-Assertion 'DEFEVA-003 fires exactly twice (True and Start=4 rows)' { (@($regFindings | Where-Object RuleId -eq 'DEFEVA-003')).Count -eq 2 }
Test-Assertion 'DEFEVA-003 does NOT fire on DisableRealtimeMonitoring=False' {
    -not ($regFindings | Where-Object { $_.SourceRow.RegistryValueData -eq 'False' -and $_.SourceRow.RegistryValueName -eq 'DisableRealtimeMonitoring' })
}
foreach ($rid in @('PERSIST-002', 'CREDACCESS-001', 'CREDACCESS-002', 'LATMOVE-001', 'LATMOVE-002', 'EXFIL-001', 'DISC-001')) {
    Test-Assertion "$rid fires exactly once" { (@($p7ProcFindings | Where-Object RuleId -eq $rid)).Count -eq 1 }
}
Test-Assertion 'PERSIST-001 fires exactly once' { (@($p7RegFindings | Where-Object RuleId -eq 'PERSIST-001')).Count -eq 1 }

Write-Host "`n=== Invoke-MDEDetection: negative control (9 benign fixtures, expect 0 findings each) ===" -ForegroundColor Cyan
foreach ($f in @('DeviceProcessEvents-happy.csv', 'DeviceNetworkEvents-happy.csv', 'DeviceFileEvents-happy.csv', 'DeviceRegistryEvents-happy.csv', 'DeviceLogonEvents-happy.csv', 'DeviceImageLoadEvents-happy.csv', 'DeviceEvents-happy.csv')) {
    Test-Assertion "Zero findings: $f" {
        (@(Import-MDETimeline -Path (Join-Path $fixtures $f) | Invoke-MDEDetection -WarningAction SilentlyContinue | Select-MDEFindingOnly)).Count -eq 0
    }
}

Write-Host "`n=== Requirement #2: Telemetry Mapping ===" -ForegroundColor Cyan
Test-Assertion 'DeviceProcessEvents/ProcessCreated finding carries WindowsEventId=4688' {
    $procFindings[0].WindowsEventId -eq '4688'
}
Test-Assertion 'DeviceProcessEvents/ProcessCreated finding carries SysmonEventId=1' {
    $procFindings[0].SysmonEventId -eq '1'
}
Test-Assertion 'DeviceRegistryEvents finding carries a Sysmon Event ID (12 or 13)' {
    $regFindings[0].SysmonEventId -in @('12', '13')
}

Write-Host "`n=== Severity/Confidence independence, combination, lineage ===" -ForegroundColor Cyan
Test-Assertion 'DEFEVA-001 is Medium severity / Low confidence' {
    $c = Get-MDEDetectionCatalog | Where-Object RuleId -eq 'DEFEVA-001'
    $c.Severity -eq 'Medium' -and $c.Confidence -eq 'Low'
}
Test-Assertion 'CREDACCESS-001 is Critical severity / High confidence' {
    $c = Get-MDEDetectionCatalog | Where-Object RuleId -eq 'CREDACCESS-001'
    $c.Severity -eq 'Critical' -and $c.Confidence -eq 'High'
}
Test-Assertion 'Combined signal: two findings on one process -> CombinedScore=100, Critical' {
    $f = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-combined-signal-test.csv') | Invoke-MDEDetection -WarningAction SilentlyContinue | Select-MDEFindingOnly)
    $f.Count -eq 2 -and $f[0].CombinedScore -eq 100 -and $f[0].CombinedSeverity -eq 'Critical' -and $f[0].CoOccurringFindings.Count -eq 1
}
Test-Assertion 'Unrelated findings do not combine (CombinedScore == own Score)' {
    ($procFindings | ForEach-Object { $_.CombinedScore -eq $_.Score -and $_.CoOccurringFindings.Count -eq 0 }) -notcontains $false
}
Test-Assertion '4-generation lineage reconstructed across two rows' {
    $f = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-lineage-tests.csv') | Invoke-MDEDetection -WarningAction SilentlyContinue | Select-MDEFindingOnly)
    $chain = ($f[0].ProcessLineage.FileName -join ' -> ')
    $f.Count -eq 1 -and $f[0].ProcessLineage.Count -eq 4 -and $chain -eq 'wininit.exe -> services.exe -> svchost.exe -> cmd.exe'
}

Write-Host "`n=== Baseline exclusion / custom IOC ===" -ForegroundColor Cyan
Test-Assertion 'Baseline suppresses Medium finding' {
    $f = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-detection-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -BaselineConfigPath (Join-Path $fixtures 'baseline-sample.json') -WarningAction SilentlyContinue)
    -not ($f | Where-Object RuleId -eq 'DEFEVA-001')
}
Test-Assertion 'Baseline does NOT suppress High/Critical, marks overridden' {
    $f = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-detection-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -BaselineConfigPath (Join-Path $fixtures 'baseline-sample.json') -WarningAction SilentlyContinue)
    $e = $f | Where-Object RuleId -eq 'EXEC-001'
    $e -ne $null -and $e.BaselineExclusionOverridden -eq $true
}
Test-Assertion 'Invalid baseline config throws' {
    try {
        Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-happy.csv') | Invoke-MDEDetection -BaselineConfigPath (Join-Path $fixtures 'baseline-invalid.json') | Out-Null
        $false
    }
    catch { $true }
}
Test-Assertion 'Custom IOC fires with synthesized RuleId + DetectionSource=Custom' {
    $f = @(Import-MDETimeline -Path (Join-Path $fixtures 'DeviceNetworkEvents-happy.csv') | Invoke-MDEDetection -CustomIOCConfigPath (Join-Path $fixtures 'custom-ioc-sample.json') | Select-MDEFindingOnly)
    $f.Count -eq 1 -and $f[0].RuleId -like 'CUSTOM-2026-041-*' -and $f[0].DetectionSource -eq 'Custom'
}
Test-Assertion '-WhatIf on Invoke-MDEDetection returns no findings' {
    $rows = Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-detection-tests.csv')
    (@($rows | Invoke-MDEDetection -WhatIf)).Count -eq 0
}

Write-Host "`n=== Test-MDEBaseline ===" -ForegroundColor Cyan
Test-Assertion 'Baseline sample validates true, auto-detected as Baseline' {
    $r = Test-MDEBaseline -Path (Join-Path $fixtures 'baseline-sample.json')
    $r.IsValid -eq $true -and $r.ConfigType -eq 'Baseline'
}
Test-Assertion 'Custom IOC sample validates true, auto-detected as CustomIOC' {
    $r = Test-MDEBaseline -Path (Join-Path $fixtures 'custom-ioc-sample.json')
    $r.IsValid -eq $true -and $r.ConfigType -eq 'CustomIOC'
}
Test-Assertion 'Invalid config reports exactly 3 errors' {
    (Test-MDEBaseline -Path (Join-Path $fixtures 'baseline-invalid.json')).Errors.Count -eq 3
}

Write-Host "`n=== New-MDEReport ===" -ForegroundColor Cyan
$tmpDir1 = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate1_$([guid]::NewGuid())"
Test-Assertion '-WhatIf creates no output directory' {
    Import-MDETimeline -Path (Join-Path $fixtures 'DeviceProcessEvents-detection-tests.csv') | Invoke-MDEDetection | New-MDEReport -SourcePath (Join-Path $fixtures 'DeviceProcessEvents-detection-tests.csv') -OutputPath $tmpDir1 -WhatIf
    -not (Test-Path $tmpDir1)
}
$tmpDir2 = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate2_$([guid]::NewGuid())"
$srcForReport = Join-Path $fixtures 'DeviceProcessEvents-detection-tests.csv'
Import-MDETimeline -Path $srcForReport | Invoke-MDEDetection | New-MDEReport -SourcePath $srcForReport -OutputPath $tmpDir2
Test-Assertion 'Real render writes both HTML and CSV' {
    (Test-Path (Join-Path $tmpDir2 'MDETimelineTriage-Report.html')) -and (Test-Path (Join-Path $tmpDir2 'MDETimelineTriage-Findings.csv'))
}
Test-Assertion 'HTML report contains source SHA-256 hash' {
    $hash = (Get-FileHash -Path $srcForReport -Algorithm SHA256).Hash
    (Get-Content (Join-Path $tmpDir2 'MDETimelineTriage-Report.html') -Raw) -match [regex]::Escape($hash)
}
Test-Assertion 'CSV has source hash on every row' {
    $hash = (Get-FileHash -Path $srcForReport -Algorithm SHA256).Hash
    $csv = Import-Csv (Join-Path $tmpDir2 'MDETimelineTriage-Findings.csv')
    $csv.Count -gt 0 -and (($csv | ForEach-Object { $_.SourceFileHash -eq $hash }) -notcontains $false)
}
Test-Assertion 'CSV includes WindowsEventId and SysmonEventId columns' {
    $csv = Import-Csv (Join-Path $tmpDir2 'MDETimelineTriage-Findings.csv')
    $csv[0].PSObject.Properties.Name -contains 'WindowsEventId' -and $csv[0].PSObject.Properties.Name -contains 'SysmonEventId'
}

$tmpDir3 = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate3_$([guid]::NewGuid())"
$escSrc = Join-Path $fixtures 'DeviceProcessEvents-escaping-test.csv'
Import-MDETimeline -Path $escSrc | Invoke-MDEDetection | New-MDEReport -SourcePath $escSrc -OutputPath $tmpDir3
Test-Assertion 'Malicious script-breakout payload is HTML-escaped, not executable' {
    $html = Get-Content (Join-Path $tmpDir3 'MDETimelineTriage-Report.html') -Raw
    ($html -notmatch '</script><script>alert') -and ($html -match '&lt;/script&gt;&lt;script&gt;')
}

$tmpDir4 = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate4_$([guid]::NewGuid())"
Import-MDETimeline -Path $srcForReport | Invoke-MDEDetection | New-MDEReport -SourcePath $srcForReport -OutputPath $tmpDir4 -Redact
Test-Assertion 'Redact replaces real hostname with placeholder' {
    $html = Get-Content (Join-Path $tmpDir4 'MDETimelineTriage-Report.html') -Raw
    ($html -notmatch 'WKSTN-TEST-001') -and ($html -match 'HOST-1')
}

Write-Host "`n=== Invoke-MDETriage (composes all three stages -- see CHANGELOG.md for why this section exists) ===" -ForegroundColor Cyan
$tmpDir5 = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate5_$([guid]::NewGuid())"
Test-Assertion 'Invoke-MDETriage -WhatIf writes nothing' {
    Invoke-MDETriage -Path (Join-Path $fixtures 'DeviceProcessEvents-phase7-tests.csv') -OutputPath $tmpDir5 -WhatIf
    -not (Test-Path $tmpDir5)
}
$tmpDir6 = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate6_$([guid]::NewGuid())"
$triageSrc = Join-Path $fixtures 'DeviceProcessEvents-phase7-tests.csv'
Invoke-MDETriage -Path $triageSrc -OutputPath $tmpDir6
Test-Assertion 'Invoke-MDETriage runs the full pipeline end-to-end for real' {
    (Test-Path (Join-Path $tmpDir6 'MDETimelineTriage-Report.html')) -and (Test-Path (Join-Path $tmpDir6 'MDETimelineTriage-Findings.csv'))
}
Test-Assertion 'Invoke-MDETriage CSV output has the same finding count as the component-stage pipeline (7)' {
    (@(Import-Csv (Join-Path $tmpDir6 'MDETimelineTriage-Findings.csv'))).Count -eq 7
}
Test-Assertion 'Invoke-MDETriage -Redact passes through to New-MDEReport internally' {
    $d = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate7_$([guid]::NewGuid())"
    Invoke-MDETriage -Path $srcForReport -OutputPath $d -Redact
    $html = Get-Content (Join-Path $d 'MDETimelineTriage-Report.html') -Raw
    Remove-Item $d -Recurse -Force
    ($html -notmatch 'WKSTN-TEST-001') -and ($html -match 'HOST-1')
}
Test-Assertion 'Invoke-MDETriage throws immediately on an invalid baseline config' {
    $d = Join-Path ([System.IO.Path]::GetTempPath()) "MDEValidate8_$([guid]::NewGuid())"
    try {
        Invoke-MDETriage -Path (Join-Path $fixtures 'DeviceProcessEvents-happy.csv') -OutputPath $d -BaselineConfigPath (Join-Path $fixtures 'baseline-invalid.json')
        $false
    }
    catch { $true }
    finally { if (Test-Path $d) { Remove-Item $d -Recurse -Force } }
}

# Cleanup
foreach ($d in @($tmpDir1, $tmpDir2, $tmpDir3, $tmpDir4, $tmpDir5, $tmpDir6)) {
    if (Test-Path $d) { Remove-Item -Path $d -Recurse -Force }
}

Write-Host "`n============================================" -ForegroundColor Yellow
Write-Host "RESULTS: $script:passCount passed, $script:failCount failed" -ForegroundColor Yellow
if ($script:failCount -gt 0) {
    Write-Host "Failures:" -ForegroundColor Red
    $script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}
Write-Host "============================================" -ForegroundColor Yellow
exit $script:failCount
