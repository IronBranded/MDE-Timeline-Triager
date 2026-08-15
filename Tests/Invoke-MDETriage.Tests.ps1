Describe 'Invoke-MDETriage' {
    BeforeAll {
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module (Join-Path -Path $moduleRoot -ChildPath 'MDETimelineTriage.psd1') -Force
        $script:fixturesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Fixtures'
    }
    # This file exists specifically because its absence let a real bug ship: the three
    # stages Invoke-MDETriage is supposed to compose were tested individually and via manual
    # pipeline composition, but nothing ever called Invoke-MDETriage itself, so it silently
    # stayed a Phase 1 stub (a hard-coded NotImplementedException) through five later phases
    # of work on the cmdlets it wraps. Every test below calls Invoke-MDETriage directly, not
    # its component stages.

    Context '-WhatIf / dry-run support' {
        It 'Does not create the output directory under -WhatIf' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDETriageWhatIf_$([guid]::NewGuid())"
            Invoke-MDETriage -Path (Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv') -OutputPath $outDir -WhatIf
            Test-Path -Path $outDir | Should -Be $false
        }

        It 'Does not throw under -WhatIf' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDETriageWhatIf2_$([guid]::NewGuid())"
            { Invoke-MDETriage -Path (Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv') -OutputPath $outDir -WhatIf } | Should -Not -Throw
        }
    }

    Context 'Real end-to-end execution' {
        BeforeAll {
            $script:triageOutDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDETriageReal_$([guid]::NewGuid())"
            $script:triageSourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv'
            Invoke-MDETriage -Path $triageSourcePath -OutputPath $triageOutDir
        }
        AfterAll {
            if (Test-Path -Path $triageOutDir) { Remove-Item -Path $triageOutDir -Recurse -Force }
        }

        It 'Writes both the HTML report and the enriched CSV in one call' {
            Test-Path -Path (Join-Path $triageOutDir 'MDETimelineTriage-Report.html') | Should -Be $true
            Test-Path -Path (Join-Path $triageOutDir 'MDETimelineTriage-Findings.csv') | Should -Be $true
        }

        It 'The CSV contains findings from the full built-in catalog, not an empty/stub result' {
            $csv = Import-Csv -Path (Join-Path $triageOutDir 'MDETimelineTriage-Findings.csv')
            # This fixture is known (Tests/Invoke-MDEDetection.Tests.ps1) to produce exactly
            # 7 findings when run through the component stages; Invoke-MDETriage composing
            # the same stages internally must produce the same result.
            @($csv).Count | Should -Be 7
        }

        It 'Records the source file hash, proving SourcePath was correctly threaded through to New-MDEReport internally' {
            $expectedHash = (Get-FileHash -Path $triageSourcePath -Algorithm SHA256).Hash
            $html = Get-Content -Path (Join-Path $triageOutDir 'MDETimelineTriage-Report.html') -Raw
            $html | Should -Match ([regex]::Escape($expectedHash))
        }
    }

    Context 'Parameter pass-through to the composed stages' {
        It 'Passes -Redact through to New-MDEReport' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDETriageRedact_$([guid]::NewGuid())"
            try {
                Invoke-MDETriage -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') -OutputPath $outDir -Redact
                $html = Get-Content -Path (Join-Path $outDir 'MDETimelineTriage-Report.html') -Raw
                $html | Should -Not -Match 'WKSTN-TEST-001'
                $html | Should -Match 'HOST-1'
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }

        It 'Passes -BaselineConfigPath through to Invoke-MDEDetection (suppresses the same finding it would standalone)' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDETriageBaseline_$([guid]::NewGuid())"
            try {
                Invoke-MDETriage -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') -OutputPath $outDir -BaselineConfigPath (Join-Path $fixturesPath 'baseline-sample.json')
                $csv = Import-Csv -Path (Join-Path $outDir 'MDETimelineTriage-Findings.csv')
                ($csv | Where-Object RuleId -eq 'DEFEVA-001') | Should -BeNullOrEmpty
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }

        It 'Throws immediately for a malformed baseline config, same as calling Invoke-MDEDetection directly' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDETriageBadConfig_$([guid]::NewGuid())"
            try {
                { Invoke-MDETriage -Path (Join-Path $fixturesPath 'DeviceProcessEvents-happy.csv') -OutputPath $outDir -BaselineConfigPath (Join-Path $fixturesPath 'baseline-invalid.json') } | Should -Throw
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }
    }

    Context 'Evidence integrity' {
        It 'Does not modify the source file' {
            $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv'
            $hashBefore = (Get-FileHash -Path $sourcePath -Algorithm SHA256).Hash
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDETriageIntegrity_$([guid]::NewGuid())"
            try {
                Invoke-MDETriage -Path $sourcePath -OutputPath $outDir
                (Get-FileHash -Path $sourcePath -Algorithm SHA256).Hash | Should -Be $hashBefore
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }
    }
}
