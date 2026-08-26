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

    Context 'Optional -OutputPath (Downloads folder auto-resolution)' {
        # Regression coverage for a real bug: Invoke-MDETriage declares its OWN separate
        # -OutputPath parameter (rather than inheriting New-MDEReport's), and when
        # New-MDEReport's -OutputPath was made optional, this cmdlet's copy was missed --
        # it stayed [Parameter(Mandatory = $true)], so calling Invoke-MDETriage without
        # -OutputPath made PowerShell interactively PROMPT for it instead of correctly
        # resolving to Downloads, which silently broke the interactive launcher
        # (Start-MDETT.ps1) the first time it was actually run end-to-end. Found only by
        # piping simulated input through the real launcher, not by reading the code.
        BeforeAll {
            $script:sourcePathForOptOut = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
            $script:mod = Get-Module MDETimelineTriage
            $script:expectedDownloadsFolder = & $mod { Get-MDEDownloadsFolder }
            $script:todayStamp = (Get-Date).ToString('yyyy-MM-dd')
        }

        It 'Does not prompt for -OutputPath -- it is a genuinely optional parameter, not just one with a default value' {
            $paramMetadata = (Get-Command Invoke-MDETriage).Parameters['OutputPath']
            $isMandatory = $paramMetadata.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } | ForEach-Object { $_.Mandatory }
            ($isMandatory -contains $true) | Should -Be $false
        }

        It 'Omitting -OutputPath resolves to Get-MDEDownloadsFolder''s result with MDETT-dated names, same as New-MDEReport directly' {
            $expectedHtml = Join-Path $expectedDownloadsFolder "MDETT-$todayStamp-Report.html"
            $expectedCsv = Join-Path $expectedDownloadsFolder "MDETT-$todayStamp-Findings.csv"
            try {
                Invoke-MDETriage -Path $sourcePathForOptOut
                Test-Path $expectedHtml | Should -Be $true
                Test-Path $expectedCsv | Should -Be $true
            }
            finally {
                if (Test-Path $expectedHtml) { Remove-Item -Path $expectedHtml -Force }
                if (Test-Path $expectedCsv) { Remove-Item -Path $expectedCsv -Force }
            }
        }
    }
}
