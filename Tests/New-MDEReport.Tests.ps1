Describe 'New-MDEReport' {
    BeforeAll {
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module (Join-Path -Path $moduleRoot -ChildPath 'MDETimelineTriage.psd1') -Force
        $script:fixturesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Fixtures'
    }
    Context '-WhatIf / dry-run support (requirement #12)' {
        BeforeEach {
            $script:testOutputDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportWhatIf_$([guid]::NewGuid())"
        }
        AfterEach {
            if (Test-Path -Path $testOutputDir) { Remove-Item -Path $testOutputDir -Recurse -Force }
        }

        It 'Does not create the output directory under -WhatIf' {
            $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
            $findings = Import-MDETimeline -Path $sourcePath | Invoke-MDEDetection
            $findings | New-MDEReport -SourcePath $sourcePath -OutputPath $testOutputDir -WhatIf
            Test-Path -Path $testOutputDir | Should -Be $false
        }

        It 'Does not write an HTML or CSV file under -WhatIf, even if the output directory already exists' {
            $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
            $findings = Import-MDETimeline -Path $sourcePath | Invoke-MDEDetection
            New-Item -Path $testOutputDir -ItemType Directory -Force | Out-Null
            $findings | New-MDEReport -SourcePath $sourcePath -OutputPath $testOutputDir -WhatIf
            Test-Path -Path (Join-Path $testOutputDir 'MDETimelineTriage-Report.html') | Should -Be $false
            Test-Path -Path (Join-Path $testOutputDir 'MDETimelineTriage-Findings.csv') | Should -Be $false
        }
    }

    Context 'Real rendering' {
        BeforeAll {
            $script:renderOutputDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportRender_$([guid]::NewGuid())"
            $script:renderSourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
            $renderFindings = Import-MDETimeline -Path $renderSourcePath | Invoke-MDEDetection
            $renderFindings | New-MDEReport -SourcePath $renderSourcePath -OutputPath $renderOutputDir
        }
        AfterAll {
            if (Test-Path -Path $renderOutputDir) { Remove-Item -Path $renderOutputDir -Recurse -Force }
        }

        It 'Writes both the HTML report and the enriched CSV' {
            Test-Path -Path (Join-Path $renderOutputDir 'MDETimelineTriage-Report.html') | Should -Be $true
            Test-Path -Path (Join-Path $renderOutputDir 'MDETimelineTriage-Findings.csv') | Should -Be $true
        }

        It 'Records the source file SHA-256 hash in the HTML report header (requirement #15)' {
            $expectedHash = (Get-FileHash -Path $renderSourcePath -Algorithm SHA256).Hash
            $html = Get-Content -Path (Join-Path $renderOutputDir 'MDETimelineTriage-Report.html') -Raw
            $html | Should -Match ([regex]::Escape($expectedHash))
        }

        It 'Records the source file hash on every row of the enriched CSV (requirement #15)' {
            $expectedHash = (Get-FileHash -Path $renderSourcePath -Algorithm SHA256).Hash
            $csv = Import-Csv -Path (Join-Path $renderOutputDir 'MDETimelineTriage-Findings.csv')
            $csv.Count | Should -BeGreaterThan 0
            foreach ($row in $csv) {
                $row.SourceFileHash | Should -Be $expectedHash
            }
        }

        It 'The HTML report labels UTC explicitly (requirement #8)' {
            $html = Get-Content -Path (Join-Path $renderOutputDir 'MDETimelineTriage-Report.html') -Raw
            $html | Should -Match 'UTC'
        }

        It 'Every finding written to the CSV independently shows both Severity and Confidence columns' {
            $csv = Import-Csv -Path (Join-Path $renderOutputDir 'MDETimelineTriage-Findings.csv')
            $csv[0].PSObject.Properties.Name | Should -Contain 'Severity'
            $csv[0].PSObject.Properties.Name | Should -Contain 'Confidence'
        }
    }

    Context 'Output sanitization (requirement #8, critical)' {
        It 'HTML-escapes a malicious ProcessCommandLine value rather than emitting it as executable markup' {
            $escOutputDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportEsc_$([guid]::NewGuid())"
            try {
                $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-escaping-test.csv'
                $findings = Import-MDETimeline -Path $sourcePath | Invoke-MDEDetection
                $findings.Count | Should -BeGreaterThan 0
                $findings | New-MDEReport -SourcePath $sourcePath -OutputPath $escOutputDir
                $html = Get-Content -Path (Join-Path $escOutputDir 'MDETimelineTriage-Report.html') -Raw
                $html | Should -Not -Match '</script><script>alert'
                $html | Should -Match '&lt;/script&gt;&lt;script&gt;'
            }
            finally {
                if (Test-Path $escOutputDir) { Remove-Item -Path $escOutputDir -Recurse -Force }
            }
        }
    }

    Context 'Redaction (requirement #17)' {
        It 'Replaces the real DeviceName with a stable placeholder when -Redact is used, and never shows the real value' {
            $redactOutputDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportRedact_$([guid]::NewGuid())"
            try {
                $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
                $findings = Import-MDETimeline -Path $sourcePath | Invoke-MDEDetection
                $findings | New-MDEReport -SourcePath $sourcePath -OutputPath $redactOutputDir -Redact
                $html = Get-Content -Path (Join-Path $redactOutputDir 'MDETimelineTriage-Report.html') -Raw
                $html | Should -Not -Match 'WKSTN-TEST-001'
                $html | Should -Match 'HOST-1'
            }
            finally {
                if (Test-Path $redactOutputDir) { Remove-Item -Path $redactOutputDir -Recurse -Force }
            }
        }

        It 'Does not redact by default' {
            $unredactedOutputDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportUnredacted_$([guid]::NewGuid())"
            try {
                $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
                $findings = Import-MDETimeline -Path $sourcePath | Invoke-MDEDetection
                $findings | New-MDEReport -SourcePath $sourcePath -OutputPath $unredactedOutputDir
                $html = Get-Content -Path (Join-Path $unredactedOutputDir 'MDETimelineTriage-Report.html') -Raw
                $html | Should -Match 'WKSTN-TEST-001'
            }
            finally {
                if (Test-Path $unredactedOutputDir) { Remove-Item -Path $unredactedOutputDir -Recurse -Force }
            }
        }
    }

    Context 'Evidence integrity (requirement #15)' {
        It 'Does not modify the source file' {
            $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
            $hashBefore = (Get-FileHash -Path $sourcePath -Algorithm SHA256).Hash
            $tempOut = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportIntegrity_$([guid]::NewGuid())"
            try {
                $findings = Import-MDETimeline -Path $sourcePath | Invoke-MDEDetection
                $findings | New-MDEReport -SourcePath $sourcePath -OutputPath $tempOut
                (Get-FileHash -Path $sourcePath -Algorithm SHA256).Hash | Should -Be $hashBefore
            }
            finally {
                if (Test-Path $tempOut) { Remove-Item -Path $tempOut -Recurse -Force }
            }
        }
    }

    Context 'No file/network telemetry (requirement #17)' {
        It 'Does not reference any external CDN URL in the rendered report (fully offline, requirement #8)' {
            $offlineOutputDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportOffline_$([guid]::NewGuid())"
            try {
                $sourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
                $findings = Import-MDETimeline -Path $sourcePath | Invoke-MDEDetection
                $findings | New-MDEReport -SourcePath $sourcePath -OutputPath $offlineOutputDir
                $html = Get-Content -Path (Join-Path $offlineOutputDir 'MDETimelineTriage-Report.html') -Raw
                $html | Should -Not -Match '(?i)cdn\.|cdnjs\.|unpkg\.com|jsdelivr\.net'
            }
            finally {
                if (Test-Path $offlineOutputDir) { Remove-Item -Path $offlineOutputDir -Recurse -Force }
            }
        }
    }

    Context 'Optional -OutputPath: Downloads folder auto-resolution and MDETT-dated naming' {
        BeforeAll {
            $script:sourcePathForNaming = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
            $script:mod = Get-Module MDETimelineTriage
            $script:expectedDownloadsFolder = & $mod { Get-MDEDownloadsFolder }
            $script:todayStamp = (Get-Date).ToString('yyyy-MM-dd')
        }

        It 'Explicit -OutputPath without -DatedFileNames still uses the traditional fixed names (backward compatibility)' {
            $customDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportFixedNames_$([guid]::NewGuid())"
            try {
                Import-MDETimeline -Path $sourcePathForNaming | Invoke-MDEDetection | New-MDEReport -SourcePath $sourcePathForNaming -OutputPath $customDir
                Test-Path (Join-Path $customDir 'MDETimelineTriage-Report.html') | Should -Be $true
                Test-Path (Join-Path $customDir 'MDETimelineTriage-Findings.csv') | Should -Be $true
            }
            finally {
                if (Test-Path $customDir) { Remove-Item -Path $customDir -Recurse -Force }
            }
        }

        It 'Explicit -OutputPath WITH -DatedFileNames uses MDETT-dated names at that custom location' {
            $customDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEReportDatedCustom_$([guid]::NewGuid())"
            try {
                Import-MDETimeline -Path $sourcePathForNaming | Invoke-MDEDetection | New-MDEReport -SourcePath $sourcePathForNaming -OutputPath $customDir -DatedFileNames
                Test-Path (Join-Path $customDir "MDETT-$todayStamp-Report.html") | Should -Be $true
                Test-Path (Join-Path $customDir "MDETT-$todayStamp-Findings.csv") | Should -Be $true
            }
            finally {
                if (Test-Path $customDir) { Remove-Item -Path $customDir -Recurse -Force }
            }
        }

        It 'Omitting -OutputPath entirely resolves to Get-MDEDownloadsFolder''s result and auto-enables dated names' {
            $expectedHtml = Join-Path $expectedDownloadsFolder "MDETT-$todayStamp-Report.html"
            $expectedCsv = Join-Path $expectedDownloadsFolder "MDETT-$todayStamp-Findings.csv"
            try {
                Import-MDETimeline -Path $sourcePathForNaming | Invoke-MDEDetection | New-MDEReport -SourcePath $sourcePathForNaming
                Test-Path $expectedHtml | Should -Be $true
                Test-Path $expectedCsv | Should -Be $true
            }
            finally {
                # Clean up only the specific files this test created, not the whole
                # Downloads folder, which may contain real unrelated content on a real
                # machine.
                if (Test-Path $expectedHtml) { Remove-Item -Path $expectedHtml -Force }
                if (Test-Path $expectedCsv) { Remove-Item -Path $expectedCsv -Force }
            }
        }

        It '-WhatIf with -OutputPath omitted reports the resolved Downloads path and creates nothing' {
            $expectedHtml = Join-Path $expectedDownloadsFolder "MDETT-$todayStamp-Report.html"
            $preExisted = Test-Path $expectedDownloadsFolder
            Import-MDETimeline -Path $sourcePathForNaming | Invoke-MDEDetection | New-MDEReport -SourcePath $sourcePathForNaming -WhatIf
            Test-Path $expectedHtml | Should -Be $false
            if (-not $preExisted) {
                Test-Path $expectedDownloadsFolder | Should -Be $false
            }
        }
    }

    Context 'Report size threshold summarization (requirement #8) -- never tested at any scale before this' {
        # A real 200,000-row/6,000-finding file was used to confirm this end-to-end
        # (sizeThresholdApplied=true, exactly 5,000 of 6,000 findings embedded in the HTML,
        # DataTables' own API confirming all 5,000 are genuinely in its data model just
        # paginated for display, the CSV still holding the complete 6,000) -- see CHANGELOG.md.
        # These tests exercise the identical code path cheaply, using -ReportSizeThreshold to
        # trigger it with the existing small fixture rather than needing a large file.
        BeforeAll {
            $script:thresholdSourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
            $script:thresholdOutDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEThreshold_$([guid]::NewGuid())"
            Import-MDETimeline -Path $thresholdSourcePath | Invoke-MDEDetection | New-MDEReport -SourcePath $thresholdSourcePath -OutputPath $thresholdOutDir -ReportSizeThreshold 2
        }
        AfterAll {
            if (Test-Path $thresholdOutDir) { Remove-Item -Path $thresholdOutDir -Recurse -Force }
        }

        It 'Sets sizeThresholdApplied=true in report-meta when findings exceed the threshold' {
            $html = Get-Content (Join-Path $thresholdOutDir 'MDETimelineTriage-Report.html') -Raw
            $meta = ($html | Select-String -Pattern '(?s)<script type="application/json" id="report-meta">(.*?)</script>').Matches[0].Groups[1].Value | ConvertFrom-Json
            $meta.sizeThresholdApplied | Should -Be $true
            $meta.totalFindingCount | Should -BeGreaterThan 2
            $meta.displayedFindingCount | Should -Be 2
        }

        It 'Embeds only the top-N findings in the HTML but keeps the complete set in the CSV' {
            $html = Get-Content (Join-Path $thresholdOutDir 'MDETimelineTriage-Report.html') -Raw
            $findingsJson = ($html | Select-String -Pattern '(?s)<script type="application/json" id="findings-data">(.*?)</script>').Matches[0].Groups[1].Value | ConvertFrom-Json
            @($findingsJson).Count | Should -Be 2
            $csv = Import-Csv (Join-Path $thresholdOutDir 'MDETimelineTriage-Findings.csv')
            @($csv).Count | Should -BeGreaterThan 2
        }

        It 'Does not apply the threshold when findings are at or below it' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEThresholdNotApplied_$([guid]::NewGuid())"
            try {
                Import-MDETimeline -Path $thresholdSourcePath | Invoke-MDEDetection | New-MDEReport -SourcePath $thresholdSourcePath -OutputPath $outDir -ReportSizeThreshold 500
                $html = Get-Content (Join-Path $outDir 'MDETimelineTriage-Report.html') -Raw
                $meta = ($html | Select-String -Pattern '(?s)<script type="application/json" id="report-meta">(.*?)</script>').Matches[0].Groups[1].Value | ConvertFrom-Json
                $meta.sizeThresholdApplied | Should -Be $false
                $meta.displayedFindingCount | Should -Be $meta.totalFindingCount
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }
    }

    Context 'ATT&CK Navigator layer export (-ExportAttackNavigatorLayer)' {
        BeforeAll {
            $script:navSourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv'
        }

        It 'Does not write a Navigator layer file by default (backward compatibility)' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDENavOff_$([guid]::NewGuid())"
            try {
                Import-MDETimeline -Path $navSourcePath -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue | New-MDEReport -SourcePath $navSourcePath -OutputPath $outDir
                (Get-ChildItem -Path $outDir -Filter '*AttackNavigatorLayer*').Count | Should -Be 0
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }

        It 'Writes a structurally valid v4.5 layer with one entry per distinct technique when the switch is set' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDENavOn_$([guid]::NewGuid())"
            try {
                Import-MDETimeline -Path $navSourcePath -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue | New-MDEReport -SourcePath $navSourcePath -OutputPath $outDir -ExportAttackNavigatorLayer
                $layerPath = Join-Path $outDir 'MDETimelineTriage-AttackNavigatorLayer.json'
                Test-Path $layerPath | Should -Be $true
                $layer = Get-Content $layerPath -Raw | ConvertFrom-Json
                $layer.domain | Should -Be 'enterprise-attack'
                $layer.versions.layer | Should -Be '4.5'
                @($layer.techniques).Count | Should -Be 7
                ($layer.techniques | Where-Object techniqueID -eq 'T1003.001').tactic | Should -Be 'credential-access'
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }

        It 'Deduplicates a technique shared by multiple rules into one entry with the combined rule list and max score' {
            $procFindings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue | Where-Object { $_.PSObject.TypeNames -notcontains 'MDETimelineTriage.RunSummary' })
            $regFindings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceRegistryEvents-detection-tests.csv') -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue | Where-Object { $_.PSObject.TypeNames -notcontains 'MDETimelineTriage.RunSummary' })
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDENavDedup_$([guid]::NewGuid())"
            try {
                $combinedSourcePath = Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv'
                (@($procFindings) + @($regFindings)) | New-MDEReport -SourcePath $combinedSourcePath -OutputPath $outDir -ExportAttackNavigatorLayer
                $layer = Get-Content (Join-Path $outDir 'MDETimelineTriage-AttackNavigatorLayer.json') -Raw | ConvertFrom-Json
                $sharedTechnique = $layer.techniques | Where-Object techniqueID -eq 'T1562.001'
                $sharedTechnique | Should -Not -BeNullOrEmpty
                $sharedTechnique.comment | Should -Match 'DEFEVA-002'
                $sharedTechnique.comment | Should -Match 'DEFEVA-003'
            }
            finally {
                if (Test-Path $outDir) { Remove-Item -Path $outDir -Recurse -Force }
            }
        }

        It '-WhatIf with the switch set mentions the Navigator path and creates nothing' {
            $outDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDENavWhatIf_$([guid]::NewGuid())"
            Import-MDETimeline -Path $navSourcePath -WarningAction SilentlyContinue | Invoke-MDEDetection -WarningAction SilentlyContinue | New-MDEReport -SourcePath $navSourcePath -OutputPath $outDir -ExportAttackNavigatorLayer -WhatIf
            Test-Path $outDir | Should -Be $false
        }
    }
}
