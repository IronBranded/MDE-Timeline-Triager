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
}
