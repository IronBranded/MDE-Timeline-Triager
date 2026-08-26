Describe 'Import-MDETimeline' {
    BeforeAll {
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module (Join-Path -Path $moduleRoot -ChildPath 'MDETimelineTriage.psd1') -Force
        $script:fixturesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Fixtures'
    }
    Context 'Schema-set detection (requirement #1) -- happy path' {
        It 'Correctly identifies <Table> from its export' -TestCases @(
            @{ Table = 'DeviceProcessEvents'; File = 'DeviceProcessEvents-happy.csv' }
            @{ Table = 'DeviceNetworkEvents'; File = 'DeviceNetworkEvents-happy.csv' }
            @{ Table = 'DeviceFileEvents'; File = 'DeviceFileEvents-happy.csv' }
            @{ Table = 'DeviceRegistryEvents'; File = 'DeviceRegistryEvents-happy.csv' }
            @{ Table = 'DeviceLogonEvents'; File = 'DeviceLogonEvents-happy.csv' }
            @{ Table = 'DeviceImageLoadEvents'; File = 'DeviceImageLoadEvents-happy.csv' }
            @{ Table = 'DeviceEvents'; File = 'DeviceEvents-happy.csv' }
        ) {
            param($Table, $File)
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath $File))
            $rows | Should -Not -BeNullOrEmpty
            $rows[0].SourceTable | Should -Be $Table
        }

        It 'Falls back to Unrecognized (not a wrong table) on a sparse, ambiguous header, and still parses it' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'malformed-low-confidence.csv'))
            $rows.Count | Should -Be 2
            $rows[0].SourceTable | Should -Be 'Unrecognized'
        }
    }

    Context 'DeviceFileEvents vs DeviceImageLoadEvents disambiguation (the bug caught during Phase 2)' {
        It 'Does not misclassify DeviceFileEvents as DeviceImageLoadEvents' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceFileEvents-happy.csv'))
            $rows[0].SourceTable | Should -Be 'DeviceFileEvents'
        }

        It 'Still correctly classifies a genuine DeviceImageLoadEvents export' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceImageLoadEvents-happy.csv'))
            $rows[0].SourceTable | Should -Be 'DeviceImageLoadEvents'
        }
    }

    Context 'Encoding detection (requirement #3)' {
        It 'Parses a UTF-16 LE with BOM export to the same row count as its UTF-8 counterpart' {
            $utf8Rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceLogonEvents-happy.csv'))
            $utf16Rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceLogonEvents-happy-utf16le.csv'))
            $utf16Rows.Count | Should -Be $utf8Rows.Count
            $utf16Rows[0].AccountName | Should -Be $utf8Rows[0].AccountName
        }

        It 'Parses a UTF-8 with BOM export to the same row count as its plain UTF-8 counterpart' {
            $plainRows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceRegistryEvents-happy.csv'))
            $bomRows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceRegistryEvents-happy-utf8bom.csv'))
            $bomRows.Count | Should -Be $plainRows.Count
        }
    }

    Context 'CSV quoting engine' {
        It 'Correctly parses a field with an embedded comma inside quotes' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-happy.csv'))
            $row = $rows | Where-Object { $_.ProcessCommandLine -like '*echo hello, world*' }
            $row | Should -Not -BeNullOrEmpty
            $row.ProcessCommandLine | Should -BeLike '*echo hello, world & whoami*'
        }

        It 'Correctly unescapes a doubled quote inside a quoted field' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-happy.csv'))
            $row = $rows | Where-Object { $_.InitiatingProcessCommandLine -like '*Q3 report*' -and $_.InitiatingProcessCommandLine -like '*WINWORD*' }
            $row | Should -Not -BeNullOrEmpty
            $row.InitiatingProcessCommandLine | Should -BeLike '*"Q3 report.docx"*'
        }
    }

    Context 'Data-corruption handling (requirement #3) -- per-row skip, never a terminating error' {
        It 'Skips a truncated row but still returns the well-formed rows' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'malformed-truncated-row.csv'))
            $rows.Count | Should -Be 2
        }

        It 'Skips a row with invalid byte sequences for the detected encoding, keeping the good rows either side of it' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'malformed-decode-corruption.csv'))
            $rows.Count | Should -Be 2
            $rows.FileName | Should -Contain 'notepad.exe'
            $rows.FileName | Should -Contain 'calc.exe'
        }

        It 'Emits a warning when rows are skipped' {
            $warnings = $null
            Import-MDETimeline -Path (Join-Path $fixturesPath 'malformed-truncated-row.csv') -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            @($warnings).Count | Should -BeGreaterThan 0
        }

        It 'Does not throw a terminating error on malformed input' {
            { Import-MDETimeline -Path (Join-Path $fixturesPath 'malformed-truncated-row.csv') -WarningAction SilentlyContinue } | Should -Not -Throw
        }
    }

    Context 'Schema-mismatch handling (requirement #1) -- distinct from data-corruption, warn-only, never a skip' {
        It 'Warns but preserves an unrecognized extra column on the returned objects rather than dropping it' {
            $rows = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'malformed-extra-column.csv'))
            $rows.Count | Should -Be 2
            $rows[0].PSObject.Properties.Name | Should -Contain 'FutureNewField'
        }
    }

    Context 'Missing-header heuristic' {
        It 'Warns when the first row looks like a timestamp rather than column names' {
            $warnings = $null
            Import-MDETimeline -Path (Join-Path $fixturesPath 'malformed-missing-header.csv') -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null
            ($warnings -join ' ') | Should -Match '(?i)missing its header row'
        }
    }

    Context 'Row-count pre-scan and line-count-based progress' {
        It 'Get-MDECsvRowCount returns the exact data row count (header excluded)' {
            $mod = Get-Module MDETimelineTriage
            $path = Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv'
            $count = & $mod { param($p) Get-MDECsvRowCount -Path $p } $path
            $count | Should -Be 12
        }

        It '-SkipRowCountPreScan produces identical parsed rows to the default pre-scanning path' {
            $path = Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv'
            $withPreScan = @(Import-MDETimeline -Path $path -WarningAction SilentlyContinue)
            $withoutPreScan = @(Import-MDETimeline -Path $path -SkipRowCountPreScan -WarningAction SilentlyContinue)
            $withPreScan.Count | Should -Be $withoutPreScan.Count
            ($withPreScan | Select-Object -First 1).ProcessCommandLine | Should -Be ($withoutPreScan | Select-Object -First 1).ProcessCommandLine
        }

        It 'Row count pre-scan correctly counts a row containing an embedded newline inside a quoted field as ONE row, not two' {
            # Regression guard for the specific correctness concern that ruled out a naive
            # '\n'-count approach: a quoted field may legitimately contain an embedded
            # newline (e.g. multi-line command output). embedded-newline-test.csv is 5
            # physical lines (header + 2 logical rows, one of which spans 3 physical lines)
            # -- a naive newline count would say 4 data rows; the real, correct answer is 2.
            $mod = Get-Module MDETimelineTriage
            $path = Join-Path $fixturesPath 'embedded-newline-test.csv'
            $realRowCount = (@(Import-MDETimeline -Path $path -WarningAction SilentlyContinue)).Count
            $preScanCount = & $mod { param($p) Get-MDECsvRowCount -Path $p } $path
            $realRowCount | Should -Be 2
            $preScanCount | Should -Be 2
        }
    }

    Context 'Evidence integrity (requirement #15)' {
        It 'Does not modify the source file' {
            $path = Join-Path $fixturesPath 'DeviceProcessEvents-happy.csv'
            $hashBefore = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            Import-MDETimeline -Path $path | Out-Null
            $hashAfter = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            $hashAfter | Should -Be $hashBefore
        }
    }

    Context 'Error handling' {
        It 'Throws for a non-existent path' {
            { Import-MDETimeline -Path (Join-Path $fixturesPath 'does-not-exist.csv') } | Should -Throw
        }
    }
}
