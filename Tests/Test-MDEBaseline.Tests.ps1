Describe 'Test-MDEBaseline' {
    BeforeAll {
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module (Join-Path -Path $moduleRoot -ChildPath 'MDETimelineTriage.psd1') -Force
        $script:fixturesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Fixtures'
    }
    Context 'Auto-detection' {
        It 'Validates a well-formed baseline config as valid, auto-detected as Baseline type' {
            $result = Test-MDEBaseline -Path (Join-Path $fixturesPath 'baseline-sample.json')
            $result.IsValid | Should -Be $true
            $result.ConfigType | Should -Be 'Baseline'
        }

        It 'Validates a well-formed custom IOC config as valid, auto-detected as CustomIOC type' {
            $result = Test-MDEBaseline -Path (Join-Path $fixturesPath 'custom-ioc-sample.json')
            $result.IsValid | Should -Be $true
            $result.ConfigType | Should -Be 'CustomIOC'
        }
    }

    Context 'Forced -ConfigType' {
        It 'Fails a baseline config forced against the CustomIOC schema (missing required Severity)' {
            $result = Test-MDEBaseline -Path (Join-Path $fixturesPath 'baseline-sample.json') -ConfigType CustomIOC
            $result.IsValid | Should -Be $false
        }
    }

    Context 'Error reporting (does not stop at the first problem)' {
        It 'Reports exactly 3 distinct errors for a config with 3 independently malformed entries' {
            $result = Test-MDEBaseline -Path (Join-Path $fixturesPath 'baseline-invalid.json')
            $result.IsValid | Should -Be $false
            $result.Errors.Count | Should -Be 3
        }

        It 'Pinpoints the missing-Pattern entry specifically' {
            $result = Test-MDEBaseline -Path (Join-Path $fixturesPath 'baseline-invalid.json')
            ($result.Errors -join ' ') | Should -Match "(?i)Entry 1.*Pattern"
        }

        It 'Pinpoints the invalid regex entry specifically' {
            $result = Test-MDEBaseline -Path (Join-Path $fixturesPath 'baseline-invalid.json')
            ($result.Errors -join ' ') | Should -Match '(?i)Entry 3.*regex'
        }
    }

    Context 'Empty config' {
        It 'Treats an empty array as valid' {
            $emptyPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "MDEEmptyConfig_$([guid]::NewGuid()).json"
            try {
                Set-Content -Path $emptyPath -Value '[]' -Encoding utf8
                $result = Test-MDEBaseline -Path $emptyPath
                $result.IsValid | Should -Be $true
            }
            finally {
                if (Test-Path $emptyPath) { Remove-Item -Path $emptyPath -Force }
            }
        }
    }

    Context 'Read-only guarantee' {
        It 'Does not modify the config file it validates' {
            $path = Join-Path $fixturesPath 'baseline-sample.json'
            $hashBefore = (Get-FileHash -Path $path -Algorithm SHA256).Hash
            Test-MDEBaseline -Path $path | Out-Null
            (Get-FileHash -Path $path -Algorithm SHA256).Hash | Should -Be $hashBefore
        }
    }

    Context 'Does not process any CSV' {
        It 'Has no parameter suggesting CSV/timeline processing' {
            (Get-Command Test-MDEBaseline).Parameters.Keys | Where-Object { $_ -match '(?i)csv|timeline' } | Should -BeNullOrEmpty
        }
    }
}
