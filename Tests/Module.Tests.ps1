Describe 'MDETimelineTriage module manifest and public surface' {
    BeforeAll {
        $script:moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        $script:manifestPath = Join-Path -Path $moduleRoot -ChildPath 'MDETimelineTriage.psd1'
    }
    It 'Has a valid module manifest' {
        { Test-ModuleManifest -Path $manifestPath -ErrorAction Stop } | Should -Not -Throw
    }

    It 'Declares semantic versioning (major.minor.patch)' {
        $manifest = Test-ModuleManifest -Path $manifestPath
        $manifest.Version.ToString() | Should -Match '^\d+\.\d+\.\d+$'
    }

    It 'Exports exactly the 7 specified public cmdlets, no more, no fewer' {
        Import-Module $manifestPath -Force
        $exported = (Get-Module MDETimelineTriage).ExportedFunctions.Keys | Sort-Object
        $expected = @(
            'ConvertFrom-MDEEncodedCommand',
            'Get-MDEDetectionCatalog',
            'Import-MDETimeline',
            'Invoke-MDEDetection',
            'Invoke-MDETriage',
            'New-MDEReport',
            'Test-MDEBaseline'
        ) | Sort-Object
        @($exported) | Should -Be @($expected)
    }

    It 'Every public cmdlet uses an approved PowerShell verb' {
        Import-Module $manifestPath -Force
        $approvedVerbs = (Get-Verb).Verb
        foreach ($cmdletName in (Get-Module MDETimelineTriage).ExportedFunctions.Keys) {
            $verb = $cmdletName.Split('-')[0]
            $approvedVerbs | Should -Contain $verb
        }
    }

    It 'Every public cmdlet has complete comment-based help with no placeholder text' -TestCases @(
        @{ CmdletName = 'ConvertFrom-MDEEncodedCommand' }
        @{ CmdletName = 'Get-MDEDetectionCatalog' }
        @{ CmdletName = 'Import-MDETimeline' }
        @{ CmdletName = 'Invoke-MDEDetection' }
        @{ CmdletName = 'Invoke-MDETriage' }
        @{ CmdletName = 'New-MDEReport' }
        @{ CmdletName = 'Test-MDEBaseline' }
    ) {
        param($CmdletName)
        Import-Module $manifestPath -Force
        $help = Get-Help -Name $CmdletName -Full
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Synopsis | Should -Not -Match '(?i)TODO|TBD|placeholder|not yet documented'
        ($help.description | Out-String) | Should -Not -BeNullOrEmpty
        @($help.parameters.parameter).Count | Should -BeGreaterThan 0
        @($help.examples.example).Count | Should -BeGreaterOrEqual 2
    }

    It 'Invoke-MDEDetection and New-MDEReport implement SupportsShouldProcess' {
        Import-Module $manifestPath -Force
        (Get-Command Invoke-MDEDetection).Parameters.Keys | Should -Contain 'WhatIf'
        (Get-Command New-MDEReport).Parameters.Keys | Should -Contain 'WhatIf'
    }

    It 'Get-MDEDownloadsFolder returns a non-empty, absolute-looking path (platform-appropriate resolution verified separately: Windows via the Shell Folders registry key, macOS/Linux via $HOME -- only the current test platform''s branch actually executes here)' {
        Import-Module $manifestPath -Force
        $mod = Get-Module MDETimelineTriage
        $result = & $mod { Get-MDEDownloadsFolder }
        $result | Should -Not -BeNullOrEmpty
        [System.IO.Path]::IsPathRooted($result) | Should -Be $true
    }
}
