Describe 'ConvertFrom-MDEEncodedCommand' {
    BeforeAll {
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module (Join-Path -Path $moduleRoot -ChildPath 'MDETimelineTriage.psd1') -Force
    }
    Context 'Base64 / -EncodedCommand decoding (in-scope, requirement #6)' {
        It 'Decodes a genuine UTF-16LE Base64 -enc payload' {
            # "Write-Host 'test'" encoded as UTF-16LE then Base64.
            $payload = 'VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA=='
            $result = ConvertFrom-MDEEncodedCommand -CommandLine "powershell.exe -enc $payload"
            $result.MethodsApplied | Should -Contain 'Base64/-EncodedCommand (UTF-16LE)'
            $result.Decoded | Should -BeLike "*Write-Host 'test'*"
            $result.Scope | Should -Be 'Decoded'
        }

        It 'Also decodes the full -EncodedCommand flag form, not just -enc' {
            $payload = 'VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAnAA=='
            $result = ConvertFrom-MDEEncodedCommand -CommandLine "powershell.exe -EncodedCommand $payload"
            $result.MethodsApplied | Should -Contain 'Base64/-EncodedCommand (UTF-16LE)'
        }

        It 'Does not decode a short flag value below the length threshold (avoids false-positive on unrelated -e flags)' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine 'someapp.exe -e config.xml'
            $result.MethodsApplied | Should -Not -Contain 'Base64/-EncodedCommand (UTF-16LE)'
        }

        It 'Does not crash or falsely decode on a non-Base64 value that happens to follow -enc' {
            { ConvertFrom-MDEEncodedCommand -CommandLine 'someapp.exe -enc not-actually-base64-content!!' } | Should -Not -Throw
        }
    }

    Context 'Tick-mark/caret removal (in-scope, requirement #6)' {
        It 'Strips a backtick between letters' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine 'p`o`w`e`r`s`h`e`l`l.exe -nop'
            $result.MethodsApplied | Should -Contain 'Tick-mark/caret removal'
            $result.Decoded | Should -BeLike '*powershell.exe*'
        }

        It 'Strips a caret between letters' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine 'c^m^d.exe /c whoami'
            $result.MethodsApplied | Should -Contain 'Tick-mark/caret removal'
            $result.Decoded | Should -BeLike '*cmd.exe*'
        }
    }

    Context 'Environment-variable expansion (in-scope, requirement #6)' {
        It 'Expands a known standard variable to its documented default value' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine '%COMSPEC% /c dir'
            $result.MethodsApplied | Should -Contain 'Environment-variable expansion (standard default values)'
            $result.Decoded | Should -BeLike '*cmd.exe*'
        }

        It 'Leaves an unrecognized variable unexpanded rather than guessing' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine '%SOME_CUSTOM_VAR% /c dir'
            $result.MethodsApplied | Should -Not -Contain 'Environment-variable expansion (standard default values)'
            $result.Decoded | Should -BeLike '*%SOME_CUSTOM_VAR%*'
        }
    }

    Context 'Simple character reversal (in-scope, requirement #6)' {
        It 'Detects a reversed known suspicious keyword' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine 'exe.llehsrewop -nop'
            $result.MethodsApplied | Should -Contain 'Simple character reversal'
        }

        It 'Does not flag an ordinary token as reversed' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine 'notepad.exe C:\temp\a.txt'
            $result.MethodsApplied | Should -Not -Contain 'Simple character reversal'
        }
    }

    Context 'Out-of-scope obfuscation (requirement #6 -- must flag, never guess)' {
        It 'Reports Clean for an ordinary, unobfuscated command line' {
            $result = ConvertFrom-MDEEncodedCommand -CommandLine 'notepad.exe C:\temp\a.txt'
            $result.Scope | Should -Be 'Clean'
        }

        It 'Reports PossiblyObfuscated (not a guessed decode) for a long Base64-shaped run outside any recognized flag' {
            $longRun = 'A' * 80
            $result = ConvertFrom-MDEEncodedCommand -CommandLine "someapp.exe --data=$longRun"
            $result.Scope | Should -Be 'PossiblyObfuscated'
            $result.Decoded | Should -Be $result.Original
        }
    }

    Context 'Original value preservation' {
        It 'Never mutates the Original property regardless of what decoding was applied' {
            $input = 'p`o`w`e`r`s`h`e`l`l.exe -nop'
            $result = ConvertFrom-MDEEncodedCommand -CommandLine $input
            $result.Original | Should -Be $input
        }
    }

    Context 'Pipeline support' {
        It 'Accepts input from the pipeline by property name' {
            $result = [PSCustomObject]@{ CommandLine = 'c^m^d.exe /c whoami' } | ConvertFrom-MDEEncodedCommand
            $result.MethodsApplied | Should -Contain 'Tick-mark/caret removal'
        }
    }
}
