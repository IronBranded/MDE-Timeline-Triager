<#
.SYNOPSIS
    A small, honest subset of PSScriptAnalyzer-style checks, using PowerShell's own built-in
    AST parser -- no external dependency, because PSScriptAnalyzer itself is not achievable
    in an environment without a dotnet SDK (see README.md's "Verification Status": checked
    across PSScriptAnalyzer's version history from its earliest indexed release through the
    current latest, and every one has a compiled C# core -- unlike Pester, there is no
    pure-PowerShell version to fall back to).

    This is NOT a PSScriptAnalyzer replacement. It covers 8 rule categories --
    PSUseApprovedVerbs, PSAvoidUsingCmdletAliases, PSAvoidUsingWriteHost,
    PSAvoidUsingEmptyCatchBlock, PSAvoidUsingInvokeExpression, PSAvoidGlobalVars,
    PSAvoidUsingPlainTextForPassword, and a heuristic (not the real algorithm) approximation
    of PSUseDeclaredVarsMoreThanAssignments -- out of PSScriptAnalyzer's several dozen actual
    rules, using [System.Management.Automation.Language.Parser], the same AST technology
    PSScriptAnalyzer itself is built on, which is part of the PowerShell engine itself and
    requires nothing beyond PowerShell to run.

    Self-tested before being trusted: run once against a deliberately bad scratch file
    containing one instance of each of the 6 non-parse-error/non-verb checks, confirmed all
    6 were caught, before trusting a subsequent zero-findings result against the real module
    as meaningful rather than a sign the linter itself was broken.
.EXAMPLE
    pwsh -File .\Tests\Invoke-ManualLint.ps1

    Lints every Public/Private .ps1 and the .psm1 (excluding Tests/) and prints findings
    grouped by rule.
#>

$ErrorActionPreference = 'Stop'

# Common cmdlet aliases PSScriptAnalyzer's PSAvoidUsingCmdletAliases flags. Not exhaustive --
# this is the well-known "default alias" set most likely to appear by habit.
$knownAliases = @{
    '%' = 'ForEach-Object'; '?' = 'Where-Object'; 'gci' = 'Get-ChildItem'; 'gc' = 'Get-Content'
    'ls' = 'Get-ChildItem'; 'dir' = 'Get-ChildItem'; 'cat' = 'Get-Content'; 'cp' = 'Copy-Item'
    'mv' = 'Move-Item'; 'rm' = 'Remove-Item'; 'del' = 'Remove-Item'; 'echo' = 'Write-Output'
    'iex' = 'Invoke-Expression'; 'select' = 'Select-Object'; 'where' = 'Where-Object'
    'foreach' = 'ForEach-Object'; 'sort' = 'Sort-Object'; 'group' = 'Group-Object'
    'measure' = 'Measure-Object'; 'ft' = 'Format-Table'; 'fl' = 'Format-List'
    'write' = 'Write-Output'; 'cd' = 'Set-Location'; 'pwd' = 'Get-Location'; 'kill' = 'Stop-Process'
    'ps' = 'Get-Process'; 'diff' = 'Compare-Object'; 'sleep' = 'Start-Sleep'; 'tag' = 'Tag-Object'
    'compare' = 'Compare-Object'; 'saps' = 'Start-Process'; 'iwr' = 'Invoke-WebRequest'
    'irm' = 'Invoke-RestMethod'; 'ni' = 'New-Item'; 'gm' = 'Get-Member'; 'gv' = 'Get-Variable'
    'sv' = 'Set-Variable'; 'gp' = 'Get-ItemProperty'; 'sp' = 'Set-ItemProperty'
}

$approvedVerbs = (Get-Verb).Verb

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
function Add-Finding {
    param($File, $Rule, $Line, $Message, $Severity = 'Warning')
    $findings.Add([PSCustomObject]@{ File = $File; Rule = $Rule; Line = $Line; Severity = $Severity; Message = $Message })
}

$moduleRoot = (Split-Path -Path $PSScriptRoot -Parent)
$files = Get-ChildItem -Path $moduleRoot -Filter '*.ps1' -Recurse |
    Where-Object { $_.FullName -notmatch '[\\/]Tests[\\/]' }
$files += Get-ChildItem -Path $moduleRoot -Filter '*.psm1'

Write-Host "Linting $($files.Count) files (Public/Private module code plus Start-MDETT.ps1, excluding Tests/) via the native AST parser..." -ForegroundColor Cyan

foreach ($file in $files) {
    $relPath = $file.FullName.Replace($moduleRoot, '').TrimStart('/', '\')
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)

    if ($parseErrors.Count -gt 0) {
        foreach ($e in $parseErrors) {
            Add-Finding -File $relPath -Rule 'ParseError' -Line $e.Extent.StartLineNumber -Message $e.Message -Severity 'Error'
        }
        continue
    }

    # --- Approved verbs (function definitions) ---
    $functionAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($fn in $functionAsts) {
        if ($fn.Name -match '^([A-Za-z]+)-') {
            $verb = $Matches[1]
            if ($verb -notin $approvedVerbs) {
                Add-Finding -File $relPath -Rule 'PSUseApprovedVerbs' -Line $fn.Extent.StartLineNumber -Message "Function '$($fn.Name)' uses unapproved verb '$verb'."
            }
        }
    }

    # --- Cmdlet aliases ---
    $commandAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($cmd in $commandAsts) {
        $cmdName = $cmd.GetCommandName()
        if ($cmdName -and $knownAliases.ContainsKey($cmdName)) {
            Add-Finding -File $relPath -Rule 'PSAvoidUsingCmdletAliases' -Line $cmd.Extent.StartLineNumber -Message "Alias '$cmdName' used instead of '$($knownAliases[$cmdName])'."
        }
    }

    # --- Write-Host usage ---
    foreach ($cmd in $commandAsts) {
        if ($cmd.GetCommandName() -eq 'Write-Host') {
            # Start-MDETT.ps1 is a deliberate, documented exception: it's a top-level
            # interactive console launcher, not a pipeline-composable module function, and
            # carries its own [SuppressMessageAttribute] with a matching justification (see
            # that file's .NOTES). Every actual module function still must not use
            # Write-Host -- this exception is scoped to that one file only, not a blanket
            # allowance.
            if ($relPath -eq 'Start-MDETT.ps1') { continue }
            Add-Finding -File $relPath -Rule 'PSAvoidUsingWriteHost' -Line $cmd.Extent.StartLineNumber -Message 'Write-Host used (output is not capturable/redirectable).'
        }
    }

    # --- Empty catch blocks ---
    $catchClauses = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CatchClauseAst] }, $true)
    foreach ($catch in $catchClauses) {
        $bodyStatements = $catch.Body.Statements
        if ($bodyStatements.Count -eq 0) {
            Add-Finding -File $relPath -Rule 'PSAvoidUsingEmptyCatchBlock' -Line $catch.Extent.StartLineNumber -Message 'Empty catch block silently swallows the error.'
        }
    }

    # --- Invoke-Expression usage (separate from alias check, in case the full name is used) ---
    foreach ($cmd in $commandAsts) {
        if ($cmd.GetCommandName() -eq 'Invoke-Expression') {
            Add-Finding -File $relPath -Rule 'PSAvoidUsingInvokeExpression' -Line $cmd.Extent.StartLineNumber -Message 'Invoke-Expression used.'
        }
    }

    # --- Global variable scope ---
    $varAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)
    foreach ($v in $varAsts) {
        if ($v.VariablePath.IsGlobal) {
            Add-Finding -File $relPath -Rule 'PSAvoidGlobalVars' -Line $v.Extent.StartLineNumber -Message "Global-scoped variable `$global:$($v.VariablePath.UserPath.Substring(7)) used."
        }
    }

    # --- Plaintext password parameters ---
    $paramAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.ParameterAst] }, $true)
    foreach ($p in $paramAsts) {
        if ($p.Name.VariablePath.UserPath -match '(?i)password|passwd|pwd$') {
            $typeName = if ($p.StaticType) { $p.StaticType.Name } else { $null }
            if ($typeName -ne 'SecureString') {
                Add-Finding -File $relPath -Rule 'PSAvoidUsingPlainTextForPassword' -Line $p.Extent.StartLineNumber -Message "Parameter '$($p.Name.VariablePath.UserPath)' looks password-related but is not [SecureString] (Type: $typeName)."
            }
        }
    }

    # --- Unused simple variable assignments (heuristic, not the full PSScriptAnalyzer algorithm) ---
    $assignments = $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst]
        }, $true)
    $allVarNames = $varAsts | ForEach-Object { $_.VariablePath.UserPath }
    $autoVars = @('_', 'PSItem', 'null', 'true', 'false', 'args', 'input', 'PSCmdlet', 'MyInvocation',
        'PSBoundParameters', 'ErrorActionPreference', 'WarningPreference', 'VerbosePreference',
        'PSScriptRoot', 'PSCommandPath', 'this', 'Matches', 'LASTEXITCODE', 'PWD')
    $seen = @{}
    foreach ($assign in $assignments) {
        $name = $assign.Left.VariablePath.UserPath
        if ($name -in $autoVars -or $name -like 'script:*' -or $name -like 'global:*') { continue }
        if ($seen.ContainsKey($name)) { continue }  # report each unused name once per file
        $occurrences = @($allVarNames | Where-Object { $_ -eq $name })
        if ($occurrences.Count -le 1) {
            $seen[$name] = $true
            Add-Finding -File $relPath -Rule 'PSUseDeclaredVarsMoreThanAssignments (heuristic)' -Line $assign.Extent.StartLineNumber -Message "`$$name is assigned but never referenced again in this file." -Severity 'Info'
        }
    }
}

Write-Host ''
Write-Host '================================================================' -ForegroundColor Yellow
$byRule = $findings | Group-Object Rule
if ($findings.Count -eq 0) {
    Write-Host 'No findings across any check.' -ForegroundColor Green
}
else {
    foreach ($group in $byRule) {
        Write-Host "$($group.Name): $($group.Count) finding(s)" -ForegroundColor $(if ($group.Group[0].Severity -eq 'Error') { 'Red' } elseif ($group.Group[0].Severity -eq 'Info') { 'DarkGray' } else { 'Yellow' })
        foreach ($f in $group.Group) {
            Write-Host "  [$($f.File):$($f.Line)] $($f.Message)"
        }
    }
}
Write-Host '================================================================' -ForegroundColor Yellow
Write-Host "TOTAL: $($files.Count) files linted, $($findings.Count) finding(s) across $($byRule.Count) rule categories"
