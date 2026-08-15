function Select-MDEFindingOnly {
    <#
    .SYNOPSIS
        Test helper: filters Invoke-MDEDetection's output down to finding objects, excluding
        the 'MDETimelineTriage.RunSummary'-tagged object now always present as the last item
        in that stream (see Invoke-MDEDetection's .OUTPUTS -- New-MDEReport does this same
        filtering internally; tests exercising Invoke-MDEDetection's raw output need to do it
        themselves).
    #>
    process {
        if ($_.PSObject.TypeNames -notcontains 'MDETimelineTriage.RunSummary') { $_ }
    }
}

Describe 'Invoke-MDEDetection' {
    BeforeAll {
        $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
        Import-Module (Join-Path -Path $moduleRoot -ChildPath 'MDETimelineTriage.psd1') -Force
        $script:fixturesPath = Join-Path -Path $PSScriptRoot -ChildPath 'Fixtures'
    }
    Context 'Built-in rule catalog -- known-answer tests (requirement #12)' {
        BeforeAll {
            $script:processFindings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') | Invoke-MDEDetection | Select-MDEFindingOnly)
            $script:registryFindings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceRegistryEvents-detection-tests.csv') | Invoke-MDEDetection | Select-MDEFindingOnly)
            $script:phase7ProcessFindings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-phase7-tests.csv') | Invoke-MDEDetection | Select-MDEFindingOnly)
            $script:phase7RegistryFindings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceRegistryEvents-phase7-tests.csv') | Invoke-MDEDetection | Select-MDEFindingOnly)
        }

        It 'Fires <RuleId> exactly once on its designated positive-case row' -TestCases @(
            @{ RuleId = 'EXEC-001'; Set = 'process' }
            @{ RuleId = 'DEFEVA-001'; Set = 'process' }
            @{ RuleId = 'DEFEVA-002'; Set = 'process' }
            @{ RuleId = 'DEFEVA-004'; Set = 'process' }
            @{ RuleId = 'PERSIST-002'; Set = 'phase7process' }
            @{ RuleId = 'CREDACCESS-001'; Set = 'phase7process' }
            @{ RuleId = 'CREDACCESS-002'; Set = 'phase7process' }
            @{ RuleId = 'LATMOVE-001'; Set = 'phase7process' }
            @{ RuleId = 'LATMOVE-002'; Set = 'phase7process' }
            @{ RuleId = 'EXFIL-001'; Set = 'phase7process' }
            @{ RuleId = 'DISC-001'; Set = 'phase7process' }
            @{ RuleId = 'PERSIST-001'; Set = 'phase7registry' }
        ) {
            param($RuleId, $Set)
            $findings = switch ($Set) {
                'process' { $processFindings }
                'phase7process' { $phase7ProcessFindings }
                'phase7registry' { $phase7RegistryFindings }
            }
            @($findings | Where-Object RuleId -eq $RuleId).Count | Should -Be 1
        }

        It 'Fires DEFEVA-003 exactly twice on the registry tampering rows (DisableRealtimeMonitoring=True and Start=4)' {
            @($registryFindings | Where-Object RuleId -eq 'DEFEVA-003').Count | Should -Be 2
        }

        It 'Does NOT fire DEFEVA-003 on DisableRealtimeMonitoring=False -- protection being left on, the opposite of tampering' {
            $falseValueRow = $registryFindings | Where-Object { $_.SourceRow.RegistryValueData -eq 'False' -and $_.SourceRow.RegistryValueName -eq 'DisableRealtimeMonitoring' }
            $falseValueRow | Should -BeNullOrEmpty
        }

        It 'Every finding exposes the complete Finding Object Schema property set' {
            $requiredProps = @('RuleName', 'Severity', 'Confidence', 'Tactic', 'TechniqueId', 'Explanation', 'BenignExplanation', 'SourceRow', 'ProcessLineage', 'Timestamp')
            foreach ($finding in $processFindings) {
                $propNames = $finding.PSObject.Properties.Name
                foreach ($prop in $requiredProps) {
                    $propNames | Should -Contain $prop
                }
            }
        }
    }

    Context 'Negative control -- benign fixtures must produce zero findings across all 13 rules' {
        It 'Produces zero findings for <File>' -TestCases @(
            @{ File = 'DeviceProcessEvents-happy.csv' }
            @{ File = 'DeviceNetworkEvents-happy.csv' }
            @{ File = 'DeviceFileEvents-happy.csv' }
            @{ File = 'DeviceRegistryEvents-happy.csv' }
            @{ File = 'DeviceLogonEvents-happy.csv' }
            @{ File = 'DeviceImageLoadEvents-happy.csv' }
            @{ File = 'DeviceEvents-happy.csv' }
        ) {
            param($File)
            $findings = @(Import-MDETimeline -Path (Join-Path $fixturesPath $File) | Invoke-MDEDetection | Select-MDEFindingOnly)
            $findings.Count | Should -Be 0
        }
    }

    Context 'Severity/Confidence independence (requirement #5)' {
        It 'DEFEVA-001 is Medium severity but Low confidence -- the two axes are never conflated' {
            $catalogEntry = Get-MDEDetectionCatalog | Where-Object RuleId -eq 'DEFEVA-001'
            $catalogEntry.Severity | Should -Be 'Medium'
            $catalogEntry.Confidence | Should -Be 'Low'
        }

        It 'CREDACCESS-001 is Critical severity AND High confidence, proving the axes are independent in both directions' {
            $catalogEntry = Get-MDEDetectionCatalog | Where-Object RuleId -eq 'CREDACCESS-001'
            $catalogEntry.Severity | Should -Be 'Critical'
            $catalogEntry.Confidence | Should -Be 'High'
        }
    }

    Context 'Multi-signal combination (requirement #5, Phase 5)' {
        It 'Combines two co-occurring findings on the same process into an elevated, capped CombinedScore' {
            $findings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-combined-signal-test.csv') | Invoke-MDEDetection | Select-MDEFindingOnly)
            $findings.Count | Should -Be 2
            $findings[0].CombinedScore | Should -Be 100
            $findings[0].CombinedSeverity | Should -Be 'Critical'
            $findings[0].CoOccurringFindings.Count | Should -Be 1
        }

        It 'Does not combine findings that sit on different processes' {
            foreach ($finding in (Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') | Invoke-MDEDetection | Select-MDEFindingOnly)) {
                $finding.CombinedScore | Should -Be $finding.Score
                $finding.CoOccurringFindings.Count | Should -Be 0
            }
        }
    }

    Context 'Process lineage reconstruction (requirement #7, Phase 5)' {
        It 'Reconstructs a 4-generation chain split across two separate rows' {
            $findings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-lineage-tests.csv') | Invoke-MDEDetection | Select-MDEFindingOnly)
            $findings.Count | Should -Be 1
            $findings[0].ProcessLineage.Count | Should -Be 4
            ($findings[0].ProcessLineage.FileName -join ' -> ') | Should -Be 'wininit.exe -> services.exe -> svchost.exe -> cmd.exe'
        }
    }

    Context 'Baseline exclusion and its precedence rule (requirement #9/#10, Phase 4)' {
        It 'Suppresses a Medium-severity finding matched by a rule-scoped baseline exclusion' {
            $findings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') |
                    Invoke-MDEDetection -BaselineConfigPath (Join-Path $fixturesPath 'baseline-sample.json') | Select-MDEFindingOnly)
            ($findings | Where-Object RuleId -eq 'DEFEVA-001') | Should -BeNullOrEmpty
        }

        It 'Does NOT suppress a High/Critical finding even when a baseline entry matches, and marks it overridden' {
            $findings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') |
                    Invoke-MDEDetection -BaselineConfigPath (Join-Path $fixturesPath 'baseline-sample.json') | Select-MDEFindingOnly)
            $execFinding = $findings | Where-Object RuleId -eq 'EXEC-001'
            $execFinding | Should -Not -BeNullOrEmpty
            $execFinding.BaselineExclusionOverridden | Should -Be $true
        }

        It 'Throws immediately for a malformed baseline config rather than silently proceeding' {
            $rows = Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-happy.csv')
            { $rows | Invoke-MDEDetection -BaselineConfigPath (Join-Path $fixturesPath 'baseline-invalid.json') } | Should -Throw
        }
    }

    Context 'RunSummary object (executive summary incident overview)' {
        BeforeAll {
            $script:runSummaryOutput = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-runsummary-tests.csv') | Invoke-MDEDetection)
            $script:runSummary = $runSummaryOutput | Where-Object { $_.PSObject.TypeNames -contains 'MDETimelineTriage.RunSummary' }
        }

        It 'Emits exactly one RunSummary-tagged object as the last item in the output stream' {
            $runSummary | Should -Not -BeNullOrEmpty
            $runSummaryOutput[-1] | Should -Be $runSummary
        }

        It 'Computes the export timeframe across every row processed, not just findings' {
            $runSummary.TotalRowsProcessed | Should -Be 4
            $runSummary.ExportTimeframeStart | Should -Be ([datetime]'2026-08-11T09:00:00Z')
            $runSummary.ExportTimeframeEnd | Should -Be ([datetime]'2026-08-11T09:45:00Z')
        }

        It 'Computes the left goalpost (first suspicious activity) from the earliest finding, not the earliest row' {
            $runSummary.FirstSuspiciousActivityTimestamp | Should -Be ([datetime]'2026-08-11T09:15:00Z')
        }

        It 'Computes the right goalpost (first heuristic response action) and its context' {
            $runSummary.FirstResponseActionTimestamp | Should -Be ([datetime]'2026-08-11T09:45:00Z')
            $runSummary.FirstResponseActionType | Should -Be 'MachineIsolationRequested'
            $runSummary.FirstResponseDeviceName | Should -Be 'WKSTN-TEST-001'
        }

        It 'Leaves the right goalpost null when no row matches the response-action heuristic' {
            $output = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-happy.csv') | Invoke-MDEDetection)
            $summary = $output | Where-Object { $_.PSObject.TypeNames -contains 'MDETimelineTriage.RunSummary' }
            $summary.FirstResponseActionTimestamp | Should -BeNullOrEmpty
        }

        It 'Detects the alert-linked row via the ActionType heuristic' {
            @($runSummary.AlertLikeRows).Count | Should -Be 1
            $runSummary.AlertLikeRows[0].ActionType | Should -Be 'AlertTriggered'
        }

        It 'A caller-supplied -ResponseActionKeywords list overrides the default heuristic' {
            $output = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-runsummary-tests.csv') | Invoke-MDEDetection -ResponseActionKeywords @('NoSuchKeyword'))
            $summary = $output | Where-Object { $_.PSObject.TypeNames -contains 'MDETimelineTriage.RunSummary' }
            $summary.FirstResponseActionTimestamp | Should -BeNullOrEmpty
        }

        It 'Records suppressed-finding detail (not just a count) when a baseline exclusion applies' {
            $output = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv') | Invoke-MDEDetection -BaselineConfigPath (Join-Path $fixturesPath 'baseline-sample.json'))
            $summary = $output | Where-Object { $_.PSObject.TypeNames -contains 'MDETimelineTriage.RunSummary' }
            $summary.SuppressedFindingsCount | Should -Be 1
            $summary.SuppressedFindingsDetail[0].RuleId | Should -Be 'DEFEVA-001'
        }
    }

    Context 'Custom IOC matching (requirement #10, Phase 4)' {
        It 'Fires a custom IOC entry with a CaseId-derived synthesized RuleId and DetectionSource=Custom' {
            $findings = @(Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceNetworkEvents-happy.csv') |
                    Invoke-MDEDetection -CustomIOCConfigPath (Join-Path $fixturesPath 'custom-ioc-sample.json') | Select-MDEFindingOnly)
            $findings.Count | Should -Be 1
            $findings[0].RuleId | Should -BeLike 'CUSTOM-2026-041-*'
            $findings[0].DetectionSource | Should -Be 'Custom'
        }
    }

    Context '-WhatIf / dry-run support (requirement #12)' {
        It 'Returns no finding objects under -WhatIf' {
            $rows = Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv')
            $result = @($rows | Invoke-MDEDetection -WhatIf)
            $result.Count | Should -Be 0
        }

        It 'Does not throw under -WhatIf with no config supplied' {
            $rows = Import-MDETimeline -Path (Join-Path $fixturesPath 'DeviceProcessEvents-detection-tests.csv')
            { $rows | Invoke-MDEDetection -WhatIf } | Should -Not -Throw
        }
    }

    Context 'Rule-catalog cross-check' {
        It 'Every function referenced by the catalog exists as a loaded command (checked from inside the module''s own scope, since these are intentionally private/non-exported functions -- Get-Command from outside the module cannot see them by design)' {
            $mod = Get-Module MDETimelineTriage
            Get-MDEDetectionCatalog | ForEach-Object {
                $functionName = $_.FunctionName
                $found = & $mod { param($n) Get-Command -Name $n -ErrorAction SilentlyContinue } $functionName
                $found | Should -Not -BeNullOrEmpty -Because "catalog entry $($_.RuleId) references $functionName"
            }
        }
    }
}
