function Invoke-MDEDetection {
    <#
    .SYNOPSIS
        Runs detection, scoring, MITRE ATT&CK tagging, baseline/custom-IOC filtering, and process-lineage correlation against parsed MDE timeline objects.

    .DESCRIPTION
        Invoke-MDEDetection is the triage stage of the MDETimelineTriage pipeline. It accepts
        parsed timeline objects -- typically piped directly from Import-MDETimeline -- and
        runs every built-in detection rule plus, if supplied, every custom IOC entry against
        each row, applies baseline/exclusion filtering, reconstructs process lineage, combines
        co-occurring signals into an elevated verdict, and returns scored Finding objects.

        Every finding carries an independent Severity tier and Confidence label -- these two
        axes are never conflated or auto-derived from one another, and a Low-confidence
        finding at High or Critical severity is never auto-suppressed (requirement #5). Each
        finding is also tagged with the standard Windows Event ID / Sysmon Event ID that
        corresponds to its row's (SourceTable, ActionType) pair where a verified correlation
        is known (requirement #2; see Data/TelemetryMapping.json and
        Get-MDETelemetryMapping).

        PROCESS LINEAGE (requirement #7): as rows stream through, a compact lineage index
        (process identity + parent-child edges, keyed on Id+CreationTime rather than PID
        alone, since PIDs are reused) is built incrementally -- see Update-MDEProcessLineage
        Index. A process's ancestors may be described in rows anywhere in the file, not
        necessarily ones already seen by the time a finding fires on it, so ProcessLineage
        cannot be attached until the whole file has streamed through; this cmdlet therefore
        buffers FINDINGS (not rows) internally and attaches ProcessLineage plus the multi-
        signal combination below once the index is complete, emitting everything at the end.
        This is a deliberate, documented departure from this module's otherwise single-pass,
        bounded-memory design (Import-MDETimeline, and this cmdlet's own Phases 3-4
        behavior): the buffered set scales with alert volume (typically a small fraction of
        total rows), not total file size, but it is not zero-buffering the way earlier phases
        were, and is worth knowing about on an unusually high-volume run.

        MULTI-SIGNAL COMBINATION (requirement #5): findings are grouped by the process they
        are about (Get-MDERowSubjectProcessKey); a lone finding keeps its own Score as
        CombinedScore. Two or more findings sharing a process are combined by weighting
        their scores in descending order at 100%, 50%, 25%, 12.5%, ... (each additional
        co-occurring signal contributes half as much as the previous one), capped at 100,
        then mapped back to a tier via Get-MDESeverityFromScore. Every finding in the group
        gets the same CombinedScore/CombinedSeverity plus CoOccurringFindings listing the
        other RuleIds involved, so the "why is this elevated" reasoning is visible on the
        finding itself rather than requiring a separate rollup lookup.

        BASELINE EXCLUSION / CUSTOM IOC (requirements #9/#10): unchanged from build Phase 4 --
        a custom IOC entry (Field/MatchType/Pattern plus Severity, optional CaseId/
        Confidence/SourceTables/Explanation) is checked like a built-in rule; a baseline
        exclusion entry may suppress a Medium/Low/Informational finding but never a High/
        Critical one, which survives with BaselineExclusionOverridden = $true instead. Both
        config files are validated via Test-MDEBaseline before use.

        This cmdlet implements SupportsShouldProcess: under -WhatIf, it reports how many
        built-in rules and custom IOC entries would run without evaluating any row or
        returning any finding objects.

    .PARAMETER InputObject
        Parsed MDE timeline object(s), typically piped from Import-MDETimeline. Mandatory,
        accepted from the pipeline by value.

    .PARAMETER BaselineConfigPath
        Path to a JSON baseline/exclusion config file (see Test-MDEBaseline for schema
        validation and Tests/Fixtures/baseline-sample.json for an example). Optional.

    .PARAMETER CustomIOCConfigPath
        Path to a JSON custom IOC/keyword config file (see Test-MDEBaseline for schema
        validation and Tests/Fixtures/custom-ioc-sample.json for an example). Optional.
    .PARAMETER ResponseActionKeywords
        Substrings to match against ActionType (case-insensitive) when estimating the first
        automated MDE response/containment action for the executive summary's incident
        overview (the "right goalpost"). Optional; defaults to the heuristic list in
        Data/ResponseActionKeywords.json ("Contain", "Isolat", "Quarantine", "Remediat",
        "Restrict") if not supplied. Microsoft does not publish an authoritative, exhaustive
        list of ActionType values -- this is explicitly a best-effort estimate, and an
        analyst with their own tenant's Defender portal schema reference should pass their
        environment's exact ActionType values here when precision matters. See
        Data/ResponseActionKeywords.json's own header note and Test-MDEResponseActionKeyword.

    .EXAMPLE
        Import-MDETimeline -Path .\host01-timeline.csv | Invoke-MDEDetection

        Runs the full built-in detection catalog, with process lineage and multi-signal
        combination applied to every finding, and no baseline/custom-IOC filtering.

    .EXAMPLE
        Import-MDETimeline -Path .\host01-timeline.csv | Invoke-MDEDetection | Where-Object { $_.CoOccurringFindings.Count -gt 0 } | Sort-Object CombinedScore -Descending

        Surfaces only findings that co-occurred with at least one other finding on the same
        process, ranked by their combined (elevated) score -- typically the highest-value
        starting point for triage on a busy timeline.

    .INPUTS
        PSCustomObject
        Parsed timeline objects, e.g. from Import-MDETimeline.

    .OUTPUTS
        PSCustomObject
        Finding objects exposing at minimum: RuleName, Severity, Confidence, Tactic,
        TechniqueId, Explanation, BenignExplanation, SourceRow, ProcessLineage, Timestamp
        (see New-MDEFinding for the additional RuleId/Score/SourceTable/DetectionSource/
        BaselineExclusionOverridden/CombinedScore/CombinedSeverity/CoOccurringFindings
        properties every finding also carries), followed by exactly one additional object
        tagged with the PSTypeName 'MDETimelineTriage.RunSummary' as the last item in the
        stream -- export timeframe, first-activity/first-response goalposts, alert-like rows,
        and suppressed-finding detail for the executive summary's incident overview (New-
        MDEReport separates this from the findings automatically by its PSTypeName; a caller
        piping into anything else should filter it out by the same tag if the extra object
        isn't wanted).

    .NOTES
        SupportsShouldProcess: -WhatIf reports the loaded rule/custom-IOC counts and target
        description without evaluating any row, building any lineage, or mutating state.

        Buffers findings (not rows) until process lineage is fully reconstructed -- see the
        Description above for why this is unavoidable given the problem, and what it does
        and does not cost in memory.

        Build status: real as of Phase 5. Full rule-catalog breadth lands in Phase 7.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject[]]
        $InputObject,

        [Parameter()]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Leaf)) {
                    throw "BaselineConfigPath '$_' does not exist or is not a file."
                }
                $true
            })]
        [string]
        $BaselineConfigPath,

        [Parameter()]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Leaf)) {
                    throw "CustomIOCConfigPath '$_' does not exist or is not a file."
                }
                $true
            })]
        [string]
        $CustomIOCConfigPath,

        [Parameter()]
        [string[]]
        $ResponseActionKeywords
    )

    begin {
        $catalogPath = Join-Path -Path (Get-MDEModuleRoot) -ChildPath 'Data/DetectionCatalog.json'
        $catalog = @(Get-Content -Path $catalogPath -Raw | ConvertFrom-Json)

        $telemetryMappingPath = Join-Path -Path (Get-MDEModuleRoot) -ChildPath 'Data/TelemetryMapping.json'
        $telemetryMapping = Get-Content -Path $telemetryMappingPath -Raw | ConvertFrom-Json

        if ($ResponseActionKeywords) {
            $responseKeywords = $ResponseActionKeywords
            Write-Verbose "Invoke-MDEDetection: using $($responseKeywords.Count) caller-supplied -ResponseActionKeywords."
        }
        else {
            $responseKeywordsPath = Join-Path -Path (Get-MDEModuleRoot) -ChildPath 'Data/ResponseActionKeywords.json'
            $responseKeywords = @((Get-Content -Path $responseKeywordsPath -Raw | ConvertFrom-Json).DefaultKeywords)
            Write-Verbose "Invoke-MDEDetection: using $($responseKeywords.Count) default heuristic -ResponseActionKeywords from Data/ResponseActionKeywords.json (not authoritative -- see that file's header note)."
        }

        $rules = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($ruleMeta in $catalog) {
            $cmd = Get-Command -Name $ruleMeta.FunctionName -ErrorAction SilentlyContinue
            if ($null -eq $cmd) {
                Write-Warning "Invoke-MDEDetection: catalog entry '$($ruleMeta.RuleId)' references function '$($ruleMeta.FunctionName)', which was not found. Skipping this rule for this run."
                continue
            }
            $rules.Add($ruleMeta)
        }
        Write-Verbose "Invoke-MDEDetection: loaded $($rules.Count) of $($catalog.Count) catalog rule(s): $(($rules | ForEach-Object { $_.RuleId }) -join ', ')"

        $baselineConfig = @()
        if ($BaselineConfigPath) {
            $validation = Test-MDEBaseline -Path $BaselineConfigPath -ConfigType Baseline
            if (-not $validation.IsValid) {
                throw "Invoke-MDEDetection: -BaselineConfigPath '$BaselineConfigPath' failed schema validation:`n$($validation.Errors -join "`n")"
            }
            $baselineConfig = @(Get-Content -Path $BaselineConfigPath -Raw | ConvertFrom-Json)
            Write-Verbose "Invoke-MDEDetection: loaded $($baselineConfig.Count) baseline exclusion entr(y/ies) from '$BaselineConfigPath'."
        }

        $customIOCs = @()
        if ($CustomIOCConfigPath) {
            $validation = Test-MDEBaseline -Path $CustomIOCConfigPath -ConfigType CustomIOC
            if (-not $validation.IsValid) {
                throw "Invoke-MDEDetection: -CustomIOCConfigPath '$CustomIOCConfigPath' failed schema validation:`n$($validation.Errors -join "`n")"
            }
            $rawCustomIOCs = @(Get-Content -Path $CustomIOCConfigPath -Raw | ConvertFrom-Json)
            for ($i = 0; $i -lt $rawCustomIOCs.Count; $i++) {
                $ioc = $rawCustomIOCs[$i]
                $caseIdPart = if ($ioc.PSObject.Properties['CaseId'] -and $ioc.CaseId) { "$($ioc.CaseId)-" } else { '' }
                $syntheticRuleId = "CUSTOM-$caseIdPart$('{0:D3}' -f ($i + 1))"
                $ioc | Add-Member -MemberType NoteProperty -Name 'RuleId' -Value $syntheticRuleId -Force
                $customIOCs += $ioc
            }
            Write-Verbose "Invoke-MDEDetection: loaded $($customIOCs.Count) custom IOC entr(y/ies) from '$CustomIOCConfigPath': $(($customIOCs | ForEach-Object { $_.RuleId }) -join ', ')"
        }

        $target = 'parsed timeline rows from the pipeline'
        $action = "Run $($rules.Count) built-in rule(s) and $($customIOCs.Count) custom IOC entr(y/ies), apply $($baselineConfig.Count) baseline exclusion entr(y/ies), reconstruct process lineage, and return scored finding objects"
        $shouldRun = $PSCmdlet.ShouldProcess($target, $action)

        $lineageIndex = New-MDEProcessLineageIndex
        $findingsBuffer = [System.Collections.Generic.List[PSCustomObject]]::new()

        $rowsProcessed = 0
        $findingsSuppressed = 0
        $startTime = Get-Date
        $progressInterval = 5000

        $exportMinTimestamp = $null
        $exportMaxTimestamp = $null
        $firstResponseTimestamp = $null
        $firstResponseActionType = $null
        $firstResponseDeviceName = $null
        $alertLikeRows = [System.Collections.Generic.List[PSCustomObject]]::new()
        $suppressedDetail = [System.Collections.Generic.List[PSCustomObject]]::new()
    }

    process {
        if (-not $shouldRun) { return }

        foreach ($row in $InputObject) {
            $rowsProcessed++
            $rowFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

            $rowTimestamp = if ($row.PSObject.Properties['Timestamp']) { ConvertTo-MDEParsedTimestamp -Value ([string]$row.Timestamp) } else { $null }
            if ($null -ne $rowTimestamp) {
                if ($null -eq $exportMinTimestamp -or $rowTimestamp -lt $exportMinTimestamp) { $exportMinTimestamp = $rowTimestamp }
                if ($null -eq $exportMaxTimestamp -or $rowTimestamp -gt $exportMaxTimestamp) { $exportMaxTimestamp = $rowTimestamp }
            }

            $rowActionType = if ($row.PSObject.Properties['ActionType']) { [string]$row.ActionType } else { $null }
            if ($null -ne $rowTimestamp -and (Test-MDEResponseActionKeyword -ActionType $rowActionType -Keywords $responseKeywords)) {
                if ($null -eq $firstResponseTimestamp -or $rowTimestamp -lt $firstResponseTimestamp) {
                    $firstResponseTimestamp = $rowTimestamp
                    $firstResponseActionType = $rowActionType
                    $firstResponseDeviceName = if ($row.PSObject.Properties['DeviceName']) { [string]$row.DeviceName } else { $null }
                }
            }

            if (Test-MDEAlertLikeRow -Row $row) {
                $alertLikeRows.Add([PSCustomObject]@{
                        Timestamp  = $rowTimestamp
                        ActionType = $rowActionType
                        DeviceName = if ($row.PSObject.Properties['DeviceName']) { [string]$row.DeviceName } else { $null }
                    })
            }

            foreach ($ruleMeta in $rules) {
                try {
                    $hit = & $ruleMeta.FunctionName -Row $row
                }
                catch {
                    $rowNum = if ($row.PSObject.Properties['SourceRowNumber']) { $row.SourceRowNumber } else { '?' }
                    Write-Warning "Invoke-MDEDetection: rule '$($ruleMeta.RuleId)' threw an error evaluating row $rowNum ($($_.Exception.Message)). Skipping this rule for this row."
                    continue
                }
                if ($null -ne $hit) {
                    $rowFindings.Add((New-MDEFinding -RuleId $hit.RuleId -Explanation $hit.Explanation -Row $row -Catalog $catalog -DetectionSource 'BuiltIn' -TelemetryMapping $telemetryMapping))
                }
            }

            foreach ($ioc in $customIOCs) {
                if ($ioc.PSObject.Properties['SourceTables'] -and $ioc.SourceTables -and $row.SourceTable -notin @($ioc.SourceTables)) {
                    continue
                }
                try {
                    $matched = Test-MDEFieldMatch -Row $row -Field $ioc.Field -MatchType $ioc.MatchType -Pattern $ioc.Pattern
                }
                catch {
                    $rowNum = if ($row.PSObject.Properties['SourceRowNumber']) { $row.SourceRowNumber } else { '?' }
                    Write-Warning "Invoke-MDEDetection: custom IOC '$($ioc.RuleId)' threw an error evaluating row $rowNum ($($_.Exception.Message)). Skipping this entry for this row."
                    continue
                }
                if ($matched) {
                    $metadata = [PSCustomObject]@{
                        RuleId            = $ioc.RuleId
                        Name              = $ioc.Name
                        Tactic            = if ($ioc.PSObject.Properties['Tactic'] -and $ioc.Tactic) { $ioc.Tactic } else { 'Custom' }
                        TechniqueId       = if ($ioc.PSObject.Properties['TechniqueId'] -and $ioc.TechniqueId) { $ioc.TechniqueId } else { @() }
                        Severity          = $ioc.Severity
                        Score             = Get-MDEScoreFromSeverity -Severity $ioc.Severity
                        Confidence        = if ($ioc.PSObject.Properties['Confidence'] -and $ioc.Confidence) { $ioc.Confidence } else { 'High' }
                        BenignExplanation = if ($ioc.PSObject.Properties['BenignExplanation'] -and $ioc.BenignExplanation) { $ioc.BenignExplanation } else { 'Case-specific custom indicator; false-positive likelihood was not automatically assessed by the module.' }
                    }
                    $explanation = if ($ioc.PSObject.Properties['Explanation'] -and $ioc.Explanation) { $ioc.Explanation } else { "Matched custom IOC '$($ioc.Name)' on field '$($ioc.Field)'." }
                    $rowFindings.Add((New-MDEFinding -Metadata $metadata -Explanation $explanation -Row $row -DetectionSource 'Custom' -TelemetryMapping $telemetryMapping))
                }
            }

            foreach ($finding in $rowFindings) {
                $exclusionMatch = if ($baselineConfig.Count -gt 0) { Test-MDEBaselineExclusion -Finding $finding -BaselineConfig $baselineConfig } else { $null }

                if ($null -eq $exclusionMatch) {
                    $findingsBuffer.Add($finding)
                }
                elseif ($finding.Severity -in @('High', 'Critical')) {
                    $finding.BaselineExclusionOverridden = $true
                    Write-Verbose "Invoke-MDEDetection: finding from '$($finding.RuleId)' on row $($row.SourceRowNumber) matched baseline exclusion but survived (Severity=$($finding.Severity)); baseline exclusions cannot suppress High/Critical findings."
                    $findingsBuffer.Add($finding)
                }
                else {
                    $findingsSuppressed++
                    $suppressedDetail.Add([PSCustomObject]@{
                            RuleId    = $finding.RuleId
                            RuleName  = $finding.RuleName
                            Severity  = $finding.Severity
                            Timestamp = $finding.Timestamp
                        })
                    Write-Verbose "Invoke-MDEDetection: finding from '$($finding.RuleId)' on row $($row.SourceRowNumber) suppressed by baseline exclusion (Severity=$($finding.Severity))."
                }
            }

            Update-MDEProcessLineageIndex -Index $lineageIndex -Row $row

            if (($rowsProcessed % $progressInterval) -eq 0) {
                Write-MDEProgress -Activity 'Running MDE detection rules' -RowsProcessed $rowsProcessed -BytesRead $rowsProcessed -TotalBytes 0 -StartTime $startTime
            }
        }
    }

    end {
        if (-not $shouldRun) { return }

        Write-Verbose "Invoke-MDEDetection: $rowsProcessed row(s) processed. Reconstructing process lineage for $($findingsBuffer.Count) buffered finding(s)..."

        $groupsByProcessKey = @{}
        foreach ($finding in $findingsBuffer) {
            $subjectKey = Get-MDERowSubjectProcessKey -Row $finding.SourceRow
            $finding.ProcessLineage = if ($subjectKey) { Get-MDEProcessLineageChain -Index $lineageIndex -StartKey $subjectKey } else { @() }

            if ($subjectKey) {
                if (-not $groupsByProcessKey.ContainsKey($subjectKey)) {
                    $groupsByProcessKey[$subjectKey] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $groupsByProcessKey[$subjectKey].Add($finding)
            }
        }

        $combinedGroupCount = 0
        foreach ($key in $groupsByProcessKey.Keys) {
            $group = $groupsByProcessKey[$key]
            if ($group.Count -lt 2) { continue }
            $combinedGroupCount++

            $sortedScores = @($group | ForEach-Object { $_.Score } | Sort-Object -Descending)
            $combined = 0.0
            $weight = 1.0
            foreach ($s in $sortedScores) {
                $combined += $s * $weight
                $weight *= 0.5
            }
            $combinedScore = [Math]::Min(100, [Math]::Round($combined))
            $combinedSeverity = Get-MDESeverityFromScore -Score $combinedScore

            foreach ($finding in $group) {
                $finding.CombinedScore = $combinedScore
                $finding.CombinedSeverity = $combinedSeverity
                $finding.CoOccurringFindings = [string[]]@($group | Where-Object { $_ -ne $finding } | ForEach-Object { $_.RuleId })
            }
            Write-Verbose "Invoke-MDEDetection: combined $($group.Count) co-occurring finding(s) on process '$key' ($(($group | ForEach-Object { $_.RuleId }) -join ', ')) -> CombinedScore=$combinedScore ($combinedSeverity)."
        }

        foreach ($finding in $findingsBuffer) {
            $finding
        }

        $leftGoalpost = $null
        if ($findingsBuffer.Count -gt 0) {
            $timestampedFindings = @($findingsBuffer | Where-Object { $null -ne $_.Timestamp })
            if ($timestampedFindings.Count -gt 0) {
                $leftGoalpost = ($timestampedFindings | Sort-Object Timestamp | Select-Object -First 1).Timestamp
            }
        }

        [PSCustomObject]@{
            PSTypeName                     = 'MDETimelineTriage.RunSummary'
            ExportTimeframeStart           = $exportMinTimestamp
            ExportTimeframeEnd             = $exportMaxTimestamp
            TotalRowsProcessed             = $rowsProcessed
            FirstSuspiciousActivityTimestamp = $leftGoalpost
            FirstResponseActionTimestamp   = $firstResponseTimestamp
            FirstResponseActionType        = $firstResponseActionType
            FirstResponseDeviceName        = $firstResponseDeviceName
            ResponseActionKeywordsUsed     = $responseKeywords
            AlertLikeRows                  = @($alertLikeRows | Sort-Object Timestamp)
            TotalFindingsCount             = $findingsBuffer.Count
            SuppressedFindingsCount        = $findingsSuppressed
            SuppressedFindingsDetail       = @($suppressedDetail | Sort-Object Timestamp)
            BaselineConfigPathUsed         = $BaselineConfigPath
            CustomIOCConfigPathUsed        = $CustomIOCConfigPath
        }

        Write-Progress -Activity 'Running MDE detection rules' -Completed
        Write-Verbose "Invoke-MDEDetection: produced $($findingsBuffer.Count) finding(s) ($combinedGroupCount combined group(s) of 2+), suppressed $findingsSuppressed finding(s) via baseline exclusion."
    }
}
