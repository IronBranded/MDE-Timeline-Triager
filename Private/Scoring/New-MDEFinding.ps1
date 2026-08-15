function New-MDEFinding {
    <#
    .SYNOPSIS
        Constructs a Finding object conforming to the module's Finding Object Schema.
    .DESCRIPTION
        Central constructor called by Invoke-MDEDetection so every finding -- regardless of
        whether it came from a built-in catalog rule or a case-specific custom IOC -- exposes
        the exact same property set (RuleName, Severity, Confidence, Tactic, TechniqueId,
        Explanation, BenignExplanation, SourceRow, ProcessLineage, Timestamp), rather than
        each caller hand-rolling its own PSCustomObject and risking a typo'd or omitted
        property.

        Two parameter sets cover the two ways a finding's static metadata can be sourced:
          - 'Catalog' (built-in rules): looks up Name/Tactic/TechniqueId/Severity/Score/
            Confidence/BenignExplanation from the loaded detection catalog by RuleId.
          - 'Explicit' (custom IOC matches, build Phase 4): accepts a pre-built metadata
            object with the same property names directly, since a custom IOC entry supplies
            its own Severity/Confidence/etc. rather than being looked up anywhere.
        Both sets converge on identical construction logic below the parameter-set-specific
        lookup, so the two kinds of finding can never end up with a different shape.

        ProcessLineage is always $null at construction time; Invoke-MDEDetection populates
        it after all rows have streamed through and the lineage index is complete (build
        Phase 5), since a process's ancestors may be described in rows anywhere in the file,
        not necessarily ones already seen at the moment this finding is created. This is
        schema-compliant either way, since the Finding Object Schema allows ProcessLineage to
        be null/empty.
        CombinedScore/CombinedSeverity default to this finding's own Score/Severity (the
        correct value when it turns out to have no co-occurring findings on the same
        process), and CoOccurringFindings defaults to an empty array; all three are
        overwritten by Invoke-MDEDetection only when this finding shares a process with at
        least one other finding (requirement #5's multi-signal combination, Phase 5).
        BaselineExclusionOverridden defaults to $false and is flipped to $true by
        Invoke-MDEDetection only when a baseline exclusion matched but could not suppress the
        finding because its severity was too high (requirement #10's precedence rule) -- it
        is always present so the property set stays uniform across every finding regardless
        of whether an override happened.
    .PARAMETER RuleId
        (Catalog parameter set) The RuleId of the built-in rule that fired (e.g. 'EXEC-001').
        Mandatory in this parameter set.
    .PARAMETER Catalog
        (Catalog parameter set) The loaded detection catalog (array of rule metadata objects,
        as read from Data/DetectionCatalog.json). Mandatory in this parameter set.
    .PARAMETER Metadata
        (Explicit parameter set) A pre-built object exposing RuleId, Name, Tactic,
        TechniqueId, Severity, Score, Confidence, and BenignExplanation -- used for custom IOC
        matches, which carry their own metadata rather than being looked up in the built-in
        catalog. Mandatory in this parameter set.
    .PARAMETER Explanation
        The dynamic, per-row explanation text. Mandatory in both parameter sets.
    .PARAMETER Row
        The originating parsed timeline row object (from Import-MDETimeline). Mandatory in
        both parameter sets.
    .PARAMETER DetectionSource
        'BuiltIn' or 'Custom'. Optional, default 'BuiltIn'.
    .PARAMETER TelemetryMapping
        The already-loaded contents of Data/TelemetryMapping.json (requirement #2). Optional;
        if omitted, WindowsEventId/SysmonEventId fields are left $null rather than throwing,
        so callers that don't care about this correlation aren't forced to load it.
    .OUTPUTS
        PSCustomObject
        The 9 Finding Object Schema properties (RuleName, Severity, Confidence, Tactic,
        TechniqueId, Explanation, BenignExplanation, SourceRow, ProcessLineage, Timestamp)
        plus additional properties RuleId, Score, SourceTable, DetectionSource,
        BaselineExclusionOverridden, CombinedScore, CombinedSeverity, CoOccurringFindings,
        WindowsEventId, WindowsEventName, SysmonEventId, and SysmonEventName.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Catalog')]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Catalog')]
        [string]$RuleId,

        [Parameter(Mandatory = $true, ParameterSetName = 'Catalog')]
        [PSObject[]]$Catalog,

        [Parameter(Mandatory = $true, ParameterSetName = 'Explicit')]
        [PSObject]$Metadata,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Explanation,

        [Parameter(Mandatory = $true)]
        [PSObject]$Row,

        [Parameter()]
        [ValidateSet('BuiltIn', 'Custom')]
        [string]$DetectionSource = 'BuiltIn',

        [Parameter()]
        [PSObject]$TelemetryMapping
    )

    if ($PSCmdlet.ParameterSetName -eq 'Catalog') {
        $ruleMeta = $Catalog | Where-Object { $_.RuleId -eq $RuleId } | Select-Object -First 1
        if ($null -eq $ruleMeta) {
            throw "New-MDEFinding: no catalog entry found for RuleId '$RuleId'. Every built-in rule function must have a matching Data/DetectionCatalog.json entry -- this indicates a rule was implemented without a corresponding catalog entry, which is a packaging bug, not a data problem."
        }
    }
    else {
        $ruleMeta = $Metadata
    }

    $timestamp = $null
    if ($Row.PSObject.Properties['Timestamp']) {
        $timestamp = ConvertTo-MDEParsedTimestamp -Value ([string]$Row.Timestamp)
        if ($null -eq $timestamp) {
            $rowNum = if ($Row.PSObject.Properties['SourceRowNumber']) { $Row.SourceRowNumber } else { '?' }
            Write-Verbose "New-MDEFinding: could not parse Timestamp '$($Row.Timestamp)' on row $rowNum for rule $($ruleMeta.RuleId) -- Timestamp left `$null on this finding."
        }
    }

    $telemetry = [PSCustomObject]@{ WindowsEventId = $null; WindowsEventName = $null; SysmonEventId = $null; SysmonEventName = $null }
    if ($TelemetryMapping) {
        $rowSourceTable = if ($Row.PSObject.Properties['SourceTable']) { [string]$Row.SourceTable } else { '' }
        $rowActionType = if ($Row.PSObject.Properties['ActionType']) { [string]$Row.ActionType } else { '' }
        $telemetry = Get-MDETelemetryMapping -MappingData $TelemetryMapping -SourceTable $rowSourceTable -ActionType $rowActionType
    }

    return [PSCustomObject]@{
        RuleName                    = $ruleMeta.Name
        RuleId                      = $ruleMeta.RuleId
        Severity                    = $ruleMeta.Severity
        Score                       = $ruleMeta.Score
        Confidence                  = $ruleMeta.Confidence
        Tactic                      = $ruleMeta.Tactic
        TechniqueId                 = $ruleMeta.TechniqueId
        Explanation                 = $Explanation
        BenignExplanation           = $ruleMeta.BenignExplanation
        SourceRow                   = $Row
        SourceTable                 = if ($Row.PSObject.Properties['SourceTable']) { $Row.SourceTable } else { $null }
        ProcessLineage              = $null
        Timestamp                   = $timestamp
        DetectionSource             = $DetectionSource
        BaselineExclusionOverridden = $false
        CombinedScore               = $ruleMeta.Score
        CombinedSeverity            = $ruleMeta.Severity
        CoOccurringFindings         = [string[]]@()
        WindowsEventId              = $telemetry.WindowsEventId
        WindowsEventName            = $telemetry.WindowsEventName
        SysmonEventId               = $telemetry.SysmonEventId
        SysmonEventName             = $telemetry.SysmonEventName
    }
}
