function Test-MDEBaseline {
    <#
    .SYNOPSIS
        Validates a baseline/exclusion or custom IOC config file's schema and reports errors.

    .DESCRIPTION
        Test-MDEBaseline validates the two kinds of external config file this module reads:
        the baseline/exclusion config (used to suppress known corporate noise, see
        Invoke-MDEDetection's -BaselineConfigPath) and the custom IOC/keyword config (used
        for case-specific detections, see Invoke-MDEDetection's -CustomIOCConfigPath). Both
        share the same base shape -- an array of objects, each with Field/MatchType/Pattern
        identifying what to match -- which is why one cmdlet validates both; a custom IOC
        entry additionally requires Severity (and optionally Confidence), which a baseline
        exclusion entry does not carry.

        By default the config type is auto-detected from whether the first entry has a
        Severity property (custom IOC entries always do; baseline exclusion entries never
        do). Pass -ConfigType explicitly to force validation against one schema and fail if
        the file doesn't match it, e.g. to catch a baseline config accidentally pointed at
        -CustomIOCConfigPath or vice versa.

        Every entry is checked (not just the first failure): a required Field/MatchType/
        Pattern is present and MatchType is one of Exact/Contains/Regex; a Regex Pattern is
        also checked for syntactic validity ([regex]::new(...) must not throw); a CustomIOC
        entry's Severity must be one of the 5 taxonomy tiers and, if present, Confidence must
        be one of High/Medium/Low. If an entry's optional RuleId does not match any RuleId
        currently in the built-in detection catalog, a -Verbose-visible warning is emitted
        (not a validation error) -- the catalog can grow in a later module version, and a
        forward-referencing RuleId is not necessarily a mistake, though it may be a typo
        worth double-checking. This cmdlet never processes a CSV.

    .PARAMETER Path
        Path to the baseline/exclusion or custom IOC config file to validate. Mandatory.

    .PARAMETER ConfigType
        One of 'Auto', 'Baseline', or 'CustomIOC'. Default: 'Auto' (detected from whether the
        first entry has a Severity property). Use 'Baseline' or 'CustomIOC' to force
        validation against one schema and fail if the file doesn't match it.

    .EXAMPLE
        Test-MDEBaseline -Path .\config\baseline.json

        Auto-detects the config type and reports any schema errors found.

    .EXAMPLE
        Test-MDEBaseline -Path .\config\case-2026-041-iocs.json -ConfigType CustomIOC -Verbose

        Validates the file specifically as a custom IOC config, failing if it doesn't match
        that schema even if it happens to parse as valid JSON. -Verbose surfaces any
        unrecognized-RuleId warnings inline.

    .INPUTS
        None. This cmdlet does not accept pipeline input; it reads directly from -Path.

    .OUTPUTS
        PSCustomObject
        One validation result object: IsValid (bool), ConfigType (the resolved or forced
        type), and Errors (string[], one entry per specific schema problem found, empty if
        valid).

    .NOTES
        Read-only guarantee: -Path is never modified.

        An empty array (`[]`) is treated as valid for either config type -- an empty
        baseline/custom-IOC config is a legitimate "no exclusions/no custom IOCs yet" state,
        not an error.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Leaf)) {
                    throw "Path '$_' does not exist or is not a file."
                }
                $true
            })]
        [string]
        $Path,

        [Parameter()]
        [ValidateSet('Auto', 'Baseline', 'CustomIOC')]
        [string]
        $ConfigType = 'Auto'
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    try {
        $content = Get-Content -Path $Path -Raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [PSCustomObject]@{
            IsValid    = $false
            ConfigType = $ConfigType
            Errors     = [string[]]@("File is not valid JSON: $($_.Exception.Message)")
        }
    }

    $entries = @($content)

    if ($entries.Count -eq 0) {
        return [PSCustomObject]@{
            IsValid    = $true
            ConfigType = if ($ConfigType -eq 'Auto') { 'Baseline' } else { $ConfigType }
            Errors     = [string[]]@()
        }
    }

    $resolvedType = $ConfigType
    if ($ConfigType -eq 'Auto') {
        $resolvedType = if ($entries[0].PSObject.Properties['Severity']) { 'CustomIOC' } else { 'Baseline' }
    }

    $validMatchTypes = @('Exact', 'Contains', 'Regex')
    $validSeverities = @('Critical', 'High', 'Medium', 'Low', 'Informational')
    $validConfidences = @('High', 'Medium', 'Low')
    $catalogRuleIds = $null

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        $prefix = "Entry $($i + 1)"

        $hasPattern = $entry.PSObject.Properties['Pattern'] -and -not [string]::IsNullOrEmpty($entry.Pattern)
        if (-not $hasPattern) {
            $errors.Add("$prefix`: missing or empty required field 'Pattern'.")
        }

        if (-not $entry.PSObject.Properties['Field'] -or [string]::IsNullOrWhiteSpace($entry.Field)) {
            $errors.Add("$prefix`: missing or empty required field 'Field'.")
        }

        if (-not $entry.PSObject.Properties['MatchType'] -or $entry.MatchType -notin $validMatchTypes) {
            $errors.Add("$prefix`: 'MatchType' must be one of $($validMatchTypes -join ', ').")
        }
        elseif ($entry.MatchType -eq 'Regex' -and $hasPattern) {
            try {
                [void][regex]::new($entry.Pattern)
            }
            catch {
                $errors.Add("$prefix`: 'Pattern' is not a syntactically valid regex: $($_.Exception.Message)")
            }
        }

        if ($resolvedType -eq 'CustomIOC') {
            if (-not $entry.PSObject.Properties['Severity'] -or $entry.Severity -notin $validSeverities) {
                $errors.Add("$prefix`: 'Severity' must be one of $($validSeverities -join ', ') for a custom IOC entry.")
            }
            if ($entry.PSObject.Properties['Confidence'] -and $entry.Confidence -and $entry.Confidence -notin $validConfidences) {
                $errors.Add("$prefix`: 'Confidence' must be one of $($validConfidences -join ', ') when present.")
            }
        }

        if ($entry.PSObject.Properties['RuleId'] -and $entry.RuleId) {
            if ($null -eq $catalogRuleIds) {
                $catalogRuleIds = @(Get-MDEDetectionCatalog | ForEach-Object { $_.RuleId })
            }
            if ($entry.RuleId -notin $catalogRuleIds) {
                Write-Verbose "Test-MDEBaseline: $prefix references RuleId '$($entry.RuleId)', which is not in the current detection catalog. Not a validation error -- the catalog may add this RuleId in a later version, or this may be a typo worth double-checking."
            }
        }
    }

    return [PSCustomObject]@{
        IsValid    = ($errors.Count -eq 0)
        ConfigType = $resolvedType
        Errors     = $errors.ToArray()
    }
}
