function ConvertTo-MDEReportFindingRecord {
    <#
    .SYNOPSIS
        Transforms one Finding object into a flat, escaped, redaction-applied record ready for the HTML report and enriched CSV.
    .DESCRIPTION
        Centralizes every requirement #8/#17 concern in one place so New-MDEReport's template
        code never touches a raw finding or row value directly:
          - Every string field is HTML-encoded via ConvertTo-MDEHtmlEncodedString before it
            is placed on the returned record -- this record is safe to serialize and embed
            in report markup as-is.
          - If -Redact is set, DeviceName and every account-name-ish field
            (AccountName/AccountDomain/InitiatingProcessAccountName/
            InitiatingProcessAccountDomain) and RemoteDeviceName are replaced with a stable
            per-value placeholder via Protect-MDESensitiveValue and -RedactionMap, BEFORE
            HTML-encoding (the placeholder text needs no encoding, but is passed through
            anyway for consistency / defense in depth).
          - Timestamps are rendered as explicit, always-labeled UTC strings; if -LocalTime is
            set, a second, separately-labeled local-time string is also produced (requirement
            #8's "clearly label which timezone is shown at all times").
          - A curated set of commonly-useful SourceRow columns (spanning all 7 supported
            tables) is copied onto the flat record under stable property names, via
            Get-MDERowFieldOrEmpty, since different rows carry different native columns and
            the report template needs one consistent shape to bind DataTables/D3 against.
          - ProcessLineageChain (array of {FileName, ProcessId} root-to-subject) feeds the
            process-tree view; CoOccurringFindings is joined into a display string.
        The SAME record feeds both the interactive HTML views (via
        ConvertTo-MDEJsonForScriptEmbed) and Export-MDEEnrichedCsv's HTML-report-facing
        preview, so there is exactly one place where "what does a finding look like once safe
        to show" is decided.
    .PARAMETER Finding
        A Finding object (from Invoke-MDEDetection). Mandatory.
    .PARAMETER Redact
        Switch. Applies username/hostname pseudonymization. Optional.
    .PARAMETER RedactionMap
        The shared hashtable passed to Protect-MDESensitiveValue across the whole report
        render. Mandatory when -Redact is set; ignored otherwise.
    .PARAMETER LocalTime
        Switch. Additionally populates TimestampLocalDisplay. Optional.
    .OUTPUTS
        PSCustomObject -- a flat record, every string property already HTML-encoded and
        (if requested) redacted.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Finding,

        [Parameter()]
        [switch]$Redact,

        [Parameter()]
        [hashtable]$RedactionMap,

        [Parameter()]
        [switch]$LocalTime
    )

    $row = $Finding.SourceRow

    $deviceName = Get-MDERowFieldOrEmpty -Row $row -Name 'DeviceName'
    $accountName = Get-MDERowFieldOrEmpty -Row $row -Name 'AccountName'
    $accountDomain = Get-MDERowFieldOrEmpty -Row $row -Name 'AccountDomain'
    $initiatingAccountName = Get-MDERowFieldOrEmpty -Row $row -Name 'InitiatingProcessAccountName'
    $initiatingAccountDomain = Get-MDERowFieldOrEmpty -Row $row -Name 'InitiatingProcessAccountDomain'
    $remoteDeviceName = Get-MDERowFieldOrEmpty -Row $row -Name 'RemoteDeviceName'

    if ($Redact) {
        $deviceName = Protect-MDESensitiveValue -Value $deviceName -Prefix 'HOST' -Map $RedactionMap
        $accountName = Protect-MDESensitiveValue -Value $accountName -Prefix 'USER' -Map $RedactionMap
        $accountDomain = Protect-MDESensitiveValue -Value $accountDomain -Prefix 'DOMAIN' -Map $RedactionMap
        $initiatingAccountName = Protect-MDESensitiveValue -Value $initiatingAccountName -Prefix 'USER' -Map $RedactionMap
        $initiatingAccountDomain = Protect-MDESensitiveValue -Value $initiatingAccountDomain -Prefix 'DOMAIN' -Map $RedactionMap
        $remoteDeviceName = Protect-MDESensitiveValue -Value $remoteDeviceName -Prefix 'HOST' -Map $RedactionMap
    }

    $timestampUtcDisplay = if ($Finding.Timestamp) {
        "$($Finding.Timestamp.ToString('yyyy-MM-dd HH:mm:ss.fff')) UTC"
    }
    else {
        '(unknown)'
    }
    $timestampLocalDisplay = ''
    if ($LocalTime -and $Finding.Timestamp) {
        $localZoneName = [System.TimeZoneInfo]::Local.Id
        $localTimeValue = [System.TimeZoneInfo]::ConvertTimeFromUtc($Finding.Timestamp, [System.TimeZoneInfo]::Local)
        $timestampLocalDisplay = "$($localTimeValue.ToString('yyyy-MM-dd HH:mm:ss.fff')) $localZoneName (local)"
    }

    $lineageChain = @()
    if ($Finding.ProcessLineage -and $Finding.ProcessLineage.Count -gt 0) {
        # Each element of ProcessLineage is a plain hashtable (Get-MDEProcessLineageChain),
        # not a [PSCustomObject] -- bracket access, not dot access.
        $lineageChain = @($Finding.ProcessLineage | ForEach-Object {
                [PSCustomObject]@{
                    Key       = "$($_['ProcessId'])|$($_['CreationTime'])"
                    FileName  = ConvertTo-MDEHtmlEncodedString -Value $(if ($_['FileName']) { $_['FileName'] } else { '(unknown)' })
                    ProcessId = ConvertTo-MDEHtmlEncodedString -Value ([string]$_['ProcessId'])
                }
            })
    }

    return [PSCustomObject]@{
        RuleId                          = ConvertTo-MDEHtmlEncodedString -Value $Finding.RuleId
        RuleName                        = ConvertTo-MDEHtmlEncodedString -Value $Finding.RuleName
        Severity                        = ConvertTo-MDEHtmlEncodedString -Value $Finding.Severity
        Confidence                      = ConvertTo-MDEHtmlEncodedString -Value $Finding.Confidence
        Tactic                          = ConvertTo-MDEHtmlEncodedString -Value $Finding.Tactic
        TechniqueIdDisplay              = ConvertTo-MDEHtmlEncodedString -Value (($Finding.TechniqueId) -join ', ')
        Explanation                     = ConvertTo-MDEHtmlEncodedString -Value $Finding.Explanation
        BenignExplanation               = ConvertTo-MDEHtmlEncodedString -Value $Finding.BenignExplanation
        Score                           = $Finding.Score
        CombinedScore                   = $Finding.CombinedScore
        CombinedSeverity                = ConvertTo-MDEHtmlEncodedString -Value $Finding.CombinedSeverity
        CoOccurringFindingsDisplay      = ConvertTo-MDEHtmlEncodedString -Value (($Finding.CoOccurringFindings) -join ', ')
        SourceTable                     = ConvertTo-MDEHtmlEncodedString -Value $Finding.SourceTable
        DetectionSource                 = ConvertTo-MDEHtmlEncodedString -Value $Finding.DetectionSource
        BaselineExclusionOverridden     = [bool]$Finding.BaselineExclusionOverridden
        TimestampUtcDisplay             = ConvertTo-MDEHtmlEncodedString -Value $timestampUtcDisplay
        TimestampLocalDisplay           = ConvertTo-MDEHtmlEncodedString -Value $timestampLocalDisplay
        TimestampSortKey                = if ($Finding.Timestamp) { $Finding.Timestamp.ToString('o') } else { '' }
        DeviceName                      = ConvertTo-MDEHtmlEncodedString -Value $deviceName
        FileName                        = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'FileName')
        FolderPath                      = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'FolderPath')
        ProcessCommandLine              = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'ProcessCommandLine')
        InitiatingProcessFileName       = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'InitiatingProcessFileName')
        InitiatingProcessCommandLine    = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'InitiatingProcessCommandLine')
        InitiatingProcessFolderPath     = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'InitiatingProcessFolderPath')
        AccountName                     = ConvertTo-MDEHtmlEncodedString -Value $accountName
        AccountDomain                   = ConvertTo-MDEHtmlEncodedString -Value $accountDomain
        InitiatingProcessAccountName    = ConvertTo-MDEHtmlEncodedString -Value $initiatingAccountName
        InitiatingProcessAccountDomain  = ConvertTo-MDEHtmlEncodedString -Value $initiatingAccountDomain
        RemoteIP                        = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'RemoteIP')
        RemotePort                      = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'RemotePort')
        RemoteUrl                       = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'RemoteUrl')
        RemoteDeviceName                = ConvertTo-MDEHtmlEncodedString -Value $remoteDeviceName
        LocalIP                         = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'LocalIP')
        LocalPort                       = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'LocalPort')
        Protocol                        = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'Protocol')
        RegistryKey                     = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'RegistryKey')
        RegistryValueName               = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'RegistryValueName')
        RegistryValueData               = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'RegistryValueData')
        SHA1                            = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'SHA1')
        SHA256                          = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'SHA256')
        MD5                             = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'MD5')
        LogonType                       = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'LogonType')
        FailureReason                   = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'FailureReason')
        SourceRowNumber                 = if ($row -and $row.PSObject.Properties['SourceRowNumber']) { $row.SourceRowNumber } else { $null }
        ReportId                        = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowFieldOrEmpty -Row $row -Name 'ReportId')
        ProcessLineageChain             = $lineageChain
        ProcessSubjectKey               = ConvertTo-MDEHtmlEncodedString -Value (Get-MDERowSubjectProcessKey -Row $row)
        EventIdMappingDisplay           = ConvertTo-MDEHtmlEncodedString -Value $(
            $parts = [System.Collections.Generic.List[string]]::new()
            if ($Finding.WindowsEventId) { $parts.Add("Windows Event ID $($Finding.WindowsEventId)") }
            if ($Finding.SysmonEventId) { $parts.Add("Sysmon Event ID $($Finding.SysmonEventId)") }
            if ($parts.Count -gt 0) { $parts -join ' / ' } else { '' }
        )
    }
}
