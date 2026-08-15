@{
    RootModule           = 'MDETimelineTriage.psm1'
    ModuleVersion        = '0.2.0'
    GUID                 = 'ea605e02-e84e-4ae1-9123-3e8cd13823b4'
    Author               = '<Your Name>'
    CompanyName          = '<Your Organization>'
    Copyright            = '(c) 2026 <Your Name/Organization>. All rights reserved.'
    Description          = 'Triage and visualization module for Microsoft Defender for Endpoint (MDE) Windows timeline CSV exports. Parses a single MDE timeline/Advanced Hunting CSV export, runs a built-in + custom detection catalog tagged to MITRE ATT&CK, scores findings on independent Severity and Confidence axes, reconstructs process lineage, and renders a self-contained offline interactive HTML report plus a Timeline Explorer-ready enriched CSV.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    # Explicit, closed list -- this module's public surface is exactly these 7 cmdlets.
    # Everything else is a private helper. Mirrored by Export-ModuleMember in the .psm1.
    FunctionsToExport    = @(
        'Invoke-MDETriage',
        'Import-MDETimeline',
        'Invoke-MDEDetection',
        'New-MDEReport',
        'ConvertFrom-MDEEncodedCommand',
        'Test-MDEBaseline',
        'Get-MDEDetectionCatalog'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    PrivateData          = @{
        PSData = @{
            Tags         = @('DFIR', 'MDE', 'MicrosoftDefenderForEndpoint', 'IncidentResponse', 'ThreatHunting', 'Windows', 'Security')
            ProjectUri   = ''
            LicenseUri   = ''
            ReleaseNotes = 'See CHANGELOG.md.'
        }
    }
}
