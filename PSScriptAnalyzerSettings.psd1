@{
    IncludeDefaultRules = $true
    Severity            = @('Error', 'Warning', 'Information')

    # Per project requirement #13: "Any deliberately suppressed rule must include an inline
    # comment justifying why (e.g., a documented exception, not a blanket disable)."
    # Nothing is suppressed at skeleton stage -- add entries here ONLY alongside a
    # justification comment explaining the specific, deliberate exception.
    ExcludeRules        = @()

    Rules               = @{
        PSUseShouldProcessForStateChangingFunctions = @{
            Enable = $true
        }
        PSProvideCommentHelp                        = @{
            Enable                  = $true
            ExportedOnly            = $false
            BlockComment            = $true
            VSCodeSnippetCorrection = $false
            Placement               = 'before'
        }
    }
}
