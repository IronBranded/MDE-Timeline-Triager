function Get-MDEModuleRoot {
    <#
    .SYNOPSIS
        Returns the root directory of the currently loaded MDETimelineTriage module.
    .DESCRIPTION
        Used by other private functions to resolve paths to shipped assets (e.g.
        Data/SchemaMap.json, Data/DetectionCatalog.json, Data/Vendor/*) without depending on
        $PSScriptRoot resolution inside a dot-sourced function, which is not guaranteed to
        behave the same way in every calling context. Uses
        $MyInvocation.MyCommand.Module.ModuleBase -- the standard, documented mechanism for a
        function to find the root of the module it belongs to, regardless of how that module
        was loaded (Import-Module by path, by name from PSModulePath, etc.).
    .OUTPUTS
        System.String
        Absolute path to the module's root directory.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $module = $MyInvocation.MyCommand.Module
    if ($null -eq $module) {
        # Fallback for the unusual case of this file being dot-sourced directly outside a
        # loaded module context (e.g. ad hoc testing during development).
        return $PSScriptRoot
    }
    return $module.ModuleBase
}
