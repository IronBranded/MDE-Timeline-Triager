#Requires -Version 5.1
<#
    MDETimelineTriage.psm1

    Root module loader: dot-sources Private (internal helper) functions first, then Public
    (exported) functions, into the module's session state, then exports only the Public set.
    See Public/*.ps1 for the 7 exported cmdlets and Private/*/README.md for what each
    internal helper area covers and which build phase populates it.

    NOTE ON Set-StrictMode: CSV rows produced by Import-MDETimeline have a variable property
    set by design -- different MDE export types (Device Timeline vs. Advanced Hunting vs.
    Live Response) carry different columns, and requirement #1 requires detecting and
    degrading gracefully rather than assuming a fixed schema. Under Set-StrictMode -Version
    Latest, direct dot-access to a property that may not exist on a given row throws. Always
    check existence first:
        if ($row.PSObject.Properties['ColumnName']) { ... }
    rather than assuming the property is present. StrictMode remains valuable for catching
    genuine typos elsewhere (e.g. finding-object or config-object property names, which ARE
    fixed schemas) -- it is only CSV-row access that needs this defensive pattern.
#>

Set-StrictMode -Version Latest

$moduleRoot = $PSScriptRoot

# Dot-source private (internal) functions first, so public functions can call them.
$privateFunctions = Get-ChildItem -Path (Join-Path -Path $moduleRoot -ChildPath 'Private') -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue
foreach ($function in $privateFunctions) {
    try {
        . $function.FullName
    }
    catch {
        Write-Error -Message "Failed to dot-source private function file '$($function.FullName)': $_"
    }
}

# Dot-source public (exported) functions.
$publicFunctions = Get-ChildItem -Path (Join-Path -Path $moduleRoot -ChildPath 'Public') -Filter '*.ps1' -ErrorAction SilentlyContinue
foreach ($function in $publicFunctions) {
    try {
        . $function.FullName
    }
    catch {
        Write-Error -Message "Failed to dot-source public function file '$($function.FullName)': $_"
    }
}

# Explicit export list mirrors FunctionsToExport in the module manifest (.psd1). This
# redundancy is deliberate: private functions never become visible even if the manifest
# is edited independently of this file, or vice versa.
Export-ModuleMember -Function $publicFunctions.BaseName
