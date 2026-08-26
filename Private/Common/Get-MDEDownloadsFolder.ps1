function Get-MDEDownloadsFolder {
    <#
    .SYNOPSIS
        Resolves the current user's Downloads folder, cross-platform.
    .DESCRIPTION
        .NET's Environment.SpecialFolder enum has never included a direct "Downloads" entry,
        so this can't be a one-line [Environment]::GetFolderPath() call. Platform detection
        uses $IsWindows/$IsMacOS/$IsLinux where available (PowerShell 6+); Windows PowerShell
        5.1 has no such variables at all, and since 5.1 only ever runs on Windows, their
        absence is itself sufficient confirmation of Windows.

        Windows: reads the actual Shell Folders registry value
        (HKCU:\...\Explorer\User Shell Folders, GUID {374DE290-123F-4565-9164-39C4925E467B})
        rather than assuming $env:USERPROFILE\Downloads, since a user with Downloads
        redirected elsewhere (a mapped drive, a OneDrive-managed folder, etc.) would
        otherwise silently get files written to the wrong place. Falls back to
        $env:USERPROFILE\Downloads only if the registry read fails for any reason.

        macOS: $HOME/Downloads -- no equivalent redirection mechanism to account for.

        Linux (not a target platform per this module's Windows-only scope, but this module
        has been developed and tested on Linux throughout, so it's handled rather than left
        to fail outright): tries `xdg-user-dir DOWNLOAD` if available, falling back to
        $HOME/Downloads.
    .OUTPUTS
        System.String -- an absolute path. Not guaranteed to exist; callers that write here
        (New-MDEReport) create the directory if needed, the same as they already do for an
        explicitly supplied -OutputPath.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $isWin = if (Test-Path -Path 'Variable:IsWindows') { $IsWindows } else { $true }
    $isMac = if (Test-Path -Path 'Variable:IsMacOS') { $IsMacOS } else { $false }
    $isLinux = if (Test-Path -Path 'Variable:IsLinux') { $IsLinux } else { $false }

    if ($isWin) {
        try {
            $regPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
            $rawValue = Get-ItemPropertyValue -Path $regPath -Name '{374DE290-123F-4565-9164-39C4925E467B}' -ErrorAction Stop
            $expanded = [System.Environment]::ExpandEnvironmentVariables($rawValue)
            if (-not [string]::IsNullOrWhiteSpace($expanded)) {
                Write-Verbose "Get-MDEDownloadsFolder: resolved via Shell Folders registry value -> $expanded"
                return $expanded
            }
        }
        catch {
            Write-Verbose "Get-MDEDownloadsFolder: Shell Folders registry lookup failed ($($_.Exception.Message)); falling back to `$env:USERPROFILE\Downloads."
        }
        return (Join-Path -Path $env:USERPROFILE -ChildPath 'Downloads')
    }

    if ($isLinux) {
        try {
            $xdgResult = & xdg-user-dir DOWNLOAD 2>$null
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($xdgResult)) {
                Write-Verbose "Get-MDEDownloadsFolder: resolved via xdg-user-dir -> $xdgResult"
                return $xdgResult.Trim()
            }
        }
        catch {
            Write-Verbose "Get-MDEDownloadsFolder: xdg-user-dir not available; falling back to `$HOME/Downloads."
        }
    }
    elseif ($isMac) {
        Write-Verbose 'Get-MDEDownloadsFolder: macOS -- no redirection mechanism to account for, using $HOME/Downloads directly.'
    }

    # macOS, or Linux without xdg-user-dir, or any other platform: $HOME/Downloads.
    return (Join-Path -Path $HOME -ChildPath 'Downloads')
}
