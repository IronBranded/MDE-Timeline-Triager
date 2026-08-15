function Get-MDEFileHash {
    <#
    .SYNOPSIS
        Computes the SHA-256 hash of a file for chain-of-custody recording.
    .DESCRIPTION
        Thin wrapper around the built-in Get-FileHash cmdlet (which already streams rather
        than loading the whole file into memory, so this is safe on large exports) used
        consistently by Import-MDETimeline (logged via -Verbose during ingest, for early
        traceability) and New-MDEReport (recorded in the report header, per requirement #15).
        Always SHA-256 -- the algorithm is not parameterized, since requirement #15 specifies
        SHA-256 specifically for chain-of-custody purposes.
    .PARAMETER Path
        Path to the file to hash. Mandatory.
    .OUTPUTS
        System.String
        The uppercase hexadecimal SHA-256 hash.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return (Get-FileHash -Path $Path -Algorithm SHA256).Hash
}
