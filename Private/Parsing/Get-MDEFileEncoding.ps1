function Get-MDEFileEncoding {
    <#
    .SYNOPSIS
        Inspects a file's leading bytes and reports which of the three in-scope CSV encodings it appears to use.
    .DESCRIPTION
        Peeks at the first 4 bytes of the file and matches known byte-order-mark signatures
        (EF BB BF for UTF-8 with BOM; FF FE for UTF-16 LE; FE FF for UTF-16 BE) purely to
        produce a human-readable name for Import-MDETimeline's -Verbose logging.

        This function does NOT itself determine the encoding used to open the file for
        reading. The actual StreamReader Import-MDETimeline constructs relies on .NET's own
        built-in detectEncodingFromByteOrderMarks behavior -- robust, well-tested BOM
        detection and automatic BOM-skipping -- rather than this function's output, so there
        is no risk of this diagnostic disagreeing with the encoding actually used to read the
        file. Splitting the concerns this way (diagnostic peek vs. actual stream construction)
        avoids a class of manual seek/skip bugs that a hand-rolled approach could introduce.
    .PARAMETER Path
        Path to the file to inspect. Mandatory.
    .OUTPUTS
        System.String
        One of: 'UTF-8 (with BOM)', 'UTF-16 LE (with BOM)', 'UTF-16 BE (with BOM)',
        'UTF-8 (no BOM, assumed)'.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $buffer = New-Object byte[] 4
    $fileStream = [System.IO.File]::OpenRead($Path)
    try {
        [void]$fileStream.Read($buffer, 0, 4)
    }
    finally {
        $fileStream.Dispose()
    }

    if ($buffer[0] -eq 0xEF -and $buffer[1] -eq 0xBB -and $buffer[2] -eq 0xBF) {
        return 'UTF-8 (with BOM)'
    }
    elseif ($buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE) {
        # Also matches the first 2 bytes of a UTF-32 LE BOM (FF FE 00 00); UTF-32 is out of
        # scope per requirement #3, and .NET's own auto-detection resolves this identically.
        return 'UTF-16 LE (with BOM)'
    }
    elseif ($buffer[0] -eq 0xFE -and $buffer[1] -eq 0xFF) {
        return 'UTF-16 BE (with BOM)'
    }
    else {
        return 'UTF-8 (no BOM, assumed)'
    }
}
