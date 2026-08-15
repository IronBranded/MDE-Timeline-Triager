function Read-MDELogicalCsvLine {
    <#
    .SYNOPSIS
        Reads one logical CSV row from a StreamReader, reassembling multi-line quoted fields.
    .DESCRIPTION
        A CSV field wrapped in double quotes may legitimately contain embedded newlines (for
        example a multi-line script captured verbatim in a ProcessCommandLine value). A naive
        line-by-line read would incorrectly split such a field across two "rows". This
        function tracks the running count of double-quote characters across physical lines;
        while that count is odd, the row is still inside an open quoted field, so subsequent
        physical lines are appended (with the newline character re-inserted) until the quote
        count balances back to even. Quote counting uses .Split('"').Length-1 rather than a
        per-character pipeline (e.g. ToCharArray() | Where-Object) for performance on
        potentially massive files -- see requirement #11.
    .PARAMETER Reader
        The open System.IO.StreamReader to read from. Mandatory.
    .OUTPUTS
        System.String, or $null at end of stream. If the file ends while a quote is still
        open (a truncated export), the partial content read so far is returned rather than
        blocking indefinitely; the caller's field-count validation will then flag that row as
        malformed via the normal data-corruption path (requirement #3), since it never closed
        its final field/quote correctly.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.StreamReader]$Reader
    )

    $line = $Reader.ReadLine()
    if ($null -eq $line) {
        return $null
    }

    $quoteCount = $line.Split('"').Length - 1

    while ($quoteCount % 2 -ne 0) {
        $nextLine = $Reader.ReadLine()
        if ($null -eq $nextLine) {
            # Truncated file: an open quote that never closes. Return what we have; the
            # caller treats this as a malformed/truncated row rather than hanging.
            break
        }
        $line = $line + "`n" + $nextLine
        $quoteCount += ($nextLine.Split('"').Length - 1)
    }

    return $line
}
