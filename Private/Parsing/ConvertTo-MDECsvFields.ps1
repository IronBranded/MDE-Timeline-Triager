function ConvertTo-MDECsvFields {
    <#
    .SYNOPSIS
        Splits one logical CSV row of raw text into an array of field values.
    .DESCRIPTION
        Hand-rolled, dependency-free CSV field splitter -- deliberately not built on
        Microsoft.VisualBasic.FileIO.TextFieldParser, whose availability/behavior is not
        something this module's authoring environment could verify identically across
        Windows PowerShell 5.1 (.NET Framework) and PowerShell 7+ (.NET / Core). Using only
        plain string operations keeps parsing behavior guaranteed-identical on both runtimes,
        per the Platform Target requirement to gate any cross-runtime divergence rather than
        assume one.

        Respects RFC 4180-style quoting: a field wrapped in double quotes may contain commas
        and (already-reassembled, see Read-MDELogicalCsvLine) newlines, and a doubled quote
        ("") inside a quoted field represents one literal quote character.

        Performance (requirement #11): if the line contains no double-quote character at all,
        no field can legitimately contain a comma, newline, or quote per RFC 4180, so a
        direct, fast .Split(',') is used. Only lines containing at least one quote fall
        through to the slower character-by-character state machine, which is what correctness
        for quoted fields requires. Many MDE CSV rows -- e.g. most DeviceRegistryEvents or
        DeviceLogonEvents rows -- take the fast path; ProcessCommandLine-bearing rows
        typically do not, since real-world command lines frequently contain commas.
    .PARAMETER Line
        The raw logical row text (already reassembled across physical lines if needed, via
        Read-MDELogicalCsvLine). Mandatory. May be an empty string.
    .OUTPUTS
        System.String[]
        Always returns an array, even for a single-field line (the function's `return ,`
        idiom guards against PowerShell's pipeline unrolling a 1-element array into a scalar).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Line
    )

    if ($Line.IndexOf('"') -lt 0) {
        return , $Line.Split(',')
    }

    $fields = [System.Collections.Generic.List[string]]::new()
    $current = [System.Text.StringBuilder]::new()
    $inQuotes = $false
    $i = 0
    $length = $Line.Length

    while ($i -lt $length) {
        $char = $Line[$i]

        if ($inQuotes) {
            if ($char -eq '"') {
                if (($i + 1) -lt $length -and $Line[$i + 1] -eq '"') {
                    [void]$current.Append('"')
                    $i += 2
                    continue
                }
                $inQuotes = $false
                $i++
                continue
            }
            [void]$current.Append($char)
            $i++
            continue
        }

        if ($char -eq '"') {
            $inQuotes = $true
            $i++
            continue
        }
        if ($char -eq ',') {
            $fields.Add($current.ToString())
            [void]$current.Clear()
            $i++
            continue
        }
        [void]$current.Append($char)
        $i++
    }

    $fields.Add($current.ToString())
    return , $fields.ToArray()
}
