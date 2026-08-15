function ConvertFrom-MDEEncodedCommand {
    <#
    .SYNOPSIS
        Decodes a single obfuscated command line using the module's in-scope deobfuscation methods.

    .DESCRIPTION
        ConvertFrom-MDEEncodedCommand is a standalone utility usable outside a full triage
        run, and is also called internally by built-in detection rules (e.g. EXEC-001) that
        need to show an analyst what an encoded command actually does.

        In-scope, applied in order (all that apply are applied, not just the first match):
          1. Base64 / PowerShell -EncodedCommand: matches '-enc'/'-EncodedCommand' followed
             by a Base64-looking payload of at least 16 characters (chosen because even a
             short one-word PowerShell command becomes at least that long once UTF-16LE
             encoded and Base64'd; this floor avoids mistaking an unrelated short flag value
             for an encoded payload). Decoded per PowerShell's own convention: Base64 bytes
             interpreted as UTF-16LE text, not UTF-8.
          2. Tick-mark/caret removal: a backtick or caret sitting between two letters within
             a single token (not a legitimate end-of-line continuation) is stripped, since
             both characters are used as PowerShell/cmd.exe escape characters to break up a
             keyword and evade naive substring-based detection.
          3. Environment-variable expansion: %VARNAME% references to a small set of
             well-known, highly standard Windows variables (COMSPEC, WINDIR, SYSTEMROOT,
             PROGRAMDATA, PUBLIC) are substituted with their standard default value. This is
             explicitly a best-effort substitution of the STANDARD default, not a value
             verified from the specific host -- a static CSV timeline export carries no live
             environment to query, so this cannot be a true "expansion" in the shell sense.
          4. Simple character reversal: any whitespace-delimited token that, reversed, matches
             a known suspicious keyword (powershell.exe, cmd.exe, iex, downloadstring, etc.)
             is flagged and annotated with its reversed form.

        Out of scope, per requirement #6: nested/multi-layer encoding, XOR, and custom
        ciphers are never guessed at. When the input looks obfuscated (a long unbroken
        Base64-charset run that did not successfully decode above, or a high proportion of
        non-printable characters) but none of the four in-scope methods explain it, the
        result is flagged Scope = 'PossiblyObfuscated' rather than silently left alone or
        incorrectly decoded.

        The Decoded output is exactly as untrusted as the Original value: neither this
        cmdlet's output, nor any caller of it, should render either without the same
        HTML-escaping New-MDEReport applies to raw fields (build Phase 6).

    .PARAMETER CommandLine
        The single command-line string to attempt to decode. Mandatory. Accepted from the
        pipeline by property name (e.g. piping objects with a CommandLine property).

    .EXAMPLE
        ConvertFrom-MDEEncodedCommand -CommandLine 'powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'

        Decodes the Base64/-EncodedCommand payload and returns the decoded text alongside
        which method(s) were applied and an overall Scope.

    .EXAMPLE
        Import-Csv .\host01-timeline.csv | Select-Object @{N = 'CommandLine'; E = { $_.ProcessCommandLine } } | ConvertFrom-MDEEncodedCommand

        Decodes command lines from raw CSV rows outside a full triage run, renaming the
        source column to CommandLine so it binds via pipeline-by-property-name.

    .INPUTS
        System.String (via property name binding), or explicit -CommandLine.

    .OUTPUTS
        PSCustomObject
        Original (the input string, unchanged), Decoded (the string after applying every
        in-scope method that matched -- identical to Original if none did), MethodsApplied
        (string[], the name of each method that fired, empty if none did), and Scope
        ('Decoded' if at least one method applied; 'Clean' if the input shows no obfuscation
        indicators at all; 'PossiblyObfuscated' if it looks obfuscated but by a method beyond
        this cmdlet's in-scope list -- manual review recommended).

    .NOTES
        Purely computational -- no file or state mutation, so this cmdlet does not implement
        SupportsShouldProcess.

        Never guesses at nested/multi-layer encoding, XOR, or custom ciphers; those are
        surfaced via Scope = 'PossiblyObfuscated' rather than silently mis-decoded.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CommandLine
    )

    process {
        $original = $CommandLine
        $working = $CommandLine
        $methodsApplied = [System.Collections.Generic.List[string]]::new()

        # 1. Base64 / -EncodedCommand (PowerShell convention: bytes are UTF-16LE, not UTF-8).
        if ($working -match '(?i)-enc(odedcommand)?\s+([A-Za-z0-9+/=]{16,})') {
            $payload = $Matches[2]
            try {
                $bytes = [System.Convert]::FromBase64String($payload)
                $decodedText = [System.Text.Encoding]::Unicode.GetString($bytes)
                if ($decodedText -match '[\x20-\x7E]') {
                    $working = $working.Replace($payload, $decodedText)
                    $methodsApplied.Add('Base64/-EncodedCommand (UTF-16LE)')
                }
            }
            catch {
                # Not valid Base64, or didn't decode to readable text -- leave $working
                # unchanged. This is deliberately a non-guess: requirement #6 is explicit
                # that anything the in-scope methods can't confidently handle should be
                # flagged, not forced.
                Write-Verbose "ConvertFrom-MDEEncodedCommand: Base64 decode attempt did not produce readable text: $($_.Exception.Message)"
            }
        }

        # 2. Tick-mark/caret removal (mid-token backtick/caret used to break up a keyword).
        if ($working -match '[a-zA-Z][`^][a-zA-Z]') {
            $stripped = $working -replace '(?<=[a-zA-Z])[`^](?=[a-zA-Z])', ''
            if ($stripped -ne $working) {
                $working = $stripped
                $methodsApplied.Add('Tick-mark/caret removal')
            }
        }

        # 3. Environment-variable expansion (standard default values only -- see .DESCRIPTION).
        $knownEnvVars = @{
            'COMSPEC'     = 'C:\Windows\System32\cmd.exe'
            'WINDIR'      = 'C:\Windows'
            'SYSTEMROOT'  = 'C:\Windows'
            'PROGRAMDATA' = 'C:\ProgramData'
            'PUBLIC'      = 'C:\Users\Public'
        }
        $envExpanded = $false
        foreach ($m in [regex]::Matches($working, '%([A-Za-z_][A-Za-z0-9_]*)%')) {
            $varName = $m.Groups[1].Value.ToUpperInvariant()
            if ($knownEnvVars.ContainsKey($varName)) {
                $working = $working.Replace($m.Value, $knownEnvVars[$varName])
                $envExpanded = $true
            }
        }
        if ($envExpanded) {
            $methodsApplied.Add('Environment-variable expansion (standard default values)')
        }

        # 4. Simple character reversal.
        $suspiciousKeywords = @('powershell.exe', 'powershell', 'cmd.exe', 'invoke-expression', 'iex', 'downloadstring', 'downloadfile', 'frombase64string', 'wscript.exe', 'mshta.exe')
        $tokens = $working -split '\s+'
        $reversalFound = $false
        for ($i = 0; $i -lt $tokens.Count; $i++) {
            if ([string]::IsNullOrEmpty($tokens[$i])) { continue }
            $chars = $tokens[$i].ToCharArray()
            [array]::Reverse($chars)
            $reversedToken = -join $chars
            if ($suspiciousKeywords -contains $reversedToken.ToLowerInvariant()) {
                $tokens[$i] = "$($tokens[$i]) [reversed => $reversedToken]"
                $reversalFound = $true
            }
        }
        if ($reversalFound) {
            $working = $tokens -join ' '
            $methodsApplied.Add('Simple character reversal')
        }

        $scope = if ($methodsApplied.Count -gt 0) { 'Decoded' } else { 'Clean' }

        if ($scope -eq 'Clean') {
            $looksLikeUndecodedBase64 = $original -match '[A-Za-z0-9+/=]{60,}'
            $nonPrintableCount = @($original.ToCharArray() | Where-Object { $_ -notmatch '[\x20-\x7E]' }).Count
            if ($looksLikeUndecodedBase64 -or $nonPrintableCount -gt 3) {
                $scope = 'PossiblyObfuscated'
            }
        }

        return [PSCustomObject]@{
            Original       = $original
            Decoded        = $working
            MethodsApplied = $methodsApplied.ToArray()
            Scope          = $scope
        }
    }
}
