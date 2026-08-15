function ConvertTo-MDEJsonForScriptEmbed {
    <#
    .SYNOPSIS
        Converts an object to JSON safe to embed as the text content of an inert <script type="application/json"> tag.
    .DESCRIPTION
        ConvertTo-Json's output is valid JSON, but JSON's own escaping rules do not touch
        '<', '>', or '&' -- a malicious field value like '</script><script>alert(1)' would
        pass through ConvertTo-Json completely unchanged inside its JSON string value. If
        that JSON text were then embedded verbatim as a <script> tag's content, the BROWSER'S
        HTML PARSER (which looks for a literal '</script' substring to find where the tag
        ends, before any JS/JSON parsing even happens) would treat that substring as the
        real closing tag and break out of the script block early -- a well-known JSON-in-HTML
        injection vector, and exactly the "properly escaped rather than string-concatenated
        into markup or inline scripts" requirement #8 calls for.

        Neutralized by replacing every '<' in the JSON text with its Unicode escape \u003C,
        which JSON.parse resolves back to a literal '<' at runtime but which never looks like
        the start of a tag to the HTML parser scanning for the script's end. Escaping every
        '<' (not just the 8-character '</script' sequence) also neutralizes any other tag --
        <style>, <img onerror=...>, etc. -- that a narrower match would miss.

        This function only handles the script-tag-breakout risk. Field values embedded in
        the report should already have passed through ConvertTo-MDEHtmlEncodedString before
        reaching here (see ConvertTo-MDEReportFindingRecord), so this is defense in depth on
        top of that, not a replacement for it.
    .PARAMETER InputObject
        The object to serialize. Mandatory.
    .PARAMETER Depth
        Passed through to ConvertTo-Json. Optional, default 10 -- finding-derived report
        records can nest a few levels (e.g. a process lineage array of objects), deeper than
        ConvertTo-Json's own default depth of 2.
    .PARAMETER ForceArray
        Guarantees the output is a JSON array ('[...]') even when -InputObject is a
        collection with exactly one element or none. ConvertTo-Json unwraps a single-element
        array piped into it to a bare JSON object rather than a one-element array -- correct
        for a genuinely single object, but wrong for anything the client-side JS treats as a
        collection (e.g. findingsData.filter(...) in the report template), where a report
        with exactly one finding would otherwise silently serialize as '{...}' instead of
        '[{...}]' and throw a client-side TypeError the moment the JS calls an array method
        on it. Only needed for -InputObject values that are semantically a collection at the
        TOP level of what's passed in -- a single object whose own properties happen to
        contain single-element arrays (e.g. the tree/network data islands' Nodes/Edges
        properties) is not affected by this collapse in the first place, since ConvertTo-Json
        only unwraps the array it receives directly as pipeline input, not nested array-typed
        properties inside an object -- confirmed directly rather than assumed, since this
        function existed under the same untested assumption once already. Optional, default
        $false.
    .OUTPUTS
        System.String -- JSON text safe to place as a <script type="application/json"> tag's
        content.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [PSObject]$InputObject,

        [Parameter()]
        [int]$Depth = 10,

        [Parameter()]
        [switch]$ForceArray
    )

    if ($ForceArray) {
        $itemsArray = @($InputObject)
        if ($itemsArray.Count -eq 0) {
            return '[]'
        }
        if ($itemsArray.Count -eq 1) {
            # ConvertTo-Json would unwrap a genuine one-element array to a bare object here;
            # serialize the single element on its own and wrap it manually instead.
            $singleJson = $itemsArray[0] | ConvertTo-Json -Depth $Depth -Compress
            return ('[' + $singleJson + ']').Replace('<', '\u003C')
        }
        $json = $itemsArray | ConvertTo-Json -Depth $Depth -Compress
        return $json.Replace('<', '\u003C')
    }

    $json = $InputObject | ConvertTo-Json -Depth $Depth -Compress
    if ($null -eq $json) { return '[]' }
    return $json.Replace('<', '\u003C')
}
