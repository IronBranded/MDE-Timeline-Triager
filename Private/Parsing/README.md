# Private/Parsing/

Encoding detection (UTF-8 / UTF-8 BOM / UTF-16), flattened-column mapping (MDE portal
exports flatten nested JSON like `InitiatingProcess.*` into individual CSV columns), and
MDE export schema-set detection (Device Timeline vs. Advanced Hunting vs. Live Response)
behind `Import-MDETimeline`. Populated in build Phase 2.

NOTE: the module sets `Set-StrictMode -Version Latest`. CSV rows have a variable property
set by design (different export types carry different columns — see requirement #1's
schema-mismatch handling). Always check property existence before use:

    if ($row.PSObject.Properties['ColumnName']) { ... }

rather than direct dot-access, when a column might legitimately be absent.
