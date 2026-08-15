# Private/Lineage/

Populated in build Phase 5, as 5 small functions rather than one monolithic one:
- `New-MDEProcessLineageIndex.ps1` -- creates the empty index (Nodes + Edges hashtables).
- `Add-MDEProcessLineageNode.ps1` -- adds/backfills one process identity node.
- `Update-MDEProcessLineageIndex.ps1` -- extracts the edge(s) observable on one row and
  feeds them in; called once per row during `Invoke-MDEDetection`'s streaming pass.
- `Get-MDERowSubjectProcessKey.ps1` -- determines which process a row (or a finding's
  `SourceRow`) is "about"; also the grouping key for multi-signal combination.
- `Get-MDEProcessLineageChain.ps1` -- walks the index upward from a key, root-first,
  cycle-safe and hop-capped.

**Why incremental, not batch:** a process's ancestors can be described in rows anywhere in
the file -- not necessarily ones already seen -- so full reconstruction genuinely requires
the whole row stream. Rather than buffer every row (which would undo the memory-bounded
design from Phases 2-4), `Invoke-MDEDetection` feeds each row into this index as it streams
past (compact -- proportional to distinct processes observed, not events) and separately
buffers only the sparse set of *findings* until the index is complete, attaching
`ProcessLineage` in its `end{}` block. See `Invoke-MDEDetection`'s comment-based help for the
full tradeoff writeup.

Identity uses a composite `Id|CreationTime` key throughout, not PID alone, since Windows PID
reuse would otherwise merge two unrelated processes that happen to share a PID at different
points in a multi-day export into one incorrect lineage node.

Feeds both the `ProcessLineage` field on finding objects (requirement #7) and the
process-tree view in the HTML report (rendering itself is Phase 6's job).
