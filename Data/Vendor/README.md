# Data/Vendor/

Vendored JS/CSS for the fully offline HTML report (no CDN references anywhere in the
rendered output — DFIR analysis often happens air-gapped):

- **D3.js v7.9.0** (`d3.min.js`, 280KB) — handles all three non-tabular views: the process
  tree (via `d3.hierarchy`/`d3.tree`), the network graph (via `d3.forceSimulation`), and the
  swimlane (via `d3.scaleTime`/`d3.axis`). Vendored via npm (`npm install d3`) and hash-
  verified against the installed package's `dist/d3.min.js`.
- **DataTables v3.0.1** (`dataTables.min.js` + `dataTables.min.css`, ~152KB combined) — the
  findings table.

**Revised from the original 3-library plan (Mermaid + D3 + DataTables):** actually vendoring
Mermaid for Phase 6 surfaced that its only genuinely self-contained (no dynamic-import
chunks that would silently try to fetch more files) browser build is `mermaid.min.js` at
**3.5MB** — over 10x every other vendored asset combined, for a diagram type (a tree)
`d3-hierarchy` already handles well and that D3 is being vendored for anyway. Dropped Mermaid
and render the process tree with D3 instead, cutting total vendored payload from an
estimated 4MB+ to under 450KB. This is a size-driven engineering call made once real numbers
were available, not a step back from the "full suite" scope the report still has all three
distinct views (tree, network graph, swimlane) plus the findings table.

**Also revised:** DataTables historically required jQuery, which would have meant a 4th
vendored file. DataTables 3.0 (released April 2026 — after this module's own training-data
grounding, confirmed via the project's own blog post rather than assumed) dropped the jQuery
dependency entirely; `datatables.net` 3.0.1's `package.json` lists zero dependencies. No
jQuery is vendored.

`New-MDEReport` inlines these directly into the generated HTML file at render time (`Private/
Reporting/New-MDEReportHtml.ps1`).
