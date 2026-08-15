# Private/Deobfuscation/

Decode helpers behind `ConvertFrom-MDEEncodedCommand`. In scope: Base64 / PowerShell
`-EncodedCommand`, environment-variable expansion, tick-mark/caret removal, simple character
reversal. Out of scope (nested/multi-layer encoding, XOR, custom ciphers): flagged as
"possibly obfuscated — manual review recommended," never guessed at.

Decoded output is exactly as untrusted as the raw value — callers must still HTML-escape it
before display (see `Private/Reporting/`).

As implemented in Phase 3, the four decode methods live directly inside
`Public/ConvertFrom-MDEEncodedCommand.ps1` as sequential, individually-commented steps,
rather than as separate helper files in this folder — none of the four is ever invoked in
isolation from the full decode pipeline, and keeping them together made the method-by-method
flow easier to review as one unit than four thin wrapper files would have. This folder
remains reserved for a future deobfuscation helper that a detection rule needs to call
independently of the full pipeline (e.g. Phase 7 rules).
