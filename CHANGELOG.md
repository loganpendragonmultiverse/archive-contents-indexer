# Changelog

## 1.2.1 — 2026-10-20

- Create reports exclusively so concurrent files and dangling symbolic links cannot be overwritten.
- Hash archives in bounded chunks instead of reading the full archive into memory.
- Reject malformed comparison metadata, including boolean sizes, invalid CRCs and non-finite ratios.
- Wrap long archive/member names and comparison evidence without losing searchable text on narrow screens.
- Document source and installed-distribution acceptance checks.

## 1.2.0 — 2026-10-15

- Compare prior JSON inventories with archive and occurrence-aware member changes.
- Record directory discovery errors and suppress removal claims for unreadable subtrees.
- Preserve source-relative archive identities and show corrupt scans as unknown.

## 1.1.0 - 2026-07-27

- Added archive SHA-256 fingerprints, compression ratios, compressed totals, and duplicate-member reporting.
- Added extension summaries and the ten largest indexed entries.

## 1.0.0 - 2026-07-26

- Added ZIP, CBZ, and EPUB member indexing without extraction.
- Added searchable self-contained HTML and structured JSON reports.
- Added corrupt-archive reporting, metadata flags, and unsafe member-path detection.
