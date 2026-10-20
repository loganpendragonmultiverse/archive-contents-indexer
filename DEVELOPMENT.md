# Development contract

Build read-only ZIP, CBZ, and EPUB inventories without extracting members.

Version 1.1 adds archive fingerprints, compression and extension summaries, largest-entry evidence, and duplicate-member warnings. Preserve escaped HTML output and never treat indexing as proof that archive contents are safe.

Every feature release must update tests, version metadata, changelog, README claims, repository metadata, release assets, and the Forge catalog together.

The 1.2.1 audit hardens exclusive report creation, streaming fingerprints and
comparison-input types. Do not weaken the 90% branch-coverage gate. Installed
wheel and source-distribution tests must run outside the source checkout.
