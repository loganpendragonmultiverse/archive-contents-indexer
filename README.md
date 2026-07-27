# Archive Contents Indexer

[![CI](https://github.com/loganpendragonmultiverse/archive-contents-indexer/actions/workflows/ci.yml/badge.svg)](https://github.com/loganpendragonmultiverse/archive-contents-indexer/actions/workflows/ci.yml)

Archive Contents Indexer creates a searchable static HTML or JSON inventory of ZIP, CBZ, and EPUB contents without permanently extracting files. Reports include member paths, sizes, compressed sizes, CRC values, encryption flags, and unsafe path warnings.

## Three-minute start

```bash
python -m pip install .
archive-index ~/Books --output archive-index.html
archive-index example.cbz --format json
```

Directory scans continue past corrupt archives and report each error. HTML output is self-contained, searchable, responsive, and escapes archive-supplied filenames. Existing reports are never replaced.

## Security boundary

The tool reads archive metadata with Python's ZIP parser and does not extract members. It flags absolute, drive-prefixed, and parent-traversal names, but it is an indexer rather than a malware scanner or full archive verifier. Do not treat a successful index as proof that contents are safe to open.

Requires Python 3.10 or newer. Development checks use Ruff, pytest with branch coverage, and package builds.

Part of the [Logan Pendragon Forge open-source collection](https://www.loganpendragonforge.com/open-source/). Licensed under the [MIT License](LICENSE).
