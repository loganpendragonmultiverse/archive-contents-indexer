# Testing

Use Python 3.10 or newer in a disposable virtual environment:

```bash
python -m pip install -e '.[dev]'
ruff format --check .
ruff check .
pytest
python -m build
```

The complete suite retains its 90% branch-coverage gate. Tests cover unsafe member
names, corrupt and unreadable archives, duplicate occurrences, discovery failures,
comparison uncertainty, malformed typed metadata, report creation races and
bounded fingerprint reads. All fixtures are synthetic; no archive is extracted.

For release acceptance, install each built wheel and source distribution into a
fresh environment outside this checkout. Run the same tests with coverage disabled
only for this installed-artifact pass (`pytest -o addopts='' /path/to/tests`), then
run `archive-index --help` and a JSON scan/compare of a synthetic ZIP. Verify the
imported module path belongs to the environment, not `src/`. Retain the source
coverage result separately. CI exercises Python 3.10 and 3.14 on Linux, Windows
and macOS; local Linux tests alone do not establish native-platform acceptance.
