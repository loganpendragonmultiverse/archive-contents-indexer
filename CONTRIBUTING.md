# Contributing

Open an issue before a large change. Pull requests should explain the problem and approach, include focused tests, update affected documentation, and pass all repository checks. The maintainer reviews correctness, security, scope, licensing, and long-term maintenance before merge.

## Local checks

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
pytest
python -m build
```

Use concise, specific commits. Do not include private manuscripts, media, credentials, generated filler, or third-party copyrighted fixtures.
