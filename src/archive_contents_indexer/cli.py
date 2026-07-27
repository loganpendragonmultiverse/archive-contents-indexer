from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import build_index, render_html, render_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Index ZIP-compatible archives without extraction."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("--format", choices=("html", "json"), default="html")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        index = build_index(args.source)
        rendered = render_json(index) if args.format == "json" else render_html(index)
        if args.output:
            if args.output.exists():
                raise ValueError(f"output already exists: {args.output}")
            args.output.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1 if index["error_count"] else 0
