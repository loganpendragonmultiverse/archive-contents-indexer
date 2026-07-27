from __future__ import annotations

import hashlib
import html
import json
import re
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

EXTENSIONS = {".zip", ".cbz", ".epub"}


def unsafe_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    path = PurePosixPath(normalized)
    return path.is_absolute() or ".." in path.parts or bool(re.match(r"^[A-Za-z]:", normalized))


def inspect_archive(path: Path) -> dict[str, Any]:
    if path.suffix.casefold() not in EXTENSIONS:
        raise ValueError(f"unsupported archive extension: {path.suffix}")
    entries: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            entries.append(
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "compression_ratio": round(info.compress_size / info.file_size, 3)
                    if info.file_size
                    else 0,
                    "directory": info.is_dir(),
                    "encrypted": bool(info.flag_bits & 1),
                    "unsafe_path": unsafe_member(info.filename),
                    "crc32": f"{info.CRC:08x}",
                }
            )
    names = [str(item["name"]) for item in entries]
    return {
        "path": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "entries": entries,
        "entry_count": len(entries),
        "uncompressed_bytes": sum(item["size"] for item in entries),
        "unsafe_paths": sum(item["unsafe_path"] for item in entries),
        "duplicate_names": sorted(name for name, count in Counter(names).items() if count > 1),
        "compressed_bytes": sum(item["compressed_size"] for item in entries),
    }


def build_index(source: Path) -> dict[str, Any]:
    if source.is_file():
        paths = [source]
    elif source.is_dir():
        paths = sorted(
            path
            for path in source.rglob("*")
            if path.is_file() and path.suffix.casefold() in EXTENSIONS
        )
    else:
        raise ValueError("source must be an archive or directory")
    archives: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for path in paths:
        try:
            archives.append(inspect_archive(path))
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append({"path": path.name, "error": str(exc)})
    all_entries = [
        {"archive": archive["path"], "name": item["name"], "size": item["size"]}
        for archive in archives
        for item in archive["entries"]
        if not item["directory"]
    ]
    extension_counts = Counter(
        PurePosixPath(str(item["name"])).suffix.casefold() or "[no extension]"
        for item in all_entries
    )
    return {
        "version": 1,
        "archive_count": len(archives),
        "error_count": len(errors),
        "archives": archives,
        "errors": errors,
        "extension_counts": dict(sorted(extension_counts.items())),
        "largest_entries": sorted(
            all_entries, key=lambda item: (-int(item["size"]), item["archive"], item["name"])
        )[:10],
    }


def render_html(index: dict[str, Any]) -> str:
    rows: list[str] = []
    for archive in index["archives"]:
        for item in archive["entries"]:
            flags = (
                ", ".join(
                    name
                    for name, present in (
                        ("directory", item["directory"]),
                        ("encrypted", item["encrypted"]),
                        ("unsafe path", item["unsafe_path"]),
                    )
                    if present
                )
                or "file"
            )
            rows.append(
                f"<tr><td>{html.escape(archive['path'])}</td><td>{html.escape(item['name'])}</td><td>{item['size']}</td><td>{html.escape(flags)}</td></tr>"
            )
    error_rows = "".join(
        f"<li>{html.escape(item['path'])}: {html.escape(item['error'])}</li>"
        for item in index["errors"]
    )
    return f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Archive contents index</title><style>body{{font:16px system-ui;margin:0;padding:24px;color:#18211d}}main{{max-width:1100px;margin:auto}}input{{width:100%;padding:12px;margin:16px 0;box-sizing:border-box}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border:1px solid;text-align:left}}th{{background:#e7ece8}}@media(max-width:700px){{table{{font-size:12px}}}}</style><main><h1>Archive Contents Index</h1><p>{index["archive_count"]} archives · {sum(a["entry_count"] for a in index["archives"])} entries · {index["error_count"]} errors</p><label>Filter entries <input id=q type=search></label><table><thead><tr><th>Archive</th><th>Entry</th><th>Bytes</th><th>Flags</th></tr></thead><tbody>{"".join(rows)}</tbody></table><ul>{error_rows}</ul></main><script>const q=document.querySelector('#q');q.addEventListener('input',()=>{{for(const row of document.querySelectorAll('tbody tr'))row.hidden=!row.textContent.toLowerCase().includes(q.value.toLowerCase())}})</script></html>\n"""


def render_json(index: dict[str, Any]) -> str:
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"
