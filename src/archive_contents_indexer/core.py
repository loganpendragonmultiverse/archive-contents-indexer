from __future__ import annotations

import hashlib
import html
import json
import os
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
    errors: list[dict[str, str]] = []
    directory_source = source.is_dir()
    if source.is_file():
        paths = [source]
    elif directory_source:
        paths = []
        pending = [source]
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda entry: entry.name)
                for entry in entries:
                    path = directory / entry.name
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(path)
                        elif entry.is_file() and path.suffix.casefold() in EXTENSIONS:
                            paths.append(path)
                    except OSError as exc:
                        errors.append(
                            {
                                "path": path.relative_to(source).as_posix(),
                                "error": type(exc).__name__,
                                "scope": "discovery",
                            }
                        )
            except OSError as exc:
                errors.append(
                    {
                        "path": directory.relative_to(source).as_posix(),
                        "error": type(exc).__name__,
                        "scope": "discovery",
                    }
                )
        paths.sort()
    else:
        raise ValueError("source must be an archive or directory")
    archives: list[dict[str, Any]] = []
    for path in paths:
        try:
            item = inspect_archive(path)
            item["path"] = path.relative_to(source).as_posix() if source.is_dir() else path.name
            archives.append(item)
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append(
                {
                    "path": path.relative_to(source).as_posix() if source.is_dir() else path.name,
                    "error": str(exc),
                }
            )
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
        "scan_complete": not errors,
        "archives": archives,
        "errors": errors,
        "extension_counts": dict(sorted(extension_counts.items())),
        "largest_entries": sorted(
            all_entries, key=lambda item: (-int(item["size"]), item["archive"], item["name"])
        )[:10],
    }


def compare_indexes(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare inventory metadata; member content equality is not established."""

    def unpack(index: dict[str, Any]) -> tuple[dict[str, Any], set[str], set[str]]:
        if not isinstance(index, dict) or index.get("version") != 1:
            raise ValueError("comparison requires a version 1 JSON inventory")
        archives, errors = index.get("archives"), index.get("errors")
        if not isinstance(archives, list) or not isinstance(errors, list):
            raise TypeError("inventory requires archives and errors arrays")
        mapped = {}
        failed = set()
        undiscovered = set()
        for item in errors:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise TypeError("inventory errors require paths")
            if item.get("scope") == "discovery":
                undiscovered.add(item["path"])
            else:
                failed.add(item["path"])
        for archive in archives:
            if not isinstance(archive, dict) or not isinstance(archive.get("path"), str):
                raise TypeError("inventory archives require paths")
            path = archive["path"]
            if path in mapped or path in failed:
                raise ValueError("ambiguous archive paths in inventory")
            if not isinstance(archive.get("entries"), list):
                raise TypeError("inventory archive requires entries")
            members = {}
            counts: Counter[str] = Counter()
            for entry in archive["entries"]:
                if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                    raise TypeError("inventory entries require names")
                if not all(
                    key in entry
                    for key in (
                        "size",
                        "compressed_size",
                        "crc32",
                        "directory",
                        "encrypted",
                        "unsafe_path",
                    )
                ):
                    raise ValueError("incomplete member metadata")
                name = entry["name"]
                counts[name] += 1
                members[(name, counts[name])] = entry
            mapped[path] = {"archive": archive, "members": members}
        return mapped, failed, undiscovered

    before, old_errors, old_discovery = unpack(previous)
    after, new_errors, new_discovery = unpack(current)
    unknown_subtrees = old_discovery | new_discovery
    unknown = (
        old_errors
        | new_errors
        | {
            path
            for path in before.keys() | after.keys()
            if any(
                prefix == "."
                or path == prefix
                or PurePosixPath(prefix) in PurePosixPath(path).parents
                for prefix in unknown_subtrees
            )
        }
    )
    changes = []
    for path in sorted(before.keys() & after.keys() - unknown):
        old, new = before[path], after[path]
        a, b = old["members"], new["members"]
        added = [
            {"name": name, "occurrence": occurrence}
            for name, occurrence in sorted(b.keys() - a.keys())
        ]
        removed = [
            {"name": name, "occurrence": occurrence}
            for name, occurrence in sorted(a.keys() - b.keys())
        ]
        modified = []
        for key in sorted(a.keys() & b.keys()):
            fields = sorted(
                field
                for field in a[key].keys() | b[key].keys()
                if a[key].get(field) != b[key].get(field)
            )
            if fields:
                modified.append(
                    {
                        "name": key[0],
                        "occurrence": key[1],
                        "fields": fields,
                        "before": a[key],
                        "after": b[key],
                    }
                )
        fingerprint_changed = old["archive"].get("sha256") != new["archive"].get("sha256")
        if added or removed or modified or fingerprint_changed:
            changes.append(
                {
                    "path": path,
                    "fingerprint_changed": fingerprint_changed,
                    "members_added": added,
                    "members_removed": removed,
                    "members_changed": modified,
                }
            )
    return {
        "archives_added": sorted(after.keys() - before.keys() - unknown),
        "archives_removed": sorted(before.keys() - after.keys() - unknown),
        "archives_changed": changes,
        "unknown_archives": sorted(unknown),
        "unknown_subtrees": sorted(unknown_subtrees),
        "complete": not unknown and not unknown_subtrees,
        "interpretation": "Metadata comparison only; CRC and size equality do not prove member content identity.",
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
    comparison = (
        "<h2>Inventory comparison</h2><pre>"
        + html.escape(json.dumps(index["comparison"], indent=2, ensure_ascii=False))
        + "</pre>"
        if "comparison" in index
        else ""
    )
    return f"""<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Archive contents index</title><style>body{{font:16px system-ui;margin:0;padding:24px;color:#18211d}}main{{max-width:1100px;margin:auto}}input{{width:100%;padding:12px;margin:16px 0;box-sizing:border-box}}table{{width:100%;border-collapse:collapse}}th,td{{padding:9px;border:1px solid;text-align:left}}th{{background:#e7ece8}}@media(max-width:700px){{table{{font-size:12px}}}}</style><main><h1>Archive Contents Index</h1><p>{index["archive_count"]} archives · {sum(a["entry_count"] for a in index["archives"])} entries · {index["error_count"]} errors</p><label>Filter entries <input id=q type=search></label><table><thead><tr><th>Archive</th><th>Entry</th><th>Bytes</th><th>Flags</th></tr></thead><tbody>{"".join(rows)}</tbody></table><ul>{error_rows}</ul>{comparison}</main><script>const q=document.querySelector('#q');q.addEventListener('input',()=>{{for(const row of document.querySelectorAll('tbody tr'))row.hidden=!row.textContent.toLowerCase().includes(q.value.toLowerCase())}})</script></html>\n"""


def render_json(index: dict[str, Any]) -> str:
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"
