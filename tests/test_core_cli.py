import json
import zipfile

import pytest

from archive_contents_indexer.cli import main
from archive_contents_indexer.core import build_index, inspect_archive, render_html, unsafe_member


def make_archive(path):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("pages/001.txt", "one")
        archive.writestr("../escape.txt", "bad")


def test_inspection_and_html(tmp_path):
    path = tmp_path / "book.cbz"
    make_archive(path)
    report = inspect_archive(path)
    assert report["entry_count"] == 2
    assert report["unsafe_paths"] == 1
    assert len(report["sha256"]) == 64
    assert "compression_ratio" in report["entries"][0]
    assert "pages/001.txt" in render_html(build_index(path))
    assert unsafe_member("C:/bad.txt")
    assert not unsafe_member("safe/file.txt")


def test_directory_collects_errors(tmp_path):
    make_archive(tmp_path / "good.zip")
    (tmp_path / "bad.epub").write_text("not a zip", encoding="utf-8")
    index = build_index(tmp_path)
    assert index["archive_count"] == 1
    assert index["error_count"] == 1
    assert index["extension_counts"] == {".txt": 2}
    assert index["largest_entries"][0]["size"] == 3
    with pytest.raises(ValueError, match="unsupported"):
        inspect_archive(tmp_path / "bad.rar")


def test_cli_json_and_safe_output(tmp_path, capsys):
    path = tmp_path / "good.zip"
    make_archive(path)
    assert main([str(path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["archive_count"] == 1
    output = tmp_path / "index.html"
    output.write_text("keep", encoding="utf-8")
    assert main([str(path), "--output", str(output)]) == 2


def test_duplicate_member_names_are_reported(tmp_path):
    path = tmp_path / "duplicates.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("same.txt", "one")
        archive.writestr("same.txt", "two")
    report = inspect_archive(path)
    assert report["duplicate_names"] == ["same.txt"]
    assert report["compressed_bytes"] > 0
