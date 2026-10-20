import copy
import hashlib
import zipfile
from pathlib import Path

import pytest

from archive_contents_indexer.cli import main
from archive_contents_indexer.core import build_index, compare_indexes, inspect_archive


def inventory(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("sample.txt", "test")
    return archive, build_index(archive)


@pytest.mark.parametrize(
    "field,value",
    [
        ("size", True),
        ("size", -1),
        ("size", "4"),
        ("compressed_size", False),
        ("compressed_size", -2),
        ("directory", 0),
        ("encrypted", "false"),
        ("unsafe_path", None),
        ("crc32", "no"),
        ("crc32", 123),
        ("compression_ratio", float("nan")),
        ("compression_ratio", float("inf")),
        ("compression_ratio", -1),
        ("compression_ratio", True),
    ],
)
def test_malformed_member_metadata_is_rejected(tmp_path, field, value):
    _, current = inventory(tmp_path)
    previous = copy.deepcopy(current)
    previous["archives"][0]["entries"][0][field] = value
    with pytest.raises((TypeError, ValueError)):
        compare_indexes(previous, current)


@pytest.mark.parametrize("fingerprint", [None, 12, "short", "z" * 64])
def test_invalid_fingerprints_are_rejected(tmp_path, fingerprint):
    _, current = inventory(tmp_path)
    previous = copy.deepcopy(current)
    previous["archives"][0]["sha256"] = fingerprint
    with pytest.raises(ValueError, match="SHA-256"):
        compare_indexes(previous, current)


def test_legacy_fingerprints_and_version_types(tmp_path):
    _, current = inventory(tmp_path)
    previous = copy.deepcopy(current)
    del previous["archives"][0]["sha256"]
    assert compare_indexes(previous, previous)["complete"]
    previous["version"] = True
    with pytest.raises(ValueError, match="version 1"):
        compare_indexes(previous, current)
    previous["version"] = 1
    previous["archives"][0]["path"] = ""
    with pytest.raises(ValueError, match="empty"):
        compare_indexes(previous, current)


def test_hashing_does_not_read_whole_archive(tmp_path, monkeypatch):
    archive, _ = inventory(tmp_path)
    expected = hashlib.sha256(archive.read_bytes()).hexdigest()

    def forbidden(*args, **kwargs):
        raise AssertionError("unbounded Path.read_bytes")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    assert inspect_archive(archive)["sha256"] == expected


def test_new_report_and_concurrent_creation(tmp_path, monkeypatch):
    archive, _ = inventory(tmp_path)
    output = tmp_path / "report.json"
    assert main([str(archive), "--format", "json", "--output", str(output)]) == 0
    original = Path.open
    raced = tmp_path / "raced.json"

    def competing_open(path, mode="r", *args, **kwargs):
        if path == raced and mode == "x":
            with original(path, "w", encoding="utf-8") as stream:
                stream.write("keep concurrent file")
        return original(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", competing_open)
    assert main([str(archive), "--output", str(raced)]) == 2
    assert raced.read_text() == "keep concurrent file"


def test_dangling_report_symlink_is_preserved(tmp_path):
    archive, _ = inventory(tmp_path)
    output = tmp_path / "report.json"
    missing = tmp_path / "missing.json"
    try:
        output.symlink_to(missing)
    except OSError:
        pytest.skip("symlinks unavailable")
    assert main([str(archive), "--output", str(output)]) == 2
    assert output.is_symlink() and not missing.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("archive_count", True),
        ("archive_count", 0),
        ("error_count", 2),
        ("scan_complete", False),
        ("scan_complete", 1),
    ],
)
def test_inconsistent_inventory_summary_rejected(tmp_path, field, value):
    _, current = inventory(tmp_path)
    previous = copy.deepcopy(current)
    previous[field] = value
    with pytest.raises(ValueError, match="disagrees"):
        compare_indexes(previous, current)


def test_large_finite_integer_ratio(tmp_path):
    _, current = inventory(tmp_path)
    previous = copy.deepcopy(current)
    previous["archives"][0]["entries"][0]["compression_ratio"] = 10**1000
    assert compare_indexes(previous, current)["complete"]


def test_hexadecimal_case_does_not_invent_changes(tmp_path):
    _, current = inventory(tmp_path)
    previous = copy.deepcopy(current)
    previous["archives"][0]["sha256"] = previous["archives"][0]["sha256"].upper()
    previous["archives"][0]["entries"][0]["crc32"] = previous["archives"][0]["entries"][0][
        "crc32"
    ].upper()
    assert compare_indexes(previous, current)["archives_changed"] == []
