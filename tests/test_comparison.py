import copy
import json
import zipfile

import pytest

from archive_contents_indexer.cli import main
from archive_contents_indexer.core import build_index, compare_indexes, render_html


def write(path, entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)


def test_archive_and_occurrence_changes(tmp_path):
    root = tmp_path / "books"
    path = root / "a.zip"
    write(path, [("same", "one"), ("same", "two"), ("remove", "r")])
    write(root / "gone.zip", [("x", "x")])
    before = build_index(root)
    write(path, [("same", "one"), ("same", "changed"), ("added", "a")])
    (root / "gone.zip").unlink()
    write(root / "new.zip", [("x", "x")])
    after = build_index(root)
    diff = compare_indexes(before, after)
    assert diff["archives_added"] == ["new.zip"]
    assert diff["archives_removed"] == ["gone.zip"]
    change = diff["archives_changed"][0]
    assert change["members_changed"][0]["occurrence"] == 2
    assert change["members_added"] == [{"name": "added", "occurrence": 1}]
    assert change["members_removed"] == [{"name": "remove", "occurrence": 1}]
    assert change["fingerprint_changed"]
    assert compare_indexes(after, after)["archives_changed"] == []


def test_nested_identity_and_corrupt_archive_unknown(tmp_path):
    write(tmp_path / "a" / "book.zip", [("x", "x")])
    write(tmp_path / "b" / "book.zip", [("y", "y")])
    before = build_index(tmp_path)
    assert [a["path"] for a in before["archives"]] == ["a/book.zip", "b/book.zip"]
    (tmp_path / "a" / "book.zip").write_bytes(b"broken")
    diff = compare_indexes(before, build_index(tmp_path))
    assert diff["unknown_archives"] == ["a/book.zip"]
    assert diff["archives_removed"] == [] and not diff["complete"]


def test_metadata_only_and_html_escaping(tmp_path):
    write(tmp_path / "a.zip", [("<script>bad</script>", "x")])
    before = build_index(tmp_path)
    after = copy.deepcopy(before)
    after["archives"][0]["entries"][0]["encrypted"] = True
    diff = compare_indexes(before, after)
    assert diff["archives_changed"][0]["members_changed"][0]["fields"] == ["encrypted"]
    assert "do not prove" in diff["interpretation"]
    after["comparison"] = diff
    assert "<script>bad</script>" not in render_html(after)
    assert "&lt;script&gt;" in render_html(after)


@pytest.mark.parametrize(
    "patch",
    [
        {},
        {"version": 2},
        {"version": 1, "archives": [], "errors": "bad"},
        {"version": 1, "archives": [{"path": "a"}], "errors": []},
        {"version": 1, "archives": [{"path": "a", "entries": [{}]}], "errors": []},
        {"version": 1, "archives": [{"path": "a", "entries": [{"name": "x"}]}], "errors": []},
        {"version": 1, "archives": [], "errors": [{}]},
        {"version": 1, "archives": [{}], "errors": []},
    ],
)
def test_malformed_inventory_rejected(patch):
    with pytest.raises((ValueError, TypeError)):
        compare_indexes(patch, {"version": 1, "archives": [], "errors": []})


def test_ambiguous_paths_rejected():
    with pytest.raises(ValueError, match="ambiguous"):
        compare_indexes(
            {"version": 1, "archives": [{"path": "a", "entries": []}] * 2, "errors": []},
            {"version": 1, "archives": [], "errors": []},
        )


def test_cli_compare_and_missing_input(tmp_path, capsys):
    path = tmp_path / "a.zip"
    write(path, [("x", "x")])
    previous = tmp_path / "before.json"
    previous.write_text(json.dumps(build_index(path)), encoding="utf-8")
    assert main([str(path), "--compare", str(previous), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["comparison"]["complete"]
    previous.write_text("{")
    assert main([str(path), "--compare", str(previous)]) == 2
    assert main([str(tmp_path / "missing"), "--compare", str(previous)]) == 2
