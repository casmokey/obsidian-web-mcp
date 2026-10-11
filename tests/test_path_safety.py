"""Path traversal, symlink escape, delete/move safety and write safety."""

import json
import os
from pathlib import Path

import pytest

from obsidian_vault_mcp import config
from obsidian_vault_mcp.frontmatter_index import FrontmatterIndex
from obsidian_vault_mcp.tools import search as search_mod
from obsidian_vault_mcp.tools.manage import vault_delete, vault_list, vault_move
from obsidian_vault_mcp.tools.read import vault_batch_read, vault_read
from obsidian_vault_mcp.tools.search import vault_search
from obsidian_vault_mcp.tools.write import vault_batch_frontmatter_update, vault_write
from obsidian_vault_mcp.vault import (
    delete_path,
    list_directory,
    move_path,
    resolve_vault_path,
    write_file_atomic,
)

SECRET = "TOPSECRET-outside-the-vault"


@pytest.fixture
def outside(tmp_path):
    """A directory next to (not inside) the vault, with a secret file in it."""
    out = tmp_path / "outside"
    out.mkdir()
    (out / "secret.md").write_text(f"---\nleak: {SECRET}\n---\n\n{SECRET}\n")
    return out


# ---------------------------------------------------------------- resolve_vault_path
@pytest.mark.parametrize("bad", [
    "../outside/secret.md",
    "subfolder/../../outside/secret.md",
    "..",
    "subfolder/..",           # ".." component is refused outright, even when it stays inside
    "/etc/passwd",            # absolute paths replace the vault root in pathlib joins
    "//etc/passwd",
    ".obsidian/config.json",
    "subfolder/.hidden.md",
    ".git/config",
    ".trash/x.md",
    "...",
])
def test_resolve_rejects_escapes_and_hidden(vault_dir, bad):
    with pytest.raises(ValueError):
        resolve_vault_path(bad)


def test_resolve_rejects_sibling_with_vault_name_prefix(vault_dir):
    """/tmp/x/test-vault-evil must not pass a naive startswith() check against /tmp/x/test-vault."""
    sibling = vault_dir.parent / (vault_dir.name + "-evil")
    sibling.mkdir()
    (sibling / "x.md").write_text("evil")
    (vault_dir / "sib").symlink_to(sibling, target_is_directory=True)
    with pytest.raises(ValueError, match="outside"):
        resolve_vault_path("sib/x.md")


def test_resolve_allows_vault_root_and_nested(vault_dir):
    assert resolve_vault_path("") == vault_dir.resolve()
    assert resolve_vault_path("subfolder/nested-note.md").is_file()


def test_symlinked_file_escape_rejected(vault_dir, outside):
    (vault_dir / "link.md").symlink_to(outside / "secret.md")
    with pytest.raises(ValueError, match="outside"):
        resolve_vault_path("link.md")
    assert "error" in json.loads(vault_read("link.md"))
    batch = json.loads(vault_batch_read(["link.md"]))
    assert batch["found"] == 0 and SECRET not in json.dumps(batch)


def test_symlinked_dir_escape_rejected(vault_dir, outside):
    (vault_dir / "linkdir").symlink_to(outside, target_is_directory=True)
    for p in ("linkdir/secret.md", "linkdir"):
        with pytest.raises(ValueError, match="outside"):
            resolve_vault_path(p)
    assert "error" in json.loads(vault_read("linkdir/secret.md"))
    assert "error" in json.loads(vault_list("linkdir"))


def test_symlink_into_hidden_dir_rejected(vault_dir):
    """A symlink must not be a way round the dotfile rule."""
    (vault_dir / "innocent").symlink_to(vault_dir / ".obsidian", target_is_directory=True)
    with pytest.raises(ValueError, match="hidden"):
        resolve_vault_path("innocent/config.json")
    assert "error" in json.loads(vault_read("innocent/config.json"))
    assert "error" in json.loads(vault_write("innocent/config.json", "{}"))
    assert (vault_dir / ".obsidian" / "config.json").read_text() == '{"theme": "dark"}'


def test_symlink_staying_inside_vault_is_fine(vault_dir):
    (vault_dir / "alias.md").symlink_to(vault_dir / "test-note.md")
    assert "test note" in json.loads(vault_read("alias.md"))["content"]


# ---------------------------------------------------------------- writes
def test_write_outside_vault_refused(vault_dir, outside):
    for p in ("../outside/pwned.md", "/tmp/pwned-by-vault-mcp.md", "subfolder/../../outside/pwned.md"):
        assert "error" in json.loads(vault_write(p, "x"))
    assert not (outside / "pwned.md").exists()
    assert not Path("/tmp/pwned-by-vault-mcp.md").exists()


def test_write_through_symlink_cannot_modify_outside_file(vault_dir, outside):
    (vault_dir / "link.md").symlink_to(outside / "secret.md")
    assert "error" in json.loads(vault_write("link.md", "overwritten"))
    assert SECRET in (outside / "secret.md").read_text()


def test_write_through_symlinked_dir_cannot_create_outside(vault_dir, outside):
    (vault_dir / "linkdir").symlink_to(outside, target_is_directory=True)
    assert "error" in json.loads(vault_write("linkdir/new.md", "x"))
    assert not (outside / "new.md").exists()


def test_write_dotfile_refused(vault_dir):
    assert "error" in json.loads(vault_write(".obsidian/evil.json", "{}"))
    assert "error" in json.loads(vault_write("sub/.env", "X=1"))
    assert not (vault_dir / ".obsidian" / "evil.json").exists()


def test_write_to_vault_root_or_directory_fails_without_damage(vault_dir):
    assert "error" in json.loads(vault_write("subfolder", "x"))
    assert (vault_dir / "subfolder" / "nested-note.md").exists()
    assert not list(vault_dir.parent.glob("*.tmp"))  # no stray temp file left next to the vault


def test_write_leaves_no_temp_file_on_failure(vault_dir, monkeypatch):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        write_file_atomic("new.md", "content")
    assert not list(vault_dir.glob("*.tmp"))
    assert not (vault_dir / "new.md").exists()


def test_write_without_create_dirs_does_not_make_parents(vault_dir):
    r = json.loads(vault_write("nope/deeper/x.md", "x", create_dirs=False))
    assert "error" in r
    assert not (vault_dir / "nope").exists()


def test_write_size_limit_counts_bytes_not_characters(vault_dir, monkeypatch):
    monkeypatch.setattr(config, "MAX_CONTENT_SIZE", 10)
    with pytest.raises(ValueError, match="exceeds"):
        write_file_atomic("big.md", "é" * 6)  # 6 chars, 12 bytes
    assert write_file_atomic("ok.md", "é" * 5)[1] == 10


def test_write_unicode_roundtrip(vault_dir):
    vault_write("uni.md", "naïve — 日本語\n")
    assert json.loads(vault_read("uni.md"))["content"] == "naïve — 日本語\n"


# ---------------------------------------------------------------- frontmatter writes
def test_merge_frontmatter_new_file_writes_as_is(vault_dir):
    r = json.loads(vault_write("fresh.md", "---\na: 1\n---\n\nbody", merge_frontmatter=True))
    assert r["created"] is True
    assert (vault_dir / "fresh.md").read_text().startswith("---\na: 1")


def test_merge_frontmatter_new_values_win_and_body_replaced(vault_dir):
    vault_write("m.md", "---\nstatus: old\nkeep: kept\n---\n\nold body")
    vault_write("m.md", "---\nstatus: new\n---\n\nnew body", merge_frontmatter=True)
    r = json.loads(vault_read("m.md"))
    assert r["frontmatter"] == {"status": "new", "keep": "kept"}
    assert "new body" in r["content"] and "old body" not in r["content"]


def test_merge_frontmatter_bad_yaml_falls_back_to_plain_write(vault_dir):
    vault_write("m.md", "---\nstatus: old\n---\n\nbody")
    r = json.loads(vault_write("m.md", "---\n: : [unclosed\n---\n\nnew", merge_frontmatter=True))
    assert "error" not in r
    assert "new" in (vault_dir / "m.md").read_text()


def test_batch_frontmatter_update_preserves_body_and_reports_per_file(vault_dir):
    r = json.loads(vault_batch_frontmatter_update([
        {"path": "test-note.md", "fields": {"status": "done", "n": 3}},
        {"path": "missing.md", "fields": {"x": 1}},
        {"path": "../outside/secret.md", "fields": {"x": 1}},
        {"path": ".obsidian/config.json", "fields": {"x": 1}},
    ]))["results"]
    assert r[0] == {"path": "test-note.md", "updated": True}
    assert [x["updated"] for x in r[1:]] == [False, False, False]
    fm = json.loads(vault_read("test-note.md"))
    assert fm["frontmatter"]["status"] == "done" and fm["frontmatter"]["n"] == 3
    assert fm["frontmatter"]["type"] == "note"
    assert "This is a test note with some content." in fm["content"]


def test_batch_frontmatter_update_cannot_touch_outside_via_symlink(vault_dir, outside):
    (vault_dir / "link.md").symlink_to(outside / "secret.md")
    r = json.loads(vault_batch_frontmatter_update([{"path": "link.md", "fields": {"pwn": 1}}]))
    assert r["results"][0]["updated"] is False
    assert "pwn" not in (outside / "secret.md").read_text()


# ---------------------------------------------------------------- move
def test_move_refuses_escape_both_ways(vault_dir, outside):
    assert "error" in json.loads(vault_move("test-note.md", "../outside/stolen.md"))
    assert "error" in json.loads(vault_move("../outside/secret.md", "pulled.md"))
    assert (vault_dir / "test-note.md").exists()
    assert (outside / "secret.md").exists() and not (outside / "stolen.md").exists()
    assert not (vault_dir / "pulled.md").exists()


def test_move_refuses_hidden_destination(vault_dir):
    assert "error" in json.loads(vault_move("test-note.md", ".obsidian/note.md"))
    assert "error" in json.loads(vault_move(".obsidian/config.json", "stolen.json"))
    assert (vault_dir / "test-note.md").exists()


def test_move_never_overwrites(vault_dir):
    r = json.loads(vault_move("test-note.md", "no-frontmatter.md"))
    assert "error" in r
    assert "test note" in (vault_dir / "test-note.md").read_text()
    assert "plain text" in (vault_dir / "no-frontmatter.md").read_text()


def test_move_missing_source(vault_dir):
    assert "error" in json.loads(vault_move("ghost.md", "x.md"))


def test_move_vault_root_is_not_possible(vault_dir):
    with pytest.raises(Exception):
        move_path("", "elsewhere")
    assert (vault_dir / "test-note.md").exists()


def test_move_symlink_to_outside_refused(vault_dir, outside):
    (vault_dir / "link.md").symlink_to(outside / "secret.md")
    assert "error" in json.loads(vault_move("link.md", "moved.md"))
    assert (outside / "secret.md").exists()


def test_move_creates_dirs_only_when_asked(vault_dir):
    assert "error" in json.loads(vault_move("test-note.md", "a/b/c.md", create_dirs=False))
    assert not (vault_dir / "a").exists()
    assert json.loads(vault_move("test-note.md", "a/b/c.md"))["moved"] is True


# ---------------------------------------------------------------- delete
def test_delete_without_confirm_changes_nothing(vault_dir):
    r = json.loads(vault_delete("test-note.md"))
    assert "error" in r and (vault_dir / "test-note.md").exists()
    assert not (vault_dir / ".trash").exists()


def test_delete_with_confirm_moves_to_trash_not_unlink(vault_dir):
    assert json.loads(vault_delete("test-note.md", confirm=True))["deleted"] is True
    assert "test note" in (vault_dir / ".trash" / "test-note.md").read_text()


def test_delete_refuses_non_empty_directory_and_root(vault_dir):
    assert "error" in json.loads(vault_delete("subfolder", confirm=True))
    assert "error" in json.loads(vault_delete("", confirm=True))
    assert (vault_dir / "subfolder" / "nested-note.md").exists()


def test_delete_empty_directory_ok(vault_dir):
    (vault_dir / "empty").mkdir()
    assert json.loads(vault_delete("empty", confirm=True))["deleted"] is True
    assert not (vault_dir / "empty").exists()


def test_delete_cannot_reach_outside_or_trash_or_hidden(vault_dir, outside):
    assert "error" in json.loads(vault_delete("../outside/secret.md", confirm=True))
    assert "error" in json.loads(vault_delete(".obsidian/config.json", confirm=True))
    (vault_dir / ".trash").mkdir()
    (vault_dir / ".trash" / "old.md").write_text("old")
    assert "error" in json.loads(vault_delete(".trash/old.md", confirm=True))
    assert (outside / "secret.md").exists()
    assert (vault_dir / ".trash" / "old.md").exists()


def test_delete_symlink_to_outside_refused(vault_dir, outside):
    (vault_dir / "link.md").symlink_to(outside / "secret.md")
    assert "error" in json.loads(vault_delete("link.md", confirm=True))
    assert (outside / "secret.md").exists()


def test_repeated_deletes_never_overwrite_earlier_trash_copies(vault_dir):
    """Same name, same second: every trashed version must survive."""
    for i in range(4):
        (vault_dir / "dup.md").write_text(f"version {i}")
        assert delete_path("dup.md") is True
    kept = sorted(p.read_text() for p in (vault_dir / ".trash").iterdir())
    assert kept == [f"version {i}" for i in range(4)]


# ---------------------------------------------------------------- list
def test_list_hides_excluded_dirs_and_clamps_depth(vault_dir):
    deep = vault_dir / "l1" / "l2" / "l3" / "l4" / "l5" / "l6"
    deep.mkdir(parents=True)
    (deep / "f.md").write_text("x")
    items = list_directory("", depth=99)
    names = {i["name"] for i in items}
    assert {".obsidian", ".git", ".trash"}.isdisjoint(names)
    assert "f.md" not in names  # beyond MAX_LIST_DEPTH


def test_list_does_not_follow_symlinks_out_of_vault(vault_dir, outside):
    (vault_dir / "linkdir").symlink_to(outside, target_is_directory=True)
    (vault_dir / "linkfile.md").symlink_to(outside / "secret.md")
    listing = json.dumps(list_directory("", depth=3))
    assert "linkdir" not in listing and "linkfile" not in listing and "secret" not in listing


def test_list_rejects_escape_and_files(vault_dir):
    assert "error" in json.loads(vault_list("../"))
    assert "error" in json.loads(vault_list("test-note.md"))


def test_list_pattern_and_type_filters(vault_dir):
    only_md = json.loads(vault_list("", depth=2, include_dirs=False, pattern="*.md"))["items"]
    assert only_md and all(i["type"] == "file" and i["name"].endswith(".md") for i in only_md)
    dirs = json.loads(vault_list("", include_files=False))["items"]
    assert [d["name"] for d in dirs] == ["subfolder"]


# ---------------------------------------------------------------- search
def test_search_path_prefix_cannot_escape(vault_dir, outside):
    assert "error" in json.loads(vault_search("TOPSECRET", path_prefix="../outside"))
    assert "error" in json.loads(vault_search("x", path_prefix=".obsidian"))
    assert "error" in json.loads(vault_search("x", path_prefix="test-note.md"))  # not a directory


@pytest.mark.skipif(not __import__("shutil").which("rg"), reason="ripgrep not installed")
def test_search_query_is_never_parsed_as_an_rg_option(vault_dir, tmp_path):
    """A query like --pre=CMD would otherwise make ripgrep execute CMD."""
    marker = tmp_path / "ran"
    script = tmp_path / "pre.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat \"$1\"\n")
    script.chmod(0o755)
    (vault_dir / "dash.md").write_text("literal --pre=thing in a note\n")

    r = json.loads(vault_search(f"--pre={script}"))
    assert not marker.exists()
    assert r["total_matches"] == 0

    # and the text is still findable as a literal
    r = json.loads(vault_search("--pre=thing"))
    assert [m["path"] for m in r["results"]] == ["dash.md"]


@pytest.mark.parametrize("use_rg", [True, False])
def test_search_respects_exclusions_and_symlinks(vault_dir, outside, monkeypatch, use_rg):
    if use_rg and not __import__("shutil").which("rg"):
        pytest.skip("ripgrep not installed")
    if not use_rg:
        monkeypatch.setattr(search_mod.shutil, "which", lambda name: None)
    (vault_dir / "linkfile.md").symlink_to(outside / "secret.md")
    (vault_dir / "linkdir").symlink_to(outside, target_is_directory=True)
    (vault_dir / ".obsidian" / "n.md").write_text(f"{SECRET} hidden config note")
    (vault_dir / "ok.md").write_text("visible TOPSECRET-marker")

    out = json.loads(vault_search("TOPSECRET"))
    assert [m["path"] for m in out["results"]] == ["ok.md"]


def test_search_python_fallback_context_and_limits(vault_dir, monkeypatch):
    monkeypatch.setattr(search_mod.shutil, "which", lambda name: None)
    (vault_dir / "many.md").write_text("\n".join(f"line {i} needle" for i in range(10)))
    out = json.loads(vault_search("NEEDLE", max_results=3, context_lines=1))
    assert out["total_matches"] == 3 and out["truncated"] is True
    assert out["results"][0]["match_context"].count("\n") <= 2


def test_search_frontmatter_index_ignores_symlinks_out_of_vault(vault_dir, outside):
    (vault_dir / "linkfile.md").symlink_to(outside / "secret.md")
    idx = FrontmatterIndex()
    idx.start()
    try:
        assert idx.search_by_field("leak", "", "exists") == []
        assert idx.search_by_field("status", "active", "exact")  # normal files still indexed
        assert idx.search_by_field("theme", "", "exists") == []  # .obsidian not indexed
    finally:
        idx.stop()


def test_search_by_field_match_types(vault_dir):
    idx = FrontmatterIndex()
    idx._index = {"a.md": {"t": "Hello World", "n": 3}, "d/b.md": {"t": "other"}}
    assert [r["path"] for r in idx.search_by_field("t", "Hello World", "exact")] == ["a.md"]
    assert [r["path"] for r in idx.search_by_field("t", "world", "contains")] == ["a.md"]
    assert [r["path"] for r in idx.search_by_field("n", "3", "exact")] == ["a.md"]
    assert [r["path"] for r in idx.search_by_field("t", "", "exists", path_prefix="d/")] == ["d/b.md"]
    assert idx.search_by_field("t", "x", "bogus") == []


# ---------------------------------------------------------------- tool wrappers / models
def test_vault_search_frontmatter_tool_uses_index_and_truncates(vault_dir, monkeypatch):
    from obsidian_vault_mcp import server
    from obsidian_vault_mcp.tools.search import vault_search_frontmatter

    idx = FrontmatterIndex()
    idx._index = {f"n{i}.md": {"type": "note", "title": f"T{i}"} for i in range(5)} | {"x.md": {"type": "note"}}
    monkeypatch.setattr(server, "frontmatter_index", idx)
    out = json.loads(vault_search_frontmatter("type", "note", "exact", max_results=3))
    assert out["total"] == 3 and out["truncated"] is True
    assert out["results"][0]["title"] == "T0"
    out = json.loads(vault_search_frontmatter("type", "note", "exact", max_results=50))
    assert {r["title"] for r in out["results"]} >= {"x", "T4"}  # falls back to the file stem


def test_batch_read_without_content_omits_body(vault_dir):
    r = json.loads(vault_batch_read(["test-note.md", "../x", ".obsidian/config.json"], include_content=False))
    assert "content" not in r["files"][0] and r["files"][0]["frontmatter"]["status"] == "active"
    assert r["found"] == 1 and r["missing"] == 2


def test_read_directory_and_missing(vault_dir):
    assert "error" in json.loads(vault_read("subfolder"))
    assert "not found" in json.loads(vault_read("ghost.md"))["error"].lower()


def test_batch_update_model_validation():
    from pydantic import ValidationError
    from obsidian_vault_mcp.models import VaultBatchFrontmatterUpdateInput as M
    assert M(updates=[{"path": "a.md", "fields": {}}])
    for bad in ([{"fields": {}}], [{"path": 1, "fields": {}}], [{"path": "a.md"}], [{"path": "a.md", "fields": "x"}], []):
        with pytest.raises(ValidationError):
            M(updates=bad)
    with pytest.raises(ValidationError):
        M(updates=[{"path": "a.md", "fields": {}}] * 21)
