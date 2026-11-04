import pytest

from lookalike_watch.scoring import Finding
from lookalike_watch.state import SeenStore, StateError


def make(domain):
    return Finding(domain=domain, ascii=domain, technique="omission", source="permutation",
                   score=50, level="high", reasons=[], a=[], mx=[], ns=[])


def test_everything_is_new_the_first_time(tmp_path):
    store = SeenStore(tmp_path / "seen.json")
    assert [f.ascii for f in store.new([make("a.com"), make("b.com")])] == ["a.com", "b.com"]


def test_remembered_domains_are_not_new_again(tmp_path):
    path = tmp_path / "seen.json"
    store = SeenStore(path)
    store.remember([make("a.com")])
    store.save()

    reopened = SeenStore(path)
    assert [f.ascii for f in reopened.new([make("a.com"), make("c.com")])] == ["c.com"]


def test_first_seen_is_kept_when_seen_again(tmp_path):
    store = SeenStore(tmp_path / "seen.json")
    store.remember([make("a.com")], when="2026-01-01T00:00:00+00:00")
    store.remember([make("a.com")], when="2026-02-01T00:00:00+00:00")
    assert store.first_seen("a.com") == "2026-01-01T00:00:00+00:00"


def test_is_empty_before_anything_saved(tmp_path):
    assert SeenStore(tmp_path / "nope.json").is_empty


def test_corrupt_state_file_raises_clear_error(tmp_path):
    path = tmp_path / "seen.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(StateError):
        SeenStore(path)


def test_save_creates_parent_folders(tmp_path):
    path = tmp_path / "deep" / "dir" / "seen.json"
    store = SeenStore(path)
    store.remember([make("a.com")])
    store.save()
    assert path.exists()
