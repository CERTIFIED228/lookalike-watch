import pytest

from lookalike_watch.similarity import edit_distance, similarity


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("paypal", "paypal", 0),
        ("paypal", "paypa", 1),     # omission
        ("paypal", "paypall", 1),   # repetition
        ("paypal", "paypwl", 1),    # replacement
        ("paypal", "papyal", 1),    # transposition counts as one edit
        ("", "abc", 3),
        ("abc", "", 3),
    ],
)
def test_edit_distance(a, b, expected):
    assert edit_distance(a, b) == expected


def test_similarity_is_one_for_identical_strings():
    assert similarity("google", "google") == 1.0


def test_similarity_drops_with_more_edits():
    assert similarity("google", "gooogle") > similarity("google", "gogle-login")


def test_similarity_of_two_empty_strings():
    assert similarity("", "") == 1.0
