import pytest

from lookalike_watch.homoglyphs import skeleton


@pytest.mark.parametrize(
    "spoof, real",
    [
        ("pаypal", "paypal"),      # Cyrillic a
        ("рaypal", "paypal"),      # Cyrillic er looks like p
        ("g00gle", "google"),
        ("paypa1", "paypal"),
        ("rnicrosoft", "microsoft"),
        ("vvikipedia", "wikipedia"),
        ("appӏe", "apple"),        # Cyrillic palochka
    ],
)
def test_skeleton_collapses_lookalikes(spoof, real):
    assert skeleton(spoof) == skeleton(real)


def test_skeleton_leaves_different_words_different():
    assert skeleton("paypal") != skeleton("payfal")


def test_skeleton_is_lowercase():
    assert skeleton("PayPal") == skeleton("paypal")
