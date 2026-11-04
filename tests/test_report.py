import csv
import io
import json

from lookalike_watch.report import as_csv, as_json, as_table
from lookalike_watch.scoring import Finding


def make(domain, score, level):
    return Finding(
        domain=domain, ascii=domain, technique="omission", source="permutation",
        score=score, level=level, reasons=["reason one", "reason two"],
        a=["203.0.113.7"], mx=[], ns=["ns1.x"],
    )


FINDINGS = [make("low.com", 10, "low"), make("bad.com", 90, "critical")]


def test_table_sorts_worst_first():
    out = as_table(FINDINGS)
    assert out.index("bad.com") < out.index("low.com")
    assert "critical" in out


def test_table_with_nothing_found():
    assert "No lookalike domains" in as_table([])


def test_json_round_trip():
    data = json.loads(as_json(FINDINGS, target="example.com"))
    assert data["target"] == "example.com"
    assert data["findings"][0]["domain"] == "bad.com"
    assert data["findings"][0]["reasons"] == ["reason one", "reason two"]
    assert "generated_at" in data


def test_csv_has_header_and_rows():
    rows = list(csv.DictReader(io.StringIO(as_csv(FINDINGS))))
    assert rows[0]["domain"] == "bad.com"
    assert rows[0]["score"] == "90"
    assert rows[0]["reasons"] == "reason one; reason two"
