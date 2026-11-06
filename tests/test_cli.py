import json

import pytest

from lookalike_watch import cli
from lookalike_watch.resolver import DnsRecord

SECRET_URL = "https://discord.com/api/webhooks/123/supersecrettoken"

FAKE_DNS = {
    "paypal.com": DnsRecord(ns=["ns1.brand-dns.net"]),
    "paypl.com": DnsRecord(ns=["ns1.cheap.net"], a=["203.0.113.7"]),
    "paypa.com": DnsRecord(ns=["ns1.cheap.net"], a=["203.0.113.8"]),
}


class FakeSession:
    def __init__(self):
        self.posts = []

    def post(self, url, json=None, timeout=None):
        self.posts.append(json)

        class R:
            status_code = 204
        return R()

    def get(self, *a, **kw):
        raise AssertionError("CT should not be queried in these tests")


@pytest.fixture
def fake_net(monkeypatch):
    session = FakeSession()
    session.lookup_args = []

    def make_lookup(timeout, nameservers=None):
        session.lookup_args.append((timeout, nameservers))
        return FAKE_DNS.get

    monkeypatch.setattr(cli, "make_lookup", make_lookup)
    monkeypatch.setattr(cli, "make_session", lambda: session)
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: None)
    monkeypatch.delenv("LOOKALIKE_WEBHOOK_URL", raising=False)
    return session


def test_generate_prints_candidates(capsys, fake_net):
    assert cli.main(["generate", "paypal.com", "-t", "omission", "--format", "csv"]) == 0
    out = capsys.readouterr().out
    assert "paypl.com" in out
    assert out.splitlines()[0] == "domain,ascii,technique"


def test_scan_json_output(capsys, fake_net):
    assert cli.main(["scan", "paypal.com", "-t", "omission", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {f["ascii"] for f in data["findings"]} == {"paypl.com", "paypa.com"}


def test_scan_writes_to_file(tmp_path, capsys, fake_net):
    out_file = tmp_path / "report.json"
    assert cli.main(["scan", "paypal.com", "-t", "omission", "-o", str(out_file)]) == 0
    assert json.loads(out_file.read_text(encoding="utf-8"))["target"] == "paypal.com"


def test_output_folder_is_created_if_missing(tmp_path, capsys, fake_net):
    out_file = tmp_path / "reports" / "paypal.csv"
    assert cli.main(["scan", "paypal.com", "-t", "omission", "-o", str(out_file)]) == 0
    assert out_file.read_text(encoding="utf-8").startswith("score,level,domain")


def test_min_score_filters(capsys, fake_net):
    cli.main(["scan", "paypal.com", "-t", "omission", "--format", "json", "--min-score", "99"])
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_bad_domain_exits_with_usage_error(capsys, fake_net):
    assert cli.main(["scan", "not a domain"]) == 2
    assert "not a domain" in capsys.readouterr().err


def test_watch_once_alerts_on_new_and_stays_quiet_after(tmp_path, monkeypatch, capsys, fake_net):
    monkeypatch.setenv("LOOKALIKE_WEBHOOK_URL", SECRET_URL)
    state = tmp_path / "seen.json"
    args = ["watch", "paypal.com", "-t", "omission", "--once", "--state", str(state),
            "--min-score", "0"]

    assert cli.main(args) == 0
    assert len(fake_net.posts) == 1
    assert "paypl.com" in fake_net.posts[0]["text"]

    assert cli.main(args) == 0
    assert len(fake_net.posts) == 1     # nothing new second time round

    output = capsys.readouterr()
    assert "supersecrettoken" not in output.out + output.err


def test_watch_baseline_records_without_alerting(tmp_path, monkeypatch, fake_net):
    monkeypatch.setenv("LOOKALIKE_WEBHOOK_URL", SECRET_URL)
    state = tmp_path / "seen.json"
    assert cli.main(["watch", "paypal.com", "-t", "omission", "--once", "--baseline",
                     "--state", str(state), "--min-score", "0"]) == 0
    assert fake_net.posts == []
    assert state.exists()


def test_watch_without_webhook_prints_instead(tmp_path, capsys, fake_net):
    assert cli.main(["watch", "paypal.com", "-t", "omission", "--once",
                     "--state", str(tmp_path / "s.json"), "--min-score", "0"]) == 0
    captured = capsys.readouterr()
    assert "paypl.com" in captured.out
    assert "no webhook" in captured.err.lower()


def test_nameserver_and_timeout_are_passed_through(capsys, fake_net):
    cli.main(["scan", "paypal.com", "-t", "omission", "--nameserver", "1.1.1.1",
              "--timeout", "5"])
    assert fake_net.lookup_args == [(5.0, ["1.1.1.1"])]


def test_lying_resolver_is_detected():
    assert cli.resolver_is_lying(lambda name: DnsRecord(a=["198.51.100.1"]))
    assert not cli.resolver_is_lying(lambda name: None)


def test_lying_resolver_stops_the_scan(monkeypatch, capsys, fake_net):
    monkeypatch.setattr(cli, "make_lookup",
                        lambda timeout, nameservers=None: lambda n: DnsRecord(a=["198.51.100.1"]))
    assert cli.main(["scan", "paypal.com", "-t", "omission"]) == 1
    captured = capsys.readouterr()
    assert "--nameserver" in captured.err
    assert captured.out == ""


def test_failed_alert_is_retried_next_run(tmp_path, monkeypatch, fake_net):
    monkeypatch.setenv("LOOKALIKE_WEBHOOK_URL", SECRET_URL)

    class Broken(FakeSession):
        def post(self, url, json=None, timeout=None):
            class R:
                status_code = 500
            return R()

    monkeypatch.setattr(cli, "make_session", lambda: Broken())
    args = ["watch", "paypal.com", "-t", "omission", "--once",
            "--state", str(tmp_path / "s.json"), "--min-score", "0"]
    assert cli.main(args) == 1

    monkeypatch.setattr(cli, "make_session", lambda: fake_net)
    assert cli.main(args) == 0
    assert len(fake_net.posts) == 1


def test_version_flag(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "0.1.0" in capsys.readouterr().out


def test_output_never_crashes_on_a_non_utf8_console():
    # Windows consoles/redirects often use cp1252, which can't show Cyrillic.
    import os
    import subprocess
    import sys

    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    proc = subprocess.run(
        [sys.executable, "-m", "lookalike_watch", "generate", "paypal.com", "-t", "homoglyph"],
        capture_output=True, env=env,
    )
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
